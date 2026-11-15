"""Passive identification of discovered devices.

Everything here is INFERRED from what a device volunteers on the network (its MAC
vendor prefix, DHCP hostname / vendor class, ports it answers on). None of it is
verified, and guests control all of it, so it never changes a risk score by itself.
Strings are reduced to a safe character set because they reach the dashboard and
the AI advisor.
"""
import re

try:  # Optional: pip install netaddr (bundles the IEEE OUI registry; works offline).
    from netaddr import EUI
    from netaddr.core import NotRegisteredError
except ImportError:  # pragma: no cover - exercised only when netaddr is absent
    EUI = None
    NotRegisteredError = ()

OUI_AVAILABLE = EUI is not None
_UNSAFE = re.compile(r"[^A-Za-z0-9 ._'\u2019-]")
MAX_PORTS = 32

# Change these labels here if the shared cloud contract uses a different vocabulary.
PHONE, TABLET, LAPTOP, MICRO, SBC = "phone", "tablet", "laptop", "microcontroller", "sbc"

# (substring of the lowercase DHCP hostname, type, label). First match wins.
HOSTNAME_RULES = (
    ("arduino", MICRO, "Arduino-style board"),
    ("esp32", MICRO, "ESP32 board"),
    ("esp8266", MICRO, "ESP8266 board"),
    ("espressif", MICRO, "Espressif (ESP32/ESP8266) board"),
    ("nodemcu", MICRO, "NodeMCU (ESP8266) board"),
    ("wemos", MICRO, "Wemos/ESP board"),
    ("iphone", PHONE, "iPhone"),
    ("ipad", TABLET, "iPad"),
    ("macbook", LAPTOP, "MacBook"),
    ("galaxy-tab", TABLET, "Samsung Galaxy tablet"),
    ("galaxy", PHONE, "Samsung Galaxy phone"),
    ("pixel", PHONE, "Google Pixel phone"),
    ("oneplus", PHONE, "OnePlus phone"),
    ("redmi", PHONE, "Xiaomi/Redmi phone"),
    ("android", PHONE, "Android device"),
)
HOSTNAME_PREFIX_RULES = (  # ESP8266's lwIP default hostname is "ESP-<last 3 MAC bytes>".
    ("esp-", MICRO, "ESP8266 board"),
    ("esp_", MICRO, "ESP board"),
)
VENDOR_RULES = (  # substring of the registered OUI organisation, lowercase.
    ("espressif", MICRO, "ESP32/ESP8266 module"),
    ("arduino", MICRO, "Arduino board"),
    ("gheo", MICRO, "Arduino Ethernet shield"),
    ("raspberry pi", SBC, "Raspberry Pi"),
)
# Arduino example sketches ship this MAC; many unrelated boards share it.
EXAMPLE_MAC_PREFIXES = (("de:ad:be:ef", MICRO, "Arduino-style board (example-sketch MAC)"),)


def safe_text(value, limit=40):
    """Printable ASCII-ish text only: guest-controlled strings must not smuggle
    instructions, markup or control characters into the dashboard or advisor."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("ascii", errors="ignore")
    return _UNSAFE.sub("", str(value or ""))[:limit].strip()


def is_randomized(mac):
    """Locally administered bit: private/randomized phone MACs and DIY firmware."""
    return bool(int(mac[:2], 16) & 2)


def oui_vendor(mac):
    if EUI is None or is_randomized(mac):
        return None
    try:
        return safe_text(EUI(mac).oui.registration().org, 60) or None
    except (NotRegisteredError, ValueError, TypeError, IndexError):
        return None


def classify(mac, hostname=None, vendor_class=None, vendor=None):
    """Return an inference dict (never raises). Confidence is 'medium' only when the
    MAC prefix is registered to the vendor; names and DHCP strings are 'low'."""
    host = (hostname or "").lower()
    klass = (vendor_class or "").lower()
    kind = label = None
    confidence = "low"
    basis = []
    if vendor:
        basis.append(f"MAC prefix registered to {vendor}")
        for needle, rule_type, rule_label in VENDOR_RULES:
            if needle in vendor.lower():
                kind, label, confidence = rule_type, rule_label, "medium"
                break
    if hostname:
        basis.append(f"DHCP hostname '{hostname}'")
        if kind is None:
            for needle, rule_type, rule_label in HOSTNAME_RULES:
                if needle in host:
                    kind, label = rule_type, rule_label
                    break
            else:
                for prefix, rule_type, rule_label in HOSTNAME_PREFIX_RULES:
                    if host.startswith(prefix):
                        kind, label = rule_type, rule_label
                        break
    if vendor_class:
        basis.append(f"DHCP vendor class '{vendor_class}'")
        if kind is None and klass.startswith("android-dhcp"):
            kind, label = PHONE, "Android device"
        elif kind is None and klass.startswith("msft"):
            kind, label = LAPTOP, "Windows PC"
    if kind is None:
        for prefix, rule_type, rule_label in EXAMPLE_MAC_PREFIXES:
            if mac.startswith(prefix):
                kind, label = rule_type, rule_label
                basis.append("MAC matches a common Arduino example sketch")
    randomized = is_randomized(mac)
    if randomized and vendor is None:
        basis.append("private/randomized MAC: vendor cannot be read from the address")
    return {"vendor": vendor, "type": kind, "label": label, "basis": basis,
            "confidence": confidence, "randomized_mac": randomized,
            "hostname": hostname or None, "dhcp_vendor_class": vendor_class or None}


class Fingerprints:
    """Per-MAC hints gathered from packets, DHCP leases and the saved discovery cache."""

    def __init__(self, max_macs=4096):
        self.hints = {}
        self._facts = {}
        self.max_macs = max_macs

    def update(self, mac, *, hostname=None, vendor_class=None, port=None, ports=()):
        if mac not in self.hints and len(self.hints) >= self.max_macs:
            return False  # a spoofing guest must not grow memory without bound
        hint = self.hints.setdefault(mac, {"hostname": None, "vendor_class": None, "ports": set()})
        changed = False
        hostname, vendor_class = safe_text(hostname) or None, safe_text(vendor_class, 60) or None
        if hostname and hint["hostname"] != hostname:
            hint["hostname"], changed = hostname, True
        if vendor_class and hint["vendor_class"] != vendor_class:
            hint["vendor_class"], changed = vendor_class, True
        candidates = list(ports or ()) + ([port] if port is not None else [])
        for value in candidates:
            if (type(value) is int and 1 <= value <= 65535 and value not in hint["ports"]
                    and len(hint["ports"]) < MAX_PORTS):
                hint["ports"].add(value)
                changed = True
        if changed:
            self._facts.pop(mac, None)
        return changed

    def facts(self, mac):
        """Values for Device.risk_facts: {'inferred': {...}, 'observed_ports': [...]}."""
        if mac not in self._facts:
            hint = self.hints.get(mac, {"hostname": None, "vendor_class": None, "ports": set()})
            self._facts[mac] = {
                "inferred": classify(mac, hint["hostname"], hint["vendor_class"], oui_vendor(mac)),
                "observed_ports": sorted(hint["ports"]),
            }
        return self._facts[mac]

    def saved(self, mac):
        hint = self.hints.get(mac)
        if not hint:
            return {}
        return {"hostname": hint["hostname"], "dhcp_vendor_class": hint["vendor_class"],
                "ports": sorted(hint["ports"])}
