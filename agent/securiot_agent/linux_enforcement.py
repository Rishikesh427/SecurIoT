"""Explicit Linux hotspot enforcement. Own tables/ACL entries only; no shell."""
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time

from .models import normalize_mac
from .storage import Storage

OWNER = "SecurIoT agent v1"
TABLE = "securiot_guard"


def unicast_mac(value):
    if not isinstance(value, str):
        raise ValueError("MAC must be a string")
    mac = normalize_mac(value)
    if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
        raise ValueError("A device must have a nonzero unicast MAC")
    return mac


HOSTAPD_KEYS = {"ap_interface", "wan_interface", "hostapd_control", "hostapd_config", "protected_macs"}
# An AP run by NetworkManager/wpa_supplicant has no hostapd control socket or deny
# list: stations are removed with nl80211 (`iw ... station del`) and kept out by
# the firewall drop plus a re-kick whenever they reassociate.
NL80211_KEYS = {"ap_interface", "wan_interface", "wifi_control", "protected_macs"}


class LinuxConfig:
    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError("Linux config must be a JSON object")
        if set(data) == NL80211_KEYS and data["wifi_control"] == "nl80211":
            self.wifi_control = "nl80211"
            required = NL80211_KEYS
        elif set(data) == HOSTAPD_KEYS:
            self.wifi_control = "hostapd"
            required = HOSTAPD_KEYS
        else:
            raise ValueError("Linux config requires exactly: " + ", ".join(sorted(HOSTAPD_KEYS))
                             + ' (hostapd) or ' + ", ".join(sorted(NL80211_KEYS)) + ' with "wifi_control": "nl80211"')
        for key in ("ap_interface", "wan_interface"):
            value = data[key]
            if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", value):
                raise ValueError("Invalid interface name")
            setattr(self, key, value)
        if self.ap_interface == self.wan_interface:
            raise ValueError("AP and WAN interfaces must differ")
        for key in ("hostapd_control", "hostapd_config"):
            if key not in data:
                setattr(self, key, None)
                continue
            if not isinstance(data[key], str) or not Path(data[key]).is_absolute():
                raise ValueError("hostapd paths must be absolute")
            setattr(self, key, data[key])
        if not isinstance(data["protected_macs"], list) or not data["protected_macs"]:
            raise ValueError("Configure at least one protected controller MAC")
        self.protected_macs = {unicast_mac(mac) for mac in data["protected_macs"]}
        self.identity = {key: data[key] for key in required - {"protected_macs"}}

    @classmethod
    def load(cls, path):
        return cls(json.loads(Path(path).read_text()))


class EnforcementError(RuntimeError):
    """A requested outcome is unconfirmed; the journal retains recovery intent."""


class LinuxEnforcer:
    simulated = False

    def __init__(self, config, state_dir, devices, *, run=subprocess.run, recovery=False):
        self.config, self.run = config, run
        self.allowed = {unicast_mac(d.mac) for d in devices}
        self.protected = config.protected_macs | {d.mac for d in devices if d.protected}
        self.storage = Storage(Path(state_dir))
        self.path = Path(state_dir) / "enforcement.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = (Path(state_dir) / "enforcement.lock").open("a")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.state = self._load()
            if platform.system() != "Linux" or os.geteuid() != 0:
                raise ValueError("Real enforcement requires Linux and root")
            if not recovery:
                self.preflight()
        except BaseException:
            self.close()
            raise

    def close(self):
        if getattr(self, "lock", None) is not None:
            self.lock.close()
            self.lock = None

    def _load(self):
        if not self.path.exists():
            return {"version": 1, "identity": self.config.identity, "desired": {}, "confirmed": {},
                    "owned_deny": [], "pending": False}
        state = json.loads(self.path.read_text())
        if state.get("version") != 1 or state.get("identity") != self.config.identity or type(state.get("pending")) is not bool:
            raise ValueError("Enforcement journal belongs to a different hotspot or is invalid")
        for field in ("desired", "confirmed"):
            if not isinstance(state.get(field), dict):
                raise ValueError("Invalid enforcement journal")
            for mac, action in state[field].items():
                if unicast_mac(mac) != mac or action not in {"blocked", "quarantined"}:
                    raise ValueError("Invalid enforcement journal restriction")
        if not isinstance(state.get("owned_deny"), list) or any(unicast_mac(m) != m for m in state["owned_deny"]):
            raise ValueError("Invalid owned deny list")
        return state

    def save(self):
        # Reuse the same fsync + atomic replace implementation as runtime snapshots.
        original = self.storage.state_path
        self.storage.state_path = self.path
        try:
            self.storage.save_state(self.state)
        finally:
            self.storage.state_path = original

    def command(self, args, *, input=None):
        try:
            result = self.run(args, input=input, text=True, capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EnforcementError("Enforcement command unavailable or timed out") from error
        if result.returncode:
            raise EnforcementError("Enforcement command failed: " + args[0])
        return result.stdout.strip()

    def hostapd(self, *args):
        return self.command(["hostapd_cli", "-p", self.config.hostapd_control,
                             "-i", self.config.ap_interface, *args])

    def _ok(self, *args):
        if self.hostapd(*args) != "OK":
            raise EnforcementError("hostapd rejected " + args[0])

    def _macs(self, *args):
        output = self.hostapd(*args)
        if "FAIL" in output or "UNKNOWN COMMAND" in output:
            raise EnforcementError("hostapd does not support " + args[0])
        return {line.split()[0].lower() for line in output.splitlines()
                if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?:\s.*)?", line)}

    @property
    def nl80211(self):
        return self.config.wifi_control == "nl80211"

    def denied(self):
        """MACs currently refused by the Wi-Fi layer."""
        # Without hostapd there is no AP deny list; our own re-kick list is the denial.
        return set(self.state["owned_deny"]) if self.nl80211 else self._macs("deny_acl", "SHOW")

    def _deny(self, mac):
        if not self.nl80211:
            self._ok("deny_acl", "ADD_MAC", mac)

    def _allow(self, mac):
        if not self.nl80211:
            self._ok("deny_acl", "DEL_MAC", mac)

    def _kick(self, mac):
        if self.nl80211:
            self.command(["iw", "dev", self.config.ap_interface, "station", "del", mac])
        else:
            self._ok("deauthenticate", mac)

    def stations(self):
        if not self.nl80211:
            return self._macs("all_sta")
        output = self.command(["iw", "dev", self.config.ap_interface, "station", "dump"])
        return {m.lower() for m in re.findall(r"^Station\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", output, re.M)}

    def maintain(self):
        """Re-kick quarantined stations that reassociated (nl80211 has no deny list).

        Their traffic is already dropped by the firewall; this keeps them from
        holding an association, and limits any direct client-to-client window."""
        if not self.nl80211 or not self.state["owned_deny"]:
            return []
        kicked = []
        present = self.stations()
        for mac in self.state["owned_deny"]:
            if mac in present:
                self._kick(mac)
                kicked.append(mac)
        return kicked

    def connected(self, mac):
        if self.nl80211:
            return mac in self.stations()
        if mac not in self._macs("all_sta"):
            return False
        # hostapd may retain a station record after deauth. Data authorization,
        # not disappearance of that historical record, determines connection state.
        info = self.hostapd("sta", mac)
        match = re.search(r"^flags=(.*)$", info, flags=re.MULTILINE)
        if match is None:
            raise EnforcementError("Cannot verify hostapd station authorization")
        return "[ASSOC]" in match[1] or "[AUTHORIZED]" in match[1]

    def ruleset(self, *, recovery=False):
        result = json.loads(self.command(["nft", "-j", "list", "ruleset"]))
        existing = set()
        for item in result["nftables"]:
            if "flowtable" in item and not recovery:
                raise EnforcementError("Disable flowtable offload on the demo router before enabling enforcement")
            table = item.get("table", {})
            if table.get("name") == TABLE and table.get("family") in {"inet", "netdev"}:
                if table.get("comment") != OWNER:
                    raise EnforcementError("Refusing to replace a table not owned by SecurIoT")
                existing.add(table["family"])
        return existing

    def preflight(self):
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise ValueError("Real enforcement requires Linux and root")
        links = json.loads(self.command(["ip", "-j", "-d", "link", "show"]))
        indexed = {link["ifname"]: link for link in links}
        for name in (self.config.ap_interface, self.config.wan_interface):
            if name not in indexed:
                raise ValueError("Missing hotspot interface: " + name)
            link = indexed[name]
            if link.get("master") or link.get("linkinfo", {}).get("info_kind") == "bridge":
                raise ValueError("This backend requires an unbridged, routed AP and WAN")
        self.protected |= {link["address"].lower() for link in links if "address" in link}
        if self.nl80211:
            info = self.command(["iw", "dev", self.config.ap_interface, "info"])
            if not re.search(r"^\s*type AP\s*$", info, re.M):
                raise ValueError("nl80211 control requires the AP interface to be in AP mode")
            self.stations()
            self.ruleset()
            return
        settings = {}
        for line in Path(self.config.hostapd_config).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                if key.strip() in {"bss", "include"}:
                    raise ValueError("Use a dedicated single-BSS hostapd configuration")
                settings[key.strip()] = value.strip()
        if (settings.get("interface") != self.config.ap_interface or settings.get("macaddr_acl") != "0"
                or settings.get("ctrl_interface") != self.config.hostapd_control):
            raise ValueError("hostapd must match AP/control path and explicitly set macaddr_acl=0")
        if self.hostapd("ping") != "PONG":
            raise EnforcementError("hostapd control socket is not responding")
        self._macs("deny_acl", "SHOW")
        self._macs("all_sta")
        self.ruleset()

    def render(self, existing):
        ap, wan = self.config.ap_interface, self.config.wan_interface
        quarantine = sorted(m for m, status in self.state["desired"].items() if status == "quarantined")
        blocked = sorted(self.state["desired"])
        def elements(macs):
            return " elements = { " + ", ".join(macs) + " };" if macs else ""
        deletes = "\n".join(f"delete table {family} {TABLE}" for family in sorted(existing))
        return deletes + f'''
table netdev {TABLE} {{
 comment "{OWNER}"
 set quarantine {{ type ether_addr;{elements(quarantine)} }}
 set wan_blocked {{ type ether_addr;{elements(blocked)} }}
 chain ap_in {{
  type filter hook ingress device "{ap}" priority -500; policy accept;
  ether saddr @quarantine counter drop
 }}
 chain ap_out {{
  type filter hook egress device "{ap}" priority -500; policy accept;
  ether daddr @quarantine counter drop
  meta iifname "{wan}" ether daddr @wan_blocked counter drop
 }}
}}
table inet {TABLE} {{
 comment "{OWNER}"
 set wan_blocked {{ type ether_addr;{elements(blocked)} }}
 chain wan_forward {{
  type filter hook forward priority -10; policy accept;
  iifname "{ap}" oifname "{wan}" ether saddr @wan_blocked counter drop
 }}
}}
'''

    def _firewall(self):
        script = self.render(self.ruleset())
        self.command(["nft", "-c", "-f", "-"], input=script)
        self.command(["nft", "-f", "-"], input=script)  # One atomic transaction, including replacement.

    @property
    def restrictions(self):
        return dict(self.state["confirmed"])

    def reconcile(self):
        # Configuration removals/protection release only restrictions owned by us.
        self.state["desired"] = {m: s for m, s in self.state["desired"].items()
                                 if m in self.allowed and m not in self.protected}
        self.state["pending"] = True
        self.save()
        self._firewall()
        wanted = {m for m, status in self.state["desired"].items() if status == "quarantined"}
        denied = self.denied()
        owned = set(self.state["owned_deny"])
        for mac in sorted(owned - wanted):
            if mac in denied:
                self._allow(mac)
            owned.remove(mac)
            self.state["owned_deny"] = sorted(owned)
            if mac in self.denied():
                raise EnforcementError("Wi-Fi restore could not be verified")
            self.save()
        for mac in sorted(wanted):
            if mac in denied and mac not in owned:
                raise EnforcementError("Target already has an external Wi-Fi deny entry; not taking ownership")
            owned.add(mac)
            self.state["owned_deny"] = sorted(owned)
            self.save()  # Intent is durable even if the command response is lost.
            if mac not in denied:
                self._deny(mac)
            if mac not in self.denied():
                raise EnforcementError("Wi-Fi deny entry could not be verified")
            if self.connected(mac):
                self._kick(mac)
            for _ in range(60):
                if not self.connected(mac):
                    break
                time.sleep(0.1)
            else:
                raise EnforcementError("Station is still connected after quarantine")
        self.state["confirmed"] = dict(self.state["desired"])
        self.state["pending"] = False
        self.save()

    @property
    def pending_macs(self):
        return set(self.state["desired"]) | set(self.state["owned_deny"]) if self.state["pending"] else set()

    def apply(self, action, mac):
        mac = unicast_mac(mac)
        if action not in {"block_wan", "quarantine", "restore"}:
            raise ValueError("Unsupported Linux enforcement action")
        if mac not in self.allowed:
            raise ValueError("Unknown device")
        if action != "restore" and mac in self.protected:
            raise ValueError("Protected device")
        if action == "restore":
            # Do not pretend to restore access if an administrator owns the ban.
            if mac in self.denied() and mac not in self.state["owned_deny"]:
                raise EnforcementError("Device has an external Wi-Fi deny entry; left unchanged")
            self.state["desired"].pop(mac, None)
        else:
            self.state["desired"][mac] = "blocked" if action == "block_wan" else "quarantined"
        self.reconcile()

    def panic(self):
        # Works even if the AP interface/config vanished. No re-creation of chains.
        self.state["desired"] = {}
        self.state["pending"] = True
        self.save()
        existing = self.ruleset(recovery=True)
        if existing:
            script = "\n".join(f"delete table {family} {TABLE}" for family in sorted(existing)) + "\n"
            self.command(["nft", "-f", "-"], input=script)
        for mac in list(self.state["owned_deny"]):
            if not self.nl80211:
                if mac in self._macs("deny_acl", "SHOW"):
                    self._ok("deny_acl", "DEL_MAC", mac)
                if mac in self._macs("deny_acl", "SHOW"):
                    raise EnforcementError("Firewall cleared, but Wi-Fi deny cleanup remains pending")
            self.state["owned_deny"].remove(mac)  # nl80211: dropping it stops the re-kicks
            self.save()
        self.state["confirmed"] = {}
        self.state["pending"] = False
        self.save()
