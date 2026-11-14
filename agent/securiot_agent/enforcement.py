"""Enforcement boundary. Only the in-memory simulation backend exists today."""

from typing import Protocol


class Enforcer(Protocol):
    simulated: bool

    def apply(self, action: str, mac: str) -> None: ...


class MockEnforcer:
    simulated = True

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.restrictions: dict[str, str] = {}

    def apply(self, action: str, mac: str) -> None:
        if action not in {"block_wan", "quarantine", "restore"}:
            raise ValueError(f"Mock enforcer does not support {action!r}")
        self.calls.append((action, mac))
        if action == "restore":
            self.restrictions.pop(mac, None)
        else:
            self.restrictions[mac] = "blocked" if action == "block_wan" else "quarantined"


import re
import subprocess

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class PiEnforcer:
    """Real enforcement on a Pi that is the router and the Wi-Fi AP. Needs root,
    nftables, and hostapd with ctrl_interface and macaddr_acl=0.
    block_wan -> drop its traffic toward the uplink (LAN still works)
    quarantine -> block_wan + drop everything it forwards + hostapd deny list + deauth
    restore -> undo all of it. Every call is idempotent."""

    simulated = False

    def __init__(self, wan_if="eth0", ap_if="wlan0", run=None):
        self.wan_if, self.ap_if = wan_if, ap_if
        self.run = run or self._run
        self.run(["nft", "delete", "table", "inet", "securiot"], check=False)
        self.run(["nft", "-f", "-"], input=f"""
table inet securiot {{
  set wan_blocked {{ type ether_addr; }}
  set isolated {{ type ether_addr; }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    ether saddr @isolated drop
    ether saddr @wan_blocked oifname "{wan_if}" drop
  }}
}}
""")

    @staticmethod
    def _run(command, input=None, check=True):
        done = subprocess.run(command, input=input, text=True, capture_output=True, timeout=5)
        output = (done.stdout or "") + (done.stderr or "")
        if check and (done.returncode != 0 or output.strip().startswith("FAIL")):
            raise RuntimeError(f"{command[0]} failed: {output.strip()[:200]}")
        return output

    def _element(self, verb, name, mac, check=True):
        self.run(["nft", verb, "element", "inet", "securiot", name, f"{{ {mac} }}"], check=check)

    def apply(self, action, mac):
        mac = mac.lower()
        if not _MAC.match(mac):
            raise ValueError("Invalid MAC address")
        if action == "block_wan":
            self._element("add", "wan_blocked", mac)
        elif action == "quarantine":
            self._element("add", "wan_blocked", mac)
            self._element("add", "isolated", mac)
            self.run(["hostapd_cli", "-i", self.ap_if, "deny_acl", "ADD_MAC", mac])
            self.run(["hostapd_cli", "-i", self.ap_if, "deauthenticate", mac], check=False)
        elif action == "restore":
            self._element("delete", "wan_blocked", mac, check=False)
            self._element("delete", "isolated", mac, check=False)
            self.run(["hostapd_cli", "-i", self.ap_if, "deny_acl", "DEL_MAC", mac], check=False)
        else:
            raise ValueError(f"PiEnforcer does not support {action!r}")
