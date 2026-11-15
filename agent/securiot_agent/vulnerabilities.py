"""Conservative, offline evidence flags; no exploit or remote login is attempted."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re

from securiot_ml.score import score_device
import securiot_ml

SERVICES = {21: "FTP", 23: "Telnet", 2323: "Telnet", 445: "SMB", 1900: "UPnP/SSDP",
            5000: "UPnP candidate", 5555: "ADB candidate", 7547: "TR-069 candidate"}


def identity(value):
    return re.sub(r"[^a-z0-9]", "", (value or "").casefold())


class VulnerabilityAssessor:
    def __init__(self, catalog=None):
        if catalog is None:
            path = Path(securiot_ml.__file__).resolve().parent.parent / "data/kev.json"
            catalog = json.loads(path.read_text())
        self.catalog = catalog
        self.index = {}
        for row in catalog.get("vulnerabilities", []):
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", row.get("cveID", "")):
                key = (identity(row.get("vendorProject")), identity(row.get("product")))
                self.index.setdefault(key, []).append(row)

    def assess(self, device, anomaly=0):
        facts = dict(device.risk_facts)
        for key in ("eol", "default_creds", "cloud_only"):
            if facts.get(key) is not None and type(facts[key]) is not bool:
                raise ValueError(f"{key} must be boolean or unknown")
        ports_input = facts.get("ports", [])
        if not isinstance(ports_input, list) or any(type(port) is not int or not 1 <= port <= 65535 for port in ports_input):
            raise ValueError("Invalid reported ports")
        persona = facts.pop("persona", {})
        if persona and not device.simulated:
            raise ValueError("Simulation personas cannot describe a real device")
        profile = {**facts, **persona}
        simulated = bool(persona) or facts.pop("_simulated_facts", False) is True
        flags = []
        def flag(category, summary, evidence, status=None):
            flags.append({"category": category, "status": status or ("simulated" if simulated else "reported"),
                          "summary": summary, "evidence": evidence})
        # Passive discovery (identify.py) supplies inferred identity and ports the device answered
        # on. They are reported as such and never feed KEV matching or the vendor/type score inputs.
        inferred = facts.pop("inferred", None)
        inferred = inferred if isinstance(inferred, dict) else {}
        observed_input = facts.pop("observed_ports", None)
        observed = {p for p in (observed_input if isinstance(observed_input, list) else [])
                    if type(p) is int and 1 <= p <= 65535}
        configured = set(facts.get("ports", []))
        ports = configured | observed
        admin_ports = set(facts.get("admin_ports", []))
        for port in sorted(ports):
            seen_only = port in observed and port not in configured
            source = "passive_observation" if seen_only else "device_configuration"
            where = "observed listening port" if seen_only else "reported port"
            if port in SERVICES:
                flag("service_review", f"{SERVICES[port]} on {where} {port}; review access and configuration",
                     {"port": port, "source": source, "verified_by_agent": False})
            elif port in (80, 8080):
                flag("http_review", f"HTTP on {where} {port}; an admin interface is not established by port number alone",
                     {"port": port, "admin_reported": port in admin_ports, "verified_by_agent": False,
                      **({"source": source} if seen_only else {})})
        for key, summary in (("default_creds", "Default credentials reported; change them and verify locally"),
                             ("eol", "End-of-life status reported; verify the vendor support policy"),
                             ("cloud_only", "Cloud-only operation reported; review dependency and egress needs")):
            if profile.get(key) is True:
                flag(key, summary, {"source": "simulation_persona" if key in persona else "device_configuration",
                                    "verified_by_agent": False})
        vendor, model = identity(profile.get("vendor")), identity(profile.get("model"))
        matches = self.index.get((vendor, model), []) if vendor and model else []
        kev = None
        if persona.get("kev") in ("confirmed", "possible"):
            kev = {"confidence": "possible"}
            flag("kev", "Simulated KEV factor; not a verified vulnerability on this device",
                 {"source": "simulation_persona"}, "simulated")
        elif matches:
            kev = {"confidence": "possible"}  # No firmware/config applicability evaluator exists yet.
            for row in matches[:10]:
                flag("kev", "Candidate catalog match; firmware and configuration applicability require verification",
                     {"cve": row["cveID"], "vendor": row["vendorProject"], "product": row["product"],
                      "source": f"https://nvd.nist.gov/vuln/detail/{row['cveID']}",
                      "catalog_version": self.catalog.get("catalogVersion"),
                      "firmware_applicability_checked": False}, "candidate")
        # Web ports get risk points only when explicitly reported as admin ports.
        scoring = {**profile, "ports": sorted((configured & SERVICES.keys()) | (configured & admin_ports)),
                   "anomaly": anomaly}
        static = score_device({**scoring, "anomaly": 0}, kev)
        result = score_device(scoring, kev)
        unknown = [key for key in ("vendor", "model", "eol", "default_creds", "cloud_only")
                   if (profile.get(key) is None or profile.get(key) == "")
                   and not (key == "vendor" and inferred.get("vendor"))]
        if "ports" not in facts:
            unknown.append("ports")
        reasons = []
        for reason in result.reasons:
            if reason.startswith("Anomalous behavior"):
                reasons.append(f"Behavioral signal strength {anomaly:.2f}; not a calibrated probability")
            elif "known exploited CVE" in reason:
                reasons.append("Simulated KEV factor" if simulated else "Candidate KEV relevance; firmware applicability unverified")
            else:
                reasons.append(("Simulated fact: " if simulated else "Reported fact (not independently checked): ") + reason)
        reasons += [f"{f['status']}: {f['summary']}" for f in flags]
        if inferred:
            basis = "; ".join(str(b) for b in inferred.get("basis", []))
            what = inferred.get("label") or inferred.get("type")
            if what or inferred.get("vendor"):
                reasons.append(f"Passive identification (inferred, not verified; {inferred.get('confidence', 'low')} confidence): "
                               f"{what or 'vendor only'}" + (f", vendor {inferred['vendor'].rstrip('.')}" if inferred.get("vendor") else "")
                               + (f". Basis: {basis}." if basis else "."))
            else:
                reasons.append("Passive identification found no vendor or device type" + (f" ({basis})" if basis else "") + ".")
        if observed:
            reasons.append("Passively observed listening ports: " + ", ".join(map(str, sorted(observed)))
                           + " (from the device's own SYN-ACK replies; not a full port scan).")
        if unknown:
            reasons.append("Unknown inputs: " + ", ".join(unknown) + ". Low risk is not proof of safety.")
        reasons.append(f"Static risk {static.score}/100; behavioral contribution {result.score - static.score} point(s).")
        age = None
        try:
            released = datetime.fromisoformat(self.catalog["dateReleased"].replace("Z", "+00:00"))
            age = max(0, (datetime.now(timezone.utc) - released).days)
        except (KeyError, ValueError, TypeError):
            pass
        return {"type": profile.get("type") or inferred.get("type") or "unknown", "eol": profile.get("eol"),
                "cloud_only": profile.get("cloud_only"), "risk": result.score, "band": result.band,
                "static_risk": static.score, "static_band": static.band,
                "behavior_points": result.score - static.score,
                "risk_factors": result.factors,
                "confidence": "possible" if kev else "n/a", "reasons": reasons, "vulnerability_flags": flags,
                "coverage": {"catalog_version": self.catalog.get("catalogVersion"), "catalog_age_days": age,
                             "identity_complete": bool(vendor and model), "unknown_inputs": unknown,
                             "facts_verified_by_agent": False, "firmware_applicability_checked": False,
                             "matching_catalog_entries": len(matches),
                             "inferred_identity": inferred or None, "observed_ports": sorted(observed),
                             "note": "No match is not proof of safety. No active port/credential checks were run."}}


def main():
    import argparse
    from .replay import load_devices
    parser = argparse.ArgumentParser(description="Review configured device facts against the local catalog; no network probes.")
    parser.add_argument("--devices", type=Path, required=True)
    args = parser.parse_args()
    assessor = VulnerabilityAssessor()
    reports = [{"mac": d.mac, "name": d.name, **assessor.assess(d)}
               for d in load_devices(args.devices).devices.values()]
    print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()
