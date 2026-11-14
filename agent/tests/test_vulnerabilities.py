"""Evidence-quality checks using fictitious catalog rows, never live targets."""
import copy
from pathlib import Path
import sys

import pytest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agent"))
from securiot_agent.models import Device
from securiot_agent.vulnerabilities import VulnerabilityAssessor

CATALOG = {"catalogVersion": "fixture", "dateReleased": "2020-01-01T00:00:00Z", "vulnerabilities": [
    {"cveID": "CVE-2099-12345", "vendorProject": "Example Vendor", "product": "Cam 100"}]}


def assess(facts, catalog=None):
    device = Device("02:00:00:00:00:20", "10.42.0.20", "Test device", risk_facts=facts)
    return VulnerabilityAssessor(copy.deepcopy(catalog or CATALOG)).assess(device)


@pytest.mark.parametrize("facts", [{}, {"eol": None}, {"eol": False, "default_creds": False},
                                   {"ports": [443]}, {"ports": [80, 8080]}])
def test_unknown_or_web_only_profiles_do_not_gain_invented_vulnerabilities(facts):
    result = assess(facts)
    assert result["risk"] == 0
    assert not any(f["status"] == "confirmed" for f in result["vulnerability_flags"])
    assert not result["coverage"]["firmware_applicability_checked"]


@pytest.mark.parametrize("port", [21, 23, 2323, 445, 1900, 5000, 5555, 7547])
def test_reported_services_are_review_items_not_confirmed_exploits(port):
    result = assess({"ports": [port]})
    flag = result["vulnerability_flags"][0]
    assert flag["status"] == "reported"
    assert not flag["evidence"]["verified_by_agent"]
    assert result["risk"] == 15


@pytest.mark.parametrize("port", [80, 8080])
def test_http_admin_points_need_explicit_admin_fact(port):
    assert assess({"ports": [port]})["risk"] == 0
    assert assess({"ports": [port], "admin_ports": [port]})["risk"] == 15


@pytest.mark.parametrize("vendor,model,match", [
    ("Example Vendor", "Cam 100", True), ("EXAMPLE-VENDOR", "cam-100", True),
    ("Example", "Cam 100", False), ("Example Vendor", "Cam", False),
    ("Example Vendor", "Cam 1000", False), ("Other Vendor", "Cam 100", False),
    ("Example Vendor", None, False), (None, "Cam 100", False),
])
def test_catalog_matching_does_not_use_loose_substrings(vendor, model, match):
    result = assess({"vendor": vendor, "model": model})
    assert result["coverage"]["matching_catalog_entries"] == int(match)
    assert result["risk"] == (15 if match else 0)
    if match:
        flag = result["vulnerability_flags"][0]
        assert flag["status"] == "candidate"
        assert not flag["evidence"]["firmware_applicability_checked"]


def test_empty_catalog_is_incomplete_coverage_not_proof_of_safety():
    result = assess({"vendor": "Example Vendor", "model": "Cam 100"}, {"vulnerabilities": []})
    assert result["risk"] == 0
    assert "not proof of safety" in result["coverage"]["note"]


def test_missing_catalog_date_is_reported_unknown():
    result = assess({}, {"vulnerabilities": []})
    assert result["coverage"]["catalog_age_days"] is None


def test_old_catalog_age_is_visible():
    assert assess({})["coverage"]["catalog_age_days"] > 0


def test_malformed_catalog_cve_is_not_used_as_a_source_link():
    catalog = copy.deepcopy(CATALOG)
    catalog["vulnerabilities"][0]["cveID"] = "../../bad-url"
    assert assess({"vendor": "Example Vendor", "model": "Cam 100"}, catalog)["risk"] == 0


@pytest.mark.parametrize("factor,points", [("default_creds", 25), ("eol", 20), ("cloud_only", 5)])
def test_reported_configuration_risk_retains_provenance(factor, points):
    result = assess({factor: True})
    assert result["risk"] == points
    assert result["vulnerability_flags"][0]["status"] == "reported"
    assert result["vulnerability_flags"][0]["evidence"]["verified_by_agent"] is False


def test_persona_cannot_turn_a_simulation_into_a_confirmed_device_vulnerability():
    result = assess({"ports": [23], "default_creds": True,
                     "persona": {"eol": True, "kev": "confirmed"}})
    assert result["risk"] == 75
    assert all(f["status"] == "simulated" for f in result["vulnerability_flags"])
    assert result["confidence"] == "possible"


def test_missing_eol_and_cloud_only_stay_unknown():
    result = assess({})
    assert result["eol"] is None and result["cloud_only"] is None


def test_multiple_risky_ports_do_not_multiply_the_port_weight():
    assert assess({"ports": [21, 23, 2323, 445]})["risk"] == 15


def test_matching_catalog_rows_are_bounded_but_total_count_remains_visible():
    catalog = copy.deepcopy(CATALOG)
    catalog["vulnerabilities"] = [dict(catalog["vulnerabilities"][0], cveID=f"CVE-2099-{10000+i}")
                                  for i in range(30)]
    result = assess({"vendor": "Example Vendor", "model": "Cam 100"}, catalog)
    assert result["coverage"]["matching_catalog_entries"] == 30
    assert len(result["vulnerability_flags"]) == 10


@pytest.mark.parametrize("facts", [{"default_creds": "false"}, {"eol": 1}, {"ports": ["23"]}, {"ports": [70000]}])
def test_assessment_boundary_rejects_mistyped_risk_facts(facts):
    with pytest.raises(ValueError):
        assess(facts)


def test_real_device_cannot_inherit_simulated_identity():
    device = Device("02:00:00:00:00:20", "10.42.0.20", "real", simulated=False,
                    risk_facts={"persona": {"eol": True}})
    with pytest.raises(ValueError):
        VulnerabilityAssessor(CATALOG).assess(device)



def test_explicitly_simulated_fixture_facts_keep_their_label():
    result = assess({"_simulated_facts": True, "ports": [23], "default_creds": True})
    assert all(flag["status"] == "simulated" for flag in result["vulnerability_flags"])
