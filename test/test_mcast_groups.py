"""Tests for the MCAST-GROUPS test: sensitive multicast streams readable from the port."""
import csv
import json
import tempfile
from pathlib import Path
from uuid import uuid4

from ptnetinspector.utils.cli import ptjsonlib_object
from ptnetinspector.utils.path import get_csv_path, set_current_interface
from ptnetinspector.vulnerability import Vulnerability

SCANNER_MAC = "aa:aa:aa:aa:aa:aa"
DEVICE_MAC = "11:22:33:44:55:66"
REPORTER_MAC = "44:55:66:77:88:99"


class SimpleIPVer:
    def __init__(self, ipv4=True, ipv6=True):
        self.ipv4 = ipv4
        self.ipv6 = ipv6


def _run(monkeypatch, version, delivered=(), reports=(), joined=(), target_codes=None):
    net_code = f"PTV-NET-{version}-MCAST-GROUPS-MISCONF"
    monkeypatch.setattr(
        "ptnetinspector.vulnerability.mcast_groups.get_joined_multicast_groups",
        lambda interface: set(joined),
    )
    interface = f"testif-{uuid4().hex[:8]}"
    set_current_interface(interface)
    ptjsonlib_object.__init__()

    groups_file = Path(get_csv_path("multicast_groups.csv", interface))
    groups_file.parent.mkdir(parents=True, exist_ok=True)
    with open(groups_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Group", "Version", "Source_MAC"])
        writer.writeheader()
        for group, group_version, mac in delivered:
            writer.writerow({"Group": group, "Version": group_version, "Source_MAC": mac})

    report_files = {"4": "IGMPv3.csv", "6": "MLDv2.csv"}
    fields = ["MAC", "IP", "protocol", "rtype", "mulip", "sources"]
    with open(Path(get_csv_path(report_files[version], interface)), "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        for mac, group in reports:
            writer.writerow({"MAC": mac, "IP": "", "protocol": "Report v2",
                             "rtype": "MODE_IS_EXCLUDE", "mulip": group, "sources": ""})

    net_vuln_file = Path(get_csv_path("vulnerability_net.csv"))
    if net_vuln_file.exists():
        net_vuln_file.unlink()
    with tempfile.TemporaryDirectory() as tmpdir:
        vuln = Vulnerability(
            interface=interface,
            mode=["p"],
            ipver=SimpleIPVer(ipv4=version == "4", ipv6=version == "6"),
            smac=SCANNER_MAC,
            network="",
            prefix_len=64,
            rpref=0,
            dns=[],
            target_codes=target_codes,
            vulnerability_file=str(Path(tmpdir) / "vulnerability.csv"),
        )
        vuln.store_mcast_groups_vulnerability()
    rows = []
    if net_vuln_file.exists():
        with open(net_vuln_file, newline="") as csvfile:
            rows = [r for r in csv.DictReader(csvfile) if r["Code"] == net_code]
    return rows


def _json_results():
    return ptjsonlib_object.json_object["results"]


def _stored_result(test_code):
    with open(get_csv_path("test_results.json"), encoding="utf-8") as handle:
        return json.load(handle)[test_code]


def test_delivered_sensitive_stream_is_a_finding(monkeypatch):
    """EtherNet/IP traffic reaching the port without joining it is label 1."""
    rows = _run(monkeypatch, "4", delivered=[("239.192.1.1", "IPv4", DEVICE_MAC)])

    assert any(r["Label"] == "1" for r in rows)
    assert [v["vulnCode"] for v in _json_results()["vulnerabilities"]] == ["PTV-NET-4-MCAST-GROUPS-MISCONF"]
    assert "239.192.1.1 (EtherNet/IP)" in _json_results()["vulnerabilities"][0]["poc"]
    assert "239.192.1.1 (EtherNet/IP)" in _stored_result("4-MCAST-GROUPS")["sentence"]


def test_sensitive_group_only_reported_is_not_readable(monkeypatch):
    """A sensitive group seen only in another host's report, not delivered here, is label 0."""
    rows = _run(monkeypatch, "4", reports=[(REPORTER_MAC, "239.192.1.1")])

    assert [r["Label"] for r in rows] == ["0"]
    assert _json_results()["vulnerabilities"] == []
    assert "not delivered" in _stored_result("4-MCAST-GROUPS")["sentence"]


def test_no_sensitive_groups_is_not_applicable(monkeypatch):
    """Only ordinary multicast (mDNS) and nothing sensitive is label 2."""
    rows = _run(monkeypatch, "4", delivered=[("224.0.0.251", "IPv4", DEVICE_MAC)])

    assert [r["Label"] for r in rows] == ["2"]
    assert _json_results()["vulnerabilities"] == []
    assert "No sensitive" in _stored_result("4-MCAST-GROUPS")["sentence"]


def test_admin_scoped_group_is_listed_but_not_a_finding(monkeypatch):
    """A plain 239.0.0.0/8 group is shown as admin-scoped, not reported as readable."""
    rows = _run(monkeypatch, "4", delivered=[("239.1.2.3", "IPv4", DEVICE_MAC)])

    assert [r["Label"] for r in rows] == ["2"]
    result = _stored_result("4-MCAST-GROUPS")
    assert ["239.1.2.3", "admin-scoped", "-", "yes"] in result["table"]["rows"]


def test_group_joined_by_this_host_is_not_readable_evidence(monkeypatch):
    """Traffic for a group this host itself joined is expected and not a finding."""
    rows = _run(monkeypatch, "4", delivered=[("239.192.1.1", "IPv4", DEVICE_MAC)], joined=["239.192.1.1"])

    assert [r["Label"] for r in rows] == ["0"]


def test_scanner_mac_source_is_ignored(monkeypatch):
    """A stream whose only source is the tester's own MAC is not foreign traffic."""
    rows = _run(monkeypatch, "4", delivered=[("239.192.1.1", "IPv4", SCANNER_MAC)])

    assert [r["Label"] for r in rows] == ["2"]


def test_ipv6_ptp_delivered_is_a_finding(monkeypatch):
    """PTP over IPv6 delivered to the port is label 1 for 6-MCAST-GROUPS."""
    rows = _run(monkeypatch, "6", delivered=[("ff05::181", "IPv6", DEVICE_MAC)])

    assert any(r["Label"] == "1" for r in rows)
    assert "ff05::181 (PTP)" in _stored_result("6-MCAST-GROUPS")["sentence"]


def test_other_ip_version_group_is_ignored(monkeypatch):
    """An IPv6 group does not count for 4-MCAST-GROUPS."""
    rows = _run(monkeypatch, "4", delivered=[("ff05::181", "IPv6", DEVICE_MAC)])

    assert [r["Label"] for r in rows] == ["2"]


def test_writes_no_log_when_another_test_is_selected(monkeypatch):
    """With -ts TRUNK selected, MCAST-GROUPS adds nothing to the JSON log."""
    rows = _run(monkeypatch, "4", delivered=[("239.192.1.1", "IPv4", DEVICE_MAC)], target_codes={"TRUNK"})

    assert rows == []
    assert _json_results()["log"] == ""
