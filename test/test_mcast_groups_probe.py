"""Tests for the MCAST-GROUPS-PROBE test: active subscription to sensitive multicast groups."""
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


class SimpleIPVer:
    def __init__(self, ipv4=True, ipv6=True):
        self.ipv4 = ipv4
        self.ipv6 = ipv6


def _run(monkeypatch, version, delivered=(), addresses=("172.16.10.200",), target_codes=None):
    net_code = f"PTV-NET-{version}-MCAST-GROUPS-PROBE-MISCONF"
    monkeypatch.setattr(
        "ptnetinspector.vulnerability.mcast_groups_probe.Interface.get_interface_ipv4_ips",
        lambda self: list(addresses) if version == "4" else [],
    )
    monkeypatch.setattr(
        "ptnetinspector.vulnerability.mcast_groups_probe.Interface.get_interface_ipv6_ips",
        lambda self: list(addresses) if version == "6" else [],
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

    net_vuln_file = Path(get_csv_path("vulnerability_net.csv"))
    if net_vuln_file.exists():
        net_vuln_file.unlink()
    with tempfile.TemporaryDirectory() as tmpdir:
        vuln = Vulnerability(
            interface=interface,
            mode=["a"],
            ipver=SimpleIPVer(ipv4=version == "4", ipv6=version == "6"),
            smac=SCANNER_MAC,
            network="",
            prefix_len=64,
            rpref=0,
            dns=[],
            target_codes=target_codes,
            vulnerability_file=str(Path(tmpdir) / "vulnerability.csv"),
        )
        vuln.store_mcast_groups_probe_vulnerability()
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


def test_sensitive_traffic_after_subscribing_is_a_finding(monkeypatch):
    """PTP traffic delivered after the port subscribes is label 1."""
    rows = _run(monkeypatch, "4", delivered=[("224.0.1.129", "IPv4", DEVICE_MAC)])

    assert any(r["Label"] == "1" for r in rows)
    assert [v["vulnCode"] for v in _json_results()["vulnerabilities"]] == ["PTV-NET-4-MCAST-GROUPS-PROBE-MISCONF"]
    assert "224.0.1.129 (PTP)" in _json_results()["vulnerabilities"][0]["poc"]
    assert "224.0.1.129 (PTP)" in _stored_result("4-MCAST-GROUPS-PROBE")["sentence"]


def test_subscription_with_no_delivery_is_not_vulnerable(monkeypatch):
    """A subscription sent with an address but nothing delivered is label 0."""
    rows = _run(monkeypatch, "4", delivered=[])

    assert [r["Label"] for r in rows] == ["0"]
    assert _json_results()["vulnerabilities"] == []
    assert "no sensitive" in _stored_result("4-MCAST-GROUPS-PROBE")["sentence"].lower()


def test_no_address_to_subscribe_is_not_applicable(monkeypatch):
    """Without a usable address the probe cannot run: label 2."""
    rows = _run(monkeypatch, "4", delivered=[("224.0.1.129", "IPv4", DEVICE_MAC)], addresses=())

    assert [r["Label"] for r in rows] == ["2"]
    assert _json_results()["vulnerabilities"] == []
    assert "No usable" in _stored_result("4-MCAST-GROUPS-PROBE")["sentence"]


def test_admin_scoped_delivery_is_not_a_finding(monkeypatch):
    """A plain 239.0.0.0/8 stream is not a sensitive category, so not a finding."""
    rows = _run(monkeypatch, "4", delivered=[("239.1.2.3", "IPv4", DEVICE_MAC)])

    assert [r["Label"] for r in rows] == ["0"]


def test_scanner_mac_source_is_ignored(monkeypatch):
    """Traffic whose only source is the tester's own MAC is not delivered content."""
    rows = _run(monkeypatch, "4", delivered=[("224.0.1.129", "IPv4", SCANNER_MAC)])

    assert [r["Label"] for r in rows] == ["0"]


def test_ipv6_ptp_after_subscribing_is_a_finding(monkeypatch):
    """PTP over IPv6 delivered after subscribing is label 1 for 6-MCAST-GROUPS-PROBE."""
    rows = _run(monkeypatch, "6", delivered=[("ff05::181", "IPv6", DEVICE_MAC)], addresses=("fe80::1",))

    assert any(r["Label"] == "1" for r in rows)
    assert "ff05::181 (PTP)" in _stored_result("6-MCAST-GROUPS-PROBE")["sentence"]


def test_other_ip_version_is_ignored(monkeypatch):
    """An IPv6 group does not count for 4-MCAST-GROUPS-PROBE."""
    rows = _run(monkeypatch, "4", delivered=[("ff05::181", "IPv6", DEVICE_MAC)])

    assert [r["Label"] for r in rows] == ["0"]


def test_writes_no_log_when_another_test_is_selected(monkeypatch):
    """With -ts FHRP-PROBE selected, MCAST-GROUPS-PROBE adds nothing to the JSON log."""
    rows = _run(monkeypatch, "4", delivered=[("224.0.1.129", "IPv4", DEVICE_MAC)], target_codes={"FHRP-PROBE"})

    assert rows == []
    assert _json_results()["log"] == ""
