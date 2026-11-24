"""Tests for the FHRP-PROBE test: gateway takeover via an unauthenticated
higher-priority HSRP or VRRP hello."""
import csv
import json
import tempfile
from pathlib import Path
from uuid import uuid4

from scapy.all import Ether, IP, UDP
from scapy.layers.hsrp import HSRP
from scapy.layers.vrrp import VRRP, VRRPv3

from ptnetinspector.utils.cli import ptjsonlib_object
from ptnetinspector.utils.path import get_csv_path, set_current_interface
from ptnetinspector.vulnerability import Vulnerability

FHRP_PROBE_CODE = "PTV-NET-FHRP-PROBE-MISCONF"
SCANNER_MAC = "aa:aa:aa:aa:aa:aa"
ROUTER_MAC = "00:00:0c:07:ac:01"


class SimpleIPVer:
    def __init__(self, ipv4=True, ipv6=True):
        self.ipv4 = ipv4
        self.ipv6 = ipv6


def _line(packet):
    return " ".join(packet.show(dump=True).replace("\r", "").replace("\n", " ").split())


def _hsrp(state=16, group=1):
    return (Ether(src=ROUTER_MAC) / IP(src="172.16.10.2", dst="224.0.0.2") / UDP(sport=1985, dport=1985)
            / HSRP(state=state, priority=100, group=group, virtualIP="172.16.10.1"))


def _vrrp2(authtype=0, vrid=1):
    return (Ether(src=ROUTER_MAC) / IP(src="172.16.10.2", proto=112, dst="224.0.0.18")
            / VRRP(version=2, vrid=vrid, priority=100, addrlist=["172.16.10.1"], authtype=authtype))


def _vrrp3(vrid=1):
    return (Ether(src=ROUTER_MAC) / IP(src="172.16.10.2", proto=112, dst="224.0.0.18")
            / VRRPv3(version=3, vrid=vrid, priority=100, addrlist=["172.16.10.1"]))


def _run(packets, smac=SCANNER_MAC, target_codes=None):
    with tempfile.TemporaryDirectory() as tmpdir:
        vuln_file = Path(tmpdir) / "vulnerability.csv"
        interface = f"testif-{uuid4().hex[:8]}"
        set_current_interface(interface)
        ptjsonlib_object.__init__()
        net_vuln_file = Path(get_csv_path("vulnerability_net.csv"))
        if net_vuln_file.exists():
            net_vuln_file.unlink()
        results_file = Path(get_csv_path("test_results.json"))
        if results_file.exists():
            results_file.unlink()

        time_file = Path(get_csv_path("time_all.csv"))
        time_file.parent.mkdir(parents=True, exist_ok=True)
        with open(time_file, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["time", "MAC", "packet"])
            writer.writeheader()
            for mac, packet in packets:
                writer.writerow({"time": "0", "MAC": mac, "packet": _line(packet)})

        vuln = Vulnerability(
            interface=interface,
            mode=["a"],
            ipver=SimpleIPVer(),
            smac=smac,
            network="",
            prefix_len=64,
            rpref=0,
            dns=[],
            target_codes=target_codes,
            vulnerability_file=str(vuln_file),
        )
        vuln.store_fhrp_probe_vulnerability()

        net_rows = []
        if net_vuln_file.exists():
            with open(net_vuln_file, newline="") as handle:
                net_rows = [r for r in csv.DictReader(handle) if r["Code"] == FHRP_PROBE_CODE]
        result = None
        if results_file.exists():
            result = json.load(open(results_file)).get("FHRP-PROBE")
        vulns = [v["vulnCode"] for v in ptjsonlib_object.json_object["results"]["vulnerabilities"]]
        return net_rows, result, vulns


def test_hsrp_gives_up_active_role_is_a_finding():
    net_rows, result, vulns = _run([(ROUTER_MAC, _hsrp(state=16)), (ROUTER_MAC, _hsrp(state=4))])
    assert net_rows and net_rows[0]["Label"] == "1"
    assert FHRP_PROBE_CODE in vulns


def test_hsrp_keeps_active_role_is_not_vulnerable():
    net_rows, result, vulns = _run([(ROUTER_MAC, _hsrp(state=16)), (ROUTER_MAC, _hsrp(state=8))])
    assert net_rows and net_rows[0]["Label"] == "0"
    assert FHRP_PROBE_CODE not in vulns


def test_vrrpv3_can_be_taken_over():
    net_rows, result, vulns = _run([(ROUTER_MAC, _vrrp3())])
    assert net_rows and net_rows[0]["Label"] == "1"
    assert FHRP_PROBE_CODE in vulns


def test_vrrpv2_without_authentication_can_be_taken_over():
    net_rows, result, vulns = _run([(ROUTER_MAC, _vrrp2(authtype=0))])
    assert net_rows and net_rows[0]["Label"] == "1"


def test_vrrpv2_with_ah_authentication_is_not_vulnerable():
    net_rows, result, vulns = _run([(ROUTER_MAC, _vrrp2(authtype=2))])
    assert net_rows and net_rows[0]["Label"] == "0"
    assert FHRP_PROBE_CODE not in vulns


def test_nothing_heard_is_not_applicable():
    net_rows, result, vulns = _run([])
    assert net_rows and net_rows[0]["Label"] == "2"
    assert FHRP_PROBE_CODE not in vulns


def test_scanner_frames_are_ignored():
    net_rows, result, vulns = _run([(SCANNER_MAC, _hsrp(state=4))], smac=SCANNER_MAC)
    assert net_rows and net_rows[0]["Label"] == "2"


def test_json_carries_the_finding():
    _, result, vulns = _run([(ROUTER_MAC, _hsrp(state=16)), (ROUTER_MAC, _hsrp(state=4))])
    assert FHRP_PROBE_CODE in vulns
    _, _, clean = _run([(ROUTER_MAC, _hsrp(state=16)), (ROUTER_MAC, _hsrp(state=8))])
    assert FHRP_PROBE_CODE not in clean


def test_unselected_code_writes_no_result():
    net_rows, result, vulns = _run([(ROUTER_MAC, _hsrp(state=4))], target_codes=["FHRP"])
    assert result is None
    assert net_rows == []
