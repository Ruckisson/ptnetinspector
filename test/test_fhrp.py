"""Tests for the FHRP test: HSRP, VRRP or GLBP running without authentication."""
import csv
import json
import tempfile
from pathlib import Path
from uuid import uuid4

from scapy.all import Ether, IP, UDP, Raw
from scapy.layers.hsrp import HSRP, HSRPmd5
from scapy.layers.vrrp import VRRP, VRRPv3

from ptnetinspector.utils.cli import ptjsonlib_object
from ptnetinspector.utils.path import get_csv_path, set_current_interface
from ptnetinspector.vulnerability import Vulnerability

FHRP_CODE = "PTV-NET-FHRP-MISCONF"
SCANNER_MAC = "aa:aa:aa:aa:aa:aa"
ROUTER_MAC = "00:00:0c:07:ac:01"


class SimpleIPVer:
    def __init__(self, ipv4=True, ipv6=True):
        self.ipv4 = ipv4
        self.ipv6 = ipv6


def _line(packet):
    return " ".join(packet.show(dump=True).replace("\r", "").replace("\n", " ").split())


def _hsrp(auth=b"cisco\x00\x00\x00", md5=False, priority=110, group=1):
    pkt = Ether(src=ROUTER_MAC) / IP(src="172.16.10.2", dst="224.0.0.2") / UDP(sport=1985, dport=1985)
    pkt = pkt / HSRP(group=group, priority=priority, virtualIP="172.16.10.1", auth=auth)
    if md5:
        pkt = pkt / HSRPmd5(authdigest=b"\x11" * 16)
    return pkt


def _vrrp2(authtype=1, vrid=1, priority=100):
    return (Ether(src=ROUTER_MAC) / IP(src="172.16.10.2", proto=112, dst="224.0.0.18")
            / VRRP(version=2, vrid=vrid, priority=priority, addrlist=["172.16.10.1"], authtype=authtype))


def _vrrp3():
    return (Ether(src=ROUTER_MAC) / IP(src="172.16.10.2", proto=112, dst="224.0.0.18")
            / VRRPv3(version=3, vrid=1, priority=100, addrlist=["172.16.10.1"]))


def _glbp(authenticated=False):
    load = b"\x02\x00\x00\x01" + (b"\x03\x00\x14" + b"\x22" * 17 if authenticated else b"\x01\x00\x28")
    return Ether(src=ROUTER_MAC) / IP(src="172.16.10.2", dst="224.0.0.102") / UDP(sport=3222, dport=3222) / Raw(load=load)


def _run(packets=(), target_codes=None, smac=SCANNER_MAC):
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
            mode=["p"],
            ipver=SimpleIPVer(),
            smac=smac,
            network="",
            prefix_len=64,
            rpref=0,
            dns=[],
            target_codes=target_codes,
            vulnerability_file=str(vuln_file),
        )
        vuln.store_fhrp_vulnerability()

        net_rows = []
        if net_vuln_file.exists():
            with open(net_vuln_file, newline="") as handle:
                net_rows = [r for r in csv.DictReader(handle) if r["Code"] == FHRP_CODE]
        result = None
        if results_file.exists():
            result = json.load(open(results_file)).get("FHRP")
        vulns = [v["vulnCode"] for v in ptjsonlib_object.json_object["results"]["vulnerabilities"]]
        return net_rows, result, vulns


def test_hsrp_plaintext_is_a_finding():
    net_rows, result, vulns = _run([(ROUTER_MAC, _hsrp())])
    assert any(r["Label"] == "1" for r in net_rows)
    assert result["label"] == 1
    assert "HSRP" in result["sentence"] or "redundancy" in result["sentence"]
    assert vulns == [FHRP_CODE]


def test_hsrp_md5_is_not_vulnerable():
    net_rows, result, vulns = _run([(ROUTER_MAC, _hsrp(md5=True))])
    assert result["label"] == 0
    assert vulns == []


def test_vrrp2_without_auth_is_a_finding():
    _, result, vulns = _run([(ROUTER_MAC, _vrrp2(authtype=0))])
    assert result["label"] == 1
    assert vulns == [FHRP_CODE]


def test_vrrp2_ah_is_not_vulnerable():
    _, result, vulns = _run([(ROUTER_MAC, _vrrp2(authtype=2))])
    assert result["label"] == 0
    assert vulns == []


def test_vrrp3_has_no_auth_and_is_a_finding():
    _, result, vulns = _run([(ROUTER_MAC, _vrrp3())])
    assert result["label"] == 1
    assert vulns == [FHRP_CODE]


def test_glbp_without_auth_is_a_finding():
    _, result, _ = _run([(ROUTER_MAC, _glbp(authenticated=False))])
    assert result["label"] == 1


def test_glbp_with_md5_is_not_vulnerable():
    _, result, _ = _run([(ROUTER_MAC, _glbp(authenticated=True))])
    assert result["label"] == 0


def test_no_fhrp_is_na():
    net_rows, result, vulns = _run([])
    assert result["label"] == 2
    assert vulns == []
    assert any(r["Label"] == "2" for r in net_rows)


def test_scanner_mac_is_ignored():
    _, result, _ = _run([(SCANNER_MAC, _hsrp())], smac=SCANNER_MAC)
    assert result["label"] == 2


def test_not_selected_code_is_skipped():
    _, result, vulns = _run([(ROUTER_MAC, _hsrp())], target_codes=["TRUNK"])
    assert result is None
    assert vulns == []


def test_password_is_not_disclosed_in_output():
    _, result, _ = _run([(ROUTER_MAC, _hsrp(auth=b"secretpw"))])
    blob = json.dumps(result) + json.dumps(_run([(ROUTER_MAC, _hsrp(auth=b"secretpw"))])[1])
    assert "secretpw" not in blob
