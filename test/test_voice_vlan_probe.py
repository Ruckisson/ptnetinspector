"""Tests for the VOICE-VLAN-PROBE test: a fake IP phone probe and the switch's
reply disclosing the voice VLAN over CDP or LLDP-MED."""
import csv
import json
import tempfile
import types
from pathlib import Path
from uuid import uuid4

from scapy.all import Dot3, LLC, SNAP, Ether
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPortID, CDPMsgVoIPVLANReply

from ptnetinspector.scan import Run, _ACTIVE_PROBES
from ptnetinspector.send.send import Send
from ptnetinspector.utils.cli import ptjsonlib_object
from ptnetinspector.utils.path import get_csv_path, set_current_interface
from ptnetinspector.vulnerability import Vulnerability

VOICE_VLAN_PROBE_CODE = "PTV-NET-VOICE-VLAN-PROBE-MISCONF"
SCANNER_MAC = "aa:aa:aa:aa:aa:aa"
SWITCH_MAC = "00:aa:bb:cc:dd:ee"


class SimpleIPVer:
    def __init__(self, ipv4=True, ipv6=True):
        self.ipv4 = ipv4
        self.ipv6 = ipv6


def _cdp_frame(vlan=None):
    cdp = CDPv2_HDR(vers=2, ttl=180) / CDPMsgDeviceID(val=b"SW0") / CDPMsgPortID(iface=b"Gi0/2")
    if vlan is not None:
        cdp = cdp / CDPMsgVoIPVLANReply(status=1, vlan=vlan)
    return bytes(Dot3(dst="01:00:0c:cc:cc:cc", src=SWITCH_MAC) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0x00000C, code=0x2000) / cdp)


def _lldp_frame(vlan=None, app=1):
    def tlv(tlv_type, body):
        length = len(body)
        return bytes([(tlv_type << 1) | ((length >> 8) & 1), length & 0xFF]) + body

    pdu = tlv(1, b"\x04\x00\x11\x22\x33\x44\x55") + tlv(2, b"\x05Gi0/2") + tlv(3, b"\x00\x78")
    if vlan is not None:
        policy_bits = (vlan << 9) | (5 << 6) | 46
        pdu += tlv(127, b"\x00\x12\xbb\x02" + bytes([app]) + policy_bits.to_bytes(3, "big"))
    pdu += tlv(0, b"")
    return bytes(Ether(dst="01:80:c2:00:00:0e", src=SWITCH_MAC, type=0x88CC) / pdu)


def _run(frames=(), target_codes=None, smac=SCANNER_MAC):
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

        frames_file = Path(get_csv_path("voice_frames.csv"))
        frames_file.parent.mkdir(parents=True, exist_ok=True)
        with open(frames_file, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["MAC", "Frame"])
            writer.writeheader()
            for mac, frame in frames:
                writer.writerow({"MAC": mac, "Frame": frame.hex()})

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
        vuln.store_voice_vlan_probe_vulnerability()

        net_rows = []
        if net_vuln_file.exists():
            with open(net_vuln_file, newline="") as handle:
                net_rows = [r for r in csv.DictReader(handle) if r["Code"] == VOICE_VLAN_PROBE_CODE]
        result = None
        if results_file.exists():
            result = json.load(open(results_file)).get("VOICE-VLAN-PROBE")
        vulns = [v["vulnCode"] for v in ptjsonlib_object.json_object["results"]["vulnerabilities"]]
        return net_rows, result, vulns


def test_voice_vlan_disclosed_over_cdp_is_a_finding():
    net_rows, result, vulns = _run([(SWITCH_MAC, _cdp_frame(20))])
    assert any(r["Label"] == "1" for r in net_rows)
    assert result["label"] == 1
    assert "disclosed" in result["sentence"] and "CDP" in result["sentence"]
    assert vulns == [VOICE_VLAN_PROBE_CODE]


def test_voice_vlan_disclosed_over_lldp_med_is_a_finding():
    _, result, vulns = _run([(SWITCH_MAC, _lldp_frame(20))])
    assert result["label"] == 1
    assert "LLDP-MED" in result["sentence"]
    assert vulns == [VOICE_VLAN_PROBE_CODE]


def test_lldp_reply_with_repeated_spaces_is_still_parsed():
    # The exact-byte capture exists because a one-line dump would drop a byte here.
    def tlv(tlv_type, body):
        length = len(body)
        return bytes([(tlv_type << 1) | ((length >> 8) & 1), length & 0xFF]) + body

    pdu = tlv(1, b"\x04\x00\x11\x22\x33\x44\x55") + tlv(2, b"\x05Gi0/2") + tlv(3, b"\x00\x78")
    pdu += tlv(6, b"Port  33  Virtual")
    pdu += tlv(127, b"\x00\x12\xbb\x02\x01" + ((20 << 9) | (5 << 6) | 46).to_bytes(3, "big"))
    pdu += tlv(0, b"")
    frame = bytes(Ether(dst="01:80:c2:00:00:0e", src=SWITCH_MAC, type=0x88CC) / pdu)
    _, result, _ = _run([(SWITCH_MAC, frame)])
    assert result["label"] == 1
    assert "20" in result["sentence"]


def test_reply_without_voice_vlan_is_not_vulnerable():
    net_rows, result, vulns = _run([(SWITCH_MAC, _cdp_frame())])
    assert any(r["Label"] == "0" for r in net_rows)
    assert result["label"] == 0
    assert vulns == []


def test_no_reply_is_undetermined():
    net_rows, result, vulns = _run([])
    assert any(r["Label"] == "2" for r in net_rows)
    assert result["label"] == 2
    assert "cannot be determined" in result["sentence"]
    assert vulns == []


def test_scanner_own_reply_is_ignored():
    _, result, _ = _run([(SCANNER_MAC.upper(), _cdp_frame(20))])
    assert result["label"] == 2


def test_repeated_reply_is_listed_once():
    _, result, _ = _run([(SWITCH_MAC, _cdp_frame(20)), (SWITCH_MAC, _cdp_frame(20))])
    assert result["table"]["rows"] == [[SWITCH_MAC, "CDP", "20"]]


def test_json_reports_poc_only_on_a_finding():
    _, _, vulns = _run([(SWITCH_MAC, _cdp_frame(20))])
    assert vulns == [VOICE_VLAN_PROBE_CODE]
    poc = ptjsonlib_object.json_object["results"]["vulnerabilities"][0]["poc"]
    assert "voice VLAN 20" in poc and "fake phone" in poc


def test_no_log_when_another_test_is_selected():
    _, result, _ = _run([(SWITCH_MAC, _cdp_frame(20))], target_codes=["TRUNK"])
    assert result is None
    assert ptjsonlib_object.json_object["results"]["log"] == ""


def test_active_probe_table_maps_the_code_to_the_sender():
    assert _ACTIVE_PROBES["VOICE-VLAN-PROBE"] is Send.send_voice_phone


def test_send_voice_phone_builds_a_cdp_and_an_lldp_med_frame(monkeypatch):
    sent = []
    monkeypatch.setattr("ptnetinspector.send.send.sendp_with_retries", lambda packets, **kwargs: sent.append(packets))
    monkeypatch.setattr("ptnetinspector.send.send.Interface", lambda interface: types.SimpleNamespace(check_interface=lambda: True))
    monkeypatch.setattr("ptnetinspector.send.send.get_if_hwaddr", lambda interface: SWITCH_MAC)

    Send.send_voice_phone("eth-test")

    assert len(sent) == 2
    from scapy.all import Raw

    cdp_payload = bytes(sent[0][Raw].load)
    lldp_payload = bytes(sent[1][Raw].load)

    classes = {message.__class__ for message in CDPv2_HDR(cdp_payload).msg}
    assert {CDPMsgDeviceID} <= classes
    assert b"\x00\x12\xbb\x01\x00\x03\x03" in lldp_payload


def test_save_voice_frames_keeps_cdp_and_lldp_exact_bytes():
    from ptnetinspector.scan import Save
    interface = f"testif-{uuid4().hex[:8]}"
    set_current_interface(interface)
    frames_file = Path(get_csv_path("voice_frames.csv"))
    if frames_file.exists():
        frames_file.unlink()
    frames_file.parent.mkdir(parents=True, exist_ok=True)
    with open(frames_file, "w", newline="") as handle:
        csv.DictWriter(handle, fieldnames=["MAC", "Frame"]).writeheader()

    cdp = Dot3(_cdp_frame(20))
    lldp = Ether(_lldp_frame(20))
    other = Ether(dst="ff:ff:ff:ff:ff:ff", src=SWITCH_MAC, type=0x0806)
    Save.save_voice_frames(interface, [cdp, lldp, other])

    with open(frames_file, newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert bytes.fromhex(rows[0]["Frame"]) == _cdp_frame(20)
