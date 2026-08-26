"""Plain asserts, no pytest, no network, no root. Under a second.

    python test_dissector.py

Every fixture is written by `synth.py`, so the expected protocol, port, flag
and byte count is known exactly rather than eyeballed from another tool. A
parser checked against captures nobody can describe is a parser checked
against its own output.

The important half is the hostile capture: eight frames whose length fields
lie. Each is a real dissector trap, and the test asserts the parser records an
error instead of inventing ports.
"""

import os
import struct
import sys
import tempfile

import analyze
import cli
import pcap
import synth

TMP = tempfile.mkdtemp(prefix="dissector-tests-")
MIXED = os.path.join(TMP, "mixed.pcap")
HOSTILE = os.path.join(TMP, "hostile.pcap")

TRUTH = synth.write_mixed(MIXED, packets=400, seed=42)
HOSTILE_CASES = synth.write_hostile(HOSTILE)
PACKETS = pcap.load(MIXED)
HOSTILE_PACKETS = pcap.load(HOSTILE)

results = []


def check(name, fn):
    try:
        fn()
    except AssertionError as exc:
        results.append((name, False, str(exc)))
    except Exception as exc:
        results.append((name, False, f"{type(exc).__name__}: {exc}"))
    else:
        results.append((name, True, ""))


# --------------------------------------------------------------------------
# the invariant: never read past your own slice, never trust a length field
# --------------------------------------------------------------------------

def test_an_ipv4_header_claiming_more_than_the_frame_holds_is_refused():
    """THE test. ihl is 4 bits, so a header can claim up to 60 bytes on a
    frame that has 26. A parser that trusts it reads the transport header
    from beyond the frame -- in a streaming parser, from the *next packet*.
    The result is a dissector reporting ports that were never on the wire."""
    p = HOSTILE_PACKETS[0]
    assert p.errors, "an IPv4 header claiming 60 bytes in a 26-byte frame was accepted"
    assert "60" in p.errors[0], f"the error should name the claimed length: {p.errors}"
    assert p.src_port == 0 and p.dst_port == 0, \
        f"ports were invented from out-of-bounds bytes: {p.src_port}/{p.dst_port}"
    assert "TCP" not in p.layers, "claimed a TCP layer it could not have parsed"


def test_a_tcp_data_offset_past_the_end_is_refused():
    """Data offset says 60 bytes of header in a 20-byte segment. Payload
    length must not go negative, and must not be computed from bytes that
    are not there."""
    p = HOSTILE_PACKETS[1]
    assert p.errors, "a TCP data offset past the end of the segment was accepted"
    assert p.payload_length == 0, f"payload length is {p.payload_length}, should be 0"
    assert p.payload_length >= 0, "payload length went negative"


def test_an_ipv4_total_length_beyond_the_capture_is_clamped_not_trusted():
    """total_length larger than the captured bytes is NORMAL -- it is what a
    snaplen looks like. It must be clamped to what exists, and parsing must
    continue rather than failing."""
    p = HOSTILE_PACKETS[2]
    assert "TCP" in p.layers, "a snaplen-truncated packet should still parse its TCP header"
    assert p.dst_port == 443, f"expected port 443, got {p.dst_port}"
    assert p.payload_length <= p.capture_length, \
        f"payload {p.payload_length} exceeds the {p.capture_length} bytes captured"


def test_a_non_first_fragment_has_no_ports():
    """THE subtle one. A fragment with offset > 0 carries no transport header
    -- its first bytes are payload. Parsing them as a TCP header produces
    convincing nonsense: ports that were never sent, in a flow table that
    looks entirely plausible."""
    p = HOSTILE_PACKETS[3]
    assert "IPv4-fragment" in p.layers, f"fragment not identified: {p.layers}"
    assert p.src_port == 0 and p.dst_port == 0, \
        f"invented ports {p.src_port}/{p.dst_port} from fragment payload"
    assert "TCP" not in p.layers, "claimed TCP on a packet with no TCP header"


def test_a_udp_length_below_its_own_header_is_refused():
    p = HOSTILE_PACKETS[4]
    assert p.errors, "a UDP length of 3 was accepted"
    assert p.payload_length >= 0, f"payload length went negative: {p.payload_length}"


def test_a_frame_too_short_for_ethernet_is_refused():
    p = HOSTILE_PACKETS[6]
    assert p.errors, "an 8-byte frame was parsed as Ethernet"
    assert p.layers == [], f"claimed layers {p.layers} on 8 bytes"


def test_the_parser_recovers_after_bad_frames():
    """Seven malformed frames then a valid one. A parser that loses
    synchronisation would fail here, and that is exactly what happens when
    a length field is trusted as a seek offset."""
    p = HOSTILE_PACKETS[7]
    assert not p.errors, f"the valid final packet reported errors: {p.errors}"
    assert p.src_port == 51000 and p.dst_port == 443, \
        f"expected 51000->443, got {p.src_port}->{p.dst_port}"
    assert p.protocol == "HTTPS"


def test_every_hostile_frame_is_accounted_for():
    """All eight parse to a Packet. None raise, none are dropped -- a
    malformed frame is data, not an exception."""
    assert len(HOSTILE_PACKETS) == len(HOSTILE_CASES), \
        f"wrote {len(HOSTILE_CASES)} frames, parsed {len(HOSTILE_PACKETS)}"
    for p in HOSTILE_PACKETS:
        assert p.capture_length >= 0 and p.payload_length >= 0, \
            f"packet #{p.number} has a negative length"


# --------------------------------------------------------------------------
# correctness against known ground truth
# --------------------------------------------------------------------------

def test_the_capture_round_trips():
    """Written by synth.py, read back by pcap.py, same count."""
    assert len(PACKETS) == TRUTH["total"] == 400, \
        f"wrote {TRUTH['total']}, read {len(PACKETS)}"
    assert not any(p.errors for p in PACKETS), \
        f"{sum(1 for p in PACKETS if p.errors)} well-formed packets reported errors"


def test_protocols_match_what_was_written():
    """Counts, not vibes. The generator recorded what it wrote."""
    from collections import Counter
    got = Counter(p.protocol for p in PACKETS)
    # HTTPS-v6 frames are also labelled HTTPS, since the label comes from the
    # port and not the IP version.
    assert got["HTTPS"] == TRUTH["protocols"]["HTTPS"] + TRUTH["protocols"]["HTTPS-v6"], \
        f"HTTPS count {got['HTTPS']} != {TRUTH['protocols']['HTTPS']} + {TRUTH['protocols']['HTTPS-v6']}"
    for proto in ("DNS", "SSH", "PostgreSQL", "ICMP", "ARP"):
        assert got[proto] == TRUTH["protocols"][proto], \
            f"{proto}: parsed {got[proto]}, wrote {TRUTH['protocols'][proto]}"


def test_ipv6_addresses_parse():
    v6 = [p for p in PACKETS if "IPv6" in p.layers]
    assert v6, "no IPv6 packets parsed, but the capture contains them"
    for p in v6:
        assert p.src_ip.startswith("2001:0db8"), f"bad IPv6 source {p.src_ip}"
        assert len(p.src_ip.split(":")) == 8, f"IPv6 address has wrong group count: {p.src_ip}"
        assert p.dst_port == 443, "IPv6 TCP ports did not parse"


def test_tcp_flags_decode():
    syn = [p for p in PACKETS if p.tcp_flags == "SYN"]
    push = [p for p in PACKETS if p.tcp_flags == "PSH,ACK"]
    assert syn, "no bare SYN packets found"
    assert push, "no PSH,ACK packets found"
    assert all(p.payload_length == 0 for p in syn), "a bare SYN carried payload"


def test_a_connection_key_is_direction_independent():
    """Request and response must land in the same conversation. Without
    sorting the endpoints, every flow is counted twice and the top-talkers
    table is wrong in a way that looks right."""
    a = pcap.Packet(1, 0, 60, 60, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                    src_port=51000, dst_port=443)
    b = pcap.Packet(2, 0, 60, 60, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                    src_port=443, dst_port=51000)
    assert a.connection == b.connection, \
        f"the two directions got different keys:\n  {a.connection}\n  {b.connection}"


def test_the_app_label_uses_the_server_port():
    """A client on ephemeral 51234 talking to 443 is HTTPS. The informative
    end is whichever is well known, not whichever is the source."""
    assert pcap._guess_app(51234, 443) == "HTTPS"
    assert pcap._guess_app(443, 51234) == "HTTPS"
    assert pcap._guess_app(51234, 51235) == "", "labelled two ephemeral ports"
    assert pcap._guess_app(80, 443) == "HTTP", "with two well-known ports, the lower wins"


def test_a_truncated_capture_is_reported_not_hidden():
    """wire_length > capture_length means a snaplen was set. The byte totals
    should use the wire length, and the fact should be visible."""
    path = os.path.join(TMP, "snaplen.pcap")
    with synth.PcapWriter(path) as w:
        frame = synth.ethernet(1, 2, 0x0800, synth.ipv4(
            synth._ip(10, 0, 0, 1), synth._ip(10, 0, 0, 2), 6,
            synth.tcp(1234, 443, 0x18, b"x" * 40)))
        w.write(frame[:60], 1.0, wire_length=1500)
    p = pcap.load(path)[0]
    assert p.truncated, "a 60-byte capture of a 1500-byte frame was not flagged truncated"
    assert p.wire_length == 1500 and p.capture_length == 60


# --------------------------------------------------------------------------
# file format handling
# --------------------------------------------------------------------------

def test_a_non_capture_file_is_refused_by_name():
    path = os.path.join(TMP, "notacapture.bin")
    with open(path, "wb") as fh:
        fh.write(b"PK\x03\x04" + b"\x00" * 100)
    try:
        pcap.load(path)
        raise AssertionError("a zip file was accepted as a capture")
    except pcap.CaptureError as exc:
        assert "magic" in str(exc).lower(), f"unhelpful error: {exc}"


def test_an_absurd_caplen_is_refused():
    """A corrupt or hostile caplen is how a parser gets talked into allocating
    a gigabyte. Bound it before reading."""
    path = os.path.join(TMP, "absurd.pcap")
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        fh.write(struct.pack("<IIII", 1, 0, 999_999_999, 999_999_999))
    try:
        pcap.load(path)
        raise AssertionError("a caplen of 1GB was accepted")
    except pcap.CaptureError as exc:
        assert "corrupt" in str(exc).lower() or "snaplen" in str(exc).lower()


def test_a_truncated_final_record_ends_cleanly():
    """A capture cut off mid-write is common -- Ctrl-C during tcpdump. It must
    return the packets it has, not raise."""
    path = os.path.join(TMP, "cut.pcap")
    with open(MIXED, "rb") as src, open(path, "wb") as dst:
        dst.write(src.read()[:2000])
    got = pcap.load(path)
    assert got, "a partially written capture returned nothing"
    assert all(p.capture_length > 0 for p in got)


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

def test_the_hierarchy_shares_do_not_exceed_one_hundred_percent():
    """Counted along each packet's own layer list. Counting layers
    independently makes the percentages sum to several hundred and mean
    nothing."""
    rows = analyze.flatten_hierarchy(analyze.protocol_hierarchy(PACKETS))
    top = [r for r in rows if r["depth"] == 0]
    assert sum(r["packets"] for r in top) == len(PACKETS), \
        "top-level layers do not sum to the packet count"
    for row in rows:
        assert row["packets"] <= len(PACKETS), f"{row['layer']} counted more than once per packet"


def test_the_planted_scanner_is_found():
    """synth.py plants one host doing a port scan. Finding it is the point of
    the detectors; the ground truth is what makes this a real test."""
    findings = analyze.find_anomalies(PACKETS)
    scan = [f for f in findings if TRUTH["scanner_ip"] in f.title]
    assert scan, f"the planted scanner {TRUTH['scanner_ip']} was not found"
    assert all(f.severity == "suspicious" for f in scan)
    assert all(f.packets for f in scan), "a finding with no evidence packets"


def test_normal_hosts_are_not_flagged_as_scanners():
    """False positives are what make a detector get ignored. The busy client
    hosts use many source ports to few destination ports -- the opposite
    shape -- and must stay quiet."""
    findings = analyze.find_anomalies(PACKETS)
    for host in ("10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"):
        flagged = [f for f in findings if f.severity == "suspicious" and host in f.title]
        assert not flagged, f"{host} was wrongly flagged: {[f.title for f in flagged]}"


def test_every_finding_carries_evidence():
    """A finding with no packet numbers is an alert nobody can act on and
    nobody can disprove."""
    for f in analyze.find_anomalies(PACKETS) + analyze.find_anomalies(HOSTILE_PACKETS):
        assert f.packets, f"finding {f.title!r} has no evidence packets"
        assert all(isinstance(n, int) for n in f.packets), "evidence is not packet numbers"
        assert f.severity in ("info", "suspicious"), \
            f"{f.title}: severity {f.severity!r} -- nothing is ever labelled malicious"


def test_malformed_frames_are_reported_as_a_finding():
    findings = analyze.find_anomalies(HOSTILE_PACKETS)
    bad = [f for f in findings if "length check" in f.title]
    assert bad, "a capture that is mostly malformed produced no finding about it"


def test_the_timeline_buckets_every_packet_exactly_once():
    """The final packet's bucket index is exactly `buckets` without a guard,
    which silently drops it off the end."""
    buckets = analyze.timeline(PACKETS, 60)
    assert sum(b["packets"] for b in buckets) == len(PACKETS), \
        f"timeline holds {sum(b['packets'] for b in buckets)} of {len(PACKETS)} packets"


def test_byte_totals_agree_across_views():
    s = analyze.summarize(PACKETS)
    assert s["bytes"] == sum(p.wire_length for p in PACKETS)
    assert sum(s["protocol_bytes"].values()) <= s["bytes"] + 1, "protocol bytes exceed the total"


# --------------------------------------------------------------------------
# the filter
# --------------------------------------------------------------------------

def test_an_unknown_filter_field_raises():
    """A filter that silently matches everything looks exactly like a capture
    with nothing interesting in it."""
    try:
        cli.parse_filter("tcp.prot=443")
        raise AssertionError("a misspelled filter field was accepted")
    except ValueError as exc:
        assert "tcp.prot" in str(exc)


def test_filters_select_the_right_packets():
    terms = cli.parse_filter("tcp.port=443")
    got = [p for p in PACKETS if cli.matches(p, terms)]
    assert got, "tcp.port=443 matched nothing"
    assert all(443 in (p.src_port, p.dst_port) for p in got)
    assert all("TCP" in p.layers for p in got), "a UDP packet matched tcp.port"

    terms = cli.parse_filter("ip=10.0.0.66")
    scanner = [p for p in PACKETS if cli.matches(p, terms)]
    assert len(scanner) == 21, f"expected 21 scanner packets, got {len(scanner)}"


def test_filter_terms_combine_with_and():
    terms = cli.parse_filter("ip=10.0.0.66,proto=TCP")
    got = [p for p in PACKETS if cli.matches(p, terms)]
    assert got and all("10.0.0.66" in (p.src_ip, p.dst_ip) for p in got)
    assert all("TCP" in p.layers for p in got)


def test_parsing_is_deterministic():
    """Same file, same output, every time."""
    first = [(p.number, p.protocol, p.src_port, p.dst_port) for p in pcap.load(MIXED)]
    for _ in range(3):
        again = [(p.number, p.protocol, p.src_port, p.dst_port) for p in pcap.load(MIXED)]
        assert again == first, "parsing is not deterministic"


TESTS = [
    ("ipv4 ihl past the frame is refused", test_an_ipv4_header_claiming_more_than_the_frame_holds_is_refused),
    ("tcp data offset past the end is refused", test_a_tcp_data_offset_past_the_end_is_refused),
    ("ipv4 total_length is clamped not trusted", test_an_ipv4_total_length_beyond_the_capture_is_clamped_not_trusted),
    ("a non-first fragment has no ports", test_a_non_first_fragment_has_no_ports),
    ("udp length below its header is refused", test_a_udp_length_below_its_own_header_is_refused),
    ("a frame too short for ethernet is refused", test_a_frame_too_short_for_ethernet_is_refused),
    ("the parser recovers after bad frames", test_the_parser_recovers_after_bad_frames),
    ("every hostile frame is accounted for", test_every_hostile_frame_is_accounted_for),
    ("the capture round trips", test_the_capture_round_trips),
    ("protocols match what was written", test_protocols_match_what_was_written),
    ("ipv6 addresses parse", test_ipv6_addresses_parse),
    ("tcp flags decode", test_tcp_flags_decode),
    ("a connection key is direction independent", test_a_connection_key_is_direction_independent),
    ("the app label uses the server port", test_the_app_label_uses_the_server_port),
    ("a truncated capture is reported", test_a_truncated_capture_is_reported_not_hidden),
    ("a non-capture file is refused by name", test_a_non_capture_file_is_refused_by_name),
    ("an absurd caplen is refused", test_an_absurd_caplen_is_refused),
    ("a truncated final record ends cleanly", test_a_truncated_final_record_ends_cleanly),
    ("hierarchy shares stay under 100%", test_the_hierarchy_shares_do_not_exceed_one_hundred_percent),
    ("the planted scanner is found", test_the_planted_scanner_is_found),
    ("normal hosts are not flagged", test_normal_hosts_are_not_flagged_as_scanners),
    ("every finding carries evidence", test_every_finding_carries_evidence),
    ("malformed frames become a finding", test_malformed_frames_are_reported_as_a_finding),
    ("the timeline buckets every packet once", test_the_timeline_buckets_every_packet_exactly_once),
    ("byte totals agree across views", test_byte_totals_agree_across_views),
    ("an unknown filter field raises", test_an_unknown_filter_field_raises),
    ("filters select the right packets", test_filters_select_the_right_packets),
    ("filter terms combine with AND", test_filter_terms_combine_with_and),
    ("parsing is deterministic", test_parsing_is_deterministic),
]


def main():
    for name, fn in TESTS:
        check(name, fn)
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, err in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {err}")
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
