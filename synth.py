"""Write valid .pcap files with known contents.

Two jobs, and the second is the important one:

1. **Fixtures with ground truth.** Every test capture is built here, so the
   expected protocol, port, flag and byte count is known exactly rather than
   eyeballed from Wireshark. A parser tested against captures nobody can
   describe is a parser tested against its own output.

2. **Deliberately malformed packets.** `--hostile` writes frames with length
   fields that lie: an IPv4 header claiming 60 bytes in a 40-byte frame, a TCP
   data offset past the end of the segment, a non-first fragment with no
   transport header. These are the inputs that turn a naive dissector into one
   that reports protocols that were never on the wire, and the suite asserts
   the parser records an error instead of inventing ports.

    python synth.py mixed.pcap --packets 500
    python synth.py hostile.pcap --hostile

Everything is seeded, so a capture regenerates byte for byte.
"""

import argparse
import random
import struct

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806


def _mac(n):
    return bytes([0x02, 0x00, 0x00, 0x00, 0x00, n & 0xFF])


def _ip(a, b, c, d):
    return bytes([a, b, c, d])


def _checksum(data):
    """The one's complement checksum used by IPv4, TCP and UDP.

    Written out because it is three lines and importing something for it would
    be silly, and because the fold-the-carry step is the part people get wrong.
    """
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)     # fold carries back in
    return ~total & 0xFFFF


def ethernet(src, dst, ethertype, payload):
    return _mac(dst) + _mac(src) + struct.pack(">H", ethertype) + payload


def ipv4(src, dst, proto, payload, ihl=5, fragment_offset=0, more_fragments=False,
         total_length=None):
    """An IPv4 packet. The odd defaults exist so hostile captures can lie.

    `ihl` and `total_length` are normally derived; passing them explicitly is
    how a malformed header gets written.
    """
    header_bytes = ihl * 4
    length = total_length if total_length is not None else header_bytes + len(payload)
    flags_frag = (0x2000 if more_fragments else 0) | (fragment_offset & 0x1FFF)

    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x40 | ihl, 0, length, 0x1234, flags_frag, 64, proto, 0, src, dst,
    )
    header = header[:10] + struct.pack(">H", _checksum(header)) + header[12:]
    padding = b"\x00" * (header_bytes - 20)          # options, if ihl > 5
    return header + padding + payload


def ipv6(src, dst, next_header, payload):
    return struct.pack(">IHBB", 0x60000000, len(payload), next_header, 64) + src + dst + payload


def tcp(src_port, dst_port, flags, payload=b"", seq=1, ack=0, data_offset=5):
    header = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, seq, ack, (data_offset << 4), flags, 65535, 0, 0,
    )
    padding = b"\x00" * max(0, (data_offset * 4) - 20)
    return header + padding + payload


def udp(src_port, dst_port, payload=b"", length=None):
    n = length if length is not None else 8 + len(payload)
    return struct.pack(">HHHH", src_port, dst_port, n, 0) + payload


def icmp(type_=8, code=0, payload=b"ping"):
    return struct.pack(">BBHHH", type_, code, 0, 1, 1) + payload


def arp(sender_ip, target_ip, sender_mac=1, target_mac=0):
    return (struct.pack(">HHBBH", 1, ETH_IPV4, 6, 4, 1)
            + _mac(sender_mac) + sender_ip + _mac(target_mac) + target_ip)


class PcapWriter:
    """Little-endian microsecond pcap, link type 1 (Ethernet)."""

    def __init__(self, path):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        self.count = 0

    def write(self, frame, timestamp, wire_length=None):
        """`wire_length` larger than the frame simulates a snaplen truncation,
        which is what a real capture with `-s 96` looks like."""
        wire = wire_length if wire_length is not None else len(frame)
        sec, usec = int(timestamp), int((timestamp % 1) * 1_000_000)
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), wire))
        self.fh.write(frame)
        self.count += 1

    def close(self):
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------
# capture recipes
# --------------------------------------------------------------------------

def write_mixed(path, packets=400, seed=42):
    """A plausible office network: web browsing, DNS, SSH, a database, some
    ICMP and ARP, and one host doing something it should not be.

    Returns the ground truth so tests can assert against intent rather than
    against whatever the parser happened to produce.
    """
    rng = random.Random(seed)
    truth = {"total": 0, "protocols": {}, "scanner_ip": "10.0.0.66",
             "scanner_ports": set(), "conversations": set()}

    hosts = [_ip(10, 0, 0, n) for n in (10, 11, 12, 13)]
    servers = {
        _ip(93, 184, 216, 34): 443,
        _ip(8, 8, 8, 8): 53,
        _ip(10, 0, 0, 20): 22,
        _ip(10, 0, 0, 21): 5432,
    }
    scanner = _ip(10, 0, 0, 66)

    def note(proto):
        truth["protocols"][proto] = truth["protocols"].get(proto, 0) + 1
        truth["total"] += 1

    with PcapWriter(path) as w:
        t = 1_700_000_000.0
        for i in range(packets):
            t += rng.uniform(0.0005, 0.02)
            roll = rng.random()
            client = rng.choice(hosts)
            ephemeral = rng.randint(32768, 60999)

            if roll < 0.42:                                    # HTTPS
                server, port = _ip(93, 184, 216, 34), 443
                flags, payload = (0x02, b"") if rng.random() < 0.1 else (0x18, bytes(rng.randint(80, 1300)))
                seg = tcp(ephemeral, port, flags, payload)
                w.write(ethernet(1, 2, ETH_IPV4, ipv4(client, server, 6, seg)), t)
                note("HTTPS")
                truth["conversations"].add(f"{'.'.join(map(str, client))}:{ephemeral}")

            elif roll < 0.60:                                  # DNS
                server, port = _ip(8, 8, 8, 8), 53
                seg = udp(ephemeral, port, bytes(rng.randint(30, 90)))
                w.write(ethernet(1, 2, ETH_IPV4, ipv4(client, server, 17, seg)), t)
                note("DNS")

            elif roll < 0.72:                                  # SSH
                seg = tcp(ephemeral, 22, 0x18, bytes(rng.randint(50, 400)))
                w.write(ethernet(1, 3, ETH_IPV4, ipv4(client, _ip(10, 0, 0, 20), 6, seg)), t)
                note("SSH")

            elif roll < 0.82:                                  # PostgreSQL
                seg = tcp(ephemeral, 5432, 0x18, bytes(rng.randint(60, 900)))
                w.write(ethernet(1, 4, ETH_IPV4, ipv4(client, _ip(10, 0, 0, 21), 6, seg)), t)
                note("PostgreSQL")

            elif roll < 0.88:                                  # the port scan
                # One source, many destination ports, all SYN, no payload.
                # This is the signal analyze.py is built to find.
                port = rng.randint(1, 9000)
                truth["scanner_ports"].add(port)
                seg = tcp(rng.randint(40000, 60000), port, 0x02)
                w.write(ethernet(9, 2, ETH_IPV4, ipv4(scanner, _ip(10, 0, 0, 20), 6, seg)), t)
                note("scan")

            elif roll < 0.93:                                  # ICMP
                w.write(ethernet(1, 2, ETH_IPV4, ipv4(client, rng.choice(hosts), 1, icmp())), t)
                note("ICMP")

            elif roll < 0.97:                                  # ARP
                w.write(ethernet(1, 255, ETH_ARP, arp(client, rng.choice(hosts))), t)
                note("ARP")

            else:                                              # IPv6 HTTPS
                src = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [rng.randint(1, 9)])
                dst = bytes([0x26, 0x06, 0x28, 0x00] + [0] * 11 + [1])
                seg = tcp(ephemeral, 443, 0x18, bytes(rng.randint(60, 800)))
                w.write(ethernet(1, 2, ETH_IPV6, ipv6(src, dst, 6, seg)), t)
                note("HTTPS-v6")

    truth["scanner_ports"] = len(truth["scanner_ports"])
    truth["conversations"] = len(truth["conversations"])
    return truth


def write_hostile(path):
    """Frames whose length fields lie. Each one is a real dissector trap.

    Returns a list of (index, what it lies about, what a correct parser must
    do) so the test can check each case by name rather than counting errors.
    """
    cases = []
    with PcapWriter(path) as w:
        t = 1_700_000_000.0

        # 1. IPv4 header claims 60 bytes (ihl=15) in a frame that has 40.
        #    A parser that trusts ihl reads the transport header from beyond
        #    the frame, or from the next packet's memory.
        frame = ethernet(1, 2, ETH_IPV4, ipv4(_ip(10, 0, 0, 1), _ip(10, 0, 0, 2), 6,
                                              tcp(1234, 80, 0x02), ihl=15)[:26])
        w.write(frame, t)
        cases.append(("ipv4 ihl past end of frame", "record an error, do not report ports"))

        # 2. TCP data offset claims 15 words (60 bytes) with 20 bytes present.
        seg = tcp(1234, 80, 0x02, data_offset=15)[:20]
        w.write(ethernet(1, 2, ETH_IPV4, ipv4(_ip(10, 0, 0, 1), _ip(10, 0, 0, 2), 6, seg)), t + 1)
        cases.append(("tcp data offset past end", "record an error, payload 0"))

        # 3. IPv4 total_length far larger than the captured bytes. Normal with
        #    a snaplen; must never be used as a slice bound.
        w.write(ethernet(1, 2, ETH_IPV4,
                         ipv4(_ip(10, 0, 0, 1), _ip(10, 0, 0, 2), 6,
                              tcp(1234, 443, 0x18, b"x" * 20), total_length=9000)), t + 2)
        cases.append(("ipv4 total_length beyond capture", "clamp to what exists, still parse TCP"))

        # 4. A non-first fragment. There is no TCP header here at all -- the
        #    first bytes are payload. Parsing them as ports is the trap.
        w.write(ethernet(1, 2, ETH_IPV4,
                         ipv4(_ip(10, 0, 0, 1), _ip(10, 0, 0, 2), 6,
                              b"\xde\xad\xbe\xef" * 6, fragment_offset=185)), t + 3)
        cases.append(("non-first fragment", "no ports, marked as a fragment"))

        # 5. UDP length field smaller than its own header.
        w.write(ethernet(1, 2, ETH_IPV4,
                         ipv4(_ip(10, 0, 0, 1), _ip(8, 8, 8, 8), 17,
                              udp(5000, 53, b"payload", length=3))), t + 4)
        cases.append(("udp length below header size", "record an error, no negative payload"))

        # 6. A 14-byte frame: Ethernet header and nothing else.
        w.write(_mac(2) + _mac(1) + struct.pack(">H", ETH_IPV4), t + 5)
        cases.append(("ipv4 declared, zero bytes follow", "record an error"))

        # 7. Truncated Ethernet frame -- 8 bytes.
        w.write(b"\x00" * 8, t + 6)
        cases.append(("frame shorter than an ethernet header", "record an error"))

        # 8. Valid packet last, to prove the parser recovers and keeps going.
        w.write(ethernet(1, 2, ETH_IPV4,
                         ipv4(_ip(10, 0, 0, 1), _ip(10, 0, 0, 2), 6,
                              tcp(51000, 443, 0x18, b"ok"))), t + 7)
        cases.append(("valid packet after seven bad ones", "parse normally, no errors"))

    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--packets", type=int, default=400)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--hostile", action="store_true",
                    help="write malformed frames instead of a normal capture")
    args = ap.parse_args()

    if args.hostile:
        cases = write_hostile(args.path)
        print(f"wrote {args.path} with {len(cases)} deliberately malformed frames:")
        for i, (what, expected) in enumerate(cases, 1):
            print(f"  {i}. {what}\n     parser must: {expected}")
    else:
        truth = write_mixed(args.path, args.packets, args.seed)
        print(f"wrote {args.path}: {truth['total']} packets, seed {args.seed}")
        for proto, n in sorted(truth["protocols"].items(), key=lambda kv: -kv[1]):
            print(f"  {proto:<12}{n:>6}")


if __name__ == "__main__":
    main()
