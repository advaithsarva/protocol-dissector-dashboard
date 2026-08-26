"""Read .pcap and .pcapng files with nothing but `struct`.

No Scapy, no libpcap, no dpkt. A capture file is a header followed by
length-prefixed records, and parsing it is the part of "I understand
networking" that is actually worth demonstrating.

THE INVARIANT
-------------
**A parser never reads past the boundary of the thing it was given, and never
trusts a length field from the file.**

Every length in a capture file is attacker-controlled -- the packet was, by
definition, written by someone else. An IPv4 header that claims `ihl=15` in a
34-byte frame, a `caplen` larger than the remaining file, a TCP data offset
pointing past the end of the segment: all of these appear in real captures,
some by accident and some on purpose. The failure mode is not a crash. It is
silently reading the *next* packet's bytes as this packet's payload, which
turns into a dissector that reports protocols that were never on the wire.

So every accessor here is bounds-checked against the slice it owns, and a
truncated or impossible field produces a recorded `error` on the packet rather
than an exception or a guess.

Byte order
----------
Network byte order is big-endian ('>'). The pcap *file* header, confusingly,
can be either -- the magic number tells you which, and getting it backwards
gives plausible-looking garbage rather than an obvious failure. That is what
`_MAGIC` is for.
"""

import struct
from dataclasses import dataclass, field

# pcap file magic. The byte order of everything else in the file follows from
# which of these matched.
_MAGIC = {
    0xA1B2C3D4: (">", 1),          # big-endian, microsecond timestamps
    0xD4C3B2A1: ("<", 1),          # little-endian, microsecond
    0xA1B23C4D: (">", 1000),       # big-endian, nanosecond
    0x4D3CB2A1: ("<", 1000),       # little-endian, nanosecond
}
_PCAPNG_MAGIC = 0x0A0D0D0A

ETHERTYPE = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q"}
IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 47: "GRE", 89: "OSPF"}

# Ports where a well-known protocol lives. Used only to *label* traffic, never
# to decide how to parse it -- see dissect.py for why that distinction matters.
WELL_KNOWN = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 514: "syslog", 587: "SMTP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5060: "SIP",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
             (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]


class CaptureError(Exception):
    """The file is not a capture we can read. Distinct from a malformed packet
    *inside* a readable capture, which is recorded rather than raised."""


@dataclass
class Packet:
    """One frame, dissected as far as it could be.

    `layers` is the protocol stack in order, e.g. ['Ethernet', 'IPv4', 'TCP',
    'HTTP']. `errors` is non-empty when a length field did not survive its
    bounds check -- the packet is still returned, with whatever was parsed
    before the problem.
    """

    number: int
    timestamp: float
    wire_length: int          # length on the wire
    capture_length: int       # bytes actually saved
    layers: list = field(default_factory=list)
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""        # deepest layer identified
    app_protocol: str = ""    # guessed from port, advisory only
    payload_length: int = 0
    tcp_flags: str = ""
    errors: list = field(default_factory=list)

    @property
    def truncated(self):
        """Saved less than was on the wire -- a snaplen was set."""
        return self.capture_length < self.wire_length

    @property
    def connection(self):
        """Bidirectional flow key: same tuple regardless of direction.

        Sorting the endpoints is what makes a request and its response belong
        to one conversation. Without it every flow is counted twice and the
        'top talkers' table is wrong in a way that looks right.
        """
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)
        lo, hi = sorted([a, b])
        return f"{lo[0]}:{lo[1]} <-> {hi[0]}:{hi[1]}"


def _mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def _ipv4(raw):
    return ".".join(str(b) for b in raw)


def _ipv6(raw):
    """Full form, no :: compression. Compression is display sugar and getting
    it subtly wrong makes two spellings of the same address look like two
    different hosts in a flow table."""
    return ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))


# --------------------------------------------------------------------------
# file readers
# --------------------------------------------------------------------------

def read_packets(path, limit=None):
    """Yield raw (timestamp, wire_length, data) from a pcap or pcapng file."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            raise CaptureError(f"{path} is too short to be a capture file")
        fh.seek(0)

        if struct.unpack(">I", head)[0] == _PCAPNG_MAGIC:
            yield from _read_pcapng(fh, limit)
        else:
            yield from _read_pcap(fh, limit)


def _read_pcap(fh, limit):
    header = fh.read(24)
    if len(header) < 24:
        raise CaptureError("truncated pcap file header")

    magic = struct.unpack(">I", header[:4])[0]
    if magic not in _MAGIC:
        raise CaptureError(
            f"unrecognised magic 0x{magic:08x}; not a pcap file "
            f"(pcapng files start with 0x0a0d0d0a)"
        )
    endian, ts_divisor = _MAGIC[magic]
    # snaplen and link type follow; only link type matters and we assume
    # Ethernet, which is what every capture from a normal NIC uses.
    link_type = struct.unpack(f"{endian}I", header[20:24])[0]
    if link_type not in (1, 113):     # 1 = Ethernet, 113 = Linux cooked
        raise CaptureError(
            f"link type {link_type} is not Ethernet; this dissector only "
            f"understands Ethernet frames"
        )

    count = 0
    while limit is None or count < limit:
        record = fh.read(16)
        if len(record) < 16:
            break                      # clean end of file
        sec, usec, caplen, wirelen = struct.unpack(f"{endian}IIII", record)

        # Do not trust caplen. A corrupt or hostile value here is the classic
        # way to make a parser allocate a gigabyte or walk off the end.
        if caplen > 262144:
            raise CaptureError(
                f"packet {count + 1} claims {caplen} captured bytes, which is "
                f"beyond any plausible snaplen; the file is corrupt"
            )
        data = fh.read(caplen)
        if len(data) < caplen:
            break                      # truncated final record; stop cleanly

        yield sec + usec / (1_000_000 * ts_divisor), wirelen, data
        count += 1


def _read_pcapng(fh, limit):
    """Enhanced Packet Blocks only -- the ones that carry packets.

    pcapng is a block format: every block is (type, total_length, body,
    total_length again). Walking it means trusting total_length, so it gets
    the same treatment as caplen above.
    """
    endian = "<"
    resolution = 1_000_000
    count = 0

    while limit is None or count < limit:
        head = fh.read(8)
        if len(head) < 8:
            break

        block_type = struct.unpack(f"{endian}I", head[:4])[0]
        if block_type == _PCAPNG_MAGIC:
            # Section Header Block: the byte-order magic sets endianness for
            # everything that follows, and it can change mid-file.
            rest = fh.read(4)
            if struct.unpack("<I", rest)[0] != 0x1A2B3C4D:
                endian = ">"
            total = struct.unpack(f"{endian}I", head[4:8])[0]
            fh.seek(total - 12, 1)
            continue

        total = struct.unpack(f"{endian}I", head[4:8])[0]
        if total < 12 or total > 16_777_216:
            raise CaptureError(f"pcapng block claims {total} bytes; file is corrupt")

        body = fh.read(total - 12)
        fh.read(4)                       # trailing length, already known

        if block_type == 6 and len(body) >= 20:          # Enhanced Packet Block
            _, ts_hi, ts_lo, caplen, wirelen = struct.unpack(f"{endian}IIIII", body[:20])
            data = body[20:20 + caplen]
            if len(data) == caplen:
                ts = ((ts_hi << 32) | ts_lo) / resolution
                yield ts, wirelen, data
                count += 1


# --------------------------------------------------------------------------
# the dissector
# --------------------------------------------------------------------------

def dissect(number, timestamp, wire_length, data):
    """Walk one frame up the stack, bounds-checking every step."""
    pkt = Packet(number=number, timestamp=timestamp, wire_length=wire_length,
                 capture_length=len(data))

    if len(data) < 14:
        pkt.errors.append(f"frame is {len(data)} bytes; an Ethernet header needs 14")
        return pkt

    pkt.layers.append("Ethernet")
    pkt.dst_mac = _mac(data[0:6])
    pkt.src_mac = _mac(data[6:12])
    ethertype = struct.unpack(">H", data[12:14])[0]
    offset = 14

    if ethertype == 0x8100:                     # VLAN tag: 4 more bytes
        if len(data) < 18:
            pkt.errors.append("802.1Q tag truncated")
            return pkt
        pkt.layers.append("802.1Q")
        ethertype = struct.unpack(">H", data[16:18])[0]
        offset = 18

    name = ETHERTYPE.get(ethertype)
    pkt.protocol = name or f"0x{ethertype:04x}"

    if name == "IPv4":
        _ipv4_layer(pkt, data, offset)
    elif name == "IPv6":
        _ipv6_layer(pkt, data, offset)
    elif name == "ARP":
        pkt.layers.append("ARP")
        pkt.payload_length = len(data) - offset
    else:
        pkt.payload_length = max(0, len(data) - offset)

    return pkt


def _ipv4_layer(pkt, data, offset):
    if len(data) - offset < 20:
        pkt.errors.append("IPv4 header truncated")
        return
    pkt.layers.append("IPv4")

    ihl = (data[offset] & 0x0F) * 4
    # The header length field is 4 bits, so it can claim up to 60 bytes on a
    # frame that does not have them. Checking it is the difference between
    # parsing the next header and parsing whatever happens to follow.
    if ihl < 20:
        pkt.errors.append(f"IPv4 header length claims {ihl} bytes; minimum is 20")
        return
    if offset + ihl > len(data):
        pkt.errors.append(
            f"IPv4 header claims {ihl} bytes but only {len(data) - offset} remain"
        )
        return

    total_length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
    proto = data[offset + 9]
    pkt.src_ip = _ipv4(data[offset + 12:offset + 16])
    pkt.dst_ip = _ipv4(data[offset + 16:offset + 20])

    flags_frag = struct.unpack(">H", data[offset + 6:offset + 8])[0]
    fragment_offset = flags_frag & 0x1FFF
    more_fragments = bool(flags_frag & 0x2000)

    payload_start = offset + ihl
    # Trust the smaller of "what the IP header says" and "what we actually
    # have". A total_length larger than the capture is normal when a snaplen
    # was set, and it must not be used as a slice bound.
    declared_end = offset + total_length
    payload_end = min(declared_end, len(data)) if total_length >= ihl else len(data)

    if fragment_offset > 0:
        # A non-first fragment has no transport header at all. Parsing its
        # first bytes as TCP is a real dissector bug and produces convincing
        # nonsense -- ports that were never sent.
        pkt.layers.append("IPv4-fragment")
        pkt.protocol = IP_PROTO.get(proto, str(proto)) + " (fragment)"
        pkt.payload_length = max(0, payload_end - payload_start)
        return

    pkt.protocol = IP_PROTO.get(proto, f"IP-proto-{proto}")
    segment = data[payload_start:payload_end]

    if proto == 6:
        _tcp_layer(pkt, segment)
    elif proto == 17:
        _udp_layer(pkt, segment)
    elif proto == 1:
        pkt.layers.append("ICMP")
        pkt.payload_length = len(segment)
        if len(segment) >= 2:
            pkt.tcp_flags = f"type={segment[0]} code={segment[1]}"
    else:
        pkt.payload_length = len(segment)

    if more_fragments:
        pkt.layers.append("fragmented")


def _ipv6_layer(pkt, data, offset):
    if len(data) - offset < 40:
        pkt.errors.append("IPv6 header truncated")
        return
    pkt.layers.append("IPv6")

    payload_length = struct.unpack(">H", data[offset + 4:offset + 6])[0]
    next_header = data[offset + 6]
    pkt.src_ip = _ipv6(data[offset + 8:offset + 24])
    pkt.dst_ip = _ipv6(data[offset + 24:offset + 40])
    pkt.protocol = IP_PROTO.get(next_header, f"IP-proto-{next_header}")

    start = offset + 40
    end = min(start + payload_length, len(data))
    segment = data[start:end]

    # Extension headers are not walked. Saying so is better than pretending:
    # a Hop-by-Hop header would make the next byte look like a transport
    # header when it is not.
    if next_header in (0, 43, 44, 60):
        pkt.layers.append("IPv6-ext")
        pkt.errors.append(f"IPv6 extension header {next_header} not parsed")
        pkt.payload_length = len(segment)
        return

    if next_header == 6:
        _tcp_layer(pkt, segment)
    elif next_header == 17:
        _udp_layer(pkt, segment)
    else:
        pkt.payload_length = len(segment)


def _tcp_layer(pkt, segment):
    if len(segment) < 20:
        pkt.errors.append(f"TCP header truncated ({len(segment)} bytes, needs 20)")
        return
    pkt.layers.append("TCP")

    pkt.src_port, pkt.dst_port = struct.unpack(">HH", segment[0:4])
    data_offset = (segment[12] >> 4) * 4
    if data_offset < 20:
        pkt.errors.append(f"TCP data offset claims {data_offset} bytes; minimum is 20")
        data_offset = 20
    if data_offset > len(segment):
        pkt.errors.append(
            f"TCP data offset claims {data_offset} bytes but only {len(segment)} remain"
        )
        pkt.payload_length = 0
    else:
        pkt.payload_length = len(segment) - data_offset

    flags = segment[13]
    pkt.tcp_flags = ",".join(name for bit, name in TCP_FLAGS if flags & bit) or "none"
    pkt.app_protocol = _guess_app(pkt.src_port, pkt.dst_port)
    if pkt.app_protocol:
        pkt.layers.append(pkt.app_protocol)
        pkt.protocol = pkt.app_protocol


def _udp_layer(pkt, segment):
    if len(segment) < 8:
        pkt.errors.append(f"UDP header truncated ({len(segment)} bytes, needs 8)")
        return
    pkt.layers.append("UDP")

    pkt.src_port, pkt.dst_port, length, _ = struct.unpack(">HHHH", segment[0:8])
    if length < 8:
        pkt.errors.append(f"UDP length claims {length}; header alone is 8")
        pkt.payload_length = max(0, len(segment) - 8)
    else:
        pkt.payload_length = min(length - 8, len(segment) - 8)

    pkt.app_protocol = _guess_app(pkt.src_port, pkt.dst_port)
    if pkt.app_protocol:
        pkt.layers.append(pkt.app_protocol)
        pkt.protocol = pkt.app_protocol


def _guess_app(src_port, dst_port):
    """Label from the port number. Advisory only.

    The *server* port is the informative one, and it is whichever end is a
    well-known port -- a client connecting from ephemeral 51234 to 443 makes
    443 the answer. When both ends are well known (or neither is), the lower
    port wins, which is the convention every capture tool uses.

    This is a label, never a parsing decision. SSH on 8443 is common and a
    dissector that parsed it as TLS because of the port would produce
    confident nonsense.
    """
    src = WELL_KNOWN.get(src_port)
    dst = WELL_KNOWN.get(dst_port)
    if src and dst:
        return src if src_port < dst_port else dst
    return dst or src or ""


def load(path, limit=None):
    """Read and dissect a capture. Returns a list of Packet."""
    out = []
    for i, (ts, wirelen, data) in enumerate(read_packets(path, limit), start=1):
        out.append(dissect(i, ts, wirelen, data))
    return out
