# Protocol Dissector Dashboard

Reads `.pcap` and `.pcapng` files, walks every frame from Ethernet up to the
application layer, and produces a protocol hierarchy, per-conversation
volumes, and a small set of flagged anomalies with the packet numbers behind
each one.

**Python standard library only.** No Scapy, no libpcap, no dpkt — the capture
file is parsed from raw bytes with `struct`, because that is the part worth
demonstrating.

**29/29 tests, including 8 deliberately malformed frames whose length fields
lie.** Full numbers in [RESULTS.md](RESULTS.md).

---

## The rule the whole thing turns on

> **A parser never reads past the boundary of the thing it was given, and
> never trusts a length field from the file.**

Every length in a capture is attacker-controlled — the packet was, by
definition, written by someone else. An IPv4 header claiming `ihl=15` in a
26-byte frame, a `caplen` bigger than the file, a TCP data offset pointing
past the end of its segment: all appear in real captures, some by accident and
some on purpose.

**The failure is not a crash.** It is silently reading the *next* packet's
bytes as this one's payload — a dissector that reports ports nobody sent, in a
flow table that looks entirely plausible. So every accessor is bounds-checked
against the slice it owns, and an impossible field produces a recorded `error`
on the packet rather than an exception or a guess.

---

## Running it

Python 3.10+. Nothing to install.

```bash
# make a capture with known contents
python synth.py captures/mixed.pcap --packets 400

python cli.py captures/mixed.pcap                  # summary + findings
python cli.py captures/mixed.pcap --hierarchy      # protocol tree
python cli.py captures/mixed.pcap --conversations  # who talked to whom
python cli.py captures/mixed.pcap --packets 20     # packet list
python cli.py captures/mixed.pcap --packet 12      # one packet, in full
python cli.py captures/mixed.pcap --filter tcp.port=443
python cli.py captures/mixed.pcap --html board.html
python cli.py captures/mixed.pcap --json
```

It reads any capture — one from `tcpdump -w`, Wireshark, or `synth.py`.

```
layer                                packets   share         bytes
Ethernet                                 400  100.0%      159.1 KB
  IPv4                                   372   93.0%      153.0 KB
    TCP                                  270   67.5%      144.2 KB
      HTTPS                              167   41.8%      112.6 KB
      SSH                                 46   11.5%       13.6 KB
      PostgreSQL                          36    9.0%       16.9 KB
    UDP                                   78   19.5%        7.7 KB
      DNS                                 78   19.5%        7.7 KB
    ICMP                                  24    6.0%        1.1 KB
  ARP                                     18    4.5%         756 B
  IPv6                                    10    2.5%        5.4 KB
```

The hierarchy is counted along each packet's own layer list, so a frame
contributes to every level of its own stack and no other. Counting layers
independently makes the shares sum to several hundred percent and mean
nothing.

---

## Findings carry their evidence

```
[suspicious] 10.0.0.66 touched 21 distinct ports on 10.0.0.20
  21 distinct destination ports across 21 packets. A client uses many *source*
  ports and one destination port; this is the opposite shape. Consistent with
  port enumeration -- which an authorised scanner also does.
  evidence: #12, #23, #29, #40, #73, #135, #157, #182 (+13 more)
  check it: python cli.py <capture> --packet 12
```

Every `Finding` carries the packet numbers behind it, and `--packet N` prints
that packet in full. A detector that says "possible port scan" with no way to
look at packet 12 is an alert nobody can act on and nobody can disprove.

**Nothing is ever labelled malicious.** The severities are `info` and
`suspicious`. These are heuristics on a single capture with no baseline for
what is normal on this network, and an authorised vulnerability scan produces
exactly the pattern the scan detector fires on. The tool cannot tell them
apart and does not pretend to.

The scan detector works on **shape**, not volume: a scan is one source port
range touching many destination ports; a busy browser is many source ports
touching one destination port. Counting only distinct destination ports keeps
the two apart, which is why the four normal hosts in the fixture stay quiet.

---

## Why `synth.py` exists

It writes valid pcap files with **known contents**, and it does two jobs:

1. **Fixtures with ground truth.** The generator records what it wrote, so the
   tests assert against intent, not against whatever the parser produced. A
   parser checked against captures nobody can describe is a parser checked
   against its own output.

2. **Frames whose length fields lie.** `--hostile` writes eight of them, each
   a real dissector trap:

| # | The lie | What a correct parser must do |
|---|---|---|
| 1 | IPv4 `ihl` claims 60 bytes in a 26-byte frame | error, no ports |
| 2 | TCP data offset claims 60 bytes of a 20-byte segment | error, payload 0 |
| 3 | IPv4 `total_length` 9000, capture much shorter | clamp, keep parsing |
| 4 | Non-first fragment (offset 185) | no ports — there is no TCP header |
| 5 | UDP length 3, smaller than its own 8-byte header | error, no negative payload |
| 6 | IPv4 declared, zero bytes follow | error |
| 7 | 8-byte frame, shorter than an Ethernet header | error |
| 8 | A valid packet after seven bad ones | parse normally |

Case 4 is the one worth dwelling on. A fragment with a non-zero offset has no
transport header at all — its first bytes are payload. Parsing them as TCP
yields ports that were never sent, and both the packet and the flow table look
completely ordinary. Case 8 exists because a parser that trusts a length as a
seek offset loses synchronisation and never recovers.

---

## Tests

```bash
python test_dissector.py     # 29/29, under a second
```

No pytest, no network, no root, no fixture files in the repo — every capture
is generated at test time from a seed.

| Group | Tests | Pins |
|---|---|---|
| Bounds checking | 8 | the eight hostile frames above |
| Ground truth | 7 | parsed protocol counts equal written counts |
| File formats | 3 | a zip is refused by name; a 1 GB `caplen` is refused; a half-written capture ends cleanly |
| Analysis | 7 | the planted scanner is found, the four normal hosts are not, every finding has evidence |
| Filters | 3 | a misspelled field raises rather than matching everything |

Two of these are worth naming:

- **`test_normal_hosts_are_not_flagged_as_scanners`** — false positives are
  what get a detector ignored. Testing that a detector fires is half a test.
- **`test_a_connection_key_is_direction_independent`** — a request and its
  response must land in the same conversation. Without sorting the endpoints
  every flow is counted twice, and the top-talkers table is wrong in a way
  that looks right.

---

## Driving it from other software

`--json` writes one JSON document to stdout and nothing else. Exit 0 on
success, 1 on an unreadable capture or an empty filter match, 2 on a missing
file.

```bash
python cli.py capture.pcap --json | jq '.findings[] | select(.severity=="suspicious")'
```

That is the project's answer to "where is the AI?" — deliberately nowhere
inside. Protocol dissection is exactly specified by RFCs; a model asked to do
it would be slower, non-deterministic, and wrong in ways that are hard to
detect. What the project offers instead is a clean machine interface and
findings that carry checkable evidence, which is what an agent actually needs.

---

## What is not here

- **No live capture.** Reading a NIC needs root or `CAP_NET_RAW` and a
  platform-specific path (`AF_PACKET` on Linux, npcap on Windows). Capture
  with `tcpdump -w` or Wireshark and point this at the file. The parsing —
  the interesting half — is identical either way.
- **Not BPF.** `--filter` is a deliberately tiny `field=value` language. Real
  BPF means linking libpcap or writing a compiler, and it belongs at capture
  time anyway. An unknown field **raises** rather than matching everything,
  because a filter that silently matches everything looks exactly like a
  capture with nothing interesting in it.
- **No TCP stream reassembly.** Per-packet only, so no reconstructed HTTP
  bodies or TLS handshakes.
- **No IPv6 extension headers.** They are detected and reported as unparsed
  rather than being walked, because guessing past a Hop-by-Hop header makes
  the next byte look like a transport header when it is not.
- **Ethernet and Linux-cooked link types only.** Anything else is refused by
  name rather than parsed as if it were Ethernet.
- **Port-based application labels are advisory.** They label traffic; they
  never decide how to parse it. SSH on port 8443 is common, and a dissector
  that parsed it as TLS because of the port would produce confident nonsense.
