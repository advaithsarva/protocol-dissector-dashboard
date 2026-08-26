# Results

Every number came from a command in this file, on this machine (Windows 11,
Python 3.12.1, standard library only). All fixtures are generated from a seed,
so every figure reproduces exactly.

---

## 1. The test suite

```bash
python test_dissector.py
```

**29 / 29 passed**, under a second. No pytest, no network, no root, no capture
files stored in the repo — every fixture is written at test time by
`synth.py`.

| Group | Tests |
|---|---|
| Bounds checking on hostile frames | 8 |
| Correctness against known ground truth | 7 |
| File format handling | 3 |
| Analysis and detectors | 7 |
| Filters and determinism | 4 |

---

## 2. The hostile capture — the numbers that matter

```bash
python synth.py captures/hostile.pcap --hostile
python cli.py captures/hostile.pcap
```

Eight frames whose length fields lie. **5 of 8 are caught and recorded as
errors; 3 parse correctly because they are supposed to.**

| # | The lie | Result | Ports reported |
|---|---|---|---|
| 1 | IPv4 `ihl`=15 (60 bytes) in a 26-byte frame | error recorded | **none** |
| 2 | TCP data offset 60 bytes in a 20-byte segment | error recorded | 1234→80, payload clamped to 0 |
| 3 | IPv4 `total_length`=9000, capture far shorter | parsed correctly | 1234→443 |
| 4 | Non-first fragment, offset 185 | marked `IPv4-fragment` | **none** |
| 5 | UDP length 3 (its own header is 8) | error recorded | 5000→53, payload not negative |
| 6 | IPv4 declared, 0 bytes follow | error recorded | none |
| 7 | 8-byte frame | error recorded | none |
| 8 | Valid packet, after seven bad ones | parsed correctly | 51000→443 |

**Cases 1 and 4 are the ones worth dwelling on**, because a naive parser
produces *plausible output* on both:

- **Case 1** — trusting `ihl` means reading the TCP header from 34 bytes past
  the end of a 26-byte frame. In a streaming parser that memory is the *next
  packet*. The output is a well-formed row with ports nobody sent.
- **Case 4** — a fragment with offset > 0 carries no transport header at all;
  its first four bytes are payload. Read as a TCP header they decode to
  `0xdead → 0xbeef`, ports 57005 and 48879. Both are valid port numbers. The
  flow table looks entirely ordinary.

Neither failure raises an exception. That is why the invariant is enforced at
every accessor rather than trusted at the top.

**Case 8 exists to prove recovery.** A parser that uses a claimed length as a
seek offset loses synchronisation on the first bad frame and never recovers —
every subsequent packet is garbage. The final valid packet parses cleanly,
with the right ports and no errors.

**Case 3 is the opposite lesson:** `total_length` exceeding the captured bytes
is *normal*, not hostile. It is exactly what `tcpdump -s 96` produces. It must
be clamped and parsing must continue, so "reject anything inconsistent" would
be wrong.

---

## 3. Parsing a normal capture against known ground truth

```bash
python synth.py captures/mixed.pcap --packets 400
python cli.py captures/mixed.pcap
```

400 packets, 159.1 KB, 4.11 s, 97.4 pkt/s, 317.4 kbit/s, mean frame 407 B,
**0 parse errors**.

| Protocol | Packets written | Packets parsed | Bytes | Byte share |
|---|---|---|---|---|
| HTTPS | 167 + 10 (IPv6) | **177** | 118.0 KB | 74.2% |
| DNS | 78 | **78** | 7.7 KB | 4.8% |
| SSH | 46 | **46** | 13.6 KB | 8.5% |
| PostgreSQL | 36 | **36** | 16.9 KB | 10.6% |
| ICMP | 24 | **24** | 1.1 KB | 0.7% |
| scan (TCP, unlabelled) | 21 | **21** | 1.1 KB | 0.7% |
| ARP | 18 | **18** | 756 B | 0.5% |

Every count matches what the generator recorded writing. The IPv4/IPv6 split
is 372/10 and the application label comes from the port, not the IP version,
so the two HTTPS groups merge — which is correct and is asserted explicitly
rather than being quietly accepted.

### Protocol hierarchy

```bash
python cli.py captures/mixed.pcap --hierarchy
```

```
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
    TCP                                   10    2.5%        5.4 KB
      HTTPS                               10    2.5%        5.4 KB
```

Top-level layers sum to exactly 400 (100.0%), which
`test_the_hierarchy_shares_do_not_exceed_one_hundred_percent` asserts.
Counting each layer independently instead of along each packet's own stack
gives shares totalling roughly 290% — a number that looks like a percentage
and is not one.

---

## 4. Detection: one planted scanner, four innocent hosts

`synth.py` plants exactly one host behaving badly: `10.0.0.66` sends SYN-only
packets to many different destination ports. Four other hosts generate normal
traffic. Ground truth is known because the generator wrote it.

```bash
python cli.py captures/mixed.pcap
```

| Finding | Severity | Evidence |
|---|---|---|
| `10.0.0.66` touched **21 distinct ports** on `10.0.0.20` | suspicious | 21 packets, listed |
| `10.0.0.66`: **100%** of TCP packets are bare SYNs (21 of 21) | suspicious | 21 packets, listed |

| Metric | Value |
|---|---|
| Planted scanners | 1 |
| **Detected** | **1** |
| Innocent hosts generating traffic | 4 |
| **False positives** | **0** |

`test_normal_hosts_are_not_flagged_as_scanners` asserts the zero explicitly.
Testing that a detector fires is half a test; false positives are what get a
detector switched off.

**Why the innocent hosts stay quiet** is the design, not luck. The four normal
hosts open plenty of connections — `10.0.0.12` alone appears in 106 packets —
but each uses *many source ports to few destination ports*. A scan is the
mirror image: few source ports, many destination ports. The detector counts
only distinct **destination** ports, so the two shapes cannot be confused.

**On the hostile capture**, the malformed-frame detector fires at
`suspicious` because 5 of 8 frames (62%) failed a length check, well past the
2% threshold at which a few truncated frames stop being normal.

Every finding carries its packet numbers and a command to check them:

```
evidence: #12, #23, #29, #40, #73, #135, #157, #182 (+13 more)
check it: python cli.py <capture> --packet 12
```

```
packet #12
  layers       Ethernet / IPv4 / TCP
  ip           10.0.0.66 -> 10.0.0.20
  ports        51954 -> 7429
  flags        SYN
  payload      0 bytes
```

---

## 5. Filtering

```bash
python cli.py captures/mixed.pcap --filter tcp.port=443    # 177 packets, 118.0 KB
python cli.py captures/mixed.pcap --filter ip=10.0.0.66    # 21 packets
python cli.py captures/mixed.pcap --filter ip=10.0.0.66,proto=TCP
```

A misspelled field is an **error**:

```
$ python cli.py captures/mixed.pcap --filter tcp.prot=443
bad filter: unknown filter field 'tcp.prot'; supported: host, ip, ip.dst, ip.src, port, proto, tcp.port, udp.port
```

A filter that silently matched everything would look exactly like a capture
with nothing interesting in it — the failure would be invisible.

---

## 6. What these numbers are not

**The captures are synthetic.** `synth.py` writes them, which is what makes
ground truth possible and what makes the detector's 0 false positives
meaningful. It also means the traffic is *cleaner than reality*: no
retransmissions, no out-of-order segments, no VPN encapsulation, no jumbo
frames, no malformed-but-benign middlebox output. A real capture will produce
findings this fixture cannot.

**The detectors are heuristics with no baseline.** They are thresholds
(15 distinct ports, 60% bare SYNs, 2% malformed) tuned on one fixture. There
is no model of what is normal for a given network. A busy load balancer, a
monitoring system, or an authorised vulnerability scan will all trip the scan
detector. That is why nothing is labelled `malicious` and why every finding
ships with the packets behind it — the tool narrows where to look, it does not
conclude.

**One capture is not a baseline.** "21 distinct ports" is suspicious on a
quiet office segment and unremarkable on a NAT gateway. Establishing normal
requires captures over time, which this tool does not do.

**Protocol labels come from port numbers and are advisory.** SSH on 8443,
HTTP on 8080, or anything on a non-standard port will be labelled by its port
or not at all. The label never affects parsing — a dissector that parsed port
8443 as TLS because of the number would produce confident nonsense — but it
does affect the protocol table, and the table should be read with that in
mind.

**No stream reassembly**, so nothing here inspects an HTTP body or a TLS
handshake. Every figure is per packet.
