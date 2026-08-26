"""Turn a list of packets into the things someone actually wants to know.

Protocol hierarchy, per-host and per-conversation volume, and a small set of
flag rules for traffic that looks odd.

The rule these detectors are built around
-----------------------------------------
**Every finding names the packets it came from.**

"Possible port scan" with no evidence is an alert nobody can act on and nobody
can disprove. Each Finding carries the packet numbers behind it, so the claim
can be checked against the capture in one command:

    python cli.py capture.pcap --packet 47

These are heuristics on a single capture with no baseline of what is normal
for this network. They are labelled `suspicious`, never `malicious`. The
difference matters: a vulnerability scanner run by your own security team
produces exactly the pattern the scan detector fires on, and so does an
attacker. This tool cannot tell them apart and does not pretend to.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field

# A host touching more than this many distinct ports on one target looks like
# enumeration rather than use. Low enough to catch a slow scan, high enough
# that a browser opening parallel connections does not trip it -- those go to
# one port from many source ports, which is the opposite shape.
SCAN_PORT_THRESHOLD = 15

# Share of a host's TCP packets that are bare SYNs. A normal client completes
# handshakes, so its SYN share is small; a scanner never does.
SYN_ONLY_RATIO = 0.6

# Ports above this with sustained traffic are worth a look, since they match
# nothing in the well-known table.
HIGH_PORT = 10000
UNUSUAL_PORT_MIN_PACKETS = 20


@dataclass
class Finding:
    severity: str            # info | suspicious
    title: str
    detail: str
    packets: list = field(default_factory=list)     # evidence, always

    def evidence(self, limit=8):
        shown = ", ".join(f"#{n}" for n in self.packets[:limit])
        more = f" (+{len(self.packets) - limit} more)" if len(self.packets) > limit else ""
        return shown + more


def protocol_hierarchy(packets):
    """Nested counts, layer 2 up to layer 7.

    Counted along each packet's own layer list, so a frame contributes to
    every level of its own stack and to no other. Counting each layer
    independently would make the percentages sum to well over 100 and mean
    nothing.
    """
    tree = {}
    for pkt in packets:
        node = tree
        for layer in pkt.layers:
            node = node.setdefault(layer, {"_count": 0, "_bytes": 0, "_children": {}})
            node["_count"] += 1
            node["_bytes"] += pkt.wire_length
            node = node["_children"]
    return tree


def flatten_hierarchy(tree, depth=0, out=None):
    out = [] if out is None else out
    for name, node in sorted(tree.items(), key=lambda kv: -kv[1]["_count"]):
        out.append({"depth": depth, "layer": name,
                    "packets": node["_count"], "bytes": node["_bytes"]})
        flatten_hierarchy(node["_children"], depth + 1, out)
    return out


def summarize(packets):
    """Everything the dashboard and the CLI both need, computed once."""
    if not packets:
        return {"packets": 0, "bytes": 0, "duration": 0.0}

    times = [p.timestamp for p in packets]
    duration = max(times) - min(times)
    total_bytes = sum(p.wire_length for p in packets)

    hosts = Counter()
    host_bytes = Counter()
    for p in packets:
        for ip in (p.src_ip, p.dst_ip):
            if ip:
                hosts[ip] += 1
                host_bytes[ip] += p.wire_length

    conversations = Counter()
    conversation_bytes = Counter()
    for p in packets:
        if p.src_ip and p.dst_ip:
            conversations[p.connection] += 1
            conversation_bytes[p.connection] += p.wire_length

    return {
        "packets": len(packets),
        "bytes": total_bytes,
        "duration": duration,
        "packets_per_second": len(packets) / duration if duration > 0 else 0.0,
        "bits_per_second": total_bytes * 8 / duration if duration > 0 else 0.0,
        "start": min(times),
        "end": max(times),
        "protocols": Counter(p.protocol for p in packets if p.protocol),
        "protocol_bytes": _bytes_by(packets, lambda p: p.protocol),
        "hosts": hosts,
        "host_bytes": host_bytes,
        "conversations": conversations,
        "conversation_bytes": conversation_bytes,
        "malformed": [p.number for p in packets if p.errors],
        "truncated": sum(1 for p in packets if p.truncated),
        "mean_frame": total_bytes / len(packets),
    }


def _bytes_by(packets, key):
    out = Counter()
    for p in packets:
        k = key(p)
        if k:
            out[k] += p.wire_length
    return out


def timeline(packets, buckets=60):
    """Packets and bytes per time bucket, for the dashboard chart."""
    if not packets:
        return []
    times = [p.timestamp for p in packets]
    start, end = min(times), max(times)
    span = end - start
    if span <= 0:
        return [{"t": 0.0, "packets": len(packets),
                 "bytes": sum(p.wire_length for p in packets)}]

    width = span / buckets
    counts = [0] * buckets
    volume = [0] * buckets
    for p in packets:
        # min() guards the final packet, whose index would otherwise be
        # exactly `buckets` and fall off the end of the list.
        i = min(buckets - 1, int((p.timestamp - start) / width))
        counts[i] += 1
        volume[i] += p.wire_length
    return [{"t": round(i * width, 4), "packets": counts[i], "bytes": volume[i]}
            for i in range(buckets)]


# --------------------------------------------------------------------------
# detectors
# --------------------------------------------------------------------------

def find_anomalies(packets):
    findings = []
    findings += _port_scan(packets)
    findings += _syn_without_handshake(packets)
    findings += _unusual_ports(packets)
    findings += _malformed(packets)
    findings += _talkers(packets)
    order = {"suspicious": 0, "info": 1}
    findings.sort(key=lambda f: (order[f.severity], -len(f.packets)))
    return findings


def _port_scan(packets):
    """One source touching many distinct destination ports on one target.

    The shape that distinguishes a scan from a busy client: a scan has ONE
    source port range and MANY destination ports; a browser has MANY source
    ports and ONE destination port. Counting only distinct destination ports
    keeps the two apart.
    """
    per_pair = defaultdict(set)
    evidence = defaultdict(list)
    for p in packets:
        if p.dst_port and p.src_ip and p.dst_ip:
            per_pair[(p.src_ip, p.dst_ip)].add(p.dst_port)
            evidence[(p.src_ip, p.dst_ip)].append(p.number)

    out = []
    for (src, dst), ports in per_pair.items():
        if len(ports) < SCAN_PORT_THRESHOLD:
            continue
        out.append(Finding(
            severity="suspicious",
            title=f"{src} touched {len(ports)} distinct ports on {dst}",
            detail=(f"{len(ports)} distinct destination ports across "
                    f"{len(evidence[(src, dst)])} packets. A client uses many "
                    f"*source* ports and one destination port; this is the "
                    f"opposite shape. Consistent with port enumeration -- which "
                    f"an authorised scanner also does."),
            packets=sorted(evidence[(src, dst)]),
        ))
    return out


def _syn_without_handshake(packets):
    """A host whose TCP traffic is mostly bare SYNs never completes a
    connection, which is what a half-open scan looks like."""
    syn = Counter()
    total = Counter()
    evidence = defaultdict(list)
    for p in packets:
        if "TCP" not in p.layers or not p.src_ip:
            continue
        total[p.src_ip] += 1
        if p.tcp_flags == "SYN":                    # SYN alone, not SYN,ACK
            syn[p.src_ip] += 1
            evidence[p.src_ip].append(p.number)

    out = []
    for host, n in total.items():
        if n < 10:
            continue
        ratio = syn[host] / n
        if ratio < SYN_ONLY_RATIO:
            continue
        out.append(Finding(
            severity="suspicious",
            title=f"{host}: {ratio:.0%} of TCP packets are bare SYNs",
            detail=(f"{syn[host]} of {n} TCP packets carry SYN with no ACK. A "
                    f"client that completes handshakes sends one SYN per "
                    f"connection and many ACKs after it."),
            packets=sorted(evidence[host]),
        ))
    return out


def _unusual_ports(packets):
    """Sustained traffic on a high port matching nothing well known."""
    counts = Counter()
    evidence = defaultdict(list)
    for p in packets:
        for port in (p.src_port, p.dst_port):
            if port > HIGH_PORT and not p.app_protocol:
                counts[port] += 1
                evidence[port].append(p.number)

    out = []
    for port, n in counts.items():
        if n < UNUSUAL_PORT_MIN_PACKETS:
            continue
        out.append(Finding(
            severity="info",
            title=f"sustained traffic on port {port}",
            detail=(f"{n} packets on a high port with no well-known service. "
                    f"Usually an ephemeral client port that happens to repeat, "
                    f"or an application on a non-standard port."),
            packets=sorted(evidence[port])[:50],
        ))
    return out


def _malformed(packets):
    """Frames whose own length fields did not survive a bounds check.

    Worth surfacing rather than hiding: a handful is normal (truncated
    captures, snaplen), a lot means either a broken capture or something
    generating deliberately malformed traffic.
    """
    bad = [p for p in packets if p.errors]
    if not bad:
        return []
    reasons = Counter(e for p in bad for e in p.errors)
    return [Finding(
        severity="suspicious" if len(bad) > len(packets) * 0.02 else "info",
        title=f"{len(bad)} of {len(packets)} frames failed a length check",
        detail="; ".join(f"{r} (x{n})" for r, n in reasons.most_common(4)),
        packets=[p.number for p in bad],
    )]


def _talkers(packets):
    """The top conversation, as context rather than as an alarm."""
    summary = summarize(packets)
    if not summary.get("conversation_bytes"):
        return []
    top, byte_count = summary["conversation_bytes"].most_common(1)[0]
    share = byte_count / summary["bytes"]
    if share < 0.25:
        return []
    numbers = [p.number for p in packets if p.src_ip and p.connection == top]
    return [Finding(
        severity="info",
        title=f"one conversation is {share:.0%} of all bytes",
        detail=f"{top} carried {byte_count:,} of {summary['bytes']:,} bytes",
        packets=numbers[:50],
    )]
