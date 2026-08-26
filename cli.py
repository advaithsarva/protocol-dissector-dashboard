"""Command line front end and dashboard generator.

    python cli.py captures/mixed.pcap                  # summary + findings
    python cli.py captures/mixed.pcap --hierarchy      # protocol tree
    python cli.py captures/mixed.pcap --conversations  # who talked to whom
    python cli.py captures/mixed.pcap --packets 20     # packet list
    python cli.py captures/mixed.pcap --packet 47      # one packet, in full
    python cli.py captures/mixed.pcap --filter tcp.port=443
    python cli.py captures/mixed.pcap --html board.html
    python cli.py captures/mixed.pcap --json

`--packet N` exists so that every finding's evidence can be checked. A
detector that says "possible port scan" without a way to look at packet 47 is
an alert nobody can act on.
"""

import argparse
import html
import json
import sys

import analyze
import pcap


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024


def parse_filter(expression):
    """A deliberately tiny filter language: `field=value`, comma separated.

    Supported: ip, ip.src, ip.dst, port, tcp.port, udp.port, proto, host.

    ponytail: not BPF. BPF means either linking libpcap or writing a compiler,
    and neither is the point of this project. If real BPF is ever needed, it
    belongs at capture time, not here. An unknown field raises rather than
    matching everything, because a filter that silently matches everything
    looks like a capture with no interesting traffic in it.
    """
    fields = {"ip", "ip.src", "ip.dst", "port", "tcp.port", "udp.port", "proto", "host"}
    terms = []
    for part in expression.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"filter term {part!r} is not field=value")
        field, value = part.split("=", 1)
        field, value = field.strip().lower(), value.strip()
        if field not in fields:
            raise ValueError(
                f"unknown filter field {field!r}; supported: {', '.join(sorted(fields))}"
            )
        terms.append((field, value))
    return terms


def matches(pkt, terms):
    for field, value in terms:
        if field in ("ip", "host"):
            if value not in (pkt.src_ip, pkt.dst_ip):
                return False
        elif field == "ip.src" and pkt.src_ip != value:
            return False
        elif field == "ip.dst" and pkt.dst_ip != value:
            return False
        elif field in ("port", "tcp.port", "udp.port"):
            try:
                port = int(value)
            except ValueError:
                return False
            if port not in (pkt.src_port, pkt.dst_port):
                return False
            if field == "tcp.port" and "TCP" not in pkt.layers:
                return False
            if field == "udp.port" and "UDP" not in pkt.layers:
                return False
        elif field == "proto":
            if value.upper() not in [l.upper() for l in pkt.layers] and \
               value.upper() != pkt.protocol.upper():
                return False
    return True


def print_summary(s, packets):
    print(f"{'packets':<22}{s['packets']:>14,}")
    print(f"{'bytes':<22}{human_bytes(s['bytes']):>14}")
    print(f"{'duration':<22}{s['duration']:>13.2f}s")
    print(f"{'rate':<22}{s['packets_per_second']:>10.1f} pkt/s")
    print(f"{'throughput':<22}{s['bits_per_second'] / 1000:>9.1f} kbit/s")
    print(f"{'mean frame':<22}{s['mean_frame']:>12.0f} B")
    print(f"{'truncated (snaplen)':<22}{s['truncated']:>14,}")
    print(f"{'malformed':<22}{len(s['malformed']):>14,}")

    print(f"\n{'protocol':<16}{'packets':>10}{'share':>8}{'bytes':>14}{'share':>8}")
    for proto, n in s["protocols"].most_common(12):
        b = s["protocol_bytes"][proto]
        print(f"{proto:<16}{n:>10,}{n / s['packets']:>8.1%}"
              f"{human_bytes(b):>14}{b / s['bytes']:>8.1%}")


def print_hierarchy(packets):
    tree = analyze.protocol_hierarchy(packets)
    total = len(packets)
    print(f"{'layer':<34}{'packets':>10}{'share':>8}{'bytes':>14}")
    for row in analyze.flatten_hierarchy(tree):
        label = "  " * row["depth"] + row["layer"]
        print(f"{label:<34}{row['packets']:>10,}{row['packets'] / total:>8.1%}"
              f"{human_bytes(row['bytes']):>14}")


def print_conversations(s, limit=15):
    print(f"{'conversation':<52}{'packets':>10}{'bytes':>14}{'share':>8}")
    for convo, n in s["conversations"].most_common(limit):
        b = s["conversation_bytes"][convo]
        print(f"{convo[:51]:<52}{n:>10,}{human_bytes(b):>14}{b / s['bytes']:>8.1%}")


def print_packets(packets, limit):
    print(f"{'#':>6}{'time':>10}{'source':>22}{'dest':>22}{'proto':<14}"
          f"{'len':>7}  flags")
    for p in packets[:limit]:
        src = f"{p.src_ip}:{p.src_port}" if p.src_port else (p.src_ip or p.src_mac)
        dst = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else (p.dst_ip or p.dst_mac)
        mark = " !" if p.errors else ""
        print(f"{p.number:>6}{p.timestamp % 1000:>10.4f}{src[:21]:>22}{dst[:21]:>22}"
              f"{p.protocol[:13]:<14}{p.wire_length:>7}  {p.tcp_flags}{mark}")
    if len(packets) > limit:
        print(f"\n... {len(packets) - limit:,} more (raise --packets)")


def print_one(packets, number):
    match = [p for p in packets if p.number == number]
    if not match:
        print(f"no packet #{number} in this capture "
              f"(it has {len(packets)})", file=sys.stderr)
        return 1
    p = match[0]
    print(f"packet #{p.number}")
    for label, value in [
        ("timestamp", f"{p.timestamp:.6f}"),
        ("layers", " / ".join(p.layers) or "(none parsed)"),
        ("wire length", f"{p.wire_length} bytes"),
        ("captured", f"{p.capture_length} bytes" + (" (truncated)" if p.truncated else "")),
        ("ethernet", f"{p.src_mac} -> {p.dst_mac}"),
        ("ip", f"{p.src_ip} -> {p.dst_ip}" if p.src_ip else "(none)"),
        ("ports", f"{p.src_port} -> {p.dst_port}" if p.src_port else "(none)"),
        ("protocol", p.protocol),
        ("app guess", p.app_protocol or "(none; port matched nothing well known)"),
        ("flags", p.tcp_flags or "(none)"),
        ("payload", f"{p.payload_length} bytes"),
        ("connection", p.connection if p.src_ip else "(none)"),
    ]:
        print(f"  {label:<12} {value}")
    if p.errors:
        print("  errors")
        for e in p.errors:
            print(f"    - {e}")
    return 0


def print_findings(findings):
    if not findings:
        print("No findings. Nothing in this capture matched the heuristics.")
        return
    for f in findings:
        print(f"\n[{f.severity}] {f.title}")
        print(f"  {f.detail}")
        print(f"  evidence: {f.evidence()}")
        print(f"  check it: python cli.py <capture> --packet {f.packets[0]}")


def write_html(path, packets, s, findings):
    esc = html.escape
    tl = analyze.timeline(packets, 60)
    peak = max((b["packets"] for b in tl), default=1) or 1

    bars = "".join(
        f'<div class=bar style="height:{b["packets"] / peak * 100:.1f}%" '
        f'title="t+{b["t"]}s: {b["packets"]} packets, {b["bytes"]:,} bytes"></div>'
        for b in tl
    )
    proto_rows = "".join(
        f"<tr><td>{esc(p)}</td><td class=n>{n:,}</td><td class=n>{n / s['packets']:.1%}</td>"
        f"<td class=n>{human_bytes(s['protocol_bytes'][p])}</td></tr>"
        for p, n in s["protocols"].most_common(14)
    )
    hier_rows = "".join(
        f"<tr><td style='padding-left:{row['depth'] * 1.4 + 0.6}rem'>{esc(row['layer'])}</td>"
        f"<td class=n>{row['packets']:,}</td><td class=n>{row['packets'] / s['packets']:.1%}</td></tr>"
        for row in analyze.flatten_hierarchy(analyze.protocol_hierarchy(packets))
    )
    convo_rows = "".join(
        f"<tr><td class=mono>{esc(c)}</td><td class=n>{n:,}</td>"
        f"<td class=n>{human_bytes(s['conversation_bytes'][c])}</td></tr>"
        for c, n in s["conversations"].most_common(15)
    )
    host_rows = "".join(
        f"<tr><td class=mono>{esc(h)}</td><td class=n>{n:,}</td>"
        f"<td class=n>{human_bytes(s['host_bytes'][h])}</td></tr>"
        for h, n in s["hosts"].most_common(12)
    )
    finding_rows = "".join(
        f"<tr class={f.severity}><td>{esc(f.severity)}</td><td>{esc(f.title)}</td>"
        f"<td>{esc(f.detail)}</td><td class=mono>{esc(f.evidence(6))}</td></tr>"
        for f in findings
    ) or "<tr><td colspan=4>no findings</td></tr>"

    doc = f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Capture dashboard</title><style>
:root{{--bg:#fbfbfa;--fg:#1a1a19;--line:#dcdad5;--muted:#6b6862;--accent:#4f7cac}}
@media(prefers-color-scheme:dark){{:root{{--bg:#191918;--fg:#eeece7;--line:#38352f;--muted:#9a968d;--accent:#7aa5cf}}}}
body{{margin:0;padding:2rem 1.5rem;background:var(--bg);color:var(--fg);
font:14px/1.55 ui-sans-serif,system-ui,sans-serif}}
main{{max-width:64rem;margin:0 auto}} h1{{font-size:1.4rem;margin:0 0 .3rem}}
h2{{font-size:1.05rem;margin:2.2rem 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}}
.sub{{color:var(--muted);margin:0 0 1.5rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:.8rem}}
.card{{border:1px solid var(--line);border-radius:7px;padding:.8rem 1rem}}
.card .v{{font-size:1.45rem;font-variant-numeric:tabular-nums}}
.card .k{{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}}
.chart{{display:flex;align-items:flex-end;gap:2px;height:120px;border-bottom:1px solid var(--line);margin-top:1rem}}
.bar{{flex:1;background:var(--accent);min-height:1px;border-radius:1px 1px 0 0}}
.scroll{{overflow-x:auto}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{padding:.35rem .7rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{color:var(--muted);font-weight:600}} .n{{text-align:right;font-variant-numeric:tabular-nums}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}
tr.suspicious td:first-child{{color:#c0563f;font-weight:600}}
footer{{margin-top:3rem;color:var(--muted);font-size:12px}}
</style></head><body><main>
<h1>Capture dashboard</h1>
<p class=sub>{s['packets']:,} packets over {s['duration']:.2f}s, parsed from raw bytes with struct - no Scapy, no libpcap.</p>

<div class=cards>
<div class=card><div class=k>packets</div><div class=v>{s['packets']:,}</div></div>
<div class=card><div class=k>volume</div><div class=v>{human_bytes(s['bytes'])}</div></div>
<div class=card><div class=k>rate</div><div class=v>{s['packets_per_second']:.0f}/s</div></div>
<div class=card><div class=k>throughput</div><div class=v>{s['bits_per_second'] / 1000:.0f} kb/s</div></div>
<div class=card><div class=k>hosts</div><div class=v>{len(s['hosts'])}</div></div>
<div class=card><div class=k>malformed</div><div class=v>{len(s['malformed'])}</div></div>
</div>

<h2>Packets over time</h2>
<div class=chart>{bars}</div>

<h2>Findings</h2>
<div class=scroll><table>
<tr><th>severity</th><th>finding</th><th>detail</th><th>evidence</th></tr>{finding_rows}</table></div>
<p class=sub>Heuristics on one capture with no baseline for this network.
Labelled suspicious, never malicious - an authorised scanner and an attacker
produce the same pattern.</p>

<h2>Protocol hierarchy</h2>
<div class=scroll><table><tr><th>layer</th><th class=n>packets</th><th class=n>share</th></tr>{hier_rows}</table></div>

<h2>Protocols</h2>
<div class=scroll><table><tr><th>protocol</th><th class=n>packets</th><th class=n>share</th><th class=n>bytes</th></tr>{proto_rows}</table></div>

<h2>Top conversations</h2>
<div class=scroll><table><tr><th>conversation</th><th class=n>packets</th><th class=n>bytes</th></tr>{convo_rows}</table></div>

<h2>Top hosts</h2>
<div class=scroll><table><tr><th>host</th><th class=n>packets</th><th class=n>bytes</th></tr>{host_rows}</table></div>

<footer>Generated by protocol-dissector-dashboard. Every number recomputes from
the capture; nothing here is cached.</footer>
</main></body></html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture", help="path to a .pcap or .pcapng file")
    ap.add_argument("--limit", type=int, help="stop after N packets")
    ap.add_argument("--filter", help="e.g. tcp.port=443 or ip=10.0.0.5,proto=DNS")
    ap.add_argument("--hierarchy", action="store_true")
    ap.add_argument("--conversations", action="store_true")
    ap.add_argument("--packets", type=int, metavar="N", help="list the first N packets")
    ap.add_argument("--packet", type=int, metavar="N", help="show one packet in full")
    ap.add_argument("--html", metavar="PATH")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        packets = pcap.load(args.capture, args.limit)
    except pcap.CaptureError as exc:
        print(f"cannot read capture: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"no such file: {args.capture}", file=sys.stderr)
        return 2

    if not packets:
        print("capture contains no packets", file=sys.stderr)
        return 1

    if args.filter:
        try:
            terms = parse_filter(args.filter)
        except ValueError as exc:
            print(f"bad filter: {exc}", file=sys.stderr)
            return 1
        before = len(packets)
        packets = [p for p in packets if matches(p, terms)]
        if not packets:
            print(f"filter matched 0 of {before} packets", file=sys.stderr)
            return 1

    if args.packet is not None:
        return print_one(packets, args.packet)

    s = analyze.summarize(packets)
    findings = analyze.find_anomalies(packets)

    if args.json:
        json.dump({
            "capture": args.capture,
            "summary": {k: (dict(v.most_common(20)) if hasattr(v, "most_common") else v)
                        for k, v in s.items()},
            "hierarchy": analyze.flatten_hierarchy(analyze.protocol_hierarchy(packets)),
            "timeline": analyze.timeline(packets),
            "findings": [{"severity": f.severity, "title": f.title,
                          "detail": f.detail, "packets": f.packets[:100]}
                         for f in findings],
        }, sys.stdout, indent=2, default=str)
        print()
        return 0

    if args.html:
        print(f"wrote {write_html(args.html, packets, s, findings)}")
        return 0

    if args.packets:
        print_packets(packets, args.packets)
        return 0
    if args.hierarchy:
        print_hierarchy(packets)
        return 0
    if args.conversations:
        print_conversations(s)
        return 0

    print(f"capture: {args.capture}"
          + (f"   filter: {args.filter}" if args.filter else "") + "\n")
    print_summary(s, packets)
    print(f"\n{'=' * 60}\nFINDINGS")
    print_findings(findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
