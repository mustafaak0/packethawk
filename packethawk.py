#!/usr/bin/env python3
"""
PacketHawk — pcap network-forensics analyzer (pure stdlib).

Parses classic pcap files (both byte orders, µs & ns timestamps, Ethernet
and raw-IP link types), reconstructs L3/L4 flows, then runs blue-team
analytics:

  - port-scan detection      (one source touching many ports/hosts)
  - C2-style beaconing       (low-jitter periodic flows)
  - data-exfil suspicion     (unusually large single flows)
  - SYN-flood signature      (SYN storms without handshakes)
  - top talkers / protocol mix
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

PORT_SCAN_FLOWS = 10     # distinct ports/hosts touched to call it a scan
SCAN_FLOW_PKTS = 3       # each scanned port gets at most this many packets
BEACON_MIN_PKTS = 10     # packets needed for periodicity analysis
BEACON_JITTER = 0.35     # std/mean of inter-arrival times below this = beacon
BEACON_MIN_INTERVAL = 1.0
EXFIL_BYTES = 3_000_000  # single flow above this = exfil suspicion
SYN_FLOOD = 30           # SYN-without-ACK packets src→dst


@dataclass
class Flow:
    pkts: int = 0
    bytes_: int = 0
    first: float = 0.0
    last: float = 0.0
    ts: list = field(default_factory=list)
    syn_only: int = 0
    syn_srcs: set = field(default_factory=set)
    syn_ts: list = field(default_factory=list)

    def note(self, ts: float, size: int, syn: bool, src: str = "") -> None:
        self.pkts += 1
        self.bytes_ += size
        self.first = ts if not self.first else min(self.first, ts)
        self.last = max(self.last, ts)
        self.ts.append(ts)
        if syn:
            self.syn_only += 1
            self.syn_srcs.add(src)
            self.syn_ts.append(ts)

    def burst_starts(self, gap: float = 2.0) -> list[float]:
        """First-packet timestamps of activity bursts (for periodicity checks)."""
        starts = []
        last = None
        for t in sorted(self.ts):
            if last is None or t - last > gap:
                starts.append(t)
            last = t
        return starts


# ----------------------------------------------------------------------------
# pcap / packet parsing
# ----------------------------------------------------------------------------

def parse_pcap(path: Path) -> tuple[list[dict], str]:
    """Return (packets, linktype). packets: dicts with l3 fields."""
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("file too short to be a pcap")

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):   # packed LE on disk
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):  # packed BE on disk
        endian = ">"
    else:
        raise ValueError(f"not a classic pcap (magic {magic.hex()})")

    _, _, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", data[4:24])
    packets, off, warned = [], 24, 0
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > len(data):
            break
        pkt = data[off:off + incl]
        off += incl
        ts = ts_sec + ts_usec / (1e9 if magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1") else 1e6)

        if linktype == 1:                      # Ethernet
            if len(pkt) < 14:
                continue
            ethertype = struct.unpack("!H", pkt[12:14])[0]
            if ethertype != 0x0800:            # not IPv4 (ARP/VLAN/IPv6…)
                continue
            ip = pkt[14:]
        elif linktype == 101:                  # raw IP
            ip = pkt
        else:
            if warned < 1:
                print(f"[!] unsupported linktype {linktype} — assuming raw IP", file=sys.stderr)
                warned = 1
            ip = pkt

        parsed = parse_ipv4(ip, ts)
        if parsed:
            packets.append(parsed)
    return packets, f"LINKTYPE_{ {1:'ETHERNET', 101:'RAWIP'}.get(linktype, linktype) }"


def parse_ipv4(ip: bytes, ts: float) -> dict | None:
    if len(ip) < 20:
        return None
    v_ihl = ip[0]
    if v_ihl >> 4 != 4:                        # not IPv4
        return None
    ihl = (v_ihl & 0x0F) * 4
    total_len = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    l4 = ip[ihl:min(total_len, len(ip))]
    rec = {"ts": ts, "src": src, "dst": dst, "proto": {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto)),
           "sport": 0, "dport": 0, "syn": False, "size": total_len}

    if proto == 6 and len(l4) >= 14:           # TCP
        rec["sport"], rec["dport"] = struct.unpack("!HH", l4[:4])
        flags = l4[13]
        rec["syn"] = bool(flags & 0x02) and not (flags & 0x10)   # SYN, no ACK
    elif proto == 17 and len(l4) >= 4:         # UDP
        rec["sport"], rec["dport"] = struct.unpack("!HH", l4[:4])
    return rec


# ----------------------------------------------------------------------------
# analytics
# ----------------------------------------------------------------------------

def flow_key(p: dict) -> tuple:
    a, b = (p["src"], p["sport"]), (p["dst"], p["dport"])
    return (tuple(sorted([a, b])), p["proto"])


def mean_std(xs: list[float]) -> tuple[float, float]:
    mu = sum(xs) / len(xs)
    var = sum((x - mu) ** 2 for x in xs) / len(xs)
    return mu, math.sqrt(var)


def analyze(packets: list[dict]) -> dict:
    flows: dict[tuple, Flow] = defaultdict(Flow)
    bytes_by_ip: dict[str, int] = defaultdict(int)
    proto_mix: dict[str, int] = defaultdict(int)
    port_touch: dict[tuple, set] = defaultdict(set)   # (src, dst_ip) → ports (TCP)
    syn_dst: dict[tuple, list] = defaultdict(list)    # (src, dst, dport) → SYN times

    for p in packets:
        flows[flow_key(p)].note(p["ts"], p["size"], p["syn"], p["src"])
        bytes_by_ip[p["src"]] += p["size"]
        proto_mix[p["proto"]] += 1
        if p["proto"] == "TCP":
            port_touch[(p["src"], p["dst"])].add(p["dport"])
            if p["syn"]:
                syn_dst[(p["src"], p["dst"], p["dport"])].append(p["ts"])

    findings = []

    # ---- port scan: sources with many thin SYN flows to distinct host:port
    per_src_ports: dict[str, set] = defaultdict(set)
    for key, fl in flows.items():
        (a, b), proto = key
        if proto != "TCP" or not (fl.pkts <= SCAN_FLOW_PKTS and fl.syn_only >= 1):
            continue
        for (src_ip, sport), (dst_ip, dport) in ((a, b), (b, a)):
            if src_ip in fl.syn_srcs:          # credit only the SYN sender
                per_src_ports[src_ip].add((dst_ip, dport))
    for src, surface in per_src_ports.items():
        if len(surface) >= PORT_SCAN_FLOWS:
            sample = ", ".join(f"{d}:{p}" for d, p in sorted(surface)[:6])
            findings.append({"type": "PORT SCAN", "subject": src, "score": min(100, 5 * len(surface)),
                             "detail": f"{len(surface)} thin SYN flows to distinct host:port "
                                       f"(e.g. {sample}…)"})

    # ---- SYN flood: density matters, not lifetime totals (normal browsing
    #      also accumulates SYNs — but spread over minutes, not milliseconds)
    for (src, dst, dport), times in syn_dst.items():
        n = len(times)
        if n < SYN_FLOOD:
            continue
        span = max(times) - min(times)
        rate = n / span if span > 0 else float("inf")
        if rate >= 10.0:                     # ≥10 bare SYNs/sec sustained
            findings.append({"type": "SYN FLOOD", "subject": f"{src} → {dst}:{dport}",
                             "score": min(100, int(rate)),
                             "detail": f"{n} SYN-without-ACK packets in {span:.2f}s "
                                       f"({rate:.0f}/s — half-open flood signature)"})

    # ---- beaconing: periodicity lives in connection starts, not every packet
    for key, fl in flows.items():
        times = fl.syn_ts if len(fl.syn_ts) >= BEACON_MIN_PKTS else fl.burst_starts()
        if len(times) < BEACON_MIN_PKTS:
            continue
        times = sorted(times)
        gaps = [b - a for a, b in zip(times, times[1:])]
        mu, sd = mean_std(gaps)
        if mu >= BEACON_MIN_INTERVAL and mu > 0 and sd / mu < BEACON_JITTER:
            (a, b), proto = key
            findings.append({"type": "C2 BEACON", "subject": f"{a[0]}:{a[1]} ⇄ {b[0]}:{b[1]}",
                             "score": min(100, round(100 * (1 - sd / mu))),
                             "detail": f"{len(times)} connections every ~{mu:.1f}s "
                                       f"(jitter {sd / mu:.2f} — machine-like periodicity)"})

    # ---- exfil
    for key, fl in flows.items():
        if fl.bytes_ >= EXFIL_BYTES:
            (a, b), proto = key
            findings.append({"type": "DATA EXFIL?", "subject": f"{a[0]}:{a[1]} → {b[0]}:{b[1]}",
                             "score": min(100, fl.bytes_ // 100_000),
                             "detail": f"{fl.bytes_ / 1e6:.1f} MB in a single {proto} flow"})

    findings.sort(key=lambda f: -f["score"])
    top = sorted(bytes_by_ip.items(), key=lambda kv: -kv[1])[:5]
    return {"packets": len(packets), "flows": len(flows), "findings": findings,
            "top_talkers": top, "proto_mix": dict(proto_mix)}


# ----------------------------------------------------------------------------
# report
# ----------------------------------------------------------------------------

def show(a: dict, linktype: str, top: int) -> None:
    print("╭─ PacketHawk " + "─" * 50)
    print(f"│ packets : {a['packets']}  ({linktype})")
    print(f"│ flows   : {a['flows']}   proto mix: "
          + " · ".join(f"{k}:{v}" for k, v in sorted(a["proto_mix"].items())))
    print("├──────────────────────────────────────────────────")
    print("│ top talkers (bytes out):")
    for ip, b in a["top_talkers"]:
        print(f"│    {ip:<16} {b / 1e6:8.2f} MB")
    print("├──────────────────────────────────────────────────")
    if not a["findings"]:
        print("│ ✔ no scan / beacon / exfil signatures — quiet capture")
    for f in a["findings"][:top]:
        print(f"│\n│ ● [{f['type']}] {f['subject']}  →  {f['score']}/100")
        print(f"│   {f['detail']}")
    print("╰" + "─" * 62)


def main() -> None:
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="PacketHawk — pcap network-forensics analyzer (stdlib only)")
    p.add_argument("pcap", help="pcap file to analyze")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--json", dest="json_out", help="export findings as JSON")
    args = p.parse_args()

    path = Path(args.pcap)
    if not path.exists():
        sys.exit(f"[!] pcap file not found: {path}")
    try:
        packets, linktype = parse_pcap(path)
    except ValueError as e:
        sys.exit(f"[!] {e}")
    if not packets:
        sys.exit("[!] no IPv4 packets extracted from this capture")

    result = analyze(packets)
    result["linktype"] = linktype
    show(result, linktype, args.top)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\n[+] JSON export → {args.json_out}")


if __name__ == "__main__":
    main()
