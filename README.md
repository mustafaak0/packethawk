# 📡 PacketHawk

> Pcap network-forensics analyzer — flows, top talkers, port scans, SYN floods, C2 beacons and exfil, straight from raw bytes. Zero dependencies, pure Python stdlib.

[![Python](https://img.shields.io/badge/Python-3.9%2B-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-00E676?style=for-the-badge&labelColor=0D1117)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-0D1117?style=for-the-badge&labelColor=00E676)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mustafaak0-0D1117?style=for-the-badge&logo=github&logoColor=00E676)](https://github.com/mustafaak0)

## 🎯 Detections

| Finding | Logic | FP defense |
|---------|-------|------------|
| 🔍 **port scan** | one source with many *thin* (≤3 pkt) SYN flows to distinct host:port | only SYN senders credited, not targets |
| 🌊 **SYN flood** | bare-SYN **density** ≥10/s sustained to one dst:port | lifetime SYN totals ignored — browsers accumulate SYNs too |
| 🕰️ **C2 beacon** | periodicity of **connection starts** (SYN times / burst starts), jitter < 0.35 | packet-level gaps are bimodal & useless; sessions are the signal |
| 📦 **data exfil** | single flow carrying ≥3 MB | per-flow, not per-host |

## 🚀 Usage

```bash
# generate a synthetic capture with planted attacks, then hunt them
python demo_gen.py --out sample.pcap
python packethawk.py sample.pcap

# real captures (tcpdump/wireshark classic pcap, µs & ns, Ethernet or raw-IP)
python packethawk.py capture.pcap --top 20 --json findings.json
```

```
╭─ PacketHawk ──────────────────────────────────────────────
│ packets : 8241  (LINKTYPE_ETHERNET)
│ flows   : 431   proto mix: ICMP:24 · TCP:8137 · UDP:80
│
│ ● [PORT SCAN] 10.0.0.99  →  100/100
│   64 thin SYN flows to distinct host:port (…:20, :21, :22, :23…)
│ ● [SYN FLOOD] 10.0.0.66 → 10.0.0.1:80  →  100/100
│   40 SYN-without-ACK packets in 0.39s (103/s)
│ ● [C2 BEACON] 10.0.0.50:49333 ⇄ 93.184.216.34:443  →  100/100
│   20 connections every ~59.9s (jitter 0.00 — machine-like periodicity)
│ ● [DATA EXFIL?] 10.0.0.7:52000 → 185.199.108.153:8443  →  51/100
│   5.1 MB in a single TCP flow
╰──────────────────────────────────────────────────────
```

## 🧪 Verified on Synthetic Attacks

`demo_gen.py` builds an 8241-packet / 8.4 MB capture: 6 workstations doing
normal HTTPS/HTTP + DNS + ICMP, plus four planted attacks. PacketHawk
catches **4/4 with zero false positives** on the normal population —
including the classic traps (browsers accumulate SYNs over time; packet
gaps inside a session are bimodal).

## 🧠 How the Parsing Works (no scapy!)

```
pcap global header → byte order (µs/ns, LE/BE) + linktype (Ethernet/raw-IP)
   └─ record headers → ts + captured length
        └─ Ethernet → ethertype 0x0800
             └─ IPv4 → ihl, total_len, protocol, src/dst
                  └─ TCP → ports + flags (SYN without ACK = probe/flood fuel)
                  └─ UDP → ports (DNS mix stats)
```

IPv4 checksums in the generator are real (one's-complement); the analyzer
doesn't require them — truncated snaplen captures still parse.

## 🔭 Roadmap

- [ ] pcapng support
- [ ] IPv6
- [ ] DNS tunnicking heuristic (TXT-heavy, long labels)
- [ ] export IoCs as CSV for your SIEM

## ⚖️ Disclaimer

For captures from networks **you are authorized to analyze**.
Blue-team tooling — hunt responsibly.

---

<div align="center">

*Every breach leaves a packet that wishes it had never been sent.*

</div>
