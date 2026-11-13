#!/usr/bin/env python3
"""
demo_gen — synthetic pcap generator for PacketHawk (pure stdlib).

Writes a classic little-endian µs pcap (Ethernet linktype) containing:
  1. normal traffic    (workstations ↔ web server, DNS, ICMP)
  2. port scan         (10.0.0.99 SYN-probing 64 ports on 10.0.0.1)
  3. C2 beacon         (10.0.0.50 → 93.184.216.34:443 every 60s, ×20)
  4. data exfiltration (5 MB upload over one TCP flow from 10.0.0.7)
  5. SYN flood burst   (10.0.0.66 → 10.0.0.1:80, 40 bare SYNs)
"""

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path

random.seed(7)


def cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0,
                      bytes(int(x) for x in src.split(".")),
                      bytes(int(x) for x in dst.split(".")))
    hdr = hdr[:10] + struct.pack("!H", cksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    off = 5 << 4
    return struct.pack("!HHIIBBHHH", sport, dport, random.randint(1000, 2**31), 0, off, flags,
                       65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def frame(src_mac: bytes, dst_mac: bytes, ip_pkt: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + ip_pkt


def rec(ts: float, pkt: bytes) -> bytes:
    sec = int(ts)
    usec = int(round((ts - sec) * 1e6))
    return struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt


def main() -> None:
    p = argparse.ArgumentParser(description="synthetic pcap generator for PacketHawk")
    p.add_argument("--out", default="sample.pcap")
    a = p.parse_args()

    M1 = bytes.fromhex("020000000001")   # gateway/server mac
    M2 = bytes.fromhex("020000000002")   # workstation mac
    pkts: list[tuple[float, bytes]] = []
    base = 177_300_0000.0                # arbitrary epoch

    # 1) normal web-ish traffic: 6 workstations ↔ 10.0.0.1:443 / :80
    t = base
    clients = [f"10.0.0.{i}" for i in range(10, 16)]
    for i in range(240):
        t += random.uniform(0.4, 3.0)
        c = random.choice(clients)
        dport = random.choice((443, 443, 443, 80))
        sp = random.randint(49152, 65000)
        # handshake
        pkts.append((t, frame(M2, M1, ip4(c, "10.0.0.1", 6, tcp(sp, dport, 0x02)))))
        pkts.append((t + 0.001, frame(M1, M2, ip4("10.0.0.1", c, 6, tcp(dport, sp, 0x12)))))
        # data both ways
        for _ in range(random.randint(4, 12)):
            pkts.append((t + random.uniform(0.01, 0.2),
                         frame(M2, M1, ip4(c, "10.0.0.1", 6, tcp(sp, dport, 0x18, b"X" * random.randint(100, 1400))))))
            pkts.append((t + random.uniform(0.01, 0.3),
                         frame(M1, M2, ip4("10.0.0.1", c, 6, tcp(dport, sp, 0x18, b"Y" * random.randint(200, 1400))))))
        # teardown
        pkts.append((t + 0.4, frame(M2, M1, ip4(c, "10.0.0.1", 6, tcp(sp, dport, 0x11)))))

    # DNS noise
    for i in range(40):
        t += random.uniform(2, 9)
        c = random.choice(clients)
        q = udp(random.randint(49152, 65000), 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
        pkts.append((t, frame(M2, M1, ip4(c, "10.0.0.1", 17, q))))
        r = udp(53, random.randint(49152, 65000), b"\x12\x34\x81\x80" + b"\x00" * 42)
        pkts.append((t + 0.01, frame(M1, M2, ip4("10.0.0.1", c, 17, r))))

    # ICMP pings
    for i in range(12):
        t += random.uniform(10, 40)
        c = random.choice(clients)
        icmp = struct.pack("!BBHHH", 8, 0, 0, i, 1) + b"pingpad" * 8
        pkts.append((t, frame(M2, M1, ip4(c, "10.0.0.1", 1, icmp))))
        reply = struct.pack("!BBHHH", 0, 0, 0, i, 1) + b"pingpad" * 8
        pkts.append((t + 0.005, frame(M1, M2, ip4("10.0.0.1", c, 1, reply))))

    # 2) port scan: 10.0.0.99 → 10.0.0.1, 64 ports, bare SYN each
    t = base + 4000
    for port in range(20, 84):
        pkts.append((t + port * 0.02, frame(M2, M1,
                     ip4("10.0.0.99", "10.0.0.1", 6, tcp(random.randint(49000, 65000), port, 0x02)))))

    # 3) C2 beacon: every 60.0±0.4s → 93.184.216.34:443, small packets, ×20
    t = base + 100
    for i in range(20):
        t += 60.0 + random.uniform(-0.4, 0.4)
        sp = 49333
        pkts.append((t, frame(M2, M1, ip4("10.0.0.50", "93.184.216.34", 6, tcp(sp, 443, 0x02)))))
        pkts.append((t + 0.01, frame(M1, M2, ip4("93.184.216.34", "10.0.0.50", 6, tcp(443, sp, 0x12)))))
        pkts.append((t + 0.05, frame(M2, M1, ip4("10.0.0.50", "93.184.216.34", 6, tcp(sp, 443, 0x18, b"B" * 64)))))
        pkts.append((t + 0.09, frame(M1, M2, ip4("93.184.216.34", "10.0.0.50", 6, tcp(443, sp, 0x18, b"R" * 64)))))

    # 4) exfil: 10.0.0.7 → 185.199.108.153:8443, ~5 MB in 1460-byte segments
    t = base + 2000
    sp = 52000
    pkts.append((t, frame(M2, M1, ip4("10.0.0.7", "185.199.108.153", 6, tcp(sp, 8443, 0x02)))))
    pkts.append((t + 0.001, frame(M1, M2, ip4("185.199.108.153", "10.0.0.7", 6, tcp(8443, sp, 0x12)))))
    n_seg = 5_000_000 // 1460
    for i in range(n_seg):
        pkts.append((t + 0.002 + i * 0.0002, frame(M2, M1,
                     ip4("10.0.0.7", "185.199.108.153", 6, tcp(sp, 8443, 0x18, b"E" * 1460)))))
        if i % 20 == 19:   # sparse ACKs back
            pkts.append((t + 0.002 + i * 0.0002 + 0.0001, frame(M1, M2,
                         ip4("185.199.108.153", "10.0.0.7", 6, tcp(8443, sp, 0x10)))))

    # 5) SYN flood: 40 bare SYNs → 10.0.0.1:80
    t = base + 6000
    for i in range(40):
        pkts.append((t + i * 0.01, frame(M2, M1,
                     ip4("10.0.0.66", "10.0.0.1", 6, tcp(random.randint(40000, 60000), 80, 0x02)))))

    pkts.sort(key=lambda x: x[0])
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    out += b"".join(rec(ts, pkt) for ts, pkt in pkts)
    Path(a.out).write_bytes(out)
    print(f"[+] wrote {len(pkts)} packets ({len(out)/1e6:.1f} MB) → {a.out}")
    print("    planted: port-scan, C2 beacon, 5MB exfil, SYN flood + normal traffic")


if __name__ == "__main__":
    main()
