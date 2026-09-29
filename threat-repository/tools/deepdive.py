#!/usr/bin/env python3
"""
deepdive.py -- targeted evidence extraction from a NITRO capture.

Modes:
  timeline   per-N-second histogram of a chosen protocol/host pair
  filter     print frames matching src/dst/port/proto/app, with decode fields
  arp        ARP request storm profile: who asks, for whom, at what rate
  burst      locate the top-N busiest 1-second windows and say what is in them
  flowpair   byte/packet totals per (src,dst,dport,proto) tuple
"""

import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_lib import read_pcap  # noqa: E402


def match(p, a):
    if a.src and p.get("src") != a.src:
        return False
    if a.dst and p.get("dst") != a.dst:
        return False
    if a.host and a.host not in (p.get("src"), p.get("dst")):
        return False
    if a.port and a.port not in (p.get("sport"), p.get("dport")):
        return False
    if a.proto and (p.get("proto") or "").upper() != a.proto.upper():
        return False
    if a.app and (p.get("app") or "") != a.app:
        return False
    return True


def fmt(no, ts, p, t0):
    bits = ["#%-7d" % no, "+%9.6f" % (ts - t0),
            "%-15s -> %-15s" % (p.get("src", "?"), p.get("dst", "?")),
            "%-5s" % (p.get("proto") or "?"),
            "len=%-5d" % p.get("framelen", 0)]
    if p.get("sport"):
        bits.append("%s>%s" % (p["sport"], p["dport"]))
    if p.get("app"):
        bits.append("[%s]" % p["app"])
    for k in ("ngap_pdu", "ngap_proc", "pfcp_msg", "pfcp_seid", "pfcp_cause",
              "pfcp_nodeid", "pfcp_teid", "gtp_msg", "gtp_teid",
              "gtp_inner_src", "gtp_inner_dst", "gtp_inner_icmp_name",
              "gtp_inner_icmp_seq", "icmp_name", "icmp_id", "icmp_seq",
              "sctp_vtag", "sctp_ppid", "tcp_flagstr", "arp_op", "arp_spa",
              "arp_tpa", "ttl"):
        v = p.get(k)
        if v is not None:
            if k in ("pfcp_seid", "gtp_teid", "sctp_vtag"):
                v = hex(v)
            bits.append("%s=%s" % (k.replace("gtp_inner_", "in."), v))
    if p.get("sctp_chunks"):
        bits.append("chunks=%s" % ",".join(p["sctp_chunks"]))
    return " ".join(bits)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("mode", choices=["timeline", "filter", "arp", "burst", "flowpair"])
    ap.add_argument("--src")
    ap.add_argument("--dst")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--proto")
    ap.add_argument("--app")
    ap.add_argument("--bin", type=int, default=10, help="timeline bin seconds")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--from-frame", type=int, default=0)
    ap.add_argument("--to-frame", type=int, default=0)
    a = ap.parse_args()

    t0 = None
    shown = 0

    if a.mode == "filter":
        for no, ts, p in read_pcap(a.pcap):
            if t0 is None:
                t0 = ts
            if a.from_frame and no < a.from_frame:
                continue
            if a.to_frame and no > a.to_frame:
                break
            if match(p, a):
                print(fmt(no, ts, p, t0))
                shown += 1
                if shown >= a.limit:
                    break

    elif a.mode == "timeline":
        bins = Counter()
        sub = defaultdict(Counter)
        for no, ts, p in read_pcap(a.pcap):
            if t0 is None:
                t0 = ts
            if not match(p, a):
                continue
            b = int((ts - t0) // a.bin) * a.bin
            bins[b] += 1
            sub[b][p.get("app") or p.get("proto") or "?"] += 1
        mx = max(bins.values()) if bins else 1
        for b in sorted(bins):
            bar = "#" * int(60 * bins[b] / mx)
            top = ",".join("%s:%d" % kv for kv in sub[b].most_common(3))
            print("+%-7d %7d %-61s %s" % (b, bins[b], bar, top))
        print("total matched:", sum(bins.values()))

    elif a.mode == "arp":
        req = Counter()
        pair = Counter()
        per_sec = Counter()
        first = {}
        for no, ts, p in read_pcap(a.pcap):
            if t0 is None:
                t0 = ts
            if p.get("app") != "ARP":
                continue
            op = p.get("arp_op")
            spa, tpa = p.get("arp_spa"), p.get("arp_tpa")
            if op == 1:
                req[tpa] += 1
                pair[(spa, tpa)] += 1
                per_sec[int(ts - t0)] += 1
                first.setdefault((spa, tpa), (no, ts - t0))
        print("-- ARP requests by target --")
        for tgt, c in req.most_common(a.top):
            print("  who-has %-16s : %d" % (tgt, c))
        print("-- ARP requester -> target --")
        for (s, d), c in pair.most_common(a.top):
            f = first[(s, d)]
            print("  %-16s asks for %-16s : %-8d  first frame #%d at +%.1fs" % (s, d, c, f[0], f[1]))
        print("-- peak ARP req/s --")
        for sec, c in per_sec.most_common(5):
            print("  +%ds : %d req/s" % (sec, c))

    elif a.mode == "burst":
        sec = Counter()
        detail = defaultdict(Counter)
        frames_at = defaultdict(list)
        for no, ts, p in read_pcap(a.pcap):
            if t0 is None:
                t0 = ts
            s = int(ts - t0)
            sec[s] += 1
            k = "%s %s->%s:%s [%s]" % (p.get("proto"), p.get("src"), p.get("dst"),
                                       p.get("dport"), p.get("app") or "-")
            detail[s][k] += 1
            if len(frames_at[s]) < 3:
                frames_at[s].append(no)
        for s, c in sec.most_common(a.top):
            print("+%-6ds  %6d pkt/s   frames %s" % (s, c, frames_at[s]))
            for k, v in detail[s].most_common(4):
                print("        %6d  %s" % (v, k))

    elif a.mode == "flowpair":
        agg = Counter()
        byt = Counter()
        for no, ts, p in read_pcap(a.pcap):
            if t0 is None:
                t0 = ts
            if not match(p, a):
                continue
            k = (p.get("src"), p.get("dst"), p.get("proto"), p.get("dport"), p.get("app"))
            agg[k] += 1
            byt[k] += p.get("framelen", 0)
        print("%-16s %-16s %-6s %-7s %-12s %10s %14s" %
              ("SRC", "DST", "PROTO", "DPORT", "APP", "PACKETS", "BYTES"))
        for k, c in agg.most_common(a.top):
            print("%-16s %-16s %-6s %-7s %-12s %10d %14d" %
                  (k[0], k[1], k[2], k[3], k[4] or "-", c, byt[k]))


if __name__ == "__main__":
    main()
