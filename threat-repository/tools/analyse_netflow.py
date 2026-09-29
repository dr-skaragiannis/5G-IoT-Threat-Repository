#!/usr/bin/env python3
"""
analyse_netflow.py -- profile the CICFlowMeter CSVs in netflows/.

These are the 84-feature bidirectional flow records derived from each capture.
For module3 the CSV is the only surviving artefact (the 581 MB pcap is not in
the repository), so the flow features carry the whole evidential weight there.

Reports: flow counts by protocol, top talkers by packets/bytes, the highest
packet-rate flows, micro-flows (candidate scan/flood residue) and the flows
that touch 5G control-plane ports.
"""

import argparse
import csv
import os
import sys
from collections import Counter, defaultdict

PROTO = {"6": "TCP", "17": "UDP", "132": "SCTP", "1": "ICMP", "0": "HOPOPT"}

CP_PORTS = {
    "38412": "NGAP/N2 (SCTP)",
    "8805": "PFCP/N4",
    "2152": "GTP-U/N3",
    "7777": "SBI HTTP/2 (Open5GS)",
    "27017": "MongoDB (subscriber DB)",
    "4997": "UERANSIM RLS (radio link sim)",
    "3000": "WebUI",
    "9999": "NRF alt",
    "80": "HTTP",
    "22": "SSH",
    "53": "DNS",
    "10051": "Zabbix",
    "1514": "Wazuh/syslog",
}


def f(x, default=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def analyse(path, top=15):
    rows = 0
    proto = Counter()
    pair = Counter()
    pair_bytes = Counter()
    dport = Counter()
    rate = []
    micro = Counter()
    cp = defaultdict(lambda: [0, 0, 0])  # port -> [flows, pkts, bytes]
    labels = Counter()
    src_fanout = defaultdict(set)
    longest = []
    biggest = []

    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        rd = csv.DictReader(fh)
        for r in rd:
            rows += 1
            p = PROTO.get(r.get("Protocol", ""), r.get("Protocol", "?"))
            proto[p] += 1
            s, d = r.get("Src IP"), r.get("Dst IP")
            dp = r.get("Dst Port")
            fwd = f(r.get("Total Fwd Packet"))
            bwd = f(r.get("Total Bwd packets"))
            pkts = fwd + bwd
            byts = f(r.get("Total Length of Fwd Packet")) + f(r.get("Total Length of Bwd Packet"))
            dur = f(r.get("Flow Duration")) / 1e6  # microseconds -> s
            pair[(s, d, p)] += pkts
            pair_bytes[(s, d, p)] += byts
            dport[(dp, p)] += 1
            labels[r.get("Label", "")] += 1
            src_fanout[s].add((d, dp))
            if dur > 0.05:
                rate.append((pkts / dur, s, d, dp, p, pkts, byts, dur,
                             r.get("Timestamp"), r.get("Flow ID")))
            if pkts <= 2:
                micro[(s, dp, p)] += 1
            if dp in CP_PORTS:
                e = cp[dp]
                e[0] += 1
                e[1] += pkts
                e[2] += byts
            longest.append((dur, s, d, dp, p, pkts, r.get("Timestamp")))
            biggest.append((pkts, s, d, dp, p, byts, dur, r.get("Timestamp"), r.get("Flow ID")))

    rate.sort(reverse=True)
    longest.sort(reverse=True)
    biggest.sort(reverse=True)

    return {
        "file": os.path.basename(path), "flows": rows,
        "proto": proto, "labels": labels,
        "top_pairs": pair.most_common(top),
        "top_pairs_bytes": pair_bytes.most_common(top),
        "top_dports": dport.most_common(top),
        "fastest": rate[:top],
        "biggest": biggest[:top],
        "longest": longest[:5],
        "micro": micro.most_common(top),
        "cp": dict(cp),
        "fanout": sorted(((len(v), k) for k, v in src_fanout.items()), reverse=True)[:top],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csvs", nargs="+")
    ap.add_argument("--top", type=int, default=12)
    a = ap.parse_args()
    for p in a.csvs:
        r = analyse(p, a.top)
        print("=" * 100)
        print("%s   flows=%d   proto=%s" % (r["file"], r["flows"], dict(r["proto"])))
        print("  labels:", dict(r["labels"]))
        print("  -- top flow pairs by packets --")
        for (s, d, pr), n in r["top_pairs"][:a.top]:
            print("     %-16s -> %-16s %-5s %12.0f pkts" % (s, d, pr, n))
        print("  -- top dst ports (flow count) --")
        for (dp, pr), n in r["top_dports"][:a.top]:
            print("     %-7s %-5s %6d flows   %s" % (dp, pr, n, CP_PORTS.get(dp, "")))
        print("  -- fastest flows (pkt/s, dur>50ms) --")
        for x in r["fastest"][:a.top]:
            print("     %10.1f pkt/s  %-16s -> %-16s :%-6s %-5s pkts=%-9.0f bytes=%-12.0f dur=%.2fs  %s"
                  % (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8]))
        print("  -- biggest flows (packets) --")
        for x in r["biggest"][:a.top]:
            print("     %10.0f pkts  %-16s -> %-16s :%-6s %-5s bytes=%-12.0f dur=%.2fs  %s"
                  % (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]))
        print("  -- 5G control-plane port totals --")
        for dp, (fl, pk, by) in sorted(r["cp"].items(), key=lambda kv: -kv[1][1]):
            print("     :%-7s %-30s flows=%-6d pkts=%-10.0f bytes=%.0f" %
                  (dp, CP_PORTS.get(dp, ""), fl, pk, by))
        print("  -- source fan-out (distinct dst:port) --")
        for n, s in r["fanout"][:8]:
            print("     %-16s touches %d distinct dst:port pairs" % (s, n))


if __name__ == "__main__":
    main()
