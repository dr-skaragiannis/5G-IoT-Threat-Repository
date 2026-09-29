#!/usr/bin/env python3
"""
analyse_pcap.py -- per-module protocol profile for the NITRO 5G captures.

Emits a JSON profile per capture: protocol mix, endpoint roles, 5G control-plane
message counts (NGAP / PFCP / GTP-U), talker pairs, burst detection and the
specific frame numbers that constitute evidence for each observed behaviour.

Usage:
    python3 tools/analyse_pcap.py exercises_logs_anonymised/captures/module0.pcap
    python3 tools/analyse_pcap.py --all --out analysis/
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_lib import read_pcap  # noqa: E402


def analyse(path, evidence_cap=12):
    proto_mix = Counter()
    app_mix = Counter()
    talkers = Counter()
    ports = Counter()
    ngap = Counter()
    ngap_ev = defaultdict(list)
    pfcp = Counter()
    pfcp_ev = defaultdict(list)
    pfcp_seids = Counter()
    pfcp_causes = Counter()
    gtp_msgs = Counter()
    gtp_teids = Counter()
    gtp_inner = Counter()
    gtp_ev = defaultdict(list)
    icmp = Counter()
    icmp_ev = defaultdict(list)
    sctp_chunks = Counter()
    sctp_ev = defaultdict(list)
    sctp_vtags = Counter()
    arp_targets = Counter()
    arp_ev = []
    hosts = Counter()
    first_ts = last_ts = None
    total = 0
    # per-second rates, to spot floods
    sec_bucket = Counter()
    sec_bucket_pair = defaultdict(Counter)
    # NGAP replay detection: identical DATA payload seen repeatedly
    ngap_payload_hash = Counter()
    ngap_payload_first = {}
    tcp_syn = Counter()
    tcp_rst = Counter()
    frame_lens = Counter()

    for no, ts, p in read_pcap(path):
        total += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        sec = int(ts)
        sec_bucket[sec] += 1
        proto = p.get("proto") or ("0x%04x" % p.get("ethertype", 0))
        proto_mix[proto] += 1
        app = p.get("app")
        if app:
            app_mix[app] += 1
        frame_lens[p.get("framelen", 0) // 100 * 100] += 1
        s, d = p.get("src"), p.get("dst")
        if s:
            hosts[s] += 1
        if d:
            hosts[d] += 1
        if s and d:
            key = (s, d)
            talkers[key] += 1
            sec_bucket_pair[key][sec] += 1
        sp, dp = p.get("sport"), p.get("dport")
        if dp:
            ports[dp] += 1

        if app == "NGAP" or app == "SCTP-DATA":
            proc = p.get("ngap_proc", "?")
            pdu = p.get("ngap_pdu", "?")
            k = "%s/%s" % (pdu, proc)
            ngap[k] += 1
            if len(ngap_ev[k]) < evidence_cap:
                ngap_ev[k].append({"frame": no, "ts": ts, "src": s, "dst": d,
                                   "sport": sp, "dport": dp,
                                   "ppid": p.get("sctp_ppid"),
                                   "vtag": p.get("sctp_vtag"),
                                   "tsn": p.get("sctp_tsn"),
                                   "len": p.get("framelen")})
            pl = p.get("l5")
            if pl:
                h = hash(bytes(pl[:64]))
                ngap_payload_hash[h] += 1
                if h not in ngap_payload_first:
                    ngap_payload_first[h] = (no, ts, k, len(pl), bytes(pl[:32]).hex())

        if app == "PFCP":
            m = p.get("pfcp_msg", "?")
            pfcp[m] += 1
            if p.get("pfcp_seid") is not None:
                pfcp_seids[p["pfcp_seid"]] += 1
            if p.get("pfcp_cause"):
                pfcp_causes["%s/%s" % (m, p["pfcp_cause"])] += 1
            if len(pfcp_ev[m]) < evidence_cap:
                pfcp_ev[m].append({"frame": no, "ts": ts, "src": s, "dst": d,
                                   "sport": sp, "dport": dp,
                                   "seid": p.get("pfcp_seid"),
                                   "fseid": p.get("pfcp_fseid"),
                                   "teid": p.get("pfcp_teid"),
                                   "nodeid": p.get("pfcp_nodeid"),
                                   "cause": p.get("pfcp_cause"),
                                   "len": p.get("framelen")})

        if app == "GTP-U":
            m = p.get("gtp_msg", "?")
            gtp_msgs[m] += 1
            if p.get("gtp_teid") is not None:
                gtp_teids[p["gtp_teid"]] += 1
            inner = None
            if p.get("gtp_inner_src"):
                inner = "%s->%s/%s" % (p["gtp_inner_src"], p["gtp_inner_dst"],
                                       p.get("gtp_inner_icmp_name") or p.get("gtp_inner_proto"))
                gtp_inner[inner] += 1
            k = m if not inner else inner
            if len(gtp_ev[k]) < evidence_cap:
                gtp_ev[k].append({"frame": no, "ts": ts, "src": s, "dst": d,
                                  "teid": p.get("gtp_teid"), "msg": m,
                                  "inner_src": p.get("gtp_inner_src"),
                                  "inner_dst": p.get("gtp_inner_dst"),
                                  "inner_proto": p.get("gtp_inner_proto"),
                                  "icmp": p.get("gtp_inner_icmp_name"),
                                  "icmp_seq": p.get("gtp_inner_icmp_seq"),
                                  "len": p.get("framelen")})

        if app == "ICMP":
            k = "%s %s->%s" % (p.get("icmp_name"), s, d)
            icmp[k] += 1
            if len(icmp_ev[k]) < evidence_cap:
                icmp_ev[k].append({"frame": no, "ts": ts, "src": s, "dst": d,
                                   "type": p.get("icmp_name"),
                                   "id": p.get("icmp_id"),
                                   "seq": p.get("icmp_seq"),
                                   "len": p.get("framelen")})

        if p.get("sctp_chunks"):
            for c in p["sctp_chunks"]:
                sctp_chunks[c] += 1
                if c in ("INIT", "INIT_ACK", "ABORT", "SHUTDOWN", "ERROR", "COOKIE_ECHO"):
                    if len(sctp_ev[c]) < evidence_cap:
                        sctp_ev[c].append({"frame": no, "ts": ts, "src": s, "dst": d,
                                           "sport": sp, "dport": dp,
                                           "vtag": p.get("sctp_vtag")})
            sctp_vtags[p.get("sctp_vtag")] += 1

        if app == "ARP":
            if p.get("arp_op") == 1:
                arp_targets[p.get("arp_tpa")] += 1
                if len(arp_ev) < 40:
                    arp_ev.append({"frame": no, "ts": ts, "who_has": p.get("arp_tpa"),
                                   "tell": p.get("arp_spa")})

        if p.get("tcp_flagstr"):
            f = p["tcp_flagstr"]
            if f == "S":
                tcp_syn[(s, d, dp)] += 1
            if "R" in f:
                tcp_rst[(s, d, dp)] += 1

    dur = (last_ts - first_ts) if first_ts else 0

    # peak packets-per-second and which pair drove it
    peak_sec, peak_pps = (sec_bucket.most_common(1) or [(0, 0)])[0]
    pair_peaks = []
    for pair, buckets in sec_bucket_pair.items():
        sec, cnt = buckets.most_common(1)[0]
        pair_peaks.append((cnt, pair, sec))
    pair_peaks.sort(reverse=True)

    # replayed NGAP payloads (same first 64 bytes seen many times)
    replays = []
    for h, cnt in ngap_payload_hash.most_common(10):
        if cnt > 2:
            no, ts, k, ln, head = ngap_payload_first[h]
            replays.append({"count": cnt, "first_frame": no, "first_ts": ts,
                            "msg": k, "payload_len": ln, "head_hex": head})

    return {
        "file": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "frames": total,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_s": dur,
        "avg_pps": (total / dur) if dur else 0,
        "peak_pps": peak_pps,
        "peak_sec_offset": (peak_sec - int(first_ts)) if first_ts else 0,
        "proto_mix": dict(proto_mix.most_common()),
        "app_mix": dict(app_mix.most_common()),
        "hosts": dict(hosts.most_common(30)),
        "top_talkers": [{"src": a, "dst": b, "packets": c}
                        for (a, b), c in talkers.most_common(25)],
        "top_pair_peak_pps": [{"src": p[0], "dst": p[1], "peak_pps": c}
                              for c, p, s in pair_peaks[:10]],
        "top_dst_ports": dict(ports.most_common(20)),
        "ngap": dict(ngap.most_common()),
        "ngap_evidence": {k: v for k, v in ngap_ev.items()},
        "ngap_replays": replays,
        "pfcp": dict(pfcp.most_common()),
        "pfcp_causes": dict(pfcp_causes.most_common()),
        "pfcp_distinct_seids": len(pfcp_seids),
        "pfcp_top_seids": [{"seid": hex(k), "count": v} for k, v in pfcp_seids.most_common(10)],
        "pfcp_evidence": {k: v for k, v in pfcp_ev.items()},
        "gtp": dict(gtp_msgs.most_common()),
        "gtp_distinct_teids": len(gtp_teids),
        "gtp_top_teids": [{"teid": hex(k), "count": v} for k, v in gtp_teids.most_common(10)],
        "gtp_inner": dict(gtp_inner.most_common(15)),
        "gtp_evidence": {k: v for k, v in gtp_ev.items()},
        "icmp": dict(icmp.most_common(20)),
        "icmp_evidence": {k: v for k, v in icmp_ev.items()},
        "sctp_chunks": dict(sctp_chunks.most_common()),
        "sctp_distinct_vtags": len(sctp_vtags),
        "sctp_top_vtags": [{"vtag": hex(k or 0), "count": v}
                           for k, v in sctp_vtags.most_common(8)],
        "sctp_evidence": {k: v for k, v in sctp_ev.items()},
        "arp_scan_targets": len(arp_targets),
        "arp_top_targets": dict(arp_targets.most_common(15)),
        "arp_evidence": arp_ev,
        "tcp_syn_top": [{"src": k[0], "dst": k[1], "dport": k[2], "count": v}
                        for k, v in tcp_syn.most_common(10)],
        "tcp_rst_top": [{"src": k[0], "dst": k[1], "dport": k[2], "count": v}
                        for k, v in tcp_rst.most_common(10)],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--dir", default="exercises_logs_anonymised/captures")
    ap.add_argument("--out", default=None, help="write JSON per capture into this dir")
    args = ap.parse_args()

    paths = args.pcaps
    if args.all:
        paths = sorted(os.path.join(args.dir, f) for f in os.listdir(args.dir)
                       if f.endswith(".pcap"))
    if args.out:
        os.makedirs(args.out, exist_ok=True)

    for p in paths:
        prof = analyse(p)
        if args.out:
            dst = os.path.join(args.out, os.path.basename(p) + ".json")
            with open(dst, "w") as fh:
                json.dump(prof, fh, indent=1, default=str)
            print("wrote %s  (%d frames)" % (dst, prof["frames"]), file=sys.stderr)
        else:
            json.dump(prof, sys.stdout, indent=1, default=str)
            print()


if __name__ == "__main__":
    main()
