#!/usr/bin/env python3
"""
dump_frame.py -- print the decoded header line plus a hex/ASCII dump of the
L5 payload of specific frames, so a finding can be quoted verbatim.

    python3 tools/dump_frame.py capture.pcap 7768 7769 --ascii
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_lib import read_pcap  # noqa: E402


def hexdump(b, width=16, limit=512):
    out = []
    b = b[:limit]
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hx = " ".join("%02x" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("  %04x  %-*s  |%s|" % (i, width * 3, hx, asc))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("frames", nargs="+", type=int)
    ap.add_argument("--ascii", action="store_true", help="printable ASCII only")
    ap.add_argument("--limit", type=int, default=600)
    a = ap.parse_args()

    want = set(a.frames)
    t0 = None
    for no, ts, p in read_pcap(a.pcap):
        if t0 is None:
            t0 = ts
        if no not in want:
            continue
        print("=" * 78)
        print("frame #%d  t=+%.6fs  %s:%s -> %s:%s  %s  len=%d  app=%s" %
              (no, ts - t0, p.get("src"), p.get("sport"), p.get("dst"),
               p.get("dport"), p.get("proto"), p.get("framelen"), p.get("app")))
        for k in ("ngap_pdu", "ngap_proc", "pfcp_msg", "pfcp_seid", "pfcp_cause",
                  "gtp_msg", "gtp_teid", "gtp_inner_src", "gtp_inner_dst",
                  "gtp_inner_icmp_name", "icmp_name", "icmp_seq",
                  "sctp_chunks", "sctp_ppid", "sctp_vtag", "tcp_flagstr"):
            if p.get(k) is not None:
                print("    %-22s %s" % (k, p[k]))
        pl = p.get("l5") or b""
        if pl:
            if a.ascii:
                txt = "".join(chr(c) if 32 <= c < 127 else "." for c in pl[:a.limit])
                print("  payload[%d]: %s" % (len(pl), txt))
            else:
                print(hexdump(bytes(pl), limit=a.limit))
        want.discard(no)
        if not want:
            break


if __name__ == "__main__":
    main()
