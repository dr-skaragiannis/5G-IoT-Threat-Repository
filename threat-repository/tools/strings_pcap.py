#!/usr/bin/env python3
"""
strings_pcap.py -- pull printable ASCII runs out of L5 payloads and attribute
them to the endpoint that sent them.  Used to fingerprint which container is
which 5G network function (SBI service paths leak the NF type even through
HPACK, because Open5GS emits many header values as literal strings).
"""

import argparse
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_lib import read_pcap  # noqa: E402

ASCII = re.compile(rb"[ -~]{%d,}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--min", type=int, default=6)
    ap.add_argument("--grep", default=None, help="regex the string must match")
    ap.add_argument("--port", type=int)
    ap.add_argument("--src")
    ap.add_argument("--dst")
    ap.add_argument("--app")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--by-host", action="store_true")
    ap.add_argument("--show-frames", action="store_true")
    ap.add_argument("--limit-frames", type=int, default=0)
    a = ap.parse_args()

    pat = ASCII.pattern.decode() % a.min
    rx = re.compile(pat.encode())
    grep = re.compile(a.grep.encode(), re.I) if a.grep else None

    counts = Counter()
    per_host = defaultdict(Counter)
    frames = defaultdict(list)

    for no, ts, p in read_pcap(a.pcap):
        if a.limit_frames and no > a.limit_frames:
            break
        pl = p.get("l5")
        if not pl:
            continue
        if a.port and a.port not in (p.get("sport"), p.get("dport")):
            continue
        if a.src and p.get("src") != a.src:
            continue
        if a.dst and p.get("dst") != a.dst:
            continue
        if a.app and p.get("app") != a.app:
            continue
        for m in rx.finditer(bytes(pl)):
            s = m.group()
            if grep and not grep.search(s):
                continue
            t = s.decode("ascii", "replace")
            counts[t] += 1
            per_host["%s->%s" % (p.get("src"), p.get("dst"))][t] += 1
            if a.show_frames and len(frames[t]) < 5:
                frames[t].append((no, p.get("src"), p.get("dst"),
                                  p.get("sport"), p.get("dport")))

    if a.by_host:
        for h, c in sorted(per_host.items(), key=lambda kv: -sum(kv[1].values()))[:15]:
            print("== %s ==" % h)
            for s, n in c.most_common(12):
                print("   %6d  %s" % (n, s))
    else:
        for s, n in counts.most_common(a.top):
            print("%6d  %s" % (n, s))
            if a.show_frames:
                for f in frames[s]:
                    print("          frame #%d  %s:%s -> %s:%s" % (f[0], f[1], f[3], f[2], f[4]))


if __name__ == "__main__":
    main()
