# Findings Report

Analysis of the NITRO 5G Exercise Dataset v1.0 — nine packet captures, ten NetFlow feature sets
and 989 operator shell commands recorded across a containerised 5G standalone core, its
simulated RAN, and an AI-based intrusion-detection pipeline.

This is the narrative. The catalogue is in [THREAT-REPOSITORY.md](THREAT-REPOSITORY.md); this
document explains what the dataset actually records and how the pieces fit together.

---

## 1. Executive summary

The dataset captures an eleven-stage red-team exercise against a lab 5G core. Reconstructed end
to end, it demonstrates a complete compromise chain that starts with nothing more than the
ability to reach a network and ends with the subscriber base cloned, the AMF flooded, the host
owned, and the intrusion-detection system blinded.

**Twenty-six threats** were catalogued: 9 Critical, 13 High, 4 Medium. Twenty-five are
Confirmed; one is Probable.

Three findings define the security posture of this deployment:

1. **The subscriber database answers anyone.** MongoDB accepts queries with no authentication
   handshake of any kind, and returns the permanent SIM key K and OPc in cleartext. All six
   subscribers share the same key pair. One 1,260-byte frame carries the entire subscriber base.
   (TR-DB-001, TR-SUB-001)

2. **Nothing is encrypted and nothing is authenticated between network functions.** N2, N3, N4
   and the whole service-based interface run in the clear with no IPsec, no TLS and no OAuth 2.0.
   Every subscriber identity, session binding, tunnel identifier and authentication vector is
   readable from a single capture point. (TR-N2-002, TR-N4-001, TR-SUB-003)

3. **There is no segmentation.** All of the above share one Docker bridge with the subscriber
   database and the RAN simulator. The "attacker must first reach interface X" precondition that
   makes many 5G weaknesses theoretical is satisfied by default for every workload on the host.
   (TR-VIRT-004)

Against that background the specific attacks are almost undemanding. The PFCP session identifier
space collapses to **12 bits** — 4,096 values, enumerable in under a second — so hijacking or
destroying any subscriber's user plane is a loop, not an exploit (TR-N4-002). A recorded NGAP
exchange replayed with 2,000× duplication is accepted and processed by the AMF, because N2 has no
anti-replay (TR-N2-001). A `mount` and a `chroot` from inside a network-function container yield
a shell on the host (TR-VIRT-001).

The AI layer fares no better. The intrusion-detection model is trained on three features —
protocol number and two packet lengths — none of which measures rate, which is the only thing
that distinguishes a flood from a ping. Multiplying one feature by 0.5 evades it roughly three
times in four (TR-AI-002, TR-AI-003). A label-flipping attack on its training corpus produces a
targeted blind spot measured as an explicit Attack Success Rate (TR-AI-001).

Throughout, Zabbix and Wazuh are running and reachable. Nothing in the dataset indicates that any
of this raised an alert. The monitoring stack watches hosts; the attacks are in the 5G control
plane, which it cannot see.

---

## 2. What the dataset records, capture by capture

Each capture is bracketed in the shell history by `sudo nohup tcpdump -i any -w moduleN.pcap ... &`
and a matching `sudo kill -15`, which is what allows commands to be attributed to captures.

| # | Window (UTC) | Frames | What happened | Threats first evidenced |
|---|---|---:|---|---|
| **0** | 26 Aug 20:23–21:04 | 107,451 | Core brought up, subscribers registered, first UE attach. An ephemeral tools container queries the subscriber database. | TR-DB-001, TR-DB-002, TR-SUB-002 |
| **1** | 27 Aug 19:19–20:06 | 131,027 | PDU sessions established; ICMP pushed through the GTP-U tunnel; TEIDs enumerated. Every G-PDU answered with an Error Indication. | TR-N3-001, TR-N3-002, TR-N4-001, TR-SUB-001, TR-SUB-003, TR-SUB-004 |
| **2** | 27 Aug 20:22–22:27 | 467,492 | Registration failures investigated; core torn down and rebuilt. The RAN storm begins: 101,159 ARP requests, 32 replies. | TR-RAN-002 |
| **3** | 27 Aug ~22:28–22:56 | 4,267,925 | **The NGAP replay flood.** 5GReplay retargeted onto the AMF, 2000x duplication. pcap excluded; NetFlow present. | TR-N2-001 |
| **4** | 28 Aug 06:40–06:51 | 31,478 | AppArmor, kernel and Docker version reconnaissance across every container. | TR-VIRT-002 |
| **5** | 28 Aug 06:54–07:01 | 63,064 | **Subscriber database dumped** — six records with K and OPc in two frames. SMF config recon. | TR-DB-002, TR-VIRT-005 |
| **6** | 9 Sep 20:25–22:14 | 276,064 | N4 attack surface mapped; `pfcpExploit.py` hunted and invoked; `arp-scan` of the core; three UEs raised; iptables used to blackhole a peer gNB. | TR-N4-002, TR-N4-003, TR-VIRT-004 |
| **7** | 9 Sep 22:16–22:52 | 92,423 | **Container escape.** Privileged/CapAdd sweep, then `mount` + `chroot` onto the host filesystem. Repeated after a restart. | TR-VIRT-001, TR-VIRT-003 |
| **8** | 9 Sep 22:53–23:11 | 59,699 | IDS corpus built with `tshark`; clean model trained; **poisoned model trained** and ASR measured. | TR-AI-001, TR-AI-003, TR-AI-004 |
| **9** | 9 Sep 23:25–23:34 | 22,347 | **Adversarial evasion** of the IDS, then adversarial training and a RandomForest ensemble as countermeasures. | TR-AI-002 |
| *extra* | 9 Sep 23:34+ | — | 5GReplay re-downloaded and replayed a second time. pcap not in the dataset. | TR-OPS-002 |

`module3.pcap` is 581.7 MB and exceeds GitHub's per-file limit, so it is excluded from this
repository. It is the single most significant capture in the set, and its NetFlow derivative
`netflows/module3.pcap_Flow.csv` carries the evidence for TR-N2-001.

---

## 3. The compromise chain

The individual findings matter less than the way they compose. Read in order, the dataset
describes one continuous path from "can send packets to the bridge" to "owns everything".

### Step 1 — Reachability is free (TR-VIRT-004)

Every 3GPP reference point, plus the subscriber database, plus the RAN simulator, sits on one
Docker bridge. ARP requests travel between pairs that have no protocol relationship — MongoDB
resolving the PCF, the UE resolving the gNB, the UPF resolving the SMF — which is only possible
in a single broadcast domain. Any workload scheduled onto this network can reach N2, N3, N4, the
SBI and TCP/27017 without traversing a single policy boundary.

This is the precondition that every sub

`module3.pcap` is 581.7 MB and exceeds GitHub's per-file limit, so it is excluded from this
repository. It is the most significant capture in the set, and its NetFlow derivative
`netflows/module3.pcap_Flow.csv` carries the evidence for TR-N2-001.

---

## 3. The compromise chain

The individual findings matter less than how they compose. Read in order, the dataset describes
one continuous path from "can send packets to the bridge" to "owns everything".

### Step 1 — Reachability is free (TR-VIRT-004)

Every 3GPP reference point, plus the subscriber database, plus the RAN simulator, sits on one
Docker bridge. ARP travels between pairs with no protocol relationship — MongoDB resolving the
PCF, the UPF resolving the SMF — which is only possible in a single broadcast domain. Any
workload on this network reaches N2, N3, N4, the SBI and TCP/27017 without crossing a policy
boundary. This is the precondition that every subsequent step assumes, and it costs nothing.

### Step 2 — The credentials are simply readable (TR-DB-001 → TR-SUB-001)

An exhaustive byte search across every MongoDB frame in the corpus for `saslStart`,
`saslContinue`, `SCRAM-SHA`, `authenticate` and `speculativeAuthenticate` returns **nothing**.
There is no failed authentication, because none is attempted and none is required.

A disposable container launched with `--rm` asks for the subscriber collection and gets

### Step 2 — The credentials are simply readable (TR-DB-001, TR-SUB-001, TR-DB-002)

An exhaustive byte search across every MongoDB frame in the corpus for `saslStart`,
`saslContinue`, `SCRAM-SHA`, `authenticate` and `speculativeAuthenticate` returns **nothing**.
There is no failed authentication, because none is attempted and none is required.

A disposable container launched with `--rm` asks for the subscriber collection and receives
frame **5243** of `module5.pcap`: 1,260 bytes containing six subscriber records, each with its
IMSI, its slice and session configuration, and a `security` sub-document holding `k` and `opc`
in plaintext hexadecimal. All six share the same pair.

The same key material also crosses the service-based interface in the clear, as
`{"authenticationMethod":"5G_AKA","encPermanentKey":...,"encOpcKey":...}` — so an attacker who
cannot reach the database can simply wait for a registration.

