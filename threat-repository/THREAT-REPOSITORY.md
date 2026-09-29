# Threat Repository

The catalogue. 26 entries derived from the NITRO 5G Exercise Dataset v1.0.

Classification scheme, severity definitions and mapping rules: [TAXONOMY.md](TAXONOMY.md).
Asset identifiers: [ENVIRONMENT.md](ENVIRONMENT.md). Narrative context:
[FINDINGS-REPORT.md](FINDINGS-REPORT.md).

---

## Index

| ID | Title | Severity | Confidence |
|---|---|:--:|:--:|
| [TR-RAN-001](#tr-ran-001) | Rogue UE instantiated with cloned SIM credentials against a live gNB | Critical | Confirmed |
| [TR-RAN-002](#tr-ran-002) | Stale RAN peer drives a sustained radio-link and ARP resolution storm | High | Confirmed |
| [TR-N2-001](#tr-n2-001) | NGAP replay flood against the AMF with 2000x duplication | Critical | Confirmed |
| [TR-N2-002](#tr-n2-002) | N2 carries NGAP and NAS with no IPsec, DTLS or anti-replay | High | Confirmed |
| [TR-N3-001](#tr-n3-001) | GTP-U tunnel endpoint identifiers enumerated from the capture position | High | Confirmed |
| [TR-N3-002](#tr-n3-002) | User-plane desynchronisation — every G-PDU answered with Error Indication | High | Confirmed |
| [TR-N4-001](#tr-n4-001) | PFCP session management unauthenticated and unencrypted on N4 | Critical | Confirmed |
| [TR-N4-002](#tr-n4-002) | PFCP session identifiers occupy 12 bits of a 64-bit space | Critical | Confirmed |
| [TR-N4-003](#tr-n4-003) | PFCP exploitation tooling staged and targeted inside the core | High | Probable |
| [TR-SUB-001](#tr-sub-001) | Long-term SIM keys recoverable in cleartext, shared across all subscribers | Critical | Confirmed |
| [TR-SUB-002](#tr-sub-002) | SUCI null-scheme leaves the permanent subscriber identity unprotected | High | Confirmed |
| [TR-SUB-003](#tr-sub-003) | SUPI and IMEISV traverse the service-based interface in cleartext | High | Confirmed |
| [TR-SUB-004](#tr-sub-004) | SUPI-to-IP bindings disclosed, enabling subscriber traffic attribution | High | Confirmed |
| [TR-DB-001](#tr-db-001) | Subscriber database accepts unauthenticated queries | Critical | Confirmed |
| [TR-DB-002](#tr-db-002) | Bulk subscriber extraction via an ephemeral administrative container | Critical | Confirmed |
| [TR-VIRT-001](#tr-virt-001) | Container escape to the host filesystem from a network-function container | Critical | Confirmed |
| [TR-VIRT-002](#tr-virt-002) | Network-function containers hold excess capabilities and privileged mode | High | Confirmed |
| [TR-VIRT-003](#tr-virt-003) | Container administration socket reachable from inside the workload | High | Confirmed |
| [TR-VIRT-004](#tr-virt-004) | All 3GPP reference points share one unsegmented L2 broadcast domain | Critical | Confirmed |
| [TR-VIRT-005](#tr-virt-005) | Container address reuse misdelivers traffic to an unrelated workload | Medium | Confirmed |
| [TR-AI-001](#tr-ai-001) | Training-data poisoning of the intrusion-detection model by label flipping | High | Confirmed |
| [TR-AI-002](#tr-ai-002) | Adversarial evasion of the IDS by scaling a single packet-length feature | High | Confirmed |
| [TR-AI-003](#tr-ai-003) | Three-feature model provides no adversarial robustness by construction | High | Confirmed |
| [TR-AI-004](#tr-ai-004) | Unprotected ML training corpus built from live 5G control-plane telemetry | Medium | Confirmed |
| [TR-OPS-001](#tr-ops-001) | Full-fidelity capture position on the container host observes every interface | Medium | Confirmed |
| [TR-OPS-002](#tr-ops-002) | Offensive tooling pulled from the public internet onto the core host | Medium | Confirmed |

---

## RAN — Radio access and radio-link simulation

<a id="tr-ran-001"></a>
### TR-RAN-001 — Rogue UE instantiated with cloned SIM credentials against a live gNB

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| RAN | **Critical** | Confirmed | UE (UERANSIM `nr-ue`), gNB `172.18.0.15`, AMF `172.18.0.14` |

**What happened.** An unprovisioned UE container was launched carrying a complete 5G-AKA
credential set on the command line — PLMN, MSISDN, the permanent key K, the OPc, the APN and the
target gNB address — and attached directly to the core's Docker network with `NET_ADMIN` and
`/dev/net/tun`. The same K and OPc are recoverable from the subscriber database (TR-DB-001), so
these are stored production credentials, not synthetic values. The UE registered successfully and
later raised three simultaneous contexts with working user-plane reachability.

**Why this is a threat.** This is the SIM-cloning primitive end to end. Possession of
(SUPI, K, OPc) is sufficient to complete 5G-AKA, because 5G-AKA proves possession of K and nothing
more — there is no cryptographic binding to a device or to the IMEISV. Nothing was guessed or
cracked: the key material was readable from the UDR store and the UE image accepts it as
environment variables. *Critical* — the outcome is full subscriber impersonation under a valid
billing identity, and K cannot be rotated remotely on a deployed SIM. *Confirmed* — invocation,
matching key values and successful registration appear in three independent artefacts.

**Evidence.**

- `bash_history_v1:43` — the rogue UE with credentials inline:
  ```
  docker run --rm -it --name e1e --network dfoiaas5llpretddralsgmsrsner \
    --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN \
    -e MCC=999 -e MNC=70 -e MSISDN=0467136224 \
    -e KEY=716443940B35EC8A7EDA57F98A9A70E6 \
    -e OP_TYPE=OPC -e OP=A14B42703DEBABBE206D7597D93D65FA \
    -e APN=internet -e GNB_IP=172.18.0.2 gradiant/snseiimm:3.2.6 uu
  ```
  Long-term key material as plain environment variables, readable afterwards by anyone who can
  run `docker inspect` or read `/proc/<pid>/environ`.

- `module5.pcap` frame **5243** (`172.18.0.2:27017 → 172.18.0.15:41984`) — the same key pair,
  returned by the subscriber database:
  ```
  imsi 999702813335208 ... security  k 716443940B35EC8A7EDA57F98A9A70E6
                                     opc A14B42703DEBABBE206D7597D93D65FA
  ```
  Proves the credentials were harvested, not invented.

- `bash_history_v2:143-148` — three UE contexts from one container, then user-plane proof:
  ```
  nr-uu -c /etc/snseiimm/uu.yaml -n 3 > /dev/null &
  ip a | grep uesimtun
  ping -I uesimtun0 8.8.8.8
  ```

- `module1.pcap` frames **77556–78250** — the network accepts it: `InitialUEMessage` →
  `DownlinkNASTransport` → `UplinkNASTransport` → `InitialContextSetup (successfulOutcome)`.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT5026](https://fight.mitre.org/techniques/FGT5026) | SIM Cloning | The attach uses the stored (SUPI, K, OPc) of an existing subscriber record. |
| FiGHT | [FGT1583.502](https://fight.mitre.org/techniques/FGT1583.502) | Acquire Infrastructure: Programmable UE Devices | A software UE is stood up specifically to attach to the victim RAN. |
| FiGHT | [FGT1195.501](https://fight.mitre.org/techniques/FGT1195.501) | Supply Chain Compromise: SIM Credentials Theft | Credentials obtained in bulk from the SIM data repository rather than a physical card. |
| ATT&CK | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Authentication succeeds with legitimate long-term credentials; nothing looks anomalous to the AMF. |
| ATT&CK | [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container | `docker run` places an attacker-controlled workload directly on the core bridge. |

**Impact.** Service consumed under the victim's billing identity; charging and lawful-intercept
records attributed to the wrong subscriber; a persistent authenticated foothold on the user plane.
Remediation requires physical SIM replacement.

**Detection.** Alert on one SUPI registering from two distinct IMEISVs, on registrations with
absent or repeated PEI, and on more UE contexts per gNB than provisioned. The operator's own
check — `docker logs <amf> | grep -i "Number of gNB-UEs"` (`bash_history_v1:425`) — is exactly the
right signal, but it was run manually rather than alerted on.

**Mitigation.** Hold K/OPc only in an HSM or SIDF vault so the core computes authentication
vectors without ever exposing the key. Enforce SUPI-to-PEI binding and reject registrations where
the pair changes. Strip `NET_ADMIN` and `/dev/net/tun` from any container that is not an
authorised RAN element, and restrict who may attach workloads to the core network.

**References.** 3GPP TS 33.501 §6.1 (5G-AKA); GSMA FS.31 Baseline Security Controls.

---
<a id="tr-ran-002"></a>
### TR-RAN-002 — Stale RAN peer drives a sustained radio-link and ARP resolution storm

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| RAN | **High** | Confirmed | UE `172.18.0.16`, gNB `172.18.0.15`, Docker bridge `172.18.0.0/16` |

**What happened.** From module2 onward the UE container keeps transmitting UERANSIM Radio Link
Simulation traffic to UDP/4997 at the gNB address after that gNB has been torn down. Because the
peer no longer answers ARP, every transmission also triggers a fresh ARP request. In module2 the
UE issued **101,159 ARP requests and received 32 replies**; in module5 and module6 it received
none at all. The RLS traffic peaks at 8,428 packets per second and drives the module2 capture to
18,947 pps — roughly 300× that capture's 62 pps average.

**Why this is a threat.** One orphaned RAN element is enough to saturate the L2 segment that
carries every 5G interface in this deployment, because there is no segmentation (TR-VIRT-004) and
no ceiling on cell-search retransmission. The UE's behaviour is its normal "searching for cell"
loop; the weakness is that the loop is unbounded and that its broadcast domain is shared with N2,
N3, N4 and the SBI. An adversary with one programmable UE reproduces this deliberately.
*High* rather than Critical because the observed event degraded rather than halted the core.
*Confirmed* — the request/reply asymmetry is measured directly across five captures.

**Evidence.**

- Derived, all captures — ARP request/reply counts for `172.18.0.16 → 172.18.0.15`:

  | Capture | Requests | Replies | Ratio |
  |---|---:|---:|---:|
  | module0 | 138 | 138 | 1:1 |
  | module1 | 186 | 186 | 1:1 |
  | module2 | 101,159 | 32 | 3,161:1 |
  | module5 | 6,132 | 0 | ∞ |
  | module6 | 96,285 | 0 | ∞ |

  Modules 0 and 1 are the healthy baseline. From module2 the reply side collapses while requests
  grow three orders of magnitude.

- `module2.pcap` busiest second (+583 s) — 19,180 pkt/s, dominated by
  `172.18.0.16 → 172.18.0.15:4997 UDP`. Peak load is the orphaned radio-link channel, not any
  core procedure.

- `netflows/module5.pcap_Flow.csv` — `172.18.0.16 → 172.18.0.15` UDP/4997: **603 flows, 44,886
  packets, 1,122,150 bytes in 424 s**. 603 distinct flows for one peer pair is continuous
  re-discovery, not a live session.

- `bash_history_v1:166-170` — the teardown/rebuild cycle that orphans the UE:
  ```
  docker compose -f ngc.yaml down
  docker compose -f g1b1.yaml down
  docker compose -f ngc.yaml up -d
  ./register_subscriber.sh
  docker compose -f g1b1.yaml up -d
  ```

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1499.001](https://attack.mitre.org/techniques/T1499/001/) | Endpoint DoS: OS Exhaustion Flood | Unbounded retransmission plus unanswered ARP consumes neighbour-table and softirq budget on every host on the bridge. |
| ATT&CK | [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | A single endpoint saturates the shared segment carrying all 5G interfaces. |
| FiGHT | [FGT1499](https://fight.mitre.org/techniques/FGT1499) | Endpoint Denial of Service | Availability degradation at a 5G endpoint through flooding. |
| FiGHT | [FGT1642.501](https://fight.mitre.org/techniques/FGT1642.501) | Endpoint DoS: Transmit Spoofed Broadcast Message | The broadcast ARP component propagates load to hosts not party to the conversation. |

**Impact.** Control-plane latency and loss for unrelated network functions; neighbour-cache
pressure on the container host; monitoring noise that masks genuine attacks. Reproduced with
several UEs it becomes a practical RAN-originated denial of service against the core.

**Detection.** Alert when ARP requests for a target exceed replies beyond a small ratio over a
rolling window — here it reached 3,161:1 against a 1:1 baseline. Baseline UDP/4997 pps per UE-gNB
pair. Track flow count per peer pair: 603 flows for one pair in 424 s is itself the anomaly.

**Mitigation.** Put the RLS/fronthaul channel on its own segment so it cannot contend with
N2/N3/N4/SBI. Apply exponential back-off and an absolute retry ceiling to UE cell search.
Rate-limit ARP per bridge port. Ensure RAN teardown also stops or reconfigures its peers rather
than leaving them pointed at a released address (TR-VIRT-005).

**References.** 3GPP TS 38.300; RFC 826.

---
## N2 — NGAP control plane

<a id="tr-n2-001"></a>
### TR-N2-001 — NGAP replay flood against the AMF with 2000x duplication

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| N2 | **Critical** | Confirmed | AMF `172.18.0.14`, Docker gateway `172.18.0.1`, gNB `172.18.0.15` |

**What happened.** The Montimage 5GReplay tool was downloaded, pointed at a sample 5G standalone
capture containing genuine NGAP exchanges, and reconfigured so its forwarding target was no
longer the loopback placeholder shipped with the tool but the live AMF at `172.18.0.14`. The
capture was replayed with every packet duplicated **2,000 times**. Injection entered the core from
the Docker bridge gateway and the AMF accepted it on SCTP/38412: **52,666 packets inbound and
55,892 outbound** on that single association inside a two-minute window. The capture covering this
activity (module3) holds 4,267,925 frames; its flow records account for 2,115,209 packets, of
which 1,473,880 are SCTP.

**Why this is a threat.** NGAP carries no message-level authentication and no anti-replay
counter, and in this deployment nothing beneath it provides one either (TR-N2-002). A previously
captured but entirely valid NGAP message therefore remains valid indefinitely and can be
re-injected by anyone who can reach the AMF's SCTP port. The 2,000× duplication converts a
recording into a volumetric attack without the adversary crafting a single packet. *Critical* —
a successful N2 flood detaches every UE served by the AMF, and the AMF is a single point of
failure for registration across the whole PLMN. *Confirmed* — the configuration edit, the command
and the resulting traffic are each independently recorded.

**Evidence.**

- `bash_history_v2:42-47` — the tool retargeted from its safe default onto the production AMF:
  ```
  grep -nEi "127.0.0.5|38412|target-host|target-port" mmt-5greplay.conf
  cp mmt-5greplay.conf mmt-5greplay.conf.bak
  sed -i 's/"127.0.0.5"/"172.18.0.14"/' mmt-5greplay.conf
  sudo ./5greplay replay -t .../5g-sa.pcap -Xforward.nb-copies=2000 -Xforward.default=FORWARD
  ```

- `netflows/module3.pcap_Flow.csv` — the AMF is not merely receiving, it is responding:
  ```
  172.18.0.1:39952  -> 172.18.0.14:38412  SCTP  52,666 pkts  13,865,896 B  119.90 s
  172.18.0.14:38412 -> 172.18.0.1:39952   SCTP  55,892 pkts  13,935,120 B  119.17 s
  ```

- `netflows/module3.pcap_Flow.csv`, derived — the tool's arithmetic signature: **69 flows contain
  exactly 4,000 packets** (42 SCTP, 27 TCP), 276,000 packets total, at 55,685–76,665 pkt/s.
  4,000 = 2,000 copies seen in both directions. The `172.16.x.x` and `2511::` endpoints in those
  flows are the original addresses *inside* the replayed sample capture, re-emitted verbatim onto
  the lab network.

- `bash_history_v1:215` — the operator searching for exactly those replayed endpoints:
  `grep -RniE "172.16.46.201|172.16.59.11" /home/noinr` — and
  `172.16.59.11 → 172.16.46.201:38412` duly appears in the flow records at 55,685 pkt/s.

- `bash_history_v2:443-449` — acquisition of tool and seed capture from the public internet onto
  the host running the core (see TR-OPS-002).

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT1498.501](https://fight.mitre.org/techniques/FGT1498.501) | Network DoS: Flooding Core Network Component | High-volume signalling directed at a core NF to exhaust it — the technique's literal definition. |
| FiGHT | [FGT1642.503](https://fight.mitre.org/techniques/FGT1642.503) | Endpoint DoS: AMF | The AMF is the named target and the injected NGAP is intended to disrupt the attach procedure. |
| FiGHT | [FGT1498.503](https://fight.mitre.org/techniques/FGT1498.503) | Network DoS: Malicious Packets To Network Functions | Crafted/replayed NGAP is sent from an off-RAN position to slow or crash the AMF. |
| ATT&CK | [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Volumetric saturation of a network service. |
| ATT&CK | [T1499.002](https://attack.mitre.org/techniques/T1499/002/) | Endpoint DoS: Service Exhaustion Flood | The AMF's NGAP processing path, not the link, is the resource being exhausted. |
| ATT&CK | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | 5GReplay is acquired from a public repository specifically to conduct the attack. |
| ATT&CK | [T1565.002](https://attack.mitre.org/techniques/T1565/002/) | Data Manipulation: Transmitted Data Manipulation | The tool rewrites forwarding targets so recorded signalling is delivered to a host that was never its destination. |

**Impact.** Registration and mobility failure for every UE served by the AMF; SCTP association
instability with all attached gNBs; exhaustion of AMF UE-context state. Because the replayed
messages are structurally valid, the AMF spends real work on each one — the attack is far cheaper
for the adversary than for the victim.

**Detection.** Alert on NGAP arriving over an SCTP association whose peer is not a provisioned
gNB — here the source was the bridge gateway `172.18.0.1`, which is not a RAN element and should
never appear on N2. Alert on NGAP message rate per association exceeding a few hundred per second
(baseline across module0/1 is under 5/s). Detect duplicate NGAP PDUs by hashing the payload:
2,000 identical copies is unambiguous. Watch for inbound SCTP INIT to 38412 from unexpected
sources.

**Mitigation.** Enforce IPsec or DTLS on N2 as TS 33.501 §9.2 requires, with peer certificates so
only provisioned gNBs can establish an association. Filter SCTP/38412 to the known gNB address
set at the fabric, not just at the host. Rate-limit NGAP per association and per gNB. Deploy
duplicate-PDU detection at the AMF ingress.

**References.** 3GPP TS 33.501 §9.2 (N2 security); 3GPP TS 38.413 (NGAP); GSMA FS.31.

> **Evidence note.** `module3.pcap` (581.7 MB) exceeds GitHub's per-file limit and is excluded
> from this repository. This entry rests on NetFlow records and shell history. The flow evidence
> is strong — packet counts, rates, exact-4000-packet flows and a live bidirectional SCTP
> association with the AMF — but no NGAP payload from the flood itself was decoded, so the
> specific procedure codes replayed are not known.

---
<a id="tr-n2-002"></a>
### TR-N2-002 — N2 carries NGAP and NAS with no IPsec, DTLS or anti-replay

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| N2 | **High** | Confirmed | AMF `172.18.0.14`, gNB `172.18.0.15` |

**What happened.** The entire N2 reference point is plain SCTP on port 38412 with PPID 60
(NGAP). No IPsec ESP, no DTLS, no IKE negotiation appears anywhere in any capture. Every NGAP
procedure — `InitialUEMessage`, `InitialContextSetup`, `PDUSessionResourceSetup`,
`UplinkNASTransport`, `DownlinkNASTransport`, `UEContextRelease` — was decoded straight from the
wire by a dependency-free parser written for this analysis, with no keys and no prior knowledge.

**Why this is a threat.** TS 33.501 §9.2 requires IPsec ESP with confidentiality, integrity and
replay protection on N2 unless the interface is physically protected. Without it the control
plane is readable by anyone with a capture position (TR-OPS-001, TR-VIRT-004) and — more
seriously — *writable*, because there is nothing to distinguish a replayed or forged NGAP PDU
from a genuine one. This is the enabling weakness for TR-N2-001: the replay flood works precisely
because there is no replay protection. *High* on its own (disclosure plus a missing control) and
*Critical* in combination, which is where TR-N2-001 sits. *Confirmed* by direct decode.

**Evidence.**

- `module1.pcap` frames **77556–78250** — a complete registration decoded in clear:
  ```
  #77556 172.18.0.15 -> 172.18.0.14  SCTP 56645>38412 [NGAP]
         ngap_pdu=initiatingMessage ngap_proc=InitialUEMessage sctp_ppid=60
  #78245 172.18.0.14 -> 172.18.0.15  ngap_proc=InitialContextSetup   (initiatingMessage)
  #78249 172.18.0.15 -> 172.18.0.14  ngap_proc=InitialContextSetup   (successfulOutcome)
  ```
  PPID 60 is NGAP carried directly over SCTP. Under IPsec transport mode there would be an ESP
  header and no readable PPID at all.

- Derived, all captures — SCTP chunk and PPID census: every SCTP DATA chunk observed across the
  corpus carries PPID 60. Zero ESP (IP protocol 50), zero AH (51), zero IKE (UDP/500 or 4500).

- `bash_history_v1:110-114` — the operator confirming the plaintext association:
  ```
  sudo tshark -i any -Y "sctp" -T fields -e sctp.srcport -e sctp.dstport -e sctp.chunk_type
  sudo tshark -i any -f "sctp port 38412" -c 20
  ```

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT1600.502](https://fight.mitre.org/techniques/FGT1600.502) | Weaken Encryption: Network Interfaces | The N2 interface operates with encryption absent, enabling eavesdropping on signalling. |
| FiGHT | [FGT5009.002](https://fight.mitre.org/techniques/FGT5009.002) | Weaken Integrity: Network Interfaces | No integrity protection on N2 permits transmitted-data manipulation and replay. |
| FiGHT | [FGT1557.503](https://fight.mitre.org/techniques/FGT1557.503) | Adversary-in-the-Middle: Non-SBI | An attacker on the shared segment can position between gNB and AMF on a non-SBI interface. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Control-plane signalling is captured and decoded without any key material. |

**Impact.** Full visibility of every UE's mobility and session signalling; the ability to inject,
replay or modify NGAP; and the loss of any cryptographic basis for trusting that a message came
from the gNB it claims to. Every N2-dependent finding in this catalogue inherits from this one.

**Detection.** Assert the *presence* of the control rather than the absence of attacks: alert if
any NGAP PDU is observable in cleartext on a monitoring tap, and alert if an SCTP association to
38412 is established without a preceding IKE exchange from the same peer.

**Mitigation.** Deploy IPsec ESP in transport mode on N2 with IKEv2 and certificate-based peer
authentication, per TS 33.501 §9.2. Where a vendor cannot support it, terminate N2 on a security
gateway. Do not rely on "the RAN is a trusted network" — in this deployment the RAN shares an L2
segment with the subscriber database.

**References.** 3GPP TS 33.501 §9.2, §9.1.2; 3GPP TS 38.412 (NGAP transport); RFC 4960.

---
## N3 — GTP-U user plane

<a id="tr-n3-001"></a>
### TR-N3-001 — GTP-U tunnel endpoint identifiers enumerated from the capture position

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| N3 | **High** | Confirmed | gNB `172.18.0.15`, UPF `172.18.0.12`, UE address pool `10.45.0.0/24` |

**What happened.** The operator ran targeted `tshark` filters to extract GTP-U Tunnel Endpoint
Identifiers from the N3 interface, correlating them with the inner UE IP address so that each
TEID could be attributed to a specific subscriber session. Two TEIDs were recovered this way —
`0xb925` for UE `10.45.0.2` and `0x1c77` for UE `10.45.0.3` — along with the complete inner
packet contents of the tunnelled traffic.

**Why this is a threat.** The TEID is the only thing identifying a GTP-U tunnel. GTP-U carries no
authentication and no integrity protection, so a party who knows a valid TEID and can reach the
UPF on UDP/2152 can inject traffic into that subscriber's bearer, or extract from it. Discovering
the TEID is therefore the whole of the precondition. Here it required no attack at all — the
tunnels are in the clear on a segment shared with everything else (TR-VIRT-004), and the inner
IP, inner protocol and inner payload are equally readable. *High* — this is a precondition for
user-plane hijack and a direct privacy breach in its own right, since the inner traffic reveals
what each subscriber is doing. *Confirmed* — both the enumeration commands and the decoded TEIDs
with their inner payloads are present.

**Evidence.**

- `bash_history_v1:98-104` — TEID extraction, explicitly keyed to a subscriber IP:
  ```
  sudo tshark -i any -Y "gtp" -T fields -e ip.src -e ip.dst -e gtp.teid -e icmp.type
  sudo tshark -i any -Y "gtp && icmp && ip.addr==10.45.0.3" -T fields -e gtp.teid
  sudo tshark -i any -f "udp port 2152" -c 40
  ```

- `module1.pcap` frames **100009–100010** — the tunnel decoded end to end, no keys required:
  ```
  #100009 +2149.044675 172.18.0.15 -> 172.18.0.12 UDP 2152>2152 [GTP-U]
          gtp_msg=G-PDU  gtp_teid=0xb925
          in.src=10.45.0.2  in.dst=8.8.8.8  in.icmp_name=EchoRequest  in.icmp_seq=1
  ```
  The outer header, the TEID, the inner source and destination and the inner ICMP sequence are
  all readable.

- Derived, `module1.pcap` — TEID census: `0xb925` ×222, `0x1c77` ×130, `0x0` ×352. Inner flows:
  `10.45.0.2 → 8.8.8.8/EchoRequest` ×222 and `10.45.0.3 → 8.8.8.8/EchoRequest` ×130. Two
  subscriber bearers fully attributed.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT5031](https://fight.mitre.org/techniques/FGT5031) | Discover Tunnel Endpoint ID (TEID) | The technique is precisely "discover a valid GTP-U TEID in order to apply additional techniques". |
| FiGHT | [FGT1040.502](https://fight.mitre.org/techniques/FGT1040.502) | Network Sniffing: Eavesdrop On U Plane Data | Inner user-plane payloads are recovered from the tunnel. |
| FiGHT | [FGT1572.501](https://fight.mitre.org/techniques/FGT1572.501) | Protocol Tunneling: UE Access Via GTP-U | Knowledge of the TEID is what enables an illicit session with the target UE. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Tunnel identifiers and payloads captured passively. |
| ATT&CK | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | UDP/2152 enumerated to locate the user-plane service. |

**Impact.** With a valid TEID an adversary can inject packets that the UPF will forward as if
they came from the subscriber, or redirect the subscriber's traffic. Combined with TR-VIRT-004
(no segmentation) the reachability precondition is already satisfied. Separately, the inner
payloads disclose subscriber activity directly.

**Detection.** Alert on GTP-U arriving at the UPF from a source that is not a provisioned gNB.
Alert on a TEID appearing from two different source addresses. Baseline the TEID set per gNB and
alert on unknown values — in this deployment only two TEIDs were ever legitimately in use.

**Mitigation.** Enforce IPsec on N3 per TS 33.501 §9.3. Allocate TEIDs from a cryptographically
random 32-bit space rather than sequentially. Bind each TEID to its peer address at the UPF and
drop packets whose source does not match the F-TEID recorded at session establishment.

**References.** 3GPP TS 33.501 §9.3; 3GPP TS 29.281 (GTP-U).

---
<a id="tr-n3-002"></a>
### TR-N3-002 — User-plane desynchronisation: every G-PDU answered with Error Indication

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| N3 | **High** | Confirmed | gNB `172.18.0.15`, UPF `172.18.0.12`, SMF `172.18.0.9` |

**What happened.** In module1 the gNB sends 352 GTP-U `G-PDU` packets on TEID `0xb925` and
`0x1c77`, and the UPF answers **every single one** with a GTP-U `Error Indication` carrying
TEID `0x0` — a 352:352, one-for-one failure rate. The gNB believes it holds a valid bearer; the
UPF has no matching forwarding state for it. The subscriber's traffic (ICMP echo to `8.8.8.8`
sourced from `10.45.0.2`) never leaves the core.

**Why this is a threat.** A GTP-U Error Indication means the receiving node has no PDR matching
the TEID — the N4 session that should have installed it is gone, while the N2/radio bearer is
still up. That is exactly the end state an attacker aims for with a PFCP session deletion or
hijack (TR-N4-002): the user plane is silently dead while the control plane still believes the
session is alive, so no alarm fires and the subscriber simply has no service. Here the cause was
a teardown/rebuild race rather than an attack, which makes it *more* useful as evidence — it
shows the signature that a real PFCP attack produces, and demonstrates that the deployment
generates it without anyone noticing. The 100% Error Indication rate also confirms the UPF
performs no fallback and no state-recovery signalling. *High* — a per-subscriber denial of
service that is invisible to control-plane monitoring. *Confirmed* — the 1:1 ratio is measured
directly.

**Evidence.**

- `module1.pcap` frames **100009–100013**, the pattern repeating 352 times:
  ```
  #100009 172.18.0.15 -> 172.18.0.12  [GTP-U] gtp_msg=G-PDU  gtp_teid=0xb925
                                      in.src=10.45.0.2 in.dst=8.8.8.8 EchoRequest seq=1
  #100012 172.18.0.12 -> 172.18.0.15  [GTP-U] gtp_msg=ErrorIndication  gtp_teid=0x0
  #100069 ... G-PDU teid=0xb925 seq=2
  #100071 ... ErrorIndication teid=0x0
  ```

- Derived, `module1.pcap` — GTP-U message census: `G-PDU` **352**, `ErrorIndication` **352**.
  A perfect 1:1 ratio; no G-PDU is ever forwarded successfully.

- `module1.pcap` PFCP trace, frames **2019–2023** — the N4 sessions being deleted shortly before:
  ```
  #2019 172.18.0.9 -> 172.18.0.12  SessionDeletionRequest   seid=0x5f2
  #2022 172.18.0.12 -> 172.18.0.9  SessionDeletionResponse  seid=0x9d1
  #2326 172.18.0.9 -> 172.18.0.12  SessionDeletionRequest   seid=0x3ea
  ```
  Session state removed on N4 while the radio bearer survives on N2 — the desynchronisation.

- `bash_history_v1:96` — the operator observing the symptom:
  `ping -I uesimtun0 -c 5 8.8.8.8` returning nothing.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT5021](https://fight.mitre.org/techniques/FGT5021) | Tunnel ID Uniqueness Failure | User traffic is disrupted because the TEID in use no longer maps to valid forwarding state. |
| FiGHT | [FGT1499.503](https://fight.mitre.org/techniques/FGT1499.503) | Endpoint DoS: DOS A UE Via gNB Or NF Signaling | Control-plane signalling leaves one or more UEs without service. |
| FiGHT | [FGT1499.504](https://fight.mitre.org/techniques/FGT1499.504) | Endpoint DoS: DOS A UE Via Established GTP-U Tunnel | The established tunnel is the vector through which service is lost. |
| ATT&CK | [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | Service availability for specific endpoints is removed. |

**Impact.** Total loss of data service for the affected subscribers with no control-plane alarm.
Deliberately induced via N4 (TR-N4-002), this is a targeted, stealthy per-subscriber denial of
service — the AMF still reports the UE as registered.

**Detection.** This is one of the highest-value detections in the whole dataset and it is cheap:
**alert on any sustained GTP-U Error Indication rate at the UPF.** A healthy user plane produces
approximately zero. Here the ratio was 1:1 for 352 consecutive packets and nothing fired. Also
reconcile N4 session count against N2 PDU-session count and alert on divergence.

**Mitigation.** Have the UPF signal PFCP Session Report on repeated Error Indication so the SMF
can tear down or re-establish the bearer. Make N2 and N4 session lifecycles transactional, so a
deleted N4 session forces a corresponding release on N2. Monitor the Error Indication counter as
a first-class KPI.

**References.** 3GPP TS 29.281 §7.3.1 (Error Indication); 3GPP TS 29.244 §7.4.4.

---
## N4 — PFCP session management

<a id="tr-n4-001"></a>
### TR-N4-001 — PFCP session management unauthenticated and unencrypted on N4

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| N4 | **Critical** | Confirmed | SMF `172.18.0.9`, UPF `172.18.0.12` |

**What happened.** The N4 reference point runs as plain UDP on port 8805 with no IPsec, no DTLS
and no PFCP-level authentication. Every session-management message was decoded directly from the
capture: `SessionEstablishmentRequest`/`Response`, `SessionModificationRequest`/`Response`,
`SessionDeletionRequest`/`Response` and continuous `HeartbeatRequest`/`Response`, each with its
SEID visible. Across the corpus 22,588 PFCP packets were observed and every one was readable.

**Why this is a threat.** PFCP has no built-in security whatsoever — TS 29.244 delegates
protection entirely to the transport, and TS 33.501 §9.9 requires IPsec on N4 for exactly this
reason. Without it, anything that can send a UDP datagram to the UPF on 8805 can issue session
management commands, and the UPF has no way to tell the real SMF from a forgery: there is no
shared secret, no sequence validation that survives a spoofed source, and no association-level
authentication. Combined with predictable SEIDs (TR-N4-002) this is a complete session hijack
primitive, and combined with the flat L2 segment (TR-VIRT-004) the reachability precondition is
already met from any container on the bridge. *Critical* — an attacker can delete, redirect or
duplicate any subscriber's user plane. *Confirmed* — full decode of every message type with no
key material.

**Evidence.**

- `module1.pcap` frames **3675–4056** — the session lifecycle in clear:
  ```
  #3675 172.18.0.9  -> 172.18.0.12  SessionEstablishmentRequest   seid=0x0
  #3679 172.18.0.12 -> 172.18.0.9   SessionEstablishmentResponse  seid=0x7b6
  #3865 172.18.0.9  -> 172.18.0.12  SessionModificationRequest    seid=0x386
  #3869 172.18.0.12 -> 172.18.0.9   SessionModificationResponse   seid=0x7b6
  #2019 172.18.0.9  -> 172.18.0.12  SessionDeletionRequest        seid=0x5f2
  ```

- Derived, all captures — PFCP totals per module: module0 1,816; module1 2,180; module2 5,456;
  module4 480; module5 312; module6 4,776. All on UDP/8805, all plaintext. Zero ESP, zero DTLS
  handshakes anywhere in the corpus.

- `bash_history_v1:117-121` — the operator confirming the interface is exposed and unprotected:
  ```
  sudo tshark -i any -f "udp port 8805" -c 20
  sudo tshark -i any -Y "pfcp" -T fields -e ip.src -e ip.dst -e pfcp.msg_type
  ```

- `bash_history_v2:102,105,123` — enumerating what is listening on N4 from inside a container:
  ```
  ss -lunp | grep 8805
  ```

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT1600.502](https://fight.mitre.org/techniques/FGT1600.502) | Weaken Encryption: Network Interfaces | N4 operates with encryption absent on a non-SBI interface. |
| FiGHT | [FGT5009.002](https://fight.mitre.org/techniques/FGT5009.002) | Weaken Integrity: Network Interfaces | No integrity protection on N4 permits forged session-management messages. |
| FiGHT | [FGT1557.503](https://fight.mitre.org/techniques/FGT1557.503) | Adversary-in-the-Middle: Non-SBI | An attacker on the shared segment can interpose between SMF and UPF. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Session-management signalling captured and decoded without keys. |
| ATT&CK | [T1565.002](https://attack.mitre.org/techniques/T1565/002/) | Data Manipulation: Transmitted Data Manipulation | Absence of integrity protection is what makes in-flight manipulation possible. |

**Impact.** Unauthorised creation, modification or deletion of any PDU session; redirection of a
subscriber's user plane to an attacker-controlled endpoint by rewriting the outer F-TEID;
silent per-subscriber denial of service that presents exactly as TR-N3-002.

**Detection.** Alert on PFCP from any source other than the provisioned SMF address. Alert on
session-management messages that do not correlate with a preceding SBI `Nsmf_PDUSession`
transaction. Track the SEID population and alert on references to SEIDs the UPF never issued.

**Mitigation.** Enforce IPsec ESP on N4 per TS 33.501 §9.9. Bind the PFCP association to an
authenticated peer identity and reject messages from unassociated sources. Place N4 on a
dedicated segment unreachable from workload containers.

**References.** 3GPP TS 33.501 §9.9; 3GPP TS 29.244 (PFCP).

---
<a id="tr-n4-002"></a>
### TR-N4-002 — PFCP session identifiers occupy 12 bits of a 64-bit space

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| N4 | **Critical** | Confirmed | SMF `172.18.0.9`, UPF `172.18.0.12`, all PDU sessions |

**What happened.** Every PFCP Session Endpoint Identifier observed across the whole corpus was
collected and measured. There are 26 distinct SEIDs and the largest is **`0xf45`** (3,909
decimal). The specification allocates 64 bits to the SEID; this deployment uses **12**. The
values are also small and clustered rather than sparse — `0xa`, `0x9b`, `0x32a`, `0x386`,
`0x3ea`, `0x55d`, `0x5f2`, `0x7b6`, `0x7bf`, `0x9d1`, `0x9f4`, `0x9f7`, `0xa15`, `0xf15`,
`0xf45` — consistent with a small sequential or low-entropy allocator.

**Why this is a threat.** The SEID is the *only* thing that identifies a PFCP session, and N4 has
no authentication to fall back on (TR-N4-001). The security of every PDU session therefore rests
entirely on an attacker being unable to guess the SEID. At 64 bits that assumption is sound;At 64 bits that assumption is sound; at 12 bits the whole keyspace is **4,096 values**, which one
host enumerates in under a second. The attack is not cryptographic, it is a `for` loop.

That collapses the cost of a session hijack from infeasible to trivial. An attacker on the bridge
sends 4,096 `SessionDeletionRequest` messages — one per candidate SEID — and every active PDU
session on that UPF is torn down. The observable result is exactly the signature already present
in TR-N3-002: G-PDU met with Error Indication, silently, with no control-plane alarm. A
`SessionModificationRequest` instead of a deletion redirects the subscriber's traffic rather than
dropping it. *Critical* — one unauthenticated host can deterministically drop or redirect every
subscriber session on a UPF. *Confirmed* — the bit width is measured, not estimated.

**Evidence.**

- Derived, all captures — SEID census:
  ```
  module0.pcap   4 distinct SEIDs   min=0x32a  max=0xf45
  module1.pcap  22 distinct SEIDs   min=0xa    max=0xf15
  ------------------------------------------------------------
  corpus        26 distinct SEIDs   max=0xf45  -> 12 bits of 64
  effective search space 2^12 = 4,096  (not 2^64 = 1.8e19)
  ```
  Reproduce with: `python3 tools/analyse_pcap.py --all` then read `pfcp_top_seids`.

- `module1.pcap` frames **3675–3684** — establishment responses allocating small adjacent values:
  ```
  #3679 172.18.0.12 -> 172.18.0.9  SessionEstablishmentResponse  seid=0x7b6
  #3683 172.18.0.12 -> 172.18.0.9  SessionEstablishmentResponse  seid=0x55d
  #4011 172.18.0.12 -> 172.18.0.9  SessionEstablishmentResponse  seid=0x9f7
  ```

- `bash_history_v2:116` — the operator inspecting exactly this property in the exploit script:
  ```
  cat pfcpExploit.py | grep -i seid
  ```

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT5021](https://fight.mitre.org/techniques/FGT5021) | Tunnel ID Uniqueness Failure | Guessable session identifiers let an attacker collide with or displace live forwarding state. |
| FiGHT | [FGT1498.503](https://fight.mitre.org/techniques/FGT1498.503) | Network DoS: Malicious Packets To Network Functions | Crafted PFCP sent to the UPF to disrupt sessions. |
| FiGHT | [FGT1499.503](https://fight.mitre.org/techniques/FGT1499.503) | Endpoint DoS: DOS A UE Via gNB Or NF Signaling | The result is targeted loss of service for specific UEs. |
| ATT&CK | [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | Session state is exhausted or destroyed. |
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | A 4,096-value identifier space is enumerated exhaustively. |
| ATT&CK | [T1565](https://attack.mitre.org/techniques/T1565/) | Data Manipulation | Session Modification rewrites forwarding rules for a subscriber. |

**Impact.** Mass teardown of every PDU session on a UPF from a single unauthenticated host, or
targeted redirection of an individual subscriber's user plane to an attacker-chosen endpoint.
Neither leaves a control-plane alarm; the symptom presents as TR-N3-002.

**Detection.** Alert on PFCP request rate to the UPF above a low threshold — a brute-force sweep
is thousands of messages in seconds against a normal rate of a handful per session event. Alert
on `SessionDeletionRequest` or `SessionModificationRequest` referencing a SEID the UPF never
issued, and on any PFCP cause value indicating "Session context not found" occurring repeatedly.
Reconcile the UPF's session count against the SMF's continuously.

**Mitigation.** Allocate SEIDs from the full 64-bit space using a CSPRNG — this is the single
highest-value fix in this catalogue relative to effort. Enforce IPsec on N4 (TR-N4-001) so
guessing the SEID is not sufficient. Rate-limit PFCP per source. Reject session-management
messages whose source address is not the associated SMF.

**References.** 3GPP TS 29.244 §7.2.2.4.2 (SEID); 3GPP TS 33.501 §9.9.

---
<a id="tr-n4-003"></a>
### TR-N4-003 — PFCP exploitation tooling staged and targeted inside the core

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| N4 | **High** | Probable | SMF `172.18.0.9`, UPF `172.18.0.12`, gNB, container host |

**What happened.** A purpose-built script named `pfcpExploit.py` was searched for across every
container on the host, inspected for its handling of SEIDs, and invoked with arguments naming the
gNB address and a "FUUP" (forward user-plane) IP. In the same window the operator enumerated what
was listening on the N4 port from inside a container and ran an ARP sweep of the local segment.
The script itself is never recovered in the captured filesystem output.

**Why this is a threat.** The invocation signature is unambiguous: a tool that takes a gNB
address and a user-plane redirection target, and whose SEID handling the operator felt the need
to inspect, is a PFCP session-hijack tool. Its two preconditions are both satisfied in this
deployment — N4 is unauthenticated (TR-N4-001) and SEIDs are 12 bits (TR-N4-002). This entry
records the *capability being staged and aimed*, which is the point at which a defender can still
act.

*Probable, not Confirmed*, and the reason matters: module6's PFCP traffic contains **only**
SMF-to-UPF heartbeats — 2,388 packets each way, zero session-management messages and zero GTP-U.
So within the captured window the exploit either did not fire, or fired outside it, or failed.
The capability is confirmed; the effect is not. Severity stays *High* because the capability plus
the two confirmed preconditions is the whole attack.

**Evidence.**

- `bash_history_v2:116` — inspecting how the tool handles session identifiers:
  ```
  cat pfcpExploit.py | grep -i seid
  ```

- `bash_history_v2:126` — the invocation, naming a gNB and a user-plane redirection target:
  ```
  python3 pfcpExploit.py --nbg-ip <nbg-ip> --fuupip <fuupip>
  ```
  followed immediately at line 127 by `ping -I uesimtun0 8.8.8.8` — a user-plane reachability
  check, i.e. testing whether the redirection took effect.

- `bash_history_v2:117-118, 128` — hunting the script across every container:
  ```
  docker exec ggpepgnoaneaus5eppm1andpa5 find / -name "pfcpExploit.py" 2>/dev/null
  for c in $(docker ps --format "{{.Names}}"); do
      echo "=== $c ==="; docker exec $c find / -name "pfcpExploit.py" 2>/dev/null; done
  ```

- `bash_history_v2:102,105,123-124` — mapping the N4 attack surface first:
  ```
  sudo ss -lunp | grep 8805
  docker exec mns1aifs1r5erp5drg1noou5mi ss -lunp | grep 8805
  docker exec mns1aifs1r5erp5drg1noou5mi tcpdump -i any udp port 8805
  ```

- Derived, `module6.pcap` — the negative result that caps confidence at Probable:
  ```
  172.18.0.9  -> 172.18.0.12  UDP 8805  PFCP  2,388 packets   (heartbeats only)
  172.18.0.12 -> 172.18.0.9   UDP 8805  PFCP  2,388 packets   (heartbeats only)
  GTP-U packets in module6: 0
  ```
  No session-management message of any kind in a 1 h 50 m capture.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | A purpose-built exploit script is acquired and staged on the target host. |
| ATT&CK | [T1608](https://attack.mitre.org/techniques/T1608/) | Stage Capabilities | The script is placed and located across containers before use. |
| ATT&CK | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | `ss -lunp | grep 8805` enumerates the N4 listener before targeting it. |
| FiGHT | [FGT1587.004](https://fight.mitre.org/techniques/FGT1587.004) | Develop Capabilities: Exploits | A 5G-specific exploit is developed or adapted for the N4 interface. |
| FiGHT | [FGT1498.503](https://fight.mitre.org/techniques/FGT1498.503) | Network DoS: Malicious Packets To Network Functions | The tool's purpose is to send crafted PFCP to the UPF. |

**Impact.** If executed successfully against this deployment the tool inherits TR-N4-001 and
TR-N4-002 and can redirect or destroy arbitrary PDU sessions. The staging activity alone
indicates an adversary that has already mapped N4 and is one step from that outcome.

**Detection.** The reconnaissance is the detectable phase and it is noisy: `docker exec ... find
/ -name "pfcpExploit.py"` across every container, repeated `ss -lunp | grep 8805`, and a
container spawning `tcpdump` on udp/8805. Alert on any container executing a packet-capture tool,
and on cluster-wide `find` sweeps.

**Mitigation.** As TR-N4-001 and TR-N4-002. Additionally: prevent `docker exec` into production
network-function containers from non-privileged operator accounts, and remove interactive shells
and packet-capture binaries from NF images.

**References.** 3GPP TS 29.244; 3GPP TS 33.501 §9.9.

---
## SUB — Subscriber identity and credential privacy

<a id="tr-sub-001"></a>
### TR-SUB-001 — Long-term SIM keys recoverable in cleartext, shared across all subscribers

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| SUB | **Critical** | Confirmed | MongoDB `172.18.0.2`, UDR `172.18.0.4`, AUSF `172.18.0.6`, all six subscriber records |

**What happened.** The permanent subscriber key **K** and the operator variant **OPc** are
recoverable in two independent ways. First, the subscriber database returns them verbatim in a
query response (TR-DB-001). Second, the UDR hands them to the AUSF over the service-based
interface as plain JSON in an authentication-vector response. Both are readable with no keys and
no decryption. Worse, **all six provisioned subscribers share the same K and the same OPc**.

**Why this is a threat.** K is the root of the entire 5G security architecture. Every session
key — K_AUSF, K_SEAF, K_AMF, K_gNB, and from there every NAS and AS key — is derived from it.
Disclosure of K is not a partial compromise; it is total, retroactive and prospective. An
attacker holding K and OPc can impersonate the subscriber (TR-RAN-001), derive the keys for any
captured session and decrypt it offline, and compute valid authentication responses without ever
contacting the home network. K cannot be rotated remotely: remediation means replacing physical
SIMs.

The JSON field names `encPermanentKey` and `encOpcKey` imply the values are encrypted at rest in
the UDR, but what crosses the wire is the usable value in a cleartext HTTP/2 body — the naming
gives false assurance. The shared-key condition compounds it: one compromised credential
compromises the entire subscriber base, and no per-subscriber isolation exists.

*Critical* on every axis. *Confirmed* — the same values appear in a database response, in an SBI
payload and in a command line, independently.

**Evidence.**

- `module5.pcap` frame **5243** (`172.18.0.2:27017 -> 172.18.0.15:41984`, 1,260 B) — the database
  response: six subscriber records, one shared key pair.
  ```
  cursor.firstBatch:
   0: imsi 999702813335208  session.name "internet"
      security: k 716443940B35EC8A7EDA57F98A9A70E6  opc A14B42703DEBABBE206D7597D93D65FA
   1: imsi 999704314796334  security: k 7164...70E6  opc A14B...65FA
   2: imsi 999705145365381  security: k 7164...70E6  opc A14B...65FA
   3: imsi 999709275422922  security: k 7164...70E6  opc A14B...65FA
   4: imsi 999707253793452  security: k 7164...70E6  opc A14B...65FA
   5: imsi 999702047615749  security: k 7164...70E6  opc A14B...65FA
   ns: "open5gs.subscribers"
  ```
  Reproduce: `python3 tools/dump_frame.py ../exercises_logs_anonymised/captures/module5.pcap 5243 --ascii`

- `module1.pcap`, `172.18.0.4 -> 172.18.0.10:7777` (UDR to SCP, cleartext HTTP/2 body) — the same
  key material crossing the service-based interface as an authentication vector, observed 20+
  times with different SQN values:
  ```json
  {"authenticationMethod":"5G_AKA",
   "encPermanentKey":"9dad38dfd5c81009342d3a992ef7af48",
   "sequenceNumber":{"sqn":"0000000000e1"},
   "authenticationManagementField":"8000",
   "encOpcKey":"c9705d1d58b33cb21f4d709507cd78dd"}
  ```
  Despite the `enc` prefixes these are the usable values, in a plaintext body, on a plaintext
  connection.

- `bash_history_v1:43` — the same K/OPc pair reused to stand up a rogue UE (TR-RAN-001),
  demonstrating the credentials are directly actionable:
  ```
  -e KEY=716443940B35EC8A7EDA57F98A9A70E6 -e OP_TYPE=OPC \
  -e OP=A14B42703DEBABBE206D7597D93D65FA
  ```

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT1195.501](https://fight.mitre.org/techniques/FGT1195.501) | Supply Chain Compromise: SIM Credentials Theft | Bulk SIM credentials obtained by compromising the SIM data repository. |
| FiGHT | [FGT5026](https://fight.mitre.org/techniques/FGT5026) | SIM Cloning | Possession of (SUPI, K, OPc) is precisely what enables cloning. |
| FiGHT | [FGT5020](https://fight.mitre.org/techniques/FGT5020) | Retrieve UE Subscription Data | Subscription records including security material are retrieved wholesale. |
| FiGHT | [FGT1600.502](https://fight.mitre.org/techniques/FGT1600.502) | Weaken Encryption: Network Interfaces | Key material crosses SBI unencrypted, so sniffing suffices. |
| ATT&CK | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Long-term secrets stored and transmitted in recoverable form. |
| ATT&CK | [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | The subscriber repository is mined for credential material. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | The same secrets are obtainable passively from SBI traffic. |

**Impact.** Complete and permanent compromise of subscriber authentication. Offline decryption
of any captured session for those subscribers, past or future. Undetectable impersonation. With
a shared key across the population, one disclosure compromises every subscriber. Recovery
requires physical SIM replacement for the entire base.

**Detection.** Alert on any query to the `subscribers` collection that projects the `security`
sub-document, and on any client other than the UDR connecting to the subscriber database. At the
network layer, alert on `encPermanentKey` or `encOpcKey` appearing in a plaintext payload — in a
correctly configured deployment that string should never be observable.

**Mitigation.** Store K in an HSM or a SIDF/credential vault and expose only a
*compute-authentication-vector* operation, never the key. Never return `security.k` or
`security.opc` from an application query. Enforce TLS on all SBI hops (TR-SUB-003). Use a unique
K per subscriber — the shared key here removes any containment. Encrypt the subscriber database
at rest with per-field keys the application cannot export in bulk.

**References.** 3GPP TS 33.501 §5.2.4, §6.1; 3GPP TS 33.102 Annex; GSMA FS.31; GSMA SAS-SM.

---
<a id="tr-sub-002"></a>
### TR-SUB-002 — SUCI null-scheme leaves the permanent subscriber identity unprotected

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| SUB | **High** | Confirmed | UE, AMF `172.18.0.14`, AUSF `172.18.0.6`, all subscribers |

**What happened.** Every SUCI observed in the captures uses **protection scheme 0** — the null
scheme. The SUCI format is
`suci-<supi type>-<mcc>-<mnc>-<routing indicator>-<protection scheme>-<HN key id>-<scheme output>`,
and in every instance the sixth field is `0`, which means the "scheme output" is the MSIN in
plaintext rather than an ECIES ciphertext:

```
suci-0-999-70-0000-0-0-0000000001
suci-0-999-70-0000-0-0-0000000002
suci-0-999-70-0000-0-0-0000000003
                 ^     ^
                 |     └── home network public key id = 0 (none)
                 └──────── protection scheme = 0 (null scheme)
```

**Why this is a threat.** The SUCI exists for exactly one purpose: to stop the permanent
identity appearing on the air interface, closing the IMSI-catcher attack that plagued 2G–4G. The
null scheme disables that protection entirely. With it, a passive receiver — or in this
deployment anyone with a capture position on the shared segment — recovers the SUPI from the
initial registration of every UE, before any security context exists. Concatenated with MCC/MNC
the value *is* the IMSI. *High* — permanent, unlinkable-by-design identity disclosure enabling
long-term tracking, targeted attack and correlation across sessions and locations; it is not
Critical only because it discloses identity rather than credentials. *Confirmed* — the scheme
field is read directly from the SUCI string.

**Evidence.**

- `module1.pcap`, `172.18.0.14 -> 172.18.0.10:7777` (AMF to AUSF via SCP), Nausf_UEAuthentication
  request bodies:
  ```json
  {"supiOrSuci":"suci-0-999-70-0000-0-0-0000000003",
   "servingNetworkName":"5G:MNC001.MCC596.3gppnetwork.org"}
  {"supiOrSuci":"suci-0-999-70-0000-0-0-0000000002", ...}
  {"supiOrSuci":"suci-0-999-70-0000-0-0-0000000001", ...}
  ```
  Reproduce: `python3 tools/strings_pcap.py ../exercises_logs_anonymised/captures/module1.pcap --grep 'suci-' --min 8`

- `module0.pcap` frames **77829, 77857** — the same null-scheme SUCI relayed AMF → SCP → AUSF,
  i.e. the unprotected identity traverses three network functions in the clear.

- Derived, all captures — zero SUCIs use protection scheme 1 (ECIES Profile A) or 2 (Profile B).
  The home-network public key identifier is `0` throughout, confirming no SIDF key is provisioned.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT5019.004](https://fight.mitre.org/techniques/FGT5019.004) | Subscriber Profile Identifier Discovery: Intercept Unencrypted SUPI | The SUPI is readable because the SUCI is unencrypted. |
| FiGHT | [FGT5019.001](https://fight.mitre.org/techniques/FGT5019.001) | Subscriber Profile Identifier Discovery: Intercept Home Network Via SUCI | The SUCI also discloses MCC/MNC and routing indicator. |
| FiGHT | [FGT5012.004](https://fight.mitre.org/techniques/FGT5012.004) | Locate UE: Core Network Function Signaling | A permanent identifier in signalling enables location tracking over time. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Identity recovered passively from signalling. |

**Impact.** Permanent subscriber tracking: the same identifier appears at every registration, in
every cell, forever. Enables targeted follow-on attack against a named subscriber, correlation of
a subscriber's movements, and confirmation of presence in a location — the classic IMSI-catcher
capability that 5G was specifically designed to eliminate.

**Detection.** Assert the control: alert on any SUCI whose protection-scheme field is `0`
arriving at the AMF. This is a single-field check on the registration path and it is definitive.
Also alert if the same `scheme output` value recurs across registrations — under ECIES it is
freshly randomised each time, so repetition proves the null scheme even without parsing the field.

**Mitigation.** Provision a home-network public key and mandate ECIES Profile A or B, rejecting
null-scheme SUCI at the AMF except for unauthenticated emergency calls as TS 33.501 §6.12.2
permits. Verify that USIM personalisation includes the SIDF key — the null scheme is usually a
provisioning omission rather than a deliberate choice.

**References.** 3GPP TS 33.501 §6.12 and Annex C (SUCI, ECIES profiles); 3GPP TS 23.003 §2.2B.

---
<a id="tr-sub-003"></a>
### TR-SUB-003 — SUPI and IMEISV traverse the service-based interface in cleartext

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| SUB | **High** | Confirmed | All SBI network functions, SCP `172.18.0.10`, NRF `172.18.0.13` |

**What happened.** The entire service-based interface runs as cleartext HTTP/2 (`h2c`) on
TCP/7777. No TLS handshake occurs anywhere in the corpus. Every inter-NF JSON body is readable,
and those bodies carry permanent subscriber identifiers in the clear — the SUPI as
`imsi-<15 digits>` embedded in resource URIs and callback references, and the device identity as
`pei: imeisv-<16 digits>`.

**Why this is a threat.** TS 33.501 §13.1 requires TLS on all SBI interfaces unless the
interfaces are within a physically protected domain; the same clause requires OAuth 2.0
authorisation between NFs. Neither is present. The consequence is that the SBI — which carries
*more* subscriber context than the radio interface ever does — is fully exposed to any party with
a capture position, which in this deployment is any workload on the bridge (TR-VIRT-004).
Embedding the SUPI in URIs is particularly damaging because URIs propagate: they end up in
callback references passed between NFs, and in access logs, proxies and traces where the
subscriber identity was never meant to travel. *High* — permanent identity plus device identity
plus full session context, for every subscriber, continuously. *Confirmed* by direct payload
extraction.

**Evidence.**

- `module1.pcap`, `172.18.0.7 -> 172.18.0.10:7777` (UDM, Nudm_UECM registration) — SUPI and
  device identity together:
  ```json
  {"amfInstanceId":"e44528d2-9746-41f1-bb50-936d1b93cf87",
   "pei":"imeisv-4370816141361512",
   "deregCallbackUri":"http://172.18.0.14:7777/namf-callback/v1/imsi-999704314796334/dereg-notify",
   "initialRegistrationInd":true,
   "guami":{"plmnId":{"mcc":"999","mnc":"70"},"amfId":"020040"},"ratType":"NR"}
  ```
  Note the scheme is `http://`, not `https://` — the callback the UDM is told to use is itself
  cleartext.

- `module1.pcap`, `172.18.0.9 -> 172.18.0.10:7777` (SMF, Nudm_SDM subscribe) — SUPI in both the
  callback URI and the monitored-resource list:
  ```json
  {"nfInstanceId":"e4266780-9746-41f1-b2f8-d7543eb0bbe1","implicitUnsubscribe":true,
   "callbackReference":"http://172.18.0.9:7777/nsmf-callback/v1/sdmsubscription-notify/imsi-999704314796334",
   "monitoredResourceUris":["imsi-999704314796334/sm-data"],
   "singleNssai":{"sst":1},"dnn":"internet","plmnId":{"mcc":"999","mnc":"70"}}
  ```

- Three distinct IMEISVs recovered across the corpus: `4370816141361512`, `4370816144617407`,
  `4370816162227071`, each bound to a named IMSI.

- Derived, all captures — TLS census on TCP/7777: zero ClientHello, zero ServerHello, zero
  certificates. Every SBI byte is `h2c` cleartext. No OAuth 2.0 `Authorization: Bearer` header or
  token-endpoint exchange appears anywhere.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT1600.502](https://fight.mitre.org/techniques/FGT1600.502) | Weaken Encryption: Network Interfaces | SBI operates with TLS absent, enabling eavesdropping on signalling. |
| FiGHT | [FGT5019.003](https://fight.mitre.org/techniques/FGT5019.003) | Subscriber Profile Identifier Discovery: Obtain Subscriber Identifier Via NF | SUPI is obtained from network-function signalling. |
| FiGHT | [FGT1557.504](https://fight.mitre.org/techniques/FGT1557.504) | Adversary-in-the-Middle: Service Based Interface | An attacker between NFs on the SBI can sniff or modify. |
| FiGHT | [FGT5003](https://fight.mitre.org/techniques/FGT5003) | Network Function Service Discovery | Unprotected NRF/SCP traffic reveals every NF, its services and its instance IDs. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Identity and session data captured passively. |
| ATT&CK | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Signalling rides HTTP/2 without transport protection. |

**Impact.** Continuous disclosure of who is on the network, what device they use, which slice and
DNN they consume and when they attach. Feeds subscriber tracking, targeted attack selection and
TR-SUB-004. Absent OAuth 2.0, a rogue NF that reaches the SCP can also *invoke* services, not
merely observe them.

**Detection.** Assert the control: alert on any cleartext HTTP/2 on an SBI port, and on any NF
service request lacking a validated OAuth 2.0 access token. Alert on `imsi-` appearing in a
plaintext payload — in a correct deployment the string should never be observable.

**Mitigation.** Enforce TLS 1.2+ with mutual certificate authentication on every SBI hop,
including SCP-to-NF, per TS 33.501 §13.1. Enable NRF-issued OAuth 2.0 access tokens and validate
them at every NF. Use the 5G-GUTI rather than the SUPI in resource URIs wherever the procedure
allows. Ensure `callbackReference` values are `https://`.

**References.** 3GPP TS 33.501 §13.1, §13.4 (SBI security, OAuth 2.0); 3GPP TS 29.500 §6.

---
<a id="tr-sub-004"></a>
### TR-SUB-004 — SUPI-to-IP bindings disclosed, enabling subscriber traffic attribution

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| SUB | **High** | Confirmed | PCF `172.18.0.8`, SMF `172.18.0.9`, UPF `172.18.0.12`, UE pool `10.45.0.0/24` |

**What happened.** Policy-control signalling on the SBI carries an explicit mapping from the
permanent subscriber identity to the IP address allocated to that subscriber's PDU session. The
bindings are readable in cleartext and change over time as sessions are re-established, so the
full history of which subscriber held which address, and when, is reconstructible from the
capture alone.

**Why this is a threat.** On its own an IP address is pseudonymous and a SUPI is an identity;
the binding converts every packet in the user plane into attributable subscriber activity. An
observer who has TR-SUB-003 (identities on the SBI) and TR-N3-001 (readable user-plane tunnels)
can now say not merely "someone browsed X" but "subscriber 999704314796334 browsed X at
14:32". That is the difference between traffic analysis and lawful-intercept-grade surveillance,
obtained without any lawful-intercept authorisation. The re-binding across sessions makes it
worse rather than better: it defeats the weak protection that address rotation would otherwise
provide, because the new binding is announced in the clear too. *High* — mass, continuous,
retrospective subscriber surveillance. *Confirmed* — the bindings are read directly from SBI
payloads.

**Evidence.**

- `module1.pcap`, SM policy control responses naming the PCF and binding SUPI to address:
  ```json
  {"supi":"imsi-999704314796334","ipv4Addr":"10.45.0.6","dnn":"internet",
   "pcfIpEndPoints":[{"ipv4Address":"172.18.0.8","port":7777}],
   "snssai":{"sst":1},"suppFeat":"2"}
  {"supi":"imsi-999702813335208","ipv4Addr":"10.45.0.7", ...}
  {"supi":"imsi-999705145365381","ipv4Addr":"10.45.0.8", ...}
  ```

- Derived, `module1.pcap` — the complete binding history recovered from one 47-minute capture:

  | SUPI | Addresses held over the capture |
  |---|---|
  | `imsi-999704314796334` | `10.45.0.6`, `10.45.0.10` |
  | `imsi-999702813335208` | `10.45.0.7`, `10.45.0.11`, `10.45.0.12` |
  | `imsi-999705145365381` | `10.45.0.8`, `10.45.0.9`, `10.45.0.13` |

- Cross-reference with TR-N3-001: the GTP-U inner addresses `10.45.0.2` and `10.45.0.3` carry
  ICMP to `8.8.8.8`. With the binding table above, that traffic is attributable to a named
  subscriber rather than to an anonymous address.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT5012.004](https://fight.mitre.org/techniques/FGT5012.004) | Locate UE: Core Network Function Signaling | Core signalling is exploited to associate a subscriber with an observable session. |
| FiGHT | [FGT5019.003](https://fight.mitre.org/techniques/FGT5019.003) | Subscriber Profile Identifier Discovery: Obtain Subscriber Identifier Via NF | The SUPI is obtained from NF signalling alongside the session context. |
| FiGHT | [FGT1040](https://fight.mitre.org/techniques/FGT1040) | Network Sniffing | The binding is captured passively from the SBI. |
| ATT&CK | [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | The binding table is built automatically from continuous signalling. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Parent technique for the capture itself. |

**Impact.** Every user-plane packet becomes attributable to a named subscriber. Enables
per-subscriber profiling, selective interception, and targeting of an individual's traffic for
TR-N3-001 follow-on. Combined with TR-SUB-002 the subscriber is identified permanently rather
than per-session.

**Detection.** Alert on `"supi"` co-occurring with `"ipv4Addr"` in any cleartext payload. Alert
on any consumer of Npcf/Nsmf policy services that is not a registered NF.

**Mitigation.** TLS on SBI (TR-SUB-003) removes the disclosure at source. Restrict policy-control
service access with OAuth 2.0 scopes so only the SMF may read SUPI-to-address bindings. Log and
review every bulk read of session bindings — that pattern has no legitimate operational use.

**References.** 3GPP TS 33.501 §13.1; 3GPP TS 29.512 (Npcf_SMPolicyControl).

---
## DB — Subscriber data repository

<a id="tr-db-001"></a>
### TR-DB-001 — Subscriber database accepts unauthenticated queries

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| DB | **Critical** | Confirmed | MongoDB `172.18.0.2`, UDR `172.18.0.4`, WebUI `172.18.0.5` |

**What happened.** The MongoDB instance backing the UDR accepts and answers queries with **no
authentication whatsoever**. Byte-level search across every MongoDB frame in the corpus for
`saslStart`, `saslContinue`, `SCRAM-SHA`, `authenticate` and `speculativeAuthenticate` returns
nothing: there is no authentication handshake to fail, because none is attempted and none is
required. Clients connect, issue `isMaster`, and query `open5gs.subscribers` directly. At least
four distinct clients did so across the captures, including two ephemeral containers that are not
part of the core.

**Why this is a threat.** The UDR backing store is the single most sensitive asset in a 5G core:
it holds every subscriber's identity, slice and DNN entitlements, and — in this deployment —
their long-term authentication keys in recoverable form (TR-SUB-001). Leaving it
unauthenticated means the security of the entire subscriber base rests on network reachability
alone, and the network is a flat bridge that any container can join (TR-VIRT-004). There is no
second factor, no per-collection authorisation and no audit identity: because every client is
anonymous, the database cannot even record *who* read the keys. *Critical* on confidentiality,
integrity (the same access permits writes) and forensics. *Confirmed* — the absence of the
handshake is verified by exhaustive byte search, and successful unauthenticated queries are
captured.

**Evidence.**

- Derived, `module0.pcap` + `module5.pcap` — authentication census over all MongoDB frames:
  ```
  searched tokens: saslStart, saslContinue, SCRAM-SHA, authenticate, speculativeAuthenticate
  result: NONE FOUND  ->  no authentication handshake exists on any connection
  ```
  Reproduce: `python3 tools/strings_pcap.py ../exercises_logs_anonymised/captures/module5.pcap --port 27017 --grep 'sasl|SCRAM|authenticate' --min 5`

- `module0.pcap` frames **7768-7769, 8159-8160, 8517** (`172.18.0.17 -> 172.18.0.2:27017`) — an
  ephemeral container querying subscriber collections straight after connecting:
  ```
  subscribers   security   subscriber_status   admin.$cmd   aggregate
  999702813335208   999704314796334   999705145365381   999709275422922
  ```

- `module0.pcap` frames **77903-77908** (`172.18.0.4 -> 172.18.0.2:27017`) — the UDR itself,
  equally unauthenticated:
  ```
  filter ... open5gs.subscribers ... security.sqn
  ```

- Client fingerprint from the handshake metadata, showing an interactive shell rather than an
  application:
  ```
  application: mongosh 2.4.2 | driver: nodejs|mongosh 6.14.2|2.4.2
  platform: Node.js v20.18.3, LE | container: docker
  ```

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | The subscriber repository is queried directly for its contents. |
| ATT&CK | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Valid Accounts: Default Accounts | The service runs in its unauthenticated default posture; no account is needed. |
| ATT&CK | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Credential material is retrievable without authenticating. |
| FiGHT | [FGT5020](https://fight.mitre.org/techniques/FGT5020) | Retrieve UE Subscription Data | Subscription data is retrieved wholesale from the repository. |
| FiGHT | [FGT1195.501](https://fight.mitre.org/techniques/FGT1195.501) | Supply Chain Compromise: SIM Credentials Theft | The SIM data repository is the compromised element. |
| FiGHT | [FGT5022](https://fight.mitre.org/techniques/FGT5022) | Alter Subscriber Profile | The same unauthenticated access permits writes, not only reads. |

**Impact.** Complete read and write access to the subscriber base for anything that can reach
TCP/27017. Read yields TR-SUB-001 (all K/OPc) and the full subscriber inventory. Write permits
provisioning fraudulent subscribers, elevating slice or AMBR entitlements, or deleting
subscribers to deny service. No audit trail attributes any of it.

**Detection.** Alert on any connection to the subscriber database from a source outside the
explicit allow-list (UDR and provisioning WebUI only) — here `172.18.0.17` and `172.18.0.15`
both appeared and neither belongs. Alert on the `mongosh` client string reaching the production
database at all: an interactive shell has no place there. Alert on any query projecting the
`security` sub-document.

**Mitigation.** Enable MongoDB SCRAM authentication with per-service accounts and
least-privilege roles, and bind the listener to the UDR's interface only. Enable TLS on the
database connection. Apply a network policy so only the UDR and provisioning service can reach
TCP/27017. Enable database auditing so every read of `security` is attributable. Remove
`mongosh` from images that reach the production database.

**References.** 3GPP TS 33.501 §5.9.3; GSMA FS.31; MongoDB Security Checklist.

---
<a id="tr-db-002"></a>
### TR-DB-002 — Bulk subscriber extraction via an ephemeral administrative container

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| DB | **Critical** | Confirmed | MongoDB `172.18.0.2`, tools containers `172.18.0.17`, `172.18.0.15` |

**What happened.** A disposable administrative container was launched onto the core's Docker
network with the subscriber database URI passed as an environment variable, and instructed to
dump the subscriber collection. It ran three separate times across the exercise. In module5 the
whole subscriber base came back in **two frames**: six records, each with IMSI, slice, session
and the `security` sub-document containing K and OPc. The container then exited, leaving nothing
on disk and no account to trace.

**Why this is a threat.** This is the exfiltration step that turns TR-DB-001 from a
misconfiguration into a breach. The technique is close to ideal for an adversary: the container
is pulled from a public registry, runs for seconds, is removed with `--rm`, authenticates to
nothing, and is indistinguishable at the network layer from legitimate operations tooling. The
entire subscriber base — identities and root keys — transits in 1,260 bytes. Detection has to
happen at the moment of the query, because afterwards there is no artefact at all. *Critical* —
complete subscriber-base disclosure including long-term keys. *Confirmed* — both the command and
the database response are captured.

**Evidence.**

- `bash_history_v1:319`, `bash_history_v1:488`, `bash_history_v2:66` — the same extraction, run
  three times across the exercise:
  ```
  docker run -it --rm --net dfoiaas5llpretddralsgmsrsner \
    -e DB_URI=mongodb://$MONGO_CONTAINER:27017/5geo5og \
    gradiant/55pttolsdeons:0.10.3 "55pttolsdeons showfiltered"
  ```
  Note `--rm` (no forensic residue), a public registry image, and a DB URI carrying no
  credentials because none are required.

- `module5.pcap` frames **5243-5244** (`172.18.0.2:27017 -> 172.18.0.15:41984`, 1,260 B each) —
  the entire subscriber base in one response: six IMSIs, each with `security.k` and
  `security.opc`, namespace `open5gs.subscribers`. Full content quoted under TR-SUB-001.

- `netflows/module5.pcap_Flow.csv` — the extraction burst: six short, high-rate flows from one
  ephemeral source, all within the same second.
  ```
  172.18.0.15 -> 172.18.0.2:27017  TCP  26 pkts  208.8 pkt/s  0.12 s  28/08/2026 06:53:40 AM
  172.18.0.15 -> 172.18.0.2:27017  TCP  26 pkts  190.0 pkt/s  0.14 s
  172.18.0.15 -> 172.18.0.2:27017  TCP  26 pkts  170.6 pkt/s  0.15 s
  172.18.0.15 -> 172.18.0.2:27017  TCP  28 pkts  143.9 pkt/s  0.19 s
  ```
  `172.18.0.15` had been the gNB; Docker reissued the released address to this tools container
  (see TR-VIRT-005), so even the source address is misleading for attribution.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container | A container is deployed to execute the collection, then discarded. |
| ATT&CK | [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | The subscriber repository is the collection target. |
| ATT&CK | [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | One command dumps the whole collection without interaction. |
| ATT&CK | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | The extracted records contain usable long-term key material. |
| ATT&CK | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Indicator Removal: File Deletion | `--rm` destroys the container and its filesystem on exit. |
| FiGHT | [FGT5013](https://fight.mitre.org/techniques/FGT5013) | Malicious VNF Instantiation | A container is instantiated on the core network to collect information. |
| FiGHT | [FGT5020](https://fight.mitre.org/techniques/FGT5020) | Retrieve UE Subscription Data | Subscription data is retrieved in bulk. |

**Impact.** The whole subscriber base — identities plus root keys — leaves the core in under a
second, enabling TR-RAN-001 for every subscriber simultaneously. The ephemeral container leaves
no host artefact, so without packet capture the event is unreconstructable after the fact.

**Detection.** Alert on container creation events whose image is not on the approved list,
especially with `--rm` and an attachment to the core network. Alert on any MongoDB
`find`/`aggregate` against `subscribers` that returns more than a handful of documents. Alert on
any connection to TCP/27017 from a source that is not the UDR or provisioning service.

**Mitigation.** Enforce MongoDB authentication and per-service authorisation (TR-DB-001) so a
tools container cannot read anything without an account. Apply admission control so only
approved images attach to the core network. Require that administrative tooling runs through an
audited bastion with per-operator identity, not as an anonymous disposable container. Remove
`security.k`/`security.opc` from any tool's output projection.

**References.** 3GPP TS 33.501 §5.9.3; GSMA FS.31; NIST SP 800-190 §4.

---
## VIRT — Virtualisation, container platform and segmentation

<a id="tr-virt-001"></a>
### TR-VIRT-001 — Container escape to the host filesystem from a network-function container

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| VIRT | **Critical** | Confirmed | Container host `10.10.3.20`, NF container `mns1aifs1r5erp5drg1noou5mi`, all co-resident containers |

**What happened.** From inside a running 5G network-function container the operator remounted
`devtmpfs` to expose the host's block devices, mounted the host's LVM root volume at `/mnt`, and
`chroot`ed into it — a shell on the host filesystem, from within the container. The escape was
confirmed by reading a file that exists only on the host, and repeated successfully after the
core was torn down and brought back up, showing it is a property of the deployment rather than
of one container instance.

**Why this is a threat.** A container escape collapses every other boundary at once. The host
runs the entire 5G core, so a shell on it yields the AMF, SMF, UPF, UDR and subscriber database
simultaneously, plus the Docker daemon and therefore every future container. It also renders the
rest of this catalogue moot as a matter of access control: an attacker at this level need not
bother with TR-DB-001 or TR-N4-002, because they can read the database files directly and edit
the network functions' configuration.

The mechanism is not a kernel exploit — it is configuration. The container holds `CAP_SYS_ADMIN`
or full privileged mode and can therefore call `mount`. Once `devtmpfs` is mounted the host's
block devices appear inside the namespace, and a filesystem mount plus `chroot` finishes the job.
Nothing about this requires a vulnerability, which is why it is *Critical* and why patching will
never fix it. *Confirmed* — the command sequence, the verification read and the successful repeat
are all recorded.

**Evidence.**

- `bash_history_v2:218-222` — the escape itself, four commands:
  ```
  docker exec -it mns1aifs1r5erp5drg1noou5mi bash
  mount -t devtmpfs devtmpfs /dev
  mount /dev/mapper/ubuntu--vg-ubuntu--lv /mnt
  chroot /mnt /bin/bash
  cat /flag.txt
  ```
  `/flag.txt` exists only on the host; reading it is the proof of escape.

- `bash_history_v2:223-228` — repeated after a restart, confirming reproducibility:
  ```
  docker exec -it mns1aifs1r5erp5drg1noou5mi bash
  mount /dev/mapper/ubuntu--vg-ubuntu--lv /mnt
  ls /dev/mapper/
  cat /flag.txt
  ```

- `bash_history_v2:249-252` — the enabling condition, enumerated explicitly:
  ```
  capsh --print
  cat /proc/self/status | grep Cap
  docker inspect mns1aifs1r5erp5drg1noou5mi --format='Privileged={{.HostConfig.Privileged}}'
  docker inspect mns1aifs1r5erp5drg1noou5mi | grep -A5 CapAdd
  ```

- `bash_history_v2:244-247` — the core torn down, restarted and escaped again, showing the
  weakness is in the compose definition, not a transient state.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | A privileged container mounts the host filesystem and executes on it — the technique's canonical example. |
| ATT&CK | [T1609](https://attack.mitre.org/techniques/T1609/) | Container Administration Command | `docker exec` is used to obtain execution inside the target container. |
| ATT&CK | [T1613](https://attack.mitre.org/techniques/T1613/) | Container and Resource Discovery | Privileged status, capabilities and mounts are enumerated across all containers first. |
| ATT&CK | [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Excess Linux capabilities are the elevation mechanism abused. |
| FiGHT | [FGT1611](https://fight.mitre.org/techniques/FGT1611) | Escape to Host | 5G-context container escape from a network function. |
| FiGHT | [FGT1611.501](https://fight.mitre.org/techniques/FGT1611.501) | Malicious Privileged container-VNF Shared Resource Access | A privileged VNF container reaches data belonging to the underlying shared resources. |
| FiGHT | [FGT1609](https://fight.mitre.org/techniques/FGT1609) | Container Administration Command | The container administration service is abused to execute commands in the VNF. |

**Impact.** Full host compromise. Every network function, the subscriber database, the Docker
daemon, the capture files and any credential on the host are exposed. From the host the
adversary can modify NF configuration, install persistence that survives container restarts, and
pivot to the management network where Zabbix and Wazuh live.

**Detection.** Alert on `mount` executed inside any container — a network function never
legitimately mounts a filesystem at runtime. Alert on `chroot` inside a container. Alert on any
container whose `HostConfig.Privileged` is true, or whose `CapAdd` includes `SYS_ADMIN`, at
admission time rather than at runtime. Watch for `capsh --print` and reads of
`/proc/self/status` Cap lines — these are reconnaissance for exactly this escape.

**Mitigation.** Remove `privileged: true` and `CAP_SYS_ADMIN` from every network-function
container; UPF and gNB usually need only `NET_ADMIN` and specific devices. Enforce a seccomp
profile that denies `mount`, `pivot_root` and `chroot`. Run containers with user namespaces so
container root is not host root. Apply the AppArmor profile the operator found unloaded. Use
admission control to reject privileged containers outright.

**References.** ATT&CK T1611; NIST SP 800-190 §3.3, §4.3; CIS Docker Benchmark 5.4, 5.3.

---
<a id="tr-virt-002"></a>
### TR-VIRT-002 — Network-function containers hold excess capabilities and privileged mode

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| VIRT | **High** | Confirmed | All 5G NF containers, container host `10.10.3.20` |

**What happened.** The operator systematically enumerated the security posture of every running
container: privileged status, added Linux capabilities, AppArmor profile assignment, and mount
configuration. The results drove the escape in TR-VIRT-001, which means at least one
network-function container was running with the capabilities needed to mount host block devices.
Separately, the rogue UE was launched with `--cap-add NET_ADMIN` and a host device passed
through.

**Why this is a threat.** Container isolation is not a boundary in itself — it is the sum of
namespaces, cgroups, capabilities, seccomp and LSM policy. Each capability granted removes part
of it. `CAP_SYS_ADMIN` in particular is close to root-equivalent: it permits `mount`, which is
the entire escape in TR-VIRT-001. AppArmor is the control that would block that even with the
capability present, and the operator's enumeration of `{{.AppArmorProfile}}` across every
container is precisely the check an attacker runs to find out whether it is there. *High* — this
is the enabling weakness rather than the escape itself, and it is systemic across the
deployment rather than confined to one container. *Confirmed* — the enumeration is recorded and
its outcome is demonstrated by TR-VIRT-001 succeeding.

**Evidence.**

- `bash_history_v2:53,55` — AppArmor profile enumeration across the core:
  ```
  docker ps -q | xargs docker inspect --format '{{.Name}}  {{.AppArmorProfile}}'
  for c in $(docker ps --format '{{.Names}}' | grep 5geo5og); do
      docker inspect "$c" --format '{{.Name}} {{.AppArmorProfile}}'; done
  ```

- `bash_history_v2:178,183,185` — privileged-mode sweep over every running container:
  ```
  docker ps -q | while read c; do echo "==== $c ====";
      docker inspect $c | grep Privileged; done
  docker ps -q | while read c; do
      docker in      docker inspect $c --format='Privileged={{.HostConfig.Privileged}}'; done
  ```

- `bash_history_v2:179,240,252` — capability enumeration:
  ```
  docker inspect <container_name> | grep CapAdd -A10
  docker inspect mns1aifs1r5erp5drg1noou5mi | grep -A5 CapAdd
  ```

- `bash_history_v2:249-250` — capabilities confirmed from inside the container:
  ```
  capsh --print
  cat /proc/self/status | grep Cap
  ```

-
      docker inspect $c --format='Privileged={{.HostConfig.Privileged}}'; done
  ```

- `bash_history_v2:179,240,252` — capability enumeration:
  ```
  docker inspect <container_name> | grep CapAdd -A10
  docker inspect mns1aifs1r5erp5drg1noou5mi | grep -A5 CapAdd
  ```

- `bash_history_v2:249-250` — capabilities confirmed from inside the container:
  ```
  capsh --print
  cat /proc/self/status | grep Cap
  ```

- `bash_history_v1:43` — a workload attached to the core with elevated privilege and a host
  device: `--device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN`.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1613](https://attack.mitre.org/techniques/T1613/) | Container and Resource Discovery | Privileged status, capabilities and LSM profiles are enumerated across the cluster. |
| ATT&CK | [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Excess capabilities are the elevation path. |
| ATT&CK | [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Kernel version, OS release and Docker version are fingerprinted (`bash_history_v2:56-60`). |
| FiGHT | [FGT1611.501](https://fight.mitre.org/techniques/FGT1611.501) | Malicious Privileged container-VNF Shared Resource Access | Privileged VNF containers can reach shared host resources. |
| FiGHT | [FGT5014](https://fight.mitre.org/techniques/FGT5014) | Shared Resource Discovery | Co-resident VNFs and their shared host resources are identified. |

**Impact.** Provides the precondition for TR-VIRT-001 and for lateral movement between network
functions on the same host. A compromised NF — reachable, for example, through TR-N4-001 — is
one `mount` away from the host rather than contained.

**Detection.** Audit at admission, not at runtime: reject any container whose `Privileged` is
true, whose `CapAdd` includes `SYS_ADMIN`/`SYS_PTRACE`/`SYS_MODULE`, or whose `AppArmorProfile`
is `unconfined`. At runtime, alert on `capsh`, on reads of `/proc/self/status` Cap fields, and
on cluster-wide `docker inspect` sweeps from an interactive session.

**Mitigation.** Drop all capabilities by default and add back only what each NF genuinely needs.
Assign a non-default AppArmor or SELinux profile to every container. Apply a restrictive seccomp
profile. Enforce these with an admission controller so they cannot be reintroduced by editing a
compose file.

**References.** NIST SP 800-190 §4.3, §4.5; CIS Docker Benchmark 5.3, 5.4, 5.12; 3GPP TS 33.848.

---
<a id="tr-virt-003"></a>
### TR-VIRT-003 — Container administration socket reachable from inside the workload

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| VIRT | **High** | Confirmed | Docker daemon on `10.10.3.20`, all NF containers |

**What happened.** Every running container was searched for a bind-mounted `docker.sock`, and
the mount configuration of a specific network-function container was inspected. `docker exec`
was then used routinely — dozens of times across both histories — to obtain interactive shells
inside production network functions including the AMF, SMF, UPF, UE and gNB.

**Why this is a threat.** The Docker socket is the control plane of the host. A container that
can reach it can create a new container with the host filesystem bind-mounted and full
privileges, which is TR-VIRT-001 without needing any capability of its own. Searching for the
socket is therefore a deliberate escape-path hunt. Independently, the availability of
`docker exec` into production NFs means the container boundary provides no operational
separation: anyone with daemon access has aroot shell in every network function. *High* — a
direct escape path if the socket is exposed, and unrestricted NF access regardless. *Confirmed* —
the search and the repeated `docker exec` use are both recorded.

**Evidence.**

- `bash_history_v2:186` — cluster-wide hunt for the socket:
  ```
  docker ps -q | while read c; do
      echo "===== $(docker inspect -f '{{.Name}}' $c) =====
root shell in every network function. *High* — a direct
escape path if the socket is exposed, and unrestricted NF access regardless. *Confirmed* — the
search and the repeated `docker exec` use are both recorded.

**Evidence.**

- `bash_history_v2:186` — cluster-wide hunt for the socket:
  `docker ps -q | while read c; do docker inspect $c | grep docker.sock; done`
- `bash_history_v2:187` — mount inspection of a target container:
  `docker inspect ggpepgnoaneaus5eppm1andpa5 | grep -A5 Mounts`
- `bash_history_v2` lines 109, 111, 114, 115, 119, 120, 129, 130, 142, 152, 157, 158, 188, 189,
  199, 210, 213–218, 223, 247 — `docker exec -it <nf> bash` into AMF, SMF, UPF, UE and gNB
  containers, twenty-plus times.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1609](https://attack.mitre.org/techniques/T1609/) | Container Administration Command | The container administration service is used to execute commands inside workloads. |
| ATT&CK | [T1613](https://attack.mitre.org/techniques/T1613/) | Container and Resource Discovery | Mounts and socket exposure are enumerated across the cluster. |
| ATT&CK | [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | An exposed docker.sock is an explicitly documented escape route. |
| FiGHT | [FGT1609](https://fight.mitre.org/techniques/FGT1609) | Container Administration Command | 5G-context abuse of the container administration service against VNFs. |
| FiGHT | [FGT1613](https://fight.mitre.org/techniques/FGT1613) | Container and Resource Discovery | Discovery of containerised network functions and their configuration. |

**Impact.** Root-equivalent execution in every network function; with an exposed socket, host
compromise without needing any container capability. Also defeats separation of duties — there
is no distinction between "may operate the AMF" and "may operate the UDR".

**Detection.** Alert on any process inside a container opening `/var/run/docker.sock`. Alert on
`docker exec` against production NF containers outside a change window, and on
`docker inspect` sweeps across all containers from one session.

**Mitigation.** Never bind-mount `docker.sock` into a workload; where an agent needs the API,
front it with a filtering proxy that permits only the required verbs. Require `docker exec` to
go through an audited bastion with per-operator identity. Remove shells from NF images.

**References.** ATT&CK T1609, T1611; NIST SP 800-190 §4.3; CIS Docker Benchmark 5.31.

---
<a id="tr-virt-004"></a>
### TR-VIRT-004 — All 3GPP reference points share one unsegmented L2 broadcast domain

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| VIRT | **Critical** | Confirmed | Entire core, Docker bridge `172.18.0.0/16` |

**What happened.** Every network function, the RAN simulator and the subscriber database sit on
a single Docker bridge. One `tcpdump -i any` on the host captures N1/N2 signalling, N3 user
traffic, N4 session management, the whole service-based interface and unauthenticated MongoDB
at once — which is exactly how this repository was produced. ARP between every pair of network
functions is visible, confirming a shared broadcast domain rather than routed isolation.

**Why this is a threat.** TS 33.501 treats N2, N3, N4 and the SBI as distinct security domains,
and permits several of them to rely on "protection provided by the transport" precisely on the
assumption that they are separated. Collapsing them into one bridge voids that assumption
retroactively: it is why TR-N2-002, TR-N4-001 and TR-SUB-003 are exploitable rather than merely
non-compliant. Any workload that can be scheduled onto this network — including the disposable
tools container in TR-DB-002 and the rogue UE in TR-RAN-001 — starts with reachability to every
interface in the core, and a compromise of the least important function is a compromise of the
position from which all the others can be attacked. The blast radius of any single weakness is
the whole core. *Critical* — it is the amplifier for most of this catalogue. *Confirmed* — the
capture itself is the proof.

**Evidence.**

- Derived, every capture — one capture point, all interfaces. From `module1.pcap` alone:
  ```
  SCTP/38412  NGAP    N2    gNB  <-> AMF
  UDP/2152    GTP-U   N3    gNB  <-> UPF
  UDP/8805    PFCP    N4    SMF  <-> UPF
  TCP/7777    HTTP/2  SBI   8 NFs <-> SCP <-> NRF
  TCP/27017   MongoDB  --   UDR/WebUI <-> subscriber DB
  UDP/4997    RLS      --   UE   <-> gNB
  ```

- Derived, `module2.pcap` — ARP between unrelated NF pairs proves a shared L2 domain:
  ```
  172.18.0.12 asks for 172.18.0.9    (SMF/UPF pair)
  172.18.0.2  asks for 172.18.0.8    (MongoDB/PCF pair)
  172.18.0.2  asks for 172.18.0.4    (MongoDB/UDR pair)
  172.18.0.16 asks for 172.18.0.15   (UE/gNB pair)
  ```
  A segmented deployment would not place the UE and the subscriber database in one ARP domain.

- `bash_history_v2:133,136` — the adversary's own confirmation, from inside a container:
  ```
  arp-scan --localnet --interface eth0
  ```

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT1557.503](https://fight.mitre.org/techniques/FGT1557.503) | Adversary-in-the-Middle: Non-SBI | A shared segment lets an attacker interpose on N2/N3/N4. |
| FiGHT | [FGT1557.504](https://fight.mitre.org/techniques/FGT1557.504) | Adversary-in-the-Middle: Service Based Interface | The same position works against SBI traffic. |
| FiGHT | [FGT1599.501](https://fight.mitre.org/techniques/FGT1599.501) | Network Boundary Bridging: Malicious Co-Tenancy Exploit Of NFVI | Co-tenancy without isolation gives access across intended boundaries. |
| FiGHT | [FGT5014](https://fight.mitre.org/techniques/FGT5014) | Shared Resource Discovery | Co-resident network functions are trivially enumerable. |
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | One capture position yields every interface. |
| ATT&CK | [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | `arp-scan --localnet` enumerates the whole core from one container. |

**Impact.** The amplifier for most of this catalogue. Converts "an attacker would need to reach
N4" into "any container can reach N4". Makes ARP-based adversary-in-the-middle viable against
every unprotected interface, and gives a single compromised workload visibility of all
subscriber signalling.

**Detection.** Structural, so audit rather than alert: assert that N2, N3, N4, SBI and the
database each sit on their own network, and alert on any container attached to more than one.
Alert on ARP requests between hosts that have no protocol reason to speak — MongoDB ARPing for
the PCF is an architecture defect made visible.

**Mitigation.** Place each reference point on its own Docker network or VLAN, with the
subscriber database on a separate one again. Apply default-deny network policy between NFs and
permit only the flows 3GPP requires. This one change would meaningfully reduce the exploitability
of TR-N2-001, TR-N4-001, TR-N4-002, TR-DB-001, TR-DB-002 and TR-SUB-003 simultaneously.

**References.** 3GPP TS 33.501 §5.9.2, §9; 3GPP TS 33.848; NIST SP 800-190 §4.1.

---
<a id="tr-virt-005"></a>
### TR-VIRT-005 — Container address reuse misdelivers traffic to an unrelated workload

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| VIRT | **Medium** | Confirmed | Docker IPAM on `172.18.0.0/16`, gNB, UE, tools container |

**What happened.** `172.18.0.15` was the gNB in modules 0–2. After that container was removed
Docker returned the address to its pool and reissued it to the next workload — the ephemeral
subscriber-database tools container of TR-DB-002. The UE, never told its peer had gone, kept
transmitting to `172.18.0.15:4997`. In module5 the orphaned UE sent **44,886 packets to an
address now owned by an unrelated container**, in the same capture and largely the same seconds
in which that container was extracting the subscriber database.

**Why this is a threat.** Two problems meet here. First, forensic integrity: addresses stop
being reliable identifiers. `172.18.0.15` in module5 means "the tools container" in one flow and
"where the gNB used to be" in another, so any detection or investigation keyed on IP is wrong by
construction — and TR-DB-002's exfiltration is attributed to what looks like the gNB. Second,
misdelivery: traffic meant for one workload reaches another with no relationship to it. In a
multi-tenant or multi-slice deployment that is a confidentiality boundary failure, not just
noise; a workload that wanted to receive another's traffic could simply wait for the address.
*Medium* — no disclosure is demonstrated here because RLS traffic carries nothing sensitive, but
the mechanism is general and the attribution damage is real. *Confirmed* — the role change and
the misdirected volume are both in the same capture.

**Evidence.**

- Derived, timeline of `172.18.0.15`:
  ```
  module0-2  gNB: holds N2 SCTP to AMF, N3 GTP-U to UPF, binds UDP/4997
  module5    tools container: queries 172.18.0.2:27017, receives the subscriber dump
             (frames 5243-5244)  -- same address, different workload
  ```

- `netflows/module5.pcap_Flow.csv` — both uses, concurrently:
  ```
  172.18.0.16 -> 172.18.0.15:4997   UDP  44,886 pkts   (UE still calling the dead gNB)
  172.18.0.15 -> 172.18.0.2:27017   TCP      26 pkts   (tools container reading subscribers)
  ```

- Derived, `module5.pcap` — 6,132 ARP requests from the UE for `172.18.0.15`, zero replies: the
  new occupant does not answer for the old role, so the misdelivery is also a storm (TR-RAN-002).

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| FiGHT | [FGT5021](https://fight.mitre.org/techniques/FGT5021) | Tunnel ID Uniqueness Failure | Identifier reuse causes new traffic to collide with state belonging to a previous session. |
| FiGHT | [FGT1599.501](https://fight.mitre.org/techniques/FGT1599.501) | Network Boundary Bridging: Malicious Co-Tenancy Exploit Of NFVI | Shared infrastructure delivers one workload's traffic to another. |
| ATT&CK | [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | The reused address makes a tools container indistinguishable from the gNB in logs. |
| ATT&CK | [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | Address recycling destroys the link between an observed indicator and the workload that produced it. |

**Impact.** Misattribution of security events — here the subscriber-database exfiltration
appears to come from the gNB's address. Potential receipt of another workload's traffic by an
unrelated, possibly attacker-controlled container.

**Detection.** Key detection on workload identity (container ID, service account, workload
certificate), never on IP alone. Alert when an address changes owner while another host is still
actively sending to it — the signature is a burst of unanswered ARP for an address that is in
fact up.

**Mitigation.** Use static or reserved addressing for long-lived network functions. Quarantine
released addresses for longer than any plausible peer timeout before reissue. Ensure teardown
of a RAN or NF element also reconfigures or stops its peers. Record container identity, not just
IP, in all flow and security logs.

**References.** NIST SP 800-190 §4.1; 3GPP TS 33.848.

---
## AI — AI/ML security of the intrusion-detection pipeline

<a id="tr-ai-001"></a>
### TR-AI-001 — Training-data poisoning of the intrusion-detection model by label flipping

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| AI | **High** | Confirmed | IDS training corpus `labeled_flows.csv`, `train_poisoned_ids.py`, deployed IDS model |

**What happened.** A network intrusion-detection classifier was trained on flows extracted from
the 5G testbed, with classes including `Benign` and `ICMP_FLOOD`. A second training script was
then written whose purpose was to poison that model: a subset of training samples had their
labels flipped, the count of flipped samples was printed, and the effect was measured as an
Attack Success Rate — the proportion of genuine `ICMP_FLOOD` test samples that the poisoned
model classifies as `Benign`.

**Why this is a threat.** Label flipping is the cheapest poisoning attack there is and it needs
no access to the model, only to the training data. In this pipeline the training data is derived
automatically from captured traffic (TR-AI-004), so an adversary who can influence what the
network sees can influence what the model learns — no insider access to the data store required.
The ASR metric makes the objective explicit: the goal is not to degrade accuracy generally but
to create a **targeted blind spot** for one attack class, leaving headline accuracy high enough
that nobody investigates. A poisoned IDS is worse than no IDS, because it manufactures
confidence. *High* — the defensive control for the entire testbed is subverted. *Confirmed* —
the poisoning script, its execution and the ASR computation are all recorded.

**Evidence.**

- `bash_history_v2:296-302` — the clean model, then the poisoned one:
  ```
  nano train_ids.py
  python3 train_ids.py
  nano train_poisoned_ids.py
  python3 train_poisoned_ids.py
  ```

- `bash_history_v2:300` — the flip counter, printed from inside the poisoning script:
  ```
  print("Poisoned samples:", flip_count)
  ```

- `bash_history_v2:303-306` — Attack Success Rate measured specifically for the target class:
  ```
  flood_test_indices = y_test[y_test == 'ICMP_FLOOD'].index
  misclass = (poisoned_preds[flood_test_indices] == 'Benign').sum()
  asr = misclass / len(flood_test_indices) if len(flood_test_indices) > 0 else 0
  print(f"ASR: {asr:.4f}")
  ```
  The metric is defined as "how often does a real flood get called benign" — a targeted
  false-negative objective, not a generic accuracy reduction.

- `bash_history_v2:281` — the attack traffic that produced the `ICMP_FLOOD` class:
  `ping -c 100 8.8.8.8`, visible in `module8.pcap` as 62 captured Echo Requests
  `10.10.3.20 -> 8.8.8.8`, id 19925, seq 1..n, starting frame **23224**.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATLAS | [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) | Training Data Poisoning | Labels in the training set are altered to influence the resulting model's behaviour. |
| ATLAS | [AML.T0018.000](https://atlas.mitre.org/techniques/AML.T0018.000) | Manipulate AI Model: Poison AI Model | Training on poisoned data produces a poisoned model. |
| ATLAS | [AML.T0031](https://atlas.mitre.org/techniques/AML.T0031) | Erode AI Model Integrity | Model performance is degraded on the class the adversary cares about. |
| ATLAS | [AML.T0042](https://atlas.mitre.org/techniques/AML.T0042) | Verify Attack | ASR is computed to confirm the poisoning worked before relying on it. |
| ATT&CK | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | Data Manipulation: Stored Data Manipulation | The stored training corpus is modified. |
| ATT&CK | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | The outcome is a defensive tool that no longer detects the attack. |

**Impact.** A targeted, persistent blind spot in the detection layer. Flood traffic passes as
benign while the model's overall metrics stay healthy, so the failure is invisible to routine
monitoring. The blind spot survives until the model is retrained on clean data — and if the
pipeline keeps ingesting from the same source, retraining reintroduces it.

**Detection.** Compare per-class recall between model versions, not just overall accuracy — a
targeted poisoning shows as one class collapsing while the aggregate holds. Checksum the
training corpus and require signed provenance for every ingest batch. Alert on label
distribution drift between training runs. Hold out a curated, immutable golden test set that the
pipeline cannot modify, and gate deployment on per-class recall against it.

**Mitigation.** Sign and version training data; reject unsigned batches. Use robust training
(trimmed loss, per-class outlier rejection) so a minority of flipped labels cannot dominate.
Separate the duty of labelling from the duty of training. Never derive labels automatically from
traffic an adversary can generate (TR-AI-004).

**References.** MITRE ATLAS AML.T0020; NIST AI 100-2e2023 §2.2 (poisoning attacks).

---
<a id="tr-ai-002"></a>
### TR-AI-002 — Adversarial evasion of the IDS by scaling a single packet-length feature

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| AI | **High** | Confirmed | Deployed IDS model, feature set `['proto','ip_len','frame_len']` |

**What happened.** With white-box access to the trained classifier, the operator took the test
set, selected the rows labelled `ICMP_FLOOD`, and multiplied one feature — `ip_len` — by 0.5.
Those rows were fed back to the model and an **evasion rate** computed: the fraction of real
flood samples now predicted `Benign`. A baseline of `0.75` appears in the later hardening work,
implying roughly three in four flood samples evaded detection after a single arithmetic change
to one field.

**Why this is a threat.** The perturbation is not an abstract gradient in embedding space — it
is a packet-length change, and an attacker controls packet lengths directly. Halving `ip_len`
means sending smaller ICMP packets, which any flooder can do while still flooding. So the
adversarial example is realisable in the real world at essentially zero cost to the attack's
effectiveness, which is the property that separates a theoretical evasion from an operational
one. White-box access made the search trivial, but with only three features a black-box attacker
would find it by trial and error in minutes. *High* — the detection control is defeated by a
change the attacker was free to make anyway. *Confirmed* — the perturbation, the prediction call
and the evasion-rate computation are all recorded.

**Evidence.**

- `bash_history_v2:330-337` — the perturbation, crafted against the target class only:
  ```
  print(df_test['label'].value_counts())
  flood_idx = df_test[df_test['label']=="ICMP_FLOOD"].index
  print(len(flood_idx))
  print(df_test.loc[flood_idx, 'ip_len'].head())
  perturbed_test = df_test.copy()
  perturbed_test.loc[flood_idx,'ip_len'] *= 0.5
  print(perturbed_test.loc[flood_idx,'ip_len'].head())
  ```

- `bash_history_v2:413-421` — the evasion measured:
  ```
  evaded_preds = model.predict(perturbed_test[['proto','ip_len','frame_len']])
  evasion_rate = (evaded_preds[flood_idx] == 'Benign').mean()
  print(f"Evasion Rate: {evasion_rate:.4f}")
  ```

- `bash_history_v2:352` — the baseline evasion rate, revealed by the improvement calculation:
  ```
  improvement = 0.75 - robust_evasion_rate
  ```

- `bash_history_v2:387-394` — the same adversarial set replayed against the hardened ensemble,
  confirming the attack was retained as a standing test case.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATLAS | [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043) | Craft Adversarial Data | Inputs are modified so the model produces the adversary's desired misclassification. |
| ATLAS | [AML.T0043.000](https://atlas.mitre.org/techniques/AML.T0043.000) | Craft Adversarial Data: White-Box Optimization | The attacker has full access to the target model and optimises against it directly. |
| ATLAS | [AML.T0043.003](https://atlas.mitre.org/techniques/AML.T0043.003) | Craft Adversarial Data: Manual Modification | A single feature is modified by hand using knowledge of the model. |
| ATLAS | [AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) | Evade AI Model | Crafted data prevents the model from identifying the attack correctly. |
| ATLAS | [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044) | Full AI Model Access | White-box access to architecture, parameters and class ontology enables offline crafting. |
| ATLAS | [AML.T0042](https://atlas.mitre.org/techniques/AML.T0042) | Verify Attack | The evasion rate is measured before the technique is relied upon. |
| ATT&CK | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | The practical effect is a detection tool that no longer fires. |

**Impact.** An ICMP flood — and by extension any attack the model is supposed to catch —
proceeds while being classified as benign. Because the change is to a field the attacker already
controls, there is no trade-off: the attack keeps working at full strength while becoming
invisible.

**Detection.** Monitor the distribution of input features at inference time and alert on drift
— a sudden population of `ICMP_FLOOD`-shaped flows with halved `ip_len` is anomalous even if the
classifier calls them benign. Keep a rule-based detector alongside the model for high-confidence
signatures such as ICMP rate per source; a threshold rule is unaffected by this perturbation.
Log low-confidence predictions and review clusters of them.

**Mitigation.** Adversarial training (which the operator went on to demonstrate — see
DETECTION.md §5). Use features the attacker cannot cheaply control — inter-arrival statistics,
flow duration, per-source rate — rather than packet length. Ensemble across models with
different feature views. Do not expose the deployed model or its parameters to any account that
does not need them.

**References.** MITRE ATLAS AML.T0043, AML.T0015; NIST AI 100-2e2023 §2.1 (evasion attacks).

---
<a id="tr-ai-003"></a>
### TR-AI-003 — Three-feature model provides no adversarial robustness by construction

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| AI | **High** | Confirmed | IDS feature pipeline `preprocess.py`, `labeled_flows.csv`, deployed model |

**What happened.** Every model in the pipeline — the clean classifier, the poisoned one, the
adversarially-trained "robust" one and the RandomForest ensemble — operates on the same three
features: `['proto','ip_len','frame_len']`. Two of the three are packet sizes and the third is
the IP protocol number. The feature list appears verbatim in three separate prediction calls.

**Why this is a threat.** The feature space *is* the attack surface of a model. Here it has
three dimensions, two of which the attacker sets directly when composing a packet, and the
third of which is fixed by the attack type. There is essentially nothing left for the model to
learn that an adversary cannot override at will — which is why TR-AI-002 succeeds with a single
multiplication. Crucially, no feature in the set describes *behaviour over time*: no rate, no
inter-arrival statistic, no flow duration, no per-source counter. But rate is the only thing
that actually distinguishes a flood from a ping. The model was therefore never detecting floods;
it was detecting packet sizes that happened to correlate with floods in the training set.
*High* — a structural defect that guarantees evasion regardless of how the model is trained.
*Confirmed* — the feature list is explicit in the recorded code.

**Evidence.**

- `bash_history_v2:274` — the extraction that defines the feature ceiling. Only these fields are
  ever captured:
  ```
  tshark -i any -T fields -e frame.time -e ip.src -e ip.dst -e ip.proto -e ip.len \
      -e tcp.srcport -e tcp.dstport -e icmp.type -Y ip -c 200 \
      -E header=y -E separator=, > raw_capture.csv
  ```
  Note `-c 200`: the first corpus was capped at 200 packets.

- `bash_history_v2:388,414` and `:342` — the feature list, used identically everywhere:
  ```
  ensemble_model.predict(perturbed_test[['proto','ip_len','frame_len']])
  model.predict(perturbed_test[['proto','ip_len','frame_len']])
  print(X_train.columns)
  ```

- Derived, `module8.pcap` — the ground truth the model had to separate. The `ICMP_FLOOD` class
  came from `ping -c 100 8.8.8.8`, which in the capture is **62 Echo Requests at ~1 per second**,
  all id 19925, all 104 bytes, from frame **23224**. A one-per-second ping is not a flood; the
  only thing distinguishing it from benign ICMP in this feature space is its size. The label
  does not describe the behaviour.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATLAS | [AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) | Evade AI Model | A minimal feature space makes evasion structurally available. |
| ATLAS | [AML.T0013](https://atlas.mitre.org/techniques/AML.T0013) | Discover AI Model Ontology | The output classes are enumerated (`ensemble_model.classes_`, `y_train.value_counts()`). |
| ATLAS | [AML.T0031](https://atlas.mitre.org/techniques/AML.T0031) | Erode AI Model Integrity | Confidence in the detector is not warranted by what it measures. |
| ATLAS | [AML.T0046](https://atlas.mitre.org/techniques/AML.T0046) | Spamming AI System with Chaff Data | A size-only model is trivially flooded with misleading detections. |

**Impact.** Any attacker who can choose their packet sizes controls the model's output. Worse,
because the detector appears to work on the training distribution, it displaces the rate-based
detection that would have caught the attack.

**Detection.** Audit the feature set before the model: for every class the model claims to
detect, check that at least one feature actually measures the distinguishing behaviour. Here
`ICMP_FLOOD` has no rate feature, and that is the finding. Track per-class recall under
deliberate perturbation of each feature as a release gate.

**Mitigation.** Add temporal and volumetric features — packets per second per source, flow
duration, inter-arrival mean and variance, unique destinations per source. The CICFlowMeter CSVs
already in this dataset provide 84 such features and would have been a far better basis than a
three-column `tshark` export. Validate that labels describe behaviour rather than an artefact of
how the sample was generated.

**References.** MITRE ATLAS AML.T0015; NIST AI 100-2e2023 §2.1.

---
<a id="tr-ai-004"></a>
### TR-AI-004 — Unprotected ML training corpus built from live 5G control-plane telemetry

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| AI | **Medium** | Confirmed | `raw_capture.csv`, `labeled_flows.csv` (25 MB), host `10.10.3.20` |

**What happened.** The IDS training corpus was produced by running `tshark` on the container
host — the same capture position that sees every 5G interface (TR-OPS-001) — writing the result
to a world-readable CSV, and post-processing it into a 25 MB labelled dataset. Both files sit in
the operator's working directory with no access control, no encryption and no integrity
protection. The corpus was read repeatedly across two separate capture windows and via a Jupyter
notebook.

**Why this is a threat.** Two separate exposures. First, confidentiality: a corpus derived from
5G control-plane traffic inherits that traffic's sensitivity — source and destination addresses,
protocol mix and timing for the whole core, and by extension the subscriber activity behind it.
It is a derived surveillance product sitting in a home directory. Second, integrity: this file
is the input to TR-AI-001. An unsigned, unversioned, writable training corpus means the
poisoning attack needs no privilege beyond filesystem write. The pipeline has no checksum, no
provenance record and no separation between the party that generates data and the party that
trains on it. *Medium* — no subscriber identifier is demonstrably in the corpus (the `tshark`
field list stops at IP addresses), but it is the enabling asset for a High finding.
*Confirmed* — the generation, size and repeated access are all recorded.

**Evidence.**

- `bash_history_v2:274-277` — corpus generated from the privileged capture position:
  ```
  tshark -i any -T fields -e frame.time -e ip.src -e ip.dst -e ip.proto -e ip.len \
      -e tcp.srcport -e tcp.dstport -e icmp.type -Y ip ... > raw_capture.csv
  ls -lh raw_capture.csv ; wc -l raw_capture.csv ; head raw_capture.csv
  ```

- `bash_history_v2:288-294` — labelled dataset produced and sized:
  ```
  nano preprocess.py ; python3 preprocess.py
  wc -l labeled_flows.csv ; ls -lh labeled_flows.csv
  ```

- `bash_history_v2:316-317` — the artefact, in a user home directory:
  ```
  ls -lh labeled_flows.csv
  -rw-r--r-- 1 user user 25M labeled_flows.csv
  ```
  Mode `644`: world-readable, owner-writable, no ACL, no encryption.

- `bash_history_v2:318,328,399` — the operator's own search confirming no model or artefact
  registry exists:
  ```
  find . -type f | grep -E "model|pickle|pkl|joblib"
  ```
  Returns nothing at any point. There is no versioning, no signing and no provenance anywhere in
  the pipeline.

- `bash_history_v2:437` — `jupyter notebook`, i.e. an interactive session with write access to
  the corpus on the same host that runs the 5G core.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATLAS | [AML.T0035](https://atlas.mitre.org/techniques/AML.T0035) | AI Artifact Collection | Datasets and telemetry produced by the AI system are collected in one place. |
| ATLAS | [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037) | Data from Local System | The corpus is a local file with no protection. |
| ATLAS | [AML.T0010.002](https://atlas.mitre.org/techniques/AML.T0010.002) | AI Supply Chain Compromise: Data | Unprotected training data is the supply-chain element an adversary targets. |
| ATLAS | [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) | Exfiltration via Cyber Means | A single readable file carries the whole corpus off the host. |
| ATT&CK | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Sensitive derived data collected from the filesystem. |
| ATT&CK | [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | `tshark` to CSV is automated bulk collection. |

**Impact.** Provides the write target for TR-AI-001 and a compact, portable summary of all core
traffic for an adversary who reaches the host — which TR-VIRT-001 shows is achievable from any
privileged container.

**Detection.** Alert on world-readable files in ML working directories. Monitor writes to the
training corpus outside the ingest pipeline's own identity. Checksum the corpus before every
training run and compare against the signed manifest.

**Mitigation.** Store training data in a versioned, access-controlled artefact store with
content hashes and signed manifests. Restrict corpus write access to the ingest service account.
Encrypt at rest. Minimise fields at extraction time. Separate the training host from the host
running production network functions.

**References.** MITRE ATLAS AML.T0010.002, AML.T0035; NIST AI 100-2e2023 §2.2.

---
## OPS — Operational security, tooling and detection posture

<a id="tr-ops-001"></a>
### TR-OPS-001 — Full-fidelity capture position on the container host observes every interface

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| OPS | **Medium** | Confirmed | Container host `10.10.3.20`, all 5G interfaces |

**What happened.** `tcpdump -i any` was run on the container host for every one of the eleven
exercise modules, each capture bracketed by a start and a `kill -15`. Because the host owns the
Docker bridge, `-i any` sees N1/N2, N3, N4, the full service-based interface, the subscriber
database and the management network in one stream. The resulting captures total 1.25 M frames in
the nine files present here, plus 4.27 M more in the excluded module3.

**Why this is a threat.** This is the position from which every other finding in this repository
was derived, which makes it the single most valuable foothold in the environment — and it
requires nothing but the ability to run `tcpdump` as root on one host. There is no cryptographic
protection on N2, N3, N4 or SBI (TR-N2-002, TR-N4-001, TR-SUB-003), so the capture yields
plaintext subscriber identities, session bindings and long-term keys rather than opaque
ciphertext. The captures then persist as files on that host, so the exposure outlives the
session. *Medium* — legitimate operational tooling in this context, but it is the enabler and
the multiplier for the Critical findings, and it demonstrates that host-level access equals
total signalling visibility.

**Evidence.**

- `bash_history_v1:355,393,417,429` and `bash_history_v2:52,75,80,175,255,309,397,442` — the
  capture pattern, eleven times:
  ```
  sudo -v
  sudo nohup tcpdump -i any -w moduleN.pcap < /dev/null > /dev/null 2>&1 &
  ...
  ps aux | grep tcpdump
  sudo kill -15 <pid>
  ```
  `nohup ... &` with output discarded is a long-running, det

**Evidence.**

- `bash_history_v1:355,393,417,429` and `bash_history_v2:52,75,80,175,255,309,397,442` — the
  same pattern eleven times:
  ```
  sudo nohup tcpdump -i any -w moduleN.pcap < /dev/null > /dev/null 2>&1 &
  ps aux | grep tcpdump
  sudo kill -15 <pid>
  ```
  `nohup ... &` with output discarded is a detached, unattended capture.

- Derived, capture linktype — all nine files are `LINKTYPE_LINUX_SLL2` (276), snaplen 262144:
  the cooked `any` interface with full payload retention, not a filtered or truncated capture.

- `bash_history_v2:124` — capture initiated *inside* a network-function container as well:
  `docker exec mns1aifs1r5erp5drg1noou5mi tcpdump -i any udp port 8805`

- This repository is itself the evidence of impact: every K/OPc, SUPI, SUCI, TEID, SEID and
  session binding cited here came out of these files.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Traffic is captured wholesale from a host with visibility of every interface. |
| ATT&CK | [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Detached, unattended capture over hours. |
| ATT&CK | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Capture files persist on the host afterwards. |
| FiGHT | [FGT1040](https://fight.mitre.org/techniques/FGT1040) | Network Sniffing | 5G-context interception of signalling and user-plane traffic. |
| FiGHT | [FGT1020.001](https://fight.mitre.org/techniques/FGT1020.001) | Automated Exfiltration: Traffic Duplication | Wholesale traffic duplication to a file for later analysis. |

**Impact.** Complete, retrospective visibility of the 5G core: subscriber identities, device
identities, session bindings, tunnel identifiers and long-term keys. Capture files left on disk
extend the exposure beyond the session, and TR-VIRT-001 shows how an attacker reaches that disk.

**Detection.** Alert on any process opening an `AF_PACKET` socket on a production host, and on
`tcpdump`, `tshark` or `dumpcap` execution outside an approved change window. Alert on capture
tooling running *inside* a container — there is no legitimate case for that. Monitor for large
`.pcap` files appearing on NF hosts.

**Mitigation.** Remove packet-capture binaries from production hosts and NF images; where
capture is needed, use a controlled TAP or a mirror port feeding an access-controlled collector.
Encrypt the interfaces (TR-N2-002, TR-N4-001, TR-SUB-003) so that a capture position yields
ciphertext rather than credentials. Restrict `CAP_NET_RAW`. Treat capture files as
subscriber-data assets with matching retention, encryption and deletion controls.

**References.** 3GPP TS 33.501 §9; GSMA FS.31; NIST SP 800-190 §4.5.

---
<a id="tr-ops-002"></a>
### TR-OPS-002 — Offensive tooling pulled from the public internet onto the core host

| Domain | Severity | Confidence | Affected assets |
|---|---|---|---|
| OPS | **Medium** | Confirmed | Container host `10.10.3.20`, egress path to the internet |

**What happened.** The host that runs the 5G core has unrestricted outbound internet access and
it was used repeatedly to fetch capability: the 5GReplay binary and its seed capture from
GitHub releases, `arp-scan` and `tshark` from distribution repositories, `pandas` and
`scikit-learn` from PyPI, and public container images (`gradiant/snseiimm`,
`gradiant/55pttolsdeons`) from a registry. Some installs were run from inside network-function
containers rather than on the host.

**Why this is a threat.** A production 5G core host with unrestricted egress and a working
package manager is a staging area. Every capability used in this exercise arrived this way, and
none of it was pre-installed — which means the same path is available to an adversary who
obtains a shell, and no supply-chain control stands between a public artefact and the host that
terminates N2, N3 and N4. `apt update && apt install` executed *inside* an NF container is
worse still: it mutates a production network function at runtime, defeating image immutability
and any signature the image once carried. *Medium* — no compromise follows from this alone, but
it is the precondition for TR-N2-001 and TR-N4-003 and it indicates the absence of egress
control and image-integrity policy. *Confirmed* — every fetch is recorded.

**Evidence.**

- `bash_history_v2:443-449` — the replay tool and its seed capture:
  ```
  sudo apt update && sudo apt install -y wget
  wget https://github.com/Montimage/5GReplay/releases/download/v0.0.1/5greplay-0.0.1_Linux_x86_64.tar.gz
  tar -xzf 5greplay-0.0.1_Linux_x86_64.tar.gz
  chmod +x 5greplay
  ./5greplay --version
  ```

- `bash_history_v2:134-136` — package installation from inside a network-function container:
  ```
  apt update
  apt install arp-scan
  arp-scan --localnet --interface eth0
  ```
  No `sudo`, because the container already runs as root (TR-VIRT-002).

- `bash_history_v2:270-273, 287, 291` — analysis tooling onto the host:
  ```
  apt update ; apt install tshark
  pip3 install pandas ; sudo apt install python3-pip
  ```

- `bash_history_v1:43` and `bash_history_v2:66` — public container images pulled straight onto
  the core network: `gradiant/snseiimm:3.2.6`, `gradiant/55pttolsdeons:0.10.3`.

**TTP mapping.**

| Framework | ID | Name | Rationale |
|---|---|---|---|
| ATT&CK | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | Tools are downloaded from public sources for use against the target. |
| ATT&CK | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Binaries are transferred onto the target host over the network. |
| ATT&CK | [T1608](https://attack.mitre.org/techniques/T1608/) | Stage Capabilities | Tools are unpacked, made executable and verified before use. |
| ATT&CK | [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container | Public images are pulled and attached to the core network. |
| ATLAS | [AML.T0016.001](https://atlas.mitre.org/techniques/AML.T0016.001) | Obtain Capabilities: Software Tools | ML libraries are obtained to build and attack the model. |
| FiGHT | [FGT1588.002](https://fight.mitre.org/techniques/FGT1588.002) | Obtain Capabilities: Tool | 5G-specific attack tooling obtained for use against the core. |

**Impact.** Arbitrary capability can be introduced to the host that terminates every 5G
reference point. An attacker with a shell inherits the same path, and runtime package
installation inside NF containers means no deployed image can be trusted to match its manifest.

**Detection.** Alert on outbound HTTP/HTTPS from NF hosts to anything outside an approved
mirror. Alert on `wget`, `curl`, `apt install` or `pip install` executing on a production NF
host or inside a container. Alert on image pulls from registries other than the approved
internal one. In this dataset every one of those signals fired and none was acted on.

**Mitigation.** Default-deny egress from NF hosts, with an allow-list to internal mirrors only.
Immutable, read-only container filesystems so runtime installation fails. Image signing with
admission-time verification. Remove package managers and download utilities from production
images.

**References.** NIST SP 800-190 §4.2, §4.4; GSMA FS.31; CIS Docker Benchmark 4.x.

---
