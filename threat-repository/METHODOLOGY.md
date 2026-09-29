# Methodology

How this repository was produced, what was verified, and where the limits are.

---

## 1. Inputs

| Artefact | Volume | Role |
|---|---|---|
| `exercises_logs_anonymised/captures/module{0,1,2,4,5,6,7,8,9}.pcap` | 9 files, 1,250,047 frames, 140 MB | Primary evidence |
| `netflows/module{0..9}.pcap_Flow.csv` | 10 files, 24,905 flow records, 84 features each | Primary evidence; **sole** evidence for module3 |
| `exercises_logs_anonymised/histories/bash_history_v{1,2}` | 989 commands | Intent and tooling |
| `exercises_logs_anonymised/anonymisation_report.{md,json}` | — | Provenance; what was redacted |

All captures are `LINKTYPE_LINUX_SLL2` (276), i.e. `tcpdump -i any` on a modern libpcap. That
matters in two ways, both handled explicitly:

- **Every frame is seen twice** on the host, once per interface it traverses (bridge and veth).
  All counts in this repository are reported as captured. Where a ratio matters — 352 G-PDU
  against 352 Error Indication, 101,159 ARP requests against 32 replies — the duplication affects
  both sides equally and the ratio is unaffected.
- **The capture point is the container host**, so it sees the whole Docker bridge: N2, N3, N4, the
  SBI and the subscriber database all at once. This is itself a finding (TR-OPS-001) and the
  reason the analysis is possible at all.

`module3.pcap` (581.7 MB, 4,267,925 frames) is excluded from the repository by `.gitignore`
because it exceeds GitHub's 100 MB hard per-file limit. Its NetFlow derivative is present and is
cited as the evidence base for TR-N2-001.

---

## 2. Tooling

No third-party libraries were available in the analysis environment and none were needed. Five
dependency-free Python 3 modules were written for this work and ship in [`tools/`](tools/):

| Tool | Purpose |
|---|---|
| `pcap_lib.py` | Streaming pcap reader. Decodes SLL2 → IPv4/IPv6 → TCP/UDP/SCTP/ICMP → NGAP, PFCP, GTP-U, HTTP/2 SBI, MongoDB, DNS, ARP. Includes NGAP procedure codes (TS 38.413), PFCP message types and cause values (TS 29.244), GTP-U message types (TS 29.281) and SCTP chunk types (RFC 4960). |
| `analyse_pcap.py` | Per-capture protocol profile: protocol mix, endpoint roles, control-plane message counts, talker pairs, per-second burst detection, and the frame numbers that evidence each behaviour. Emits JSON. |
| `analyse_netflow.py` | CICFlowMeter CSV profile: flows by protocol, top talkers, fastest flows, micro-flows, control-plane port totals, source fan-out. |
| `deepdive.py` | Targeted extraction: `timeline`, `filter`, `arp`, `burst`, `flowpair` modes over any src/dst/port/proto/app selector. |
| `strings_pcap.py` | Printable-ASCII extraction from L5 payloads, attributed to the sending endpoint. Used to fingerprint network functions from SBI JSON and to locate credential material. |
| `dump_frame.py` | Hex and ASCII dump of named frames with their decoded headers, for verbatim quotation. |

Whole-corpus analysis runs in about eight seconds, so every figure in this repository is cheap to
re-derive.

---

## 3. Procedure

### 3.1 Establish the ground truth of the environment

Network-function roles were **not** assumed from IP ordering or container names (the names are
pseudonymised and unreadable). They were derived from observed behaviour:

- Service-based interface roles from the JSON that the functions emit on TCP/7777. For example
  `{"ausfInstanceId":"e3860042-..."}` identifies 172.18.0.6 as the AUSF, and
  `{"pcfIpEndPoints":[{"ipv4Address":"172.18.0.8","port":7777}]}` identifies the PCF.
- Proxy and repository roles from the SBI connection graph: eight distinct network functions
  connect to 172.18.0.10:7777, and 172.18.0.10 is the **only** client of 172.18.0.13:7777. That
  is an SCP in indirect-communication mode fronting an NRF, and nothing else fits.
- Reference-point roles from the transport: SCTP/38412 identifies N2 and therefore the AMF;
  UDP/8805 identifies N4 and therefore the SMF–UPF pair; UDP/2152 identifies N3.
- The RAN pair from UDP/4997, UERANSIM's radio-link simulation channel, cross-checked against
  which endpoint also holds the N2 association.

The result is [ENVIRONMENT.md](ENVIRONMENT.md). Each attribution there records the evidence that
produced it.

### 3.2 Profile every capture

`analyse_pcap.py --all` was run over all nine captures, producing the JSON profiles in
[`evidence/module-profiles/`](evidence/module-profiles/). Each profile records protocol mix,
control-plane message counts by type, distinct TEIDs and SEIDs, SCTP chunk distribution, ARP
target counts, per-second peaks and the frames that evidence them.

### 3.3 Find the anomalies quantitatively

Rather than looking for known attack signatures, each capture was compared against the others and
against its own baseline:

- **Rate outliers.** Peak packets-per-second per capture, and the endpoint pair responsible.
  module2 peaks at 18,947 pps against a 62 pps average; module5 at 8,534 pps against 149.
- **Protocol ratio outliers.** In module1, GTP-U G-PDU and GTP-U Error Indication both total 352 —
  a 100% failure rate on the user plane.
- **Request/response asymmetry.** ARP requests against ARP replies for the same pair, tracked
  across all captures. Balanced in module0 and module1 (138/138, 186/186), collapsing to
  101,159/32 in module2 and to zero replies from module5 onward.
- **Identifier entropy.** Every PFCP SEID observed across the corpus was collected and its bit
  width measured. The maximum is `0xf45`, so 12 bits, against the 64 bits the specification
  provides.

### 3.4 Correlate with operator intent

The two shell histories were read end to end and aligned to the captures using the `tcpdump -w
moduleN.pcap` invocations that bracket each module. This gives each capture a purpose and turns
ambiguous traffic into explained traffic. The mapping is in
[FINDINGS-REPORT.md](FINDINGS-REPORT.md) section 2.

Shell history is treated as evidence of **intent and capability**, never of effect: it carries no
timestamps and no exit codes. Where history and traffic disagree, traffic wins, and the
disagreement is recorded (see TR-N4-003).

### 3.5 Extract literal evidence

Every finding was reduced to specific frames, flow rows or history lines, and those were dumped
verbatim with `dump_frame.py` or `strings_pcap.py`. No finding in the catalogue is supported by a
paraphrase.

### 3.6 Classify

Findings were mapped against MITRE ATT&CK Enterprise, MITRE ATLAS and MITRE FiGHT using the rules
in [TAXONOMY.md](TAXONOMY.md) section 6. Technique identifiers and names were verified against
`attack.mitre.org`, `atlas.mitre.org` and `fight.mitre.org` at the time of writing rather than
recalled — ATLAS in particular has renamed several techniques (for example `AML.T0020` is now
*Training Data Poisoning*, and its "ML" techniques are now "AI" techniques), and stale identifiers
would make the mapping useless.

---

## 4. Verification performed

| Check | Method | Result |
|---|---|---|
| Decoder correctness | Protocol field values cross-checked against 3GPP message-type tables; NGAP procedure codes and PFCP message types resolve to sensible procedure sequences (InitialUEMessage → InitialContextSetup → PDUSessionResourceSetup). | Pass |
| MongoDB unauthenticated | Byte search for `saslStart`, `saslContinue`, `SCRAM-SHA`, `authenticate`, `speculativeAuthenticate` across all MongoDB frames in module0 and module5. | No token found — no authentication handshake exists |
| Credential correlation | The K and OPc in the module5 database response byte-compared against the values in `bash_history_v1` line 43. | Identical |
| SEID bit width | All PFCP SEIDs across all captures collected; maximum value measured. | `0xf45`, 12 bits |
| Replay signature | Flow records with exactly 4,000 packets counted in module3. | 69 flows, matching `-Xforward.nb-copies=2000` observed bidirectionally |
| Network-function attribution | Each role derived independently from at least two of: SBI JSON content, connection graph, transport port. | All roles consistent |
| Capture integrity | Frame counts compared against `anonymisation_report.md`. | Match for all nine present captures |

---

## 5. Limits and caveats

These are stated plainly because a threat repository that hides its gaps is not usable.

1. **module3 has no packet-level evidence.** TR-N2-001 rests on CICFlowMeter records and shell
   history. The flow evidence is strong — packet counts, rates, exact-4000-packet flows, the
   bidirectional SCTP association with the AMF — but no NGAP payload from the flood itself was
   examined, so the specific procedure codes replayed are not known.

2. **`-i any` double-counts.** Absolute packet counts are roughly twice the on-wire figure.
   Reported consistently as captured; ratios and rates are unaffected.

3. **Shell history is undated.** Command-to-capture alignment relies on the `tcpdump -w` markers.
   Where a command sits between two markers its capture is known, but its position within that
   window is not.

4. **HTTP/2 is only partially decoded.** HPACK is not implemented. Header names and paths are
   frequently compressed away; the findings that depend on SBI content rely on JSON **bodies**,
   which are not compressed and were recovered in full. No finding depends on a reconstructed
   HTTP/2 header.

5. **NAS payloads are not decoded.** NAS inside NGAP is security-protected after the initial
   exchange. SUCI and SUPI evidence therefore comes from the SBI JSON where the AMF and AUSF pass
   them in the clear, not from the NAS itself. This does not weaken the finding — it relocates it
   from N1 to N8/N12.

6. **Pseudonymised identifiers.** Every IMSI, IMEISV, MSISDN and key value is a pseudonym, and
   the anonymisation report confirms that no original key material survives in any encoding. The
   mapping is injective and subnet-preserving, so structural conclusions — key reuse across
   subscribers, SEID bit width, subnet topology, protocol ratios — all hold. The *values* are not
   real and must not be treated as such.

   Two of the report's own verification checks return **FAIL**, and both are worth stating:
   two MSISDN fragments survive in `module0.pcap`, and 22 distinct original addresses (the
   RFC 1918 Docker bridge addresses such as `172.18.0.14` and `172.18.0.2`) were deliberately not
   rewritten, appearing 240,036 times. Neither affects the findings here — the addresses are
   private and non-routable, and this analysis treats them as topology labels. They do mean the
   dataset should not be assumed fully scrubbed if it is redistributed.

7. **One exploit script is discussed without being read.** `pfcpExploit.py` is never present in
   the captured filesystem output — the operator searches every container for it and does not find
   it. Its behaviour is inferred from its invocation signature and from the `grep -i seid` run
   against it. TR-N4-003 is rated Probable for exactly this reason.

8. **No ML model artefacts survive.** The AI findings rest entirely on shell history: the
   training scripts, the perturbation expressions and the metric prints. Searches for
   `model|pkl|joblib|pickle` in the history return nothing, and no model file is in the dataset.
   The attack *methods* are unambiguous from the code that was typed; the resulting model
   performance figures are not independently verifiable.

---

## 6. Reproducing a specific finding

Each catalogue entry cites its locators. To re-derive the headline evidence:

```bash
cd threat-repository

# TR-DB-001 / TR-SUB-001 : SIM keys on the wire
python3 tools/dump_frame.py ../exercises_logs_anonymised/captures/module5.pcap 5243 --ascii

# TR-DB-001 : absence of any MongoDB authentication handshake
python3 tools/strings_pcap.py ../exercises_logs_anonymised/captures/module5.pcap \
        --port 27017 --grep 'sasl|SCRAM|authenticate' --min 5

# TR-N2-001 : the replay flood, from flow records
python3 tools/analyse_netflow.py ../netflows/module3.pcap_Flow.csv --top 12

# TR-N3-002 : user-plane desynchronisation
python3 tools/deepdive.py ../exercises_logs_anonymised/captures/module1.pcap filter --app GTP-U

# TR-RAN-002 : the ARP storm
python3 tools/deepdive.py ../exercises_logs_anonymised/captures/module2.pcap arp

# TR-SUB-003 : subscriber identifiers in cleartext SBI
python3 tools/strings_pcap.py ../exercises_logs_anonymised/captures/module1.pcap \
        --grep 'suci-|imsi-|imeisv-|encPermanentKey' --min 8
```
