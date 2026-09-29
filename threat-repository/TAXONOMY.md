# Taxonomy

The classification scheme used throughout this repository. It exists so that two people reading
the same evidence arrive at the same label.

---

## 1. Identifier syntax

```
TR-<DOMAIN>-<NNN>
 │      │       └── three-digit sequence, allocated in order of discovery within the domain
 │      └────────── domain key, see section 2
 └───────────────── "threat repository"
```

Identifiers are **stable and never reused**. If an entry is withdrawn its ID is retired, not
recycled, so that external references stay meaningful.

---

## 2. Domains

The domain says *where in the 5G system* the threat lives. It follows the 3GPP reference-point
decomposition rather than a generic IT taxonomy, because the interface a weakness sits on
determines who can reach it and which specification governs it.

| Key | Domain | Reference points | Scope |
|---|---|---|---|
| `RAN` | Radio access and radio-link simulation | Uu, RLS | UE, gNB, cell search, attach behaviour |
| `N2` | NGAP control plane | N2 | gNB to AMF over SCTP, NAS transport |
| `N3` | GTP-U user plane | N3 | gNB to UPF tunnels, TEIDs, user traffic |
| `N4` | PFCP session management | N4 | SMF to UPF, session establishment and deletion |
| `SUB` | Subscriber identity and credentials | N1, N8, N12, N13 | SUPI, SUCI, IMEISV, K, OPc, privacy |
| `DB` | Subscriber data repository | UDR backing store | MongoDB, provisioning, bulk access |
| `VIRT` | Virtualisation and segmentation | NFVI | containers, capabilities, escape, L2 design |
| `AI` | AI/ML security | IDS pipeline | training data, models, features, evasion |
| `OPS` | Operational security | cross-cutting | tooling, capture position, detection posture |

A threat gets exactly one domain — the one where the **weakness** lives, not where the impact
lands. TR-N4-002 (predictable PFCP session IDs) is `N4` even though the impact is a dropped user
session on N3, because N4 is where the fix goes.

---

## 3. Severity

Severity answers: *if a capable adversary exploited this in a production network, how bad is it?*
It is a property of the weakness, not of the exercise. The exercise was authorised; the weakness
would not be.

| Level | Definition | Test |
|---|---|---|
| **Critical** | Directly yields subscriber impersonation, long-term credential disclosure, core-wide denial of service, or host compromise. No further weakness needed. | Would this alone justify an emergency change window? |
| **High** | Discloses subscriber-identifying data, enables session-level attack against specific users, or materially defeats a security control. Usually needs one more step to reach full impact. | Would this alone justify a prioritised fix in the next cycle? |
| **Medium** | Provides reconnaissance value, degrades service, or weakens defence in depth without directly compromising anything. | Would this appear as a finding in an audit report? |
| **Low** | Hygiene. Noise, poor practice, or a latent condition with no demonstrated path to impact. | Worth recording, not worth escalating. |

Three rules keep this honest:

1. **Severity is not reduced because the environment is a lab.** The finding describes the
   weakness; the lab is just where it was observed.
2. **Severity is not increased because a tool was used.** Running 5GReplay does not make NGAP
   replay more severe than it already is — the absence of anti-replay on N2 is the finding.
3. **Chained severity is recorded on the chain, not the link.** Where several Medium findings
   combine into a Critical outcome, the individual entries keep their own rating and the chain is
   documented in [FINDINGS-REPORT.md](FINDINGS-REPORT.md).

---

## 4. Confidence

Confidence answers: *how certain are we that this happened, or that this weakness is real?*

| Level | Definition |
|---|---|
| **Confirmed** | Observed directly in at least one artefact, and either corroborated by a second independent artefact or demonstrated by protocol-level decode. No inference required. |
| **Probable** | Strongly implied by observed artefacts and consistent with all of them, but the decisive moment is not itself captured. A reasonable alternative explanation exists but is less likely. |
| **Possible** | Consistent with the evidence and worth recording, but other explanations fit equally well. Recorded so it can be tested, not relied upon. |

Worked examples from this dataset:

- **Confirmed** — TR-DB-001. The MongoDB response carrying six subscriber records with `k` and
  `opc` fields is in `module5.pcap` frame 5243. The absence of any SCRAM handshake on the same
  connection is verified by byte search. Two artefacts, no inference.
- **Probable** — TR-N4-003. `pfcpExploit.py` is searched for across every container in the shell
  history and `cat pfcpExploit.py | grep -i seid` is run, so the script exists and targets SEIDs.
  But module6's PFCP traffic shows only SMF-to-UPF heartbeats, so the exploit either did not fire
  or fired outside the capture window. The capability is confirmed; the execution is not.
- **Possible** — noted inline where it occurs; no Possible-only entry is rated above Medium.

---

## 5. Evidence classes

Every evidence item is tagged with its source class, because the classes have different
evidential weight.

| Class | What it is | Strength | Weakness |
|---|---|---|---|
| `pcap` | Bytes on the wire, decoded to protocol fields | Strongest. Shows what actually happened, not what was intended. | Only covers the capture window; `-i any` sees duplicates. |
| `netflow` | CICFlowMeter 84-feature bidirectional records | Survives when the pcap does not (module3). Good for rate and volume. | No payload; direction inference can be wrong for UDP. |
| `bash` | Operator shell history | Shows intent and tool invocation explicitly. | No timestamps, no exit codes; a command in history may have failed. |
| `derived` | Aggregates computed by the tooling in `tools/` | Quantifies patterns invisible frame by frame. | Only as good as the script; every derived figure names the command that produced it. |

**A finding rated Confirmed must cite at least one `pcap` or `netflow` item, or two independent
`bash` items.** Shell history alone never confirms an effect, only an attempt.

---

## 6. TTP mapping rules

Three frameworks are used together because no single one covers this system:

| Framework | Covers | Used for |
|---|---|---|
| [MITRE ATT&CK Enterprise](https://attack.mitre.org/) | General IT adversary behaviour | Containers, credentials, discovery, DoS, collection |
| [MITRE ATLAS](https://atlas.mitre.org/) | Adversarial threats to AI systems | Everything touching the IDS model and its training data |
| [MITRE FiGHT](https://fight.mitre.org/) | 5G-specific adversary behaviour | NGAP, PFCP, GTP-U, SUPI/SUCI, RAN, network functions |

Mapping rules:

1. **Map behaviour, not tooling.** The technique is "replay valid signalling at volume", not
   "5GReplay was installed".
2. **Prefer the most specific framework.** If FiGHT has `FGT5031 Discover Tunnel Endpoint ID`,
   use it rather than the generic ATT&CK `T1046`. Where both add information, cite both — FiGHT
   techniques carry an `&` marker upstream when they are adaptations of ATT&CK, and the parent is
   given alongside.
3. **Every mapping carries a rationale.** A technique ID without a sentence explaining why the
   observed behaviour matches it is not a mapping, it is decoration.
4. **Sub-techniques where the evidence supports them.** `T1499.001` is only used when the
   exhaustion mechanism is actually visible; otherwise the parent `T1499` is used.
5. **No speculative mapping.** Techniques the adversary *could* have used next are discussed in
   the impact text, not added to the mapping table.

---

## 7. Entry template

Every catalogue entry carries the same fields, in the same order:

| Field | Contract |
|---|---|
| **Domain / Severity / Confidence** | Per sections 2–4. |
| **Affected assets** | Identifiers from [ENVIRONMENT.md](ENVIRONMENT.md), never bare IPs. |
| **What happened** | Plain description of the observed behaviour. No jargon that is not defined. |
| **Why this is a threat** | The justification. Must explain both the mechanism and the severity/confidence choice. |
| **Evidence** | Literal quotes with artefact and locator. Nothing paraphrased. |
| **TTP mapping** | Framework, ID, name, rationale. |
| **Impact** | What a real adversary gets. |
| **Detection** | What a defender watches for, with thresholds from this dataset where available. |
| **Mitigation** | What removes the weakness, ordered most-effective first. |
| **References** | 3GPP / GSMA / RFC anchors. |
