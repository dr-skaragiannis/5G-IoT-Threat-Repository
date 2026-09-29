# Novelty Assessment — competitive positioning against prior art

**Status:** advisory. Literature checked 2026-09-30. Companion to
[`PUBLICATION-PLAN.md`](PUBLICATION-PLAN.md).

---

## 1. The honest verdict

**As currently framed, no — there is not a defensible novelty claim.** Every individual pillar of
the work has close, recent, peer-reviewed prior art, and in two cases the prior art uses the same
core implementation, the same RAN simulator and the same flow-extraction tool that this dataset
uses. A reviewer who knows the 5G security literature will find these papers in an afternoon.

That is not the same as saying the work is worthless. It says the *contribution has been claimed
in the wrong place*. There are two surviving angles that the literature genuinely has not covered
(§4), and they are reachable from what is already on disk — but they require the paper to stop
being about the catalogue and start being about the **method of reconstruction** and the
**limits of observability**.

This document exists so that you find this out now rather than from Reviewer 2.

> **Correction to earlier advice.** `PUBLICATION-PLAN.md` §2d calls the labelled dataset "the
> single most citable thing you can produce". That was written before the dataset literature was
> checked and it is **wrong** — see §2, row 3. Treat the labels as necessary infrastructure for
> your own evaluation, not as a headline contribution.

---

## 2. Prior-art collision table

| Your claim | Closest prior art | Collision |
|---|---|---|
| Threat catalogue mapped to ATT&CK + FiGHT | Vanderveen, *Threat framework for 5G* (FiGHT), 2022; Pell et al. 2021 (ATT&CK-to-5G-core); *Threat Hunting on a 5G Testbed Using MITRE FiGHT*, IEEE 2025 | **Total.** FiGHT-mapping a 5G testbed is done and published. |
| Your claim | Closest prior art | Collision |
|---|---|---|
| PFCP unauthenticated, SEID space enumerable, session teardown invisible to other NFs (`TR-N4-001/002/003`) | Amponis et al., *Threatening the 5G core via PFCP DoS attacks*, EURASIP JWCN 2022 | **Total.** They implemented session deletion/modification/establishment floods on **Open5GS and free5GC**, brute-forced the SEID, and reported that the other NFs log nothing. Your `TR-N4-*` entries independently re-observe their result. |
| GTP-U / TEID discovery and user-plane abuse (`TR-N3-001/002`) | Chen et al., *Invade the Walled Garden: Evaluating GTP Security in Cellular Networks*, IEEE S&P 2025 | **Substantial.** 38 exploitable GTP message types, 6 attack classes incl. session hijacking and user tracking, validated on Open5GS and free5GC. |
| Labelled 5G core attack dataset with CICFlowMeter flow statistics | **5GC PFCP Intrusion Detection Dataset** (Amponis, Radoglou-Grammatikis et al., 2023), IEEE DataPort + Zenodo | **Near-total, and uncomfortably close.** Same core (**Open5GS**), same RAN (**UERANSIM**), same flow tool (**CICFlowMeter**), labelled flows, PFCP attacks, published dataset. Also: 5G-NIDD (1,215,890 labelled flows, real 5GTN network, IEEE Data Descriptions 2025); *A Comprehensive 5G Dataset for Control and Data Plane Security*, IEEE CSR 2025. "Another labelled 5G core dataset" is a crowded claim. |
| Container escape, `docker.sock` abuse, lateral movement between NF containers (`TR-VIRT-001/002/003`) | **5GLatte** — *Malicious Lateral Movement in 5G Core With Network Slicing And Its Detection*, arXiv 2312.01681 | **Severe.** Multi-stage campaigns *built on ATT&CK and FiGHT*, exposed Docker/K8s API → container access → scan for NRF/SMF → escape to host → UPF traffic redirection. They also build a host-container access graph with path scoring and evaluate TPR/FPR against baselines. This pre-empts both your VIRT findings **and** the attack-graph idea in `PUBLICATION-PLAN.md` §3 Study F. |
| Your claim | Closest prior art | Collision |
|---|---|---|
| "Suricata and Zeek are blind to the 5G control plane" (Study C) | Körnings & Sjöström, *The Detection Capabilities of Zeek and Suricata in a 5GCN*, DiVA 2024 | **Partial but direct.** They tested exactly this on N4 and SBI and found neither tool identifies PFCP at all — both see only UDP — and Suricata's default ruleset triggered nothing. It is an undergraduate thesis, not a journal paper, so it is weak prior art you can cite and extend; but the *headline* is no longer a surprise. |
| Rigorous evaluation methodology for 5G core detection (Study B) | **SAGE-5GC**, arXiv 2602.03596, ITASEC 2026 | **Partial.** Guidelines for evaluating 5GC anomaly detectors, including strip-the-identifiers, preserve class imbalance, and adversarial robustness. It is ML-specific, so your deterministic analytics are not directly covered — but "we propose a rigorous evaluation methodology for 5GC detection" is taken. |
| Holistic multi-source monitoring of a containerised 5G core | *Simulation of IIoT-Driven Attack Vectors on 5G Core Networks*, ACM 2024 | **Partial.** K8s-deployed 5G core with Prometheus metrics, Loki logs and tcpdump captures combined, explicitly claiming a "uniquely holistic perspective". |
| Signals invisible to any single telemetry source | Ganiuly et al., *Cross-Layer Detection of Wireless Misbehavior Using 5G RAN Telemetry*, arXiv 2511.21803 | **Conceptual only.** Same intuition — "a distinct and reproducible signature that is not visible from any single telemetry source" — but at PHY/MAC/RAN, not the core. Your core-side version survives. |
| SUCI null scheme, cleartext SUPI/IMEISV, SIM credential exposure (`TR-SUB-*`) | Extensive IMSI-catcher and SUPI-privacy literature | **Total.** Well-trodden ground. |

### 2a. The uncomfortable detail

Amponis, Radoglou-Grammatikis and Sarigiannidis are authors on **both** the PFCP attack paper
**and** the 5GC PFCP Intrusion Detection Dataset. They are an active Greek 5G-security group
publishing continuously in this exact space. There is a real chance they end up reviewing this
paper. Cite them thoroughly, early, and generously, and be explicit about what you add.

---

## 3. What this means

Three claims are dead and should not be made:

1. **"We present a threat repository for 5G-IoT."** Repositories are not contributions.
2. **"We are the first to map 5G attacks to FiGHT."** Demonstrably false.
3. **"We release a labelled 5G core attack dataset."** True, but it joins at least four others,
   one of which was built with the identical toolchain.

Three claims are weakened but survivable if you add the delta explicitly:

4. **PFCP / GTP-U / SUCI findings** → reposition as *independent confirmation in an environment
   the authors did not construct*. Replication has value; just label it replication.
5. **Suricata/Zeek blindness** → extend from 2 incident types to 26 behaviours, add Wazuh and
   Zabbix, and you have breadth no one else has.
6. **Evaluation rigour** → yours is deterministic and non-ML, where SAGE-5GC is ML. State that.

---

## 4. What is actually novel

Two things survive the literature check. Both are methodological rather than phenomenological —
which is fine, because method is what journals reward.

### 4a. Reconstruction without control of the ground truth *(strongest)*

Every 5G security dataset paper in §2 shares one property: **the authors built the attack.**
5G-NIDD states it plainly — *"We control the attacker generating the DoS traffic and therefore
have the ground-truth knowledge about when the attack is executed and which attack types."* The
same holds for 5GC PFCP IDD, the IEEE CSR 2025 dataset, 5GLatte and the IIoT-attack-vector paper.
Labels are a byproduct of authorship.

Your situation is the inverse, and it is the situation every real analyst is in. You did not
design this exercise. You received packet captures, flow records and two shell histories, and had
to work out what happened. That reframes the whole thing from *dataset construction* to
**evidential reconstruction under uncertainty**, and it supports a research question the 5G
literature has not asked:

> *Given only the telemetry a real operator would retain, how much of a multi-stage 5G core
> attack campaign can be reconstructed, at what confidence, and what is systematically
> unrecoverable?*
You already have the machinery for this and did not realise it was the contribution:

- The **Confirmed / Probable / Possible** confidence scheme in `TAXONOMY.md`, with four evidence
  classes tied to specific artifact types. Prior work has no confidence calculus because prior
  work has certainty by construction. Yours has 25 Confirmed and 1 Probable — that distribution
  *is* a result.
- The **inference chain for NF identity**: `.15 = gNB`, `.14 = AMF`, `.12 = UPF`, `.9 = SMF`,
  `.13 = NRF`, `.10 = SCP`, derived from SBI JSON bodies, connection graphs and transport
  behaviour, not from a deployment manifest. That is attribution under uncertainty and it is
  exactly what a responder does.
- The **failure cases**: container IP reuse (`TR-VIRT-005`) destroys IP-as-identity over time;
  the bash-history oracle misses unlogged shells; a single vantage point (`TR-OPS-001`) bounds
  what is knowable. Prior work cannot report these because it never faces them.

**To defend it you must measure it**, not assert it: report reconstruction coverage (what
fraction of the attack campaign was recovered), confidence distribution, the residual `unknown`
class, and a falsification pass where you check your reconstruction against the exercise's own
documented script and report where you were **wrong**. Publishing your own reconstruction errors
is the single most credible thing this paper could do, and nobody else is positioned to do it.

### 4b. Telemetry sufficiency, quantified *(clean, defensible, smaller)*

No prior 5G core work systematically answers *which telemetry tier is the minimum sufficient one,
per behaviour*. The closest is a RAN/PHY-layer paper (§2, last row) with the same intuition in a
different layer. Your T0/T1/T2/T3 matrix over 26 behaviours, with a headline count of how many
are invisible below full packet capture, is a genuinely new and practitioner-relevant number.

It is also the result that survives every other criticism: it does not depend on the findings
being new, only on the environment being representative and the analysis being careful.

### 4c. Honourable mention

The **spec / implementation / exercise-artefact** classification (RQ5). Not novel as a technique,
but almost nobody does it, and it is the difference between "Open5GS allocates 12-bit SEIDs" and
"3GPP TS 29.244 does not mandate SEID unpredictability, so this is a specification gap".

---

## 5. The reframing

> **Old thesis.** "We built a 5G-IoT threat repository from the NITRO dataset and mapped it to
> MITRE." — a catalogue. Rejected as a technical report.

> **New thesis.** "Operators cannot detect what they cannot observe, and cannot investigate what
> they did not capture. Using a 5G-IoT cyber-range exercise we did not design, we reconstruct a
> multi-stage campaign from retained telemetry alone, measure how much is recoverable and at what
> confidence, quantify the minimum telemetry tier required per behaviour, and show that neither
> the range's own monitoring stack nor open-source NIDS detect most of it."

Working title: *What the telemetry knew: reconstructing a multi-stage 5G-IoT attack campaign from
retained evidence, and the observability limits it reveals.*

The 26 findings stop being the contribution and become the **corpus** the method is demonstrated
on. That is a much stronger position, and it is the only one in which the prior art in §2
becomes supporting citation rather than competition.

---

## 6. Consequences for venue

This changes the §12 recommendation in `PUBLICATION-PLAN.md` less than you might expect, but it
shifts the balance.

- **ACM DTRAP moves up.** Its charter asks for reproducible results on *extant* threats, studies
  of *security operations practices and TTPs*, and *assessment and measurement of security
  architectures*. A reconstruction-and-observability study is squarely that, and DTRAP is the
  venue least likely to demand phenomenological novelty. The "laboratory model" objection remains
  and still needs answering in the cover letter.
- **Computers & Security stays viable** *with the new thesis only*. COSE will accept a
  measurement and detection-engineering paper with a practitioner payload; it will not accept a
  catalogue, and it will not accept "we re-found the PFCP weaknesses".
- **IEEE TNSM** is a good fit for the observability framing specifically — telemetry sufficiency
  is a network-management question as much as a security one.

Decide the thesis before the venue. With the catalogue framing, none of them work.

---

## 7. Reading list before you write a word

Non-negotiable. Read in full, not by abstract.

1. Amponis et al., *Threatening the 5G core via PFCP DoS attacks*, EURASIP JWCN 2022 —
   `https://link.springer.com/article/10.1186/s13638-022-02204-5`
2. Amponis, Radoglou-Grammatikis et al., *5G Core PFCP Intrusion Detection Dataset*, 2023 —
   IEEE DataPort / Zenodo
3. **5GLatte**, *Malicious Lateral Movement in 5G Core With Network Slicing*, arXiv 2312.01681
4. Chen et al., *Invade the Walled Garden: Evaluating GTP Security*, IEEE S&P 2025
5. **SAGE-5GC**, arXiv 2602.03596, ITASEC 2026
6. Siriwardhana et al., *Descriptor: 5G-NIDD*, IEEE Data Descriptions 2025
7. Körnings & Sjöström, *Detection Capabilities of Zeek and Suricata in a 5GCN*, DiVA 2024
8. *Threat Hunting on 5G Future Communication Testbed Using MITRE FiGHT*, IEEE 2025
9. *A Comprehensive 5G Dataset for Control and Data Plane Security*, IEEE CSR 2025

For each, write one sentence: *what they did, and what we do that they did not.* If you cannot
write the second half for a paper, that part of your work is not a contribution.

## 8. Decision point

Answer these before investing the 7–8 weeks in `PUBLICATION-PLAN.md` §10:

1. **Will you adopt the reconstruction-and-observability thesis (§5)?** If no, stop — there is no
   publishable novelty at Q1 level and the work should be released as a technical report or
   project deliverable instead, which is a perfectly respectable outcome.
2. **Can you obtain the exercise's authored attack script** to run the falsification pass in §4a?
   Without it you can still report confidence distributions, but you lose the strongest single
   result — measured reconstruction accuracy including your own errors.
3. **Is a second vantage point or a re-run of the exercise available?** If yes, the observability
   study gets much stronger, because you can measure what a *different* capture position would
   have revealed.

---


---

## 9. Appendix — what "the authored attack script" means

Referenced in §8, decision point 2. Defined here because it is the difference between a
reconstruction you can grade and one you cannot.

### 9a. Definition

The **authored attack script** is the exercise designer's own specification of what the exercise
was supposed to do, written *before* it ran. In cyber-range practice it appears as some mix of:

- a **scenario definition** — modules, objectives, and the attack assigned to each;
- a **master scenario events list (MSEL)** or inject schedule — what fires, against what, when;
- **orchestration code** — the Ansible playbooks, shell wrappers or CI jobs that launched the
  attacks, including the tool configuration they passed;
- **tool configuration** — for this exercise specifically, the 5GReplay rule XML files. The
  histories already reference `/home/noinr/5Greplay-0.0.1/rules/forward-localhost.xml`, so these
  files exist somewhere and are a partial oracle on their own;
- **attacker and target inventory** — which host played attacker, which container was the target.

It is *statement of intent*. It is authoritative because it was written by the people who
decided what would happen.

### 9b. Why the bash histories are not the same thing

The histories are **residue of execution**, not statement of intent. The difference matters:

| | Authored script | Bash history |
|---|---|---|
| Written | before the exercise, by the designer | during, by the shell, incidentally |
| Covers | everything planned | only what was typed in a logged, interactive bash |
| Misses | what actually deviated from plan | GUI actions, `docker exec` internals, cron, unlogged shells, other users |
| Timing | explicit schedule | **none — these files have no timestamps** |
| Intent | explicit | must be inferred |

Using history to check a reconstruction that was *derived from* history is circular. The
authored script is the only independent oracle available.

### 9c. Why it is worth chasing

It enables the **falsification pass** in §4a: freeze your reconstruction, then compare it against
the script and report where you were wrong — missed attacks, phantom attacks, misattributed
actors, wrong intervals. Measured reconstruction accuracy, including your own errors, is the
single most credible result this paper could contain, and it is unavailable to every prior work
in §2 because they all authored their own attacks.

### 9d. It is not in the dataset

Confirmed by inspection. `exercises_logs_anonymised/` contains only the nine pcaps, the two
histories and the anonymisation report; `netflows/` contains only the ten CICFlowMeter CSVs.
There is no scenario document, module description or orchestration code anywhere in the
repository. It must be requested from whoever ran the exercise.

### 9e. What to ask the NITRO partners for

1. The scenario or module definition — the mapping from `module0`…`module9` to intended activity.
2. The inject schedule or timeline, with wall-clock times if they exist.
3. Orchestration scripts and the 5GReplay rule XML files actually used.
4. The host/container inventory: attacker origin, intended targets, and the NF-to-IP mapping, so
   your inferred topology (`.15` gNB, `.14` AMF, `.12` UPF, `.9` SMF, `.13` NRF, `.10` SCP) can
   be scored rather than asserted.
5. Confirmation that the subscriber population is synthetic — needed for §6a regardless.

Ask for items 1 and 4 even if nothing else is available; alone they let you score module
segmentation and NF attribution.

### 9f. If it cannot be obtained

Ranked substitutes, none as strong:

1. **Pre-registration.** Freeze and publish the reconstruction with a hash, *then* request the
   script. If it arrives later, the comparison is more credible than if you had it all along. If
   it never arrives, the frozen artifact still demonstrates the method was not fitted post hoc.
2. **Independent blind reconstruction.** A co-author reconstructs from the same evidence without
   seeing your results; report agreement and every disagreement. This measures *reliability*
   rather than *accuracy* — weaker, but honest, and it is co-author coding, not human subjects.
3. **Partial oracles.** The 5GReplay rule files define what was injected; the module boundaries
   imply intended segmentation; NF container names in `docker` commands partially confirm the
   IP-to-NF mapping.
4. **Report confidence only.** Drop accuracy claims, publish the Confirmed/Probable/Possible
   distribution and the `unknown` count, and state plainly in threats-to-validity that no
   independent ground truth was available. Weakest option, but survivable if §4b carries the
   paper.

---

*Literature checked 2026-09-30 via arXiv, IEEE Xplore, ACM DL, SpringerLink and DiVA. Impact of
any single collision depends on the reviewer; the aggregate is what matters, and the aggregate
here is decisive.*
