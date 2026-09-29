# Publication Plan — targeting *Computers & Security* (Elsevier)

**Status:** advisory document. Written 2026-09-30 against the contents of
[`../threat-repository/`](../threat-repository/). Not part of the threat repository itself.

> **Read [`NOVELTY-ASSESSMENT.md`](NOVELTY-ASSESSMENT.md) first.** A literature check found close
> prior art for most of the contributions claimed below, including a labelled 5G dataset built
> with the identical Open5GS + UERANSIM + CICFlowMeter toolchain. That document supersedes the
> contribution framing in §2d and the paper thesis in §2b.

---

## 0. Verdict in one paragraph

What exists today is a high-quality **engineering artifact**: 26 evidence-linked findings from one
cyber-range exercise, mapped to three MITRE frameworks. That is a *deliverable*, not yet a *paper*.
A reviewer at a Q1 venue will ask three questions — *what is the research contribution?*, *how was
it evaluated?*, *does it generalise beyond one testbed?* — and the repository currently answers
none of them. The good news: the raw material to answer all three is already on disk, and the
single highest-value addition (ground-truth labels + a quantitative detection evaluation) needs no
new experiments and no human subjects. The bad news: **there is a scope problem with *Computers &
Security* specifically**, described next, and it is a desk-reject risk rather than a review risk.

---

## 1. BLOCKING: the C&S AI/ML moratorium

Verbatim from the journal's Aims and Scope page (checked 2026-09-30):

> **AI and ML:** As of early 2024, we have instituted a moratorium on consideration of submissions
> that feature AI or ML as significant components. Thus, submissions about applying an AI/ML
> technique to system security and privacy topics will not be considered. Also, items directed to
> the security of AI/ML systems themselves (such as LLM and federated learning) are out of scope of
> the journal and should be submitted to a venue primarily about AI/ML.

> **Cryptology:** ... excluded ... since 2006 ... submissions with some aspect of cryptology
> (including blockchains, watermarking, and steganography) as a principal component will not be
> considered for review.

This has two consequences for the current material.

**1a. The four AI entries are out of scope as a headline.** `TR-AI-001` (training-data poisoning),
`TR-AI-002` (adversarial evasion), `TR-AI-003` (three-feature model), `TR-AI-004` (unprotected
corpus) are precisely "the security of AI/ML systems themselves". Likewise the ATLAS mapping —
currently 16 techniques / 19 mappings — is the framework *for* AI security. If AI is a pillar of
the paper, C&S is the wrong journal.

*Mitigations, in order of preference:*

- **Demote, do not delete.** Keep the AI findings as one sub-section of the results, framed as
  *"the range's detection layer was itself attacked, and it is one more monitored asset that
  produced no alert"*. Do not put AI/ATLAS in the title, abstract, contributions, or RQs. Judge
  the risk by weight: if AI content exceeds roughly 10% of the paper, expect a desk reject.
- **Split the paper.** Publish the 22 network/virtualisation findings at C&S; publish the AI
  thread separately at an AI-security venue where ATLAS is welcome. Two papers, cleaner claims.
- **Change venue** (see §1c).

**1b. Keep the crypto findings, but frame them as deployment security.** `TR-SUB-001` (K/OPc in
cleartext), `TR-SUB-002` (SUCI null-scheme) and `TR-N2-002` (no IPsec) are *not* cryptology
research — no algorithm, cryptanalysis or construction is proposed. They are key-management and
configuration failures observed on the wire. Say so explicitly in the paper so a screening editor
does not mistake them for crypto work. Never write "we analyse the SUCI encryption scheme"; write
"we observe that the null protection scheme is deployed, so SUPIs traverse the air interface and
N2 in cleartext".

**1c. Venue alternatives.** See **§12** for the full venue analysis and the recommended
submission sequence. Short version: with the AI thread removed, *Computers & Security* becomes
the right target; with the AI thread central, it is the wrong one.

---

## 2. The contribution gap — what the paper must claim

### 2a. What is wrong with the current framing

"We built a threat repository from a dataset" is a *description*. Descriptions are rejected at Q1
venues with the phrase *"the paper reads as a technical report; the scientific contribution is
unclear"*. Three specific weaknesses:

1. **Enumeration is not synthesis.** 26 entries cannot go in the body. The paper needs findings
   *about* the 26 — patterns, rates, a theory of why they were missed — with the catalogue itself
   relegated to an appendix and the online artifact.
2. **No novelty position.** Applying FiGHT to a 5G testbed has been done (see §7). Documenting
   PFCP/SEID weakness in Open5GS has been done, in detail, by Amponis et al. (2022). Without an
   explicit delta, the contribution reads as a replication.
3. **No evaluated claim.** Every claim currently is "we observed X". None is "X holds, and here is
   the measurement, the baseline, the error bars, and the held-out test that confirms it".

### 2b. The reframing that works

Lead with the **detection failure**, not the catalogue. The strongest empirical fact already in
hand is that a fully instrumented range — Zabbix plus Wazuh plus flow export — produced **no
alert** for attacks that are trivially visible in the packet record. That is a measurable,
practitioner-relevant, non-AI result, and it is exactly the "we don't only highlight the threats,
we give you the solutions" posture C&S advertises.

> **Working title.** *Blind spots in 5G core telemetry: an evidence-linked threat
> characterisation and detection-engineering evaluation on a containerised 5G-IoT range.*

### 2c. Research questions

- **RQ1 — Characterisation.** What adversary behaviours are observable in the packet, flow and
  host record of a containerised 5G-IoT range exercise, and how do they map onto ATT&CK and FiGHT?
- **RQ2 — Telemetry sufficiency.** For each behaviour, which telemetry tier (host agent, bi-flow
  record, full packet capture) is *sufficient* for detection, and which tiers are blind?
- **RQ3 — Detection.** Can deterministic, threshold-based analytics derived from measured
  baselines detect these behaviours at operationally acceptable precision and latency, and do
  thresholds fitted on one capture transfer to unseen captures?
- **RQ4 — Comparison.** How much of the behaviour is detected by the state of practice — the
  range's own Zabbix/Wazuh deployment, and open-source NIDS (Suricata with ET Open, Zeek)?
- **RQ5 — Generality.** Which findings are *specification*-level (any conformant 5G core) versus
  *implementation*-level (this Open5GS build) versus *exercise artefacts*?

RQ5 is cheap to answer and disproportionately valuable: it is the axis that turns "we found bugs
in one testbed" into "we found a class of weakness". Example: SUCI null-scheme is permitted by
3GPP TS 33.501, so `TR-SUB-002` is spec-level; a 12-bit SEID space is an Open5GS allocation
choice, so `TR-N4-002` is implementation-level; the stale-RAN-peer ARP storm is probably an
exercise artefact of container IP reuse and should be labelled as such, honestly.

### 2d. Claimable contributions

- **C1.** An evidence-linked threat characterisation of a containerised 5G-IoT range: 26 findings,
  each traceable to a specific frame, flow record or shell command, released machine-readable.
- **C2.** A **labelled derivative** of the NITRO 5G Exercise Dataset — ground-truth attack
  intervals and per-flow labels — released with a DOI. *(See §3, Study A. The shipped `Label`
  column is `NeedManualLabel` for all 24,885 flow records, so you need these labels for your own
  evaluation. **Downgraded**: at least four labelled 5G core attack datasets already exist, one
  built with the same toolchain — see `NOVELTY-ASSESSMENT.md` §2. Necessary infrastructure, not a
  headline contribution.)*
- **C3.** A **telemetry-sufficiency matrix**: which of the 26 behaviours are detectable from host
  agents, from bi-flow records, and only from full packet capture — quantified.
- **C4.** Deterministic detection analytics with measured thresholds, evaluated for precision,
  recall, detection latency and threshold sensitivity, with **cross-capture** (train/test)
  validation and no machine learning.
- **C5.** A quantified state-of-practice baseline: what the range's own Zabbix/Wazuh stack and
  what Suricata/Zeek detect, out of the 26.
- **C6.** A spec-vs-implementation-vs-artefact classification of every finding (RQ5), plus
  candidate techniques that FiGHT does not currently represent — concrete feedback to MITRE.

C2, C3 and C5 are the ones that do not already exist in the literature. C1 alone is not enough.

---

## 3. The analyses you still need (none require human subjects)

Each study below states what it answers, what input it needs, and whether the data is already on
disk. **Studies A–E need nothing but the existing captures.** F–H need extra work.

### Study A — Ground truth labelling *(P0, blocking everything else)*

**Problem.** Every flow record in `netflows/module*.csv` carries `Label = NeedManualLabel`. All
24,885 of them. Without labels there is no confusion matrix, hence no evaluation, hence no paper.

**Method.**
1. Build an **attack timeline oracle** from the two bash histories (`bash_history_v1`, 500 lines;
   `bash_history_v2`, 489 lines). Each attack command gives a start marker; the next unrelated
   command or a measured quiescence gives an end marker.

   > **Correction (verified 2026-09-30).** Two constraints found by inspecting the files:
   > **(a) The histories carry no timestamps.** Neither file was written with `HISTTIMEFORMAT`;
   > the only two `#` lines are commented-out commands, not epoch markers. So history-to-capture
   > alignment cannot use a clock offset and must be done by **content anchoring** — match a
   > command to the packets it must have produced (e.g. the 21 `./5greplay` invocations against
   > the NGAP flood in module3), then order the rest by history sequence between anchors.
   > **(b) The histories are mixed-purpose.** Command census: `docker` 276, `kill` 50, `tshark`
   > 49, `nohup` 47, `ps` 45, `find` 43, `ls` 40, `grep` 26, `./5greplay` 21, `python3` 17,
   > `tcpdump` 11. Capture setup, container administration and exploration dominate; genuine
   > attack invocations are a minority. Classify every line as setup / exploration / attack /
   > analysis before using it as an oracle, and report that breakdown — it is itself a result
   > about how much of an operator's shell record is evidentially useful.
2. Align history time to capture time. The anonymisation report states relative timing is
   preserved with a **constant offset of 19,515,057 µs** — that offset applies to *packet*
   timestamps only, so use it to relate captures to each other, not to relate history to capture.
   Validate any alignment on an event visible in both records (e.g. the first 5GReplay packet in
   module3 versus a `./5greplay` invocation).
3. Emit **labelled intervals**: `(capture, t_start, t_end, TR-id, actor_ip, victim_ip, protocol)`.
4. Project intervals onto (a) packets and (b) CICFlowMeter bi-flows by 5-tuple and time overlap.
   State the overlap rule precisely — a flow is `attack` iff its `[Timestamp, Timestamp+Duration]`
   intersects an interval **and** its 5-tuple matches the actor/victim pair.
5. Label classes: `benign`, plus one class per attack family, plus `unknown` for anything the
   oracle cannot adjudicate. **Publish the `unknown` count.** Honest abstention is a strength;
   silently labelling everything benign is the classic flaw in derived datasets.

**Validation (and why this is not human-subjects research).** Two or three co-authors
independently label a stratified sample of ~400 flows; report **Cohen's κ** (two coders) or
**Fleiss' κ** (three) plus the disagreement taxonomy. Coding by the author team is standard
methodological practice, not research *on* human participants — no IRB/ethics board involvement is
normally required. The same applies to the severity re-scoring in Study F. Only recruiting
*external* participants (e.g. surveying SOC analysts about usability) would raise a human-subjects
question, and none of the studies here need that.

**Output.** `artifact/labels/*.csv`, a labelling script, and a datasheet. Deposit on Zenodo.
**Effort.** 3–5 days. **Paper value:** very high — it is a standalone citable artifact.

### Study B — Evaluate the detection analytics *(P0)*

`DETECTION.md` is planned but unwritten. **A proposed rule is worth very little; an evaluated
rule is a contribution.** Do not ship detection logic without a confusion matrix.

**Method.** For each rule, using Study A labels:

- **Effectiveness:** TP / FP / FN / TN, precision, recall, F1, and false positives per hour on
  benign-only windows. Report FP/hour, not just FPR — reviewers from operations care about alert
  volume, and a 0.1% FPR on 10^6 flows/hour is 1,000 alerts.
- **Threshold sensitivity.** Sweep each threshold and plot detection rate against FP/hour. This
  is the non-ML equivalent of an ROC curve and is entirely legitimate under the C&S moratorium —
  it is descriptive statistics, not a learned model. Justify the operating point you pick.
- **Cross-capture validation.** Fit thresholds on a subset of captures, test on held-out ones —
  e.g. fit the ARP ratio and NGAP rate bounds on modules 0/1/5, test on 2/3/6. Report both. This
  pre-empts "your thresholds are overfitted to the traffic you looked at".
- **Detection latency.** Packets and wall-clock seconds from the first attack packet to the rule
  firing. For the module3 NGAP flood, latency at a 1-second window versus a 10-second window.
- **Cost.** Throughput (packets/s, flows/s) and peak memory of the detector on commodity
  hardware, to argue line-rate feasibility. A table of per-rule cost is cheap to produce and
  reviewers like it.

**Thresholds already measured** and ready to be turned into evaluated rules:

| Signal | Benign baseline | Attack observation |
|---|---|---|
| ARP request:reply ratio | 1:1 (m0 138/138, m1 186/186) | 3161:1 (m2 101,159/32); m5 6,132/0; m6 96,285/0 |
| GTP-U Error Indication rate | ~0 | 352 G-PDU vs 352 Error Indication (m1) |
| NGAP messages/s per association | < 5/s | 69 flows of exactly 4,000 packets (m3) |
| PFCP SEID entropy | 32-bit space expected | 26 distinct SEIDs, max `0xf45` = 12 bits |
| MongoDB client string | absent | `mongosh 2.4.2` against `open5gs.subscribers`, no auth |
| Cleartext identifiers on SBI | none expected | `imsi-`, `encPermanentKey`, `encOpcKey` in the clear |

### Study C — State-of-practice baseline *(P0, this is your comparison section)*

Every Q1 paper needs a comparison against what exists. Yours writes itself:

1. **The range's own stack.** Zabbix and Wazuh were deployed and, per the exercise record,
   produced nothing. Quantify it: of 26 findings, how many produced *any* alert, any log line,
   any metric excursion? Retain the raw evidence — a null result you can document is worth far
   more than a null result you assert.
2. **Open-source NIDS, replayed offline.** Run **Suricata** (ET Open ruleset) and **Zeek** over
   each pcap and count which of the 26 behaviours raise an alert or a notice. Both read pcap
   directly, so no testbed is needed. Expect them to catch almost nothing — Suricata has scant
   PFCP/NGAP coverage and Zeek needs a 5G package — and *that is the result*: the state of
   practice is blind to the 5G control plane.
3. **Optional, strong:** the same for a commercial or open 5G-aware probe if you have access.

Report as a single table: rows = 26 findings, columns = {Wazuh, Zabbix, Suricata, Zeek, ours},
cells = detected / partial / missed. This one table will carry the paper.

*Caveat to handle up front:* the pcaps are anonymised and were captured at one vantage point, so
a missed detection might be an artefact of the capture rather than of the tool. Check, and say so.

### Study D — Telemetry-sufficiency matrix *(P1, novel and cheap)*

For each of the 26 findings, determine the **minimum telemetry tier** that suffices:

| Tier | What it is | Example finding it can/can't see |
|---|---|---|
| T0 host agent | Wazuh/auditd on the container host | sees `TR-VIRT-001` container escape commands; blind to N4 |
| T1 bi-flow | CICFlowMeter 84-feature records | sees the m3 NGAP flood as volume; blind to `TR-N4-002` SEID content |
| T2 headers | 5-tuple + protocol decode, no payload | sees GTP-U Error Indication storms and TEID reuse |
| T3 full payload | complete capture | required for `TR-SUB-001` K/OPc, `TR-DB-002` Mongo extraction |

Then state the headline number: *"N of 26 behaviours are invisible below T2, and operators
overwhelmingly deploy T0+T1."* That is a genuinely new, practitioner-facing, non-AI result, and it
follows directly from analysis you have already done.

### Study E — Framework coverage and gap analysis *(P1)*

You have 83 distinct techniques across three frameworks. Turn that into measurement:

- **Coverage.** What fraction of FiGHT's 5G technique space does this one exercise exercise?
  Report as a heatmap over FiGHT tactics. Tactics with zero coverage are a **dataset gap map** —
  useful to anyone building the next 5G range, and a contribution in itself.
- **Declared gaps as findings.** You already note no Persistence and no C2 in `MITRE-MAPPING.md`.
  Do not bury that: an exercise with no persistence and no C2 is not a full kill chain, and
  saying so plainly is the kind of honesty reviewers reward.
- **Technique gaps in FiGHT.** Any behaviour you had to map to a generic ATT&CK technique because
  FiGHT lacked one is a **candidate sub-technique proposal**. Even three well-argued proposals
  make a real contribution and give the discussion section something forward-looking.
- **Mapping reliability.** Two coders independently map a sample of findings to techniques;
  report κ. Framework mapping is subjective and reviewers know it; measuring the subjectivity
  disarms the objection.

### Study F — Defensible risk scoring *(P1)*

Critical/High/Medium as currently assigned is expert judgement with a rubric. That is defensible
only if it is reproducible. Do one of:

- **CVSS v4.0** base + threat metrics per finding, with the full vector string published so
  anyone can recompute. Cheap, familiar to reviewers, but a poor fit for signalling-plane
  weaknesses — acknowledge that.
- **Attack-graph composition.** Chain the 26 into multi-stage paths (e.g. `TR-VIRT-004` flat L2 →
  `TR-DB-001` open Mongo → `TR-SUB-001` K/OPc theft → `TR-RAN-001` rogue UE) and score paths, not
  atoms. Richer, more novel, more work. Three or four well-drawn kill chains as figures would
  strengthen the paper considerably.
- **Both**, with CVSS in the appendix table and attack graphs in the body.

Whichever you choose, report **inter-rater agreement on severity** and a sensitivity analysis:
how many findings change tier if one rubric weight changes? Again, co-author coding — not human
subjects.

### Study G — External validity *(P1; the "one testbed" objection)*

This is the objection most likely to sink the paper: *one exercise, one containerised Open5GS
deployment, synthetic traffic, ten captures.* Three escalating answers:

1. **Cheapest — cross-dataset rule transfer.** Apply your detection rules unchanged to a second,
   independent public 5G dataset such as **5G-NIDD** (Siriwardhana et al.; public DOI
   `10.23729/e80ac9df-d9fb-47e7-8d0d-01384a415361`). Report precision/recall there. Even partial
   transfer is strong evidence the analytics are not testbed-specific. Cost: days.
2. **Medium — second implementation.** Reproduce two or three key findings on **free5GC** rather
   than Open5GS (SEID width, PFCP acceptance without authentication, SUCI scheme in use). If both
   implementations behave the same way, the finding is class-level rather than a bug in one
   product. Cost: 1–2 weeks with a testbed.
3. **Free — the RQ5 classification.** Label every finding spec / implementation / artefact with a
   cited justification (3GPP TS 33.501, TS 29.244, TS 38.413). Costs nothing but reading, and
   converts a large part of the external-validity objection into an analysis contribution.

Do at least 1 and 3. Do 2 if a testbed is available.

### Study H — Validate the countermeasures *(P2, but high reward)*

C&S markets itself on *"we don't only highlight the threats, we give you the solutions"*.
Unvalidated recommendations ("enable IPsec on N2") read as boilerplate. Pick **three** findings
and actually measure the fix:

| Finding | Fix to test | Measure |
|---|---|---|
| `TR-N4-002` 12-bit SEID | patch SEID allocation to 32-bit CSPRNG | attacker attempts to hit a live SEID; session-establishment latency and UPF CPU before/after |
| `TR-N2-002` no IPsec on N2 | enable IPsec/IKEv2 gNB–AMF | replay attack success; attach latency and throughput cost |
| `TR-DB-001` open MongoDB | SCRAM auth + bind to management net | extraction attempt fails; NF start-up and query latency delta |

Report effectiveness **and overhead**. A residual-risk table — which findings remain after all
proposed mitigations, and why — is a strong way to close the paper.

---

## 4. Measurement rigour — fixing the statistics

The repository currently reports raw counts. Counts alone invite "so what?". Upgrade:

- **Baselines with dispersion.** For every signal used in a rule, characterise the benign
  distribution across all captures: median, IQR, 95th/99th percentile, n. "ARP request:reply is
  1:1" should become "1.00 (IQR 0.98–1.02, n = 324 over two captures)".
- **Effect size, not just ratio.** 3161:1 is vivid but unanchored. Express as standard deviations
  from the benign mean, or as a likelihood ratio. Reviewers will ask how the 3161:1 figure would
  look under a noisier, production workload — answer pre-emptively.
- **Confidence intervals** on every rate reported in the paper (Wilson intervals for
  proportions, bootstrap for ratios). Tiny effort, large credibility gain.
- **Per-capture n everywhere.** Several captures are small (module9: 456 flows). Do not average
  across captures of wildly different size without saying so.
- **Negative controls.** Run the rules over captures with no corresponding attack and report the
  false-positive count explicitly, per capture.
- **Sensitivity to the capture window.** Report the exact UTC window per capture (you have these)
  and note that some findings may be window artefacts.

## 5. Threats to validity — write this section explicitly

Reviewers grade honesty. `METHODOLOGY.md` already lists eight limitations; promote them into a
proper section organised the standard way.

**Construct validity.** Bash history is an imperfect oracle: it omits commands run in unlogged
shells, GUI actions and anything run in a container without history. Absence in history is not
absence of activity. CICFlowMeter's bi-flow abstraction discards exactly the payload that several
findings depend on.

**Internal validity.** Single vantage point (`TR-OPS-001`) — the capture position determines what
is observable, so "not detected" may mean "not visible from here". Attribution of an IP to a
network function is inferred from SBI JSON and connection graphs, not from ground truth. Container
IP reuse (`TR-VIRT-005`) makes IP-based identity unstable across time.

**External validity.** One range, one core implementation, one exercise script, synthetic
subscriber population, IoT traffic that is emulated rather than real. Traffic volumes are orders
of magnitude below a production core, so false-positive rates measured here are lower bounds.

**Conclusion validity.** Anonymisation altered the data. Be specific: the anonymisation report
records **two failed checks** — MSISDN material surviving in `module0.pcap`, and 22 distinct
original RFC1918 addresses surviving 240,036 occurrences. Payload rewriting can also break
checksums and length fields in ways that affect parsing. State which findings depend on rewritten
fields. Also note `module3.pcap` (581.7 MB) is excluded from the repository for size, so that
capture's packet-level claims rest on the flow CSV alone — a reviewer will spot this.

## 6. Ethics, data availability, and Elsevier administrivia

**6a. Resolve the anonymisation failures before submission.** This is the item most likely to
cause a problem at editorial screening, and it is currently unresolved.

- If the subscribers are **synthetic test SIMs** in a cyber range — which the shared K/OPc across
  six IMSIs strongly suggests — then there is no personal data and no GDPR issue. **Say this
  explicitly, with evidence**, in a data statement. Do not leave the reader to infer it.
- If any identifier could relate to a real person, re-run anonymisation until all checks pass and
  re-publish the report. Do not submit with two failing checks and no explanation.
- Either way, publish the anonymisation report as a supplement. Documented imperfect
  anonymisation is respectable; undocumented is not.

**6b. Permission and provenance.** NITRO is an EU-funded project with its own published cyber
range paper (ACM, DOI `10.1145/3664476.3669919`). Confirm in writing that you may analyse and
publish findings from the dataset, cite the NITRO paper as the dataset source, and state the
licence under which your derived labels are released (CC BY 4.0 is the usual choice).

**6c. Responsible disclosure.** Separate *misconfiguration of this deployment* from *weakness in
an upstream product*. If anything is the latter (e.g. Open5GS SEID allocation width), notify the
maintainers before publication and record the disclosure timeline in the paper. Reviewers at C&S
do check for this.

**6d. Elsevier submission requirements** — cheap to satisfy, embarrassing to miss.

- **Highlights:** 3–5 bullets, max 85 characters each.
- **Declaration of generative AI use:** Elsevier requires a statement if AI tools assisted the
  writing. This analysis pipeline and drafting were AI-assisted, so a declaration is required.
  Note that AI tools cannot be listed as authors, and the authors remain fully responsible for
  every claim — which means every number in the paper must be independently re-verified by a
  human before submission.
- **CRediT author statement**, declaration of competing interests, funding statement (NITRO grant
  number).
- **Data availability statement** pointing at the Zenodo DOI for code and labels.
- Length: a C&S research article typically runs 8,000–12,000 words. The 26-entry catalogue does
  **not** fit and must move to an appendix plus the online artifact.

## 7. Related work you must engage (non-negotiable)

Missing any of these invites "the authors appear unaware of closely related work".

| Work | Why it matters to you |
|---|---|
| Amponis et al., *Threatening the 5G core via PFCP DoS attacks*, EURASIP JWCN 2022 | **Closest prior work.** Implements unauthorised PFCP session deletion/modification/establishment floods against Open5GS **and** free5GC, including SEID brute-forcing and the observation that other NFs log nothing. This overlaps `TR-N4-001/002/003` and part of `TR-N3-002`. You must cite it and state your delta — yours is *observational from an independent exercise, with detection analytics and an evaluation*; theirs is *constructive attack implementation*. |
| Chen et al., *Invade the Walled Garden: Evaluating GTP Security in Cellular Networks*, IEEE S&P 2025 | GTP/GTP-U attack classes incl. session hijacking and user tracking; overlaps `TR-N3-001/002`. |
| Salazar et al., **5GReplay** | The tool that produced the module3 NGAP flood. Cite as the attack instrument. |
| Vanderveen, *Threat framework for 5G cellular communications* (FiGHT), 2022 | The framework paper for FiGHT. |
| *Threat Hunting on 5G Future Communication Testbed Using MITRE FiGHT*, IEEE 2025 | **Direct precedent** for FiGHT-based analysis of a 5G testbed — so "first FiGHT mapping" is not a claim you can make. Differentiate on evidence linkage, labels and detection evaluation. |

| Work | Why it matters to you |
|---|---|
| Pell et al., *Towards dynamic threat modelling in 5G core networks based on MITRE ATT&CK*, 2021 | Prior ATT&CK-to-5G mapping. |
| 5G-NIDD (Siriwardhana et al., IEEE Data Descriptions 2025) | The comparison dataset for Study G, and the model to imitate for how to document a released dataset. |
| ENISA *5G Threat Landscape*; 3GPP TR 33.926; GSMA FS.11 / FS.31 baseline controls; NIST SP 1800-33 | Standards-side threat catalogues. Reviewers will ask how your taxonomy relates to them. A short mapping table from your 9 domains to TR 33.926 asset classes and GSMA FS.31 controls would answer it in half a page. |
| NITRO cyber range paper, ACM 2024, DOI `10.1145/3664476.3669919` | The source of your dataset. Cite for the testbed description. |

Also survey 5G dataset papers generally, and position your labelled derivative among them.

## 8. Proposed paper structure

| § | Content | Words |
|---|---|---:|
| 1 | Introduction: 5G core telemetry blind spots; contributions C1–C6; RQ1–RQ5 | 1,000 |
| 2 | Background: 5G SBA, N2/N3/N4 reference points, ATT&CK/FiGHT (ATLAS one sentence) | 900 |
| 3 | Related work, with an explicit delta table | 1,000 |
| 4 | Dataset and environment: range architecture, captures, anonymisation and its failures | 900 |
| 5 | Methodology: analysis pipeline, labelling protocol, κ, mapping rules, threat model | 1,500 |
| 6 | Results I — characterisation: synthesis of 26 findings by domain; spec/impl/artefact split (RQ1, RQ5) | 1,800 |
| 7 | Results II — telemetry sufficiency (RQ2) | 800 |
| 8 | Results III — detection evaluation and state-of-practice comparison (RQ3, RQ4) | 1,800 |
| 9 | Mitigations and validated countermeasures; residual risk | 900 |
| 10 | Threats to validity | 700 |
| 11 | Discussion, FiGHT gap proposals, conclusion | 900 |
| — | Appendix: full 26-entry catalogue, CVSS vectors, rule listings | — |

**Figures and tables that must exist** (there are currently none — a paper with no figures will
not survive review):

1. Range architecture with capture vantage points and the two networks marked.
2. Exercise timeline: captures on the x-axis, attack intervals shaded, findings annotated.
3. Coverage heatmap: 26 findings x FiGHT/ATT&CK tactics.
4. Telemetry-sufficiency matrix (Study D).
5. Detection-rate versus false-positives-per-hour curves for the main rules (Study B).
6. Detection comparison table: findings x {Wazuh, Zabbix, Suricata, Zeek, ours} (Study C).
7. Two or three attack-graph kill chains (Study F).
8. Baseline-versus-attack distributions for two or three headline signals, with dispersion.

## 9. Anticipated reviewer objections and prepared answers

| Objection | Answer you need to have ready |
|---|---|
| "This is a technical report, not research." | RQ1–RQ5, an evaluation with confusion matrices, and a comparison baseline. This is the whole point of §3. |
| "Only one testbed." | Study G: cross-dataset transfer to 5G-NIDD, plus the spec/impl/artefact classification. |
| "PFCP attacks are already known (Amponis 2022)." | Agreed and cited. Delta: independent observational confirmation, plus detection analytics and evaluation, which prior work did not provide. |
| "Synthetic traffic; your FP rates are meaningless at scale." | Report FP/hour with volume caveats; state explicitly that they are lower bounds; sensitivity analysis over traffic volume. |
| "Thresholds are overfitted." | Cross-capture train/test split and the threshold sweep. |
| "Ground truth is unreliable." | Published labelling protocol, κ, explicit `unknown` class, released labels for scrutiny. |
| "AI content is out of scope." | Demote to one sub-section; keep ATLAS out of title/abstract/contributions. |
| "Anonymisation failed twice." | Data statement explaining synthetic subscribers, or re-anonymised data. Resolve before submission. |
| "module3.pcap is not in the repository." | State the size constraint, publish the checksum, and make the pcap available on request or via Zenodo. |
| "Severity ratings are subjective." | CVSS v4.0 vectors published, inter-rater agreement reported, sensitivity analysis. |

## 10. Prioritised work plan

**P0 — without these there is no paper** (all doable from data already on disk):

| # | Task | Study | Est. |
|---|---|---|---|
| 1 | Ground-truth labels from the bash-history oracle; publish protocol, κ, `unknown` count | A | 3–5 d |
| 2 | Write `DETECTION.md` rules, then evaluate them: P/R/F1, FP/hour, latency, threshold sweep, cross-capture split | B | 5–8 d |
| 3 | Suricata + Zeek + Wazuh/Zabbix comparison table over all 26 findings | C | 3–4 d |
| 4 | Reframe around RQ1–RQ5; rewrite `FINDINGS-REPORT.md` as synthesis, not enumeration | §2 | 3 d |
| 5 | Related-work section with the delta table; obtain and read Amponis 2022 and Chen 2025 in full | §7 | 3 d |
| 6 | Resolve the anonymisation failures and write the data statement | §6a | 1–2 d |

**P1 — the difference between "accept with revisions" and "reject":**

| # | Task | Study | Est. |
|---|---|---|---|
| 7 | Telemetry-sufficiency matrix | D | 2 d |
| 8 | Spec / implementation / artefact classification of all 26, with 3GPP citations | G3 | 2–3 d |
| 9 | Cross-dataset rule transfer to 5G-NIDD | G1 | 3–5 d |
| 10 | CVSS v4.0 vectors + inter-rater agreement + sensitivity | F | 2–3 d |
| 11 | Coverage heatmap and FiGHT gap proposals | E | 2 d |
| 12 | Statistical upgrade: baselines with IQR/CIs, effect sizes, negative controls | §4 | 2–3 d |

**P2 — strong extras:**

| # | Task | Study | Est. |
|---|---|---|---|
| 13 | Validated countermeasures for three findings, with overhead | H | 1–2 wk (needs testbed) |
| 14 | Reproduce key findings on free5GC | G2 | 1–2 wk (needs testbed) |
| 15 | Attack-graph kill chains and path scoring | F | 4 d |
| 16 | Zenodo artifact: code, labels, rules, datasheet, DOI | C2 | 2 d |

Rough total: **P0 ≈ 4 weeks, P0+P1 ≈ 7–8 weeks**, excluding writing.

## 11. The three things that matter most

If time is short, this is the ranking.

1. **Ground-truth labels and a detection evaluation** (Studies A + B). This is what converts a
   catalogue into research. Nothing else has the same return, and it needs no new data.
2. **A comparison baseline** (Study C). "Zabbix, Wazuh, Suricata and Zeek detected *n* of 26; our
   analytics detected *m*" is the sentence that makes the abstract worth reading.
3. **Deciding the AI question** (§1). Demote it for C&S, or pick another venue. Getting this
   wrong wastes a submission cycle on a desk reject.

Everything else — CVSS vectors, heatmaps, attack graphs — improves the paper. Those three
determine whether it is publishable at this tier at all.

---

## 12. Venue selection (with the AI thread removed)

All figures checked 2026-09-30 from the publishers' own pages; impact metrics move yearly, so
re-check before submitting.

### 12a. The candidates

| Venue | Publisher | IF | CiteScore/SJR | OA model | Scope fit | Verdict |
|---|---|---:|---:|---|---|---|
| **Computers & Security (COSE)** | Elsevier | **6.8** | 15.4 | Hybrid, APC optional (USD 3,190 if OA) | Threat analysis + detection + practical controls; audit/control audience | **Primary target** |
| **ACM DTRAP** | ACM | ~3.0 | SJR 0.615 (Q1) | Gold OA, APC mandatory | Purpose-built for TTP studies, threat landscapes, detection practice | **Best scope fit; use if COSE rejects** |
| **IEEE TNSM** | IEEE | **5.7** | 10.9 | Hybrid | Network/service management, monitoring, case studies | Strong alternative |
| **Computer Networks (COMNET)** | Elsevier | 4.7 | 8.9 | Hybrid | §4 Network Security incl. IDS and DoS | Solid fallback + dataset article venue |
| **JISA** | Elsevier | ~4.5 | — | Hybrid | Applied infosec | Fallback |
| **IEEE Access** | IEEE | ~3.4 | — | Gold OA | Anything | Only if speed beats prestige |
| **IEEE TIFS / TDSC** | IEEE | 8+ | — | Hybrid | Deep novelty, often theoretical | **Do not** — a measurement-plus-catalogue paper will not clear the novelty bar |

### 12b. Why *Computers & Security* is still the right primary target

1. **The only blocker was the AI moratorium.** Remove the AI thread and the scope objection
   disappears. Nothing else in the work — 5G signalling, container security, telemetry gaps,
   detection engineering — is excluded. Cryptology is excluded too, but your key-management
   findings are observational, not cryptographic research (§1b).
2. **Best metrics of any realistic option.** IF 6.8, CiteScore 15.4 — higher than TNSM (5.7),
   COMNET (4.7) and DTRAP (~3.0).
3. **Editorial posture matches the paper you should write.** COSE advertises *"We don't only
   highlight the threats, we give you the solutions"* and targets practitioners in security,
   audit and control. A paper whose punchline is *"here is what your monitoring stack cannot
   see, and here are evaluated detections for it"* is written for that readership.
4. **No mandatory APC.** COSE is hybrid, so the subscription route costs nothing. DTRAP is Gold
   OA and the APC is unavoidable — relevant if the NITRO grant has no publication budget.
5. **Turnaround is good for a Q1 journal.** Published timeline: ~3 days to first decision (i.e.
   desk screening), ~53–56 days submission-to-decision after review, ~150–162 days to
   acceptance, ~6–12 days to online publication. The fast desk screening cuts both ways: a scope
   or framing error is caught in days, so §1 and §2 must be right at submission.

**The catch.** COSE's bar is the evaluation, not the subject. Submitting the catalogue as it
stands — 26 described findings, no labels, no confusion matrix, no comparison baseline — will
fail. Studies A, B and C in §3 are the price of admission at this venue.

### 12c. When to choose ACM DTRAP instead

DTRAP's stated scope reads like a description of your work: *adversary tactics*, *threat
landscape studies*, *systems analysis*, *studies of security operations processes/practices/
TTPs*, *assessment and measurement of security architectures*, *threat information management
and sharing*, *impact of new technologies/protocols on the threat landscape*. It also has a
**Field Notes** article type for empirical observations that do not fill a full research paper,
and it explicitly values reproducibility and released artifacts — which is exactly what a threat
repository plus labelled dataset is.

**One real risk, stated plainly.** The DTRAP charter says the journal *"welcomes manuscripts
that address extant digital threats, rather than laboratory models of potential threats"*. A
cyber-range exercise is, literally, a laboratory model. You can answer this — the weaknesses are
in real deployed software (Open5GS), real protocol design (PFCP has no authentication by
specification) and real operator configurations (SUCI null scheme) — but you must answer it in
the cover letter, not leave the editor to notice it.

### 12d. The two-paper strategy (recommended)

Do not try to publish the dataset, the repository and the detection evaluation in one article.
Split them; each is stronger alone, and the pair cross-cite.

**Paper 1 — the research article.** *Computers & Security.* The narrative of §2b: telemetry
blind spots in the 5G core, 22 non-AI findings synthesised, telemetry-sufficiency matrix,
evaluated detection analytics, comparison against Wazuh/Zabbix/Suricata/Zeek. The 26-entry
catalogue goes to an appendix and the online artifact.

**Paper 2 — the data descriptor.** The labelled derivative of the NITRO dataset (Study A). Three
good homes, in order:

| Venue | Why |
|---|---|
| **IEEE Data Descriptions** | Published the 5G-NIDD descriptor — direct precedent, same audience, same subject area. Short article, peer-reviewed, indexed. |
| **Computer Networks — Dataset Article** | COMNET explicitly publishes *micro-articles describing open datasets*, and separately *open-source software articles*. Your tooling could go the same route. |
| **Elsevier *Data in Brief*** | Lowest bar, fastest, least prestige. |

Submit Paper 2 first or in parallel. It gives Paper 1 a citable data-availability anchor, and a
descriptor is much easier to get accepted than a full research article, so it banks a result
early.

**Paper 3 — optional, later.** The AI thread (`TR-AI-001`–`004`, ATLAS mappings) at an
AI-security venue. Do not let it delay Papers 1 and 2.

### 12e. Recommended sequence

1. Finish `FINDINGS-REPORT.md` and `DETECTION.md`, then execute Studies A, B, C (§3, P0).
2. Submit **Paper 2** (data descriptor) to IEEE Data Descriptions; deposit labels on Zenodo or
   IEEE DataPort with a DOI.
3. Submit **Paper 1** to *Computers & Security*, AI thread demoted to a short sub-section or cut
   entirely, with a cover letter that states the contribution and pre-empts the "one testbed"
   objection.
4. If COSE rejects on fit rather than substance, go to **ACM DTRAP** (reframed for practitioners,
   possibly as two Field Notes) or **IEEE TNSM** (reframed around monitoring and management).
   Keep *Computer Networks* and *JISA* in reserve.

---

*Sources checked 2026-09-30: aims-and-scope pages for Computers & Security and Computer Networks
(sciencedirect.com); ACM DTRAP charter and CFP (dl.acm.org/journal/dtrap); IEEE Data Descriptions
aims and scope (ieeexplore.ieee.org); SCImago and publisher metric pages for IF/CiteScore/SJR;
label census over `netflows/module*.csv` (24,885 records, all `NeedManualLabel`);
`exercises_logs_anonymised/anonymisation_report.md`.*
