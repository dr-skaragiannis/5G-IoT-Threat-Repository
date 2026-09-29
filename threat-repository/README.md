# NITRO 5G-IoT Threat Repository

An evidence-backed catalogue of threats, weaknesses and adversary behaviours observed in the
**NITRO 5G Exercise Dataset v1.0** — nine packet captures, ten NetFlow feature sets and two shell
histories recorded across a containerised 5G standalone core, its simulated RAN, and an
AI/ML-based intrusion-detection pipeline built on top of them.

Every entry in this repository is derived from the artefacts in this git repository. Nothing is
hypothetical, and nothing is inherited from a generic threat list. Each finding quotes the packet
frame, flow record or shell command it rests on.

---

## What is here

| Document | What it gives you |
|---|---|
| **[THREAT-REPOSITORY.md](THREAT-REPOSITORY.md)** | The catalogue. One entry per threat: what happened, why it matters, the literal evidence, the TTP mapping, impact, detection and mitigation. |
| **[FINDINGS-REPORT.md](FINDINGS-REPORT.md)** | The narrative. What the dataset actually records, capture by capture, reconstructed as a single timeline. Read this first if you want the story. |
| **[MITRE-MAPPING.md](MITRE-MAPPING.md)** | Coverage matrices against MITRE ATT&CK Enterprise, MITRE ATLAS and MITRE FiGHT, plus the tactic-by-tactic kill chain. |
| **[TAXONOMY.md](TAXONOMY.md)** | The classification scheme: domains, severity model, confidence model, identifier syntax, and the rules used to decide them. |
| **[METHODOLOGY.md](METHODOLOGY.md)** | How the analysis was done, what tooling was written, what was verified and what the known limits are. Enough to reproduce the results. |
| **[ENVIRONMENT.md](ENVIRONMENT.md)** | The asset inventory and network topology, reconstructed purely from traffic. Which IP is which network function and how that was proven. |
| **[DETECTION.md](DETECTION.md)** | Detection logic per threat: what to alert on, with thresholds taken from the measured baselines in this dataset. |

Machine-readable views live in **[data/](data/)**; raw derived evidence lives in
**[evidence/](evidence/)**; the analysis tooling lives in **[tools/](tools/)**.

---

## Headline findings

| ID | Threat | Severity |
|---|---|---|
| TR-DB-001 | Subscriber database answers unauthenticated queries and returns permanent SIM keys | Critical |
| TR-SUB-001 | SIM long-term keys (K and OPc) recoverable in cleartext for every subscriber | Critical |
| TR-RAN-001 | Rogue UE attaches to the live core using those cloned credentials | Critical |
| TR-N2-001 | NGAP replay flood against the AMF, 2000x duplication, accepted and processed | Critical |
| TR-N4-002 | PFCP session identifiers fit in 12 bits — a 4,096-entry brute-force space, not 2^64 | Critical |
| TR-VIRT-001 | Container escape to the host from a privileged network-function container | Critical |
| TR-AI-001 | Training-data poisoning of the intrusion-detection model | High |
| TR-AI-002 | Adversarial evasion of that model by halving one packet-length feature | High |

The full catalogue contains **26 entries** across nine domains.

---

## The dataset this was built from

```
exercises_logs_anonymised/
  captures/module{0,1,2,4,5,6,7,8,9}.pcap    9 captures, 1.25 M frames, 140 MB
  histories/bash_history_v{1,2}              989 operator shell commands
  anonymisation_report.{md,json}             provenance and redaction record
netflows/
  module{0..9}.pcap_Flow.csv                 10 CICFlowMeter feature sets, 84 features
```

`module3.pcap` is **not** in this repository — at 581.7 MB it exceeds GitHub's hard per-file limit.
It is the most important capture in the set, because it contains the NGAP replay flood. Its
NetFlow derivative `netflows/module3.pcap_Flow.csv` **is** present and carries the full evidential
weight for TR-N2-001. Findings that depend on it are marked accordingly.

All identifiers in the dataset are pseudonyms. See
[`../exercises_logs_anonymised/anonymisation_report.md`](../exercises_logs_anonymised/anonymisation_report.md)
for what was replaced and what survived. The pseudonyms are internally consistent, so the analysis
is unaffected; the values must not be treated as real subscriber data.

---

## How to reproduce

The tooling has no third-party dependencies — Python 3 alone.

```bash
# protocol profile for every capture
python3 tools/analyse_pcap.py --all --out evidence/module-profiles/

# flow-level profile, including the module3 replay flood
python3 tools/analyse_netflow.py ../netflows/module3.pcap_Flow.csv

# the frame that leaks the SIM keys
python3 tools/dump_frame.py ../exercises_logs_anonymised/captures/module5.pcap 5243 --ascii

# GTP-U tunnel state, showing 100% Error Indication
python3 tools/deepdive.py ../exercises_logs_anonymised/captures/module1.pcap filter --app GTP-U
```

See [METHODOLOGY.md](METHODOLOGY.md) for the full command set behind each finding.

---

## Scope and intent

This repository is a **defensive** artefact. It exists to let a blue team, an auditor or a
researcher see precisely which weaknesses a 5G standalone core of this shape exposes, how those
weaknesses appear on the wire, and what would have to change to close them. Techniques are
described at the level of detail needed to detect and fix them, and no further: no exploit code is
reproduced here, and the one exploit script referenced in the shell history (`pfcpExploit.py`) is
discussed by behaviour and not by content.

The environment is a laboratory exercise range. The operator activity in the shell histories is
authorised red-team and research work, not an intrusion. It is classified with adversary
frameworks here because that is the most useful way to reason about what the same actions would
mean in production — which is the point of the exercise.
