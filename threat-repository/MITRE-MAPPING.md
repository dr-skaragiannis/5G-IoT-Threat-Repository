# MITRE Mapping

Coverage of the 26 catalogue entries against the three frameworks used in this repository.
Mapping rules are in [TAXONOMY.md](TAXONOMY.md) §6. Machine-readable form:
[`data/mitre-mappings.csv`](data/mitre-mappings.csv).

| Framework | Scope | Techniques cited | Mappings |
|---|---|---:|---:|
| [MITRE ATT&CK Enterprise](https://attack.mitre.org/) | General IT adversary behaviour | 31 | 62 |
| [MITRE ATLAS](https://atlas.mitre.org/) | Adversarial threats to AI systems | 16 | 19 |
| [MITRE FiGHT](https://fight.mitre.org/) | 5G-specific adversary behaviour | 36 | 60 |
| **Total** | | **83** | **141** |

## Why three frameworks

ATT&CK describes what an adversary does to computers; it has no vocabulary for NGAP, PFCP, SUCI
or TEIDs. ATLAS describes what an adversary does to AI systems; it has no vocabulary for
telecommunications. FiGHT is the 5G-specific extension of ATT&CK and covers precisely the
signalling-layer behaviour that dominates this dataset — but it stops at the AI boundary.

Because this exercise is a 5G core *with* an AI intrusion-detection layer bolted on, and because
both are attacked, no single framework describes it. The three are used together, with the most
specific one preferred where they overlap: `FGT5031 Discover Tunnel Endpoint ID` rather than a
generic `T1046`, but `T1040 Network Sniffing` where the behaviour genuinely is just sniffing.

FiGHT techniques marked `&` upstream are adaptations of an ATT&CK parent; where the parent adds
information both are cited.

## Attack narrative by tactic

The exercise traverses a coherent kill chain. Read left to right:

| Tactic | What happened here | Threats |
|---|---|---|
| **Reconnaissance** | Container, capability, AppArmor and kernel enumeration; ARP sweep of the core; N4 listener discovery; NF service discovery via unprotected NRF/SCP traffic | TR-VIRT-002, TR-VIRT-003, TR-VIRT-004, TR-N4-003 |
| **Resource Development** | 5GReplay, `arp-scan`, `tshark`, ML libraries and public container images pulled onto the core host | TR-OPS-002, TR-N2-001, TR-N4-003 |
| **Initial Access** | Rogue UE attaches with cloned SIM credentials; disposable container attaches to the core network | TR-RAN-001, TR-DB-002 |
| **Execution** | `docker exec` into production network functions; exploit script invoked against N4 | TR-VIRT-003, TR-N4-003 |
| **Privilege Escalation** | `mount` + `chroot` out of a privileged NF container onto the host | TR-VIRT-001, TR-VIRT-002 |
| **Credential Access** | Unauthenticated read of the subscriber database yields K and OPc for every subscriber | TR-DB-001, TR-SUB-001 |
| **Discovery** | TEID enumeration on N3; SEID observation on N4; SUPI-to-IP bindings from the SBI | TR-N3-001, TR-N4-002, TR-SUB-004 |
| **Collection** | Host-wide packet capture across all eleven modules; ML corpus built from that capture | TR-OPS-001, TR-AI-004 |
| **Exfiltration** | Entire subscriber base returned in two frames to an ephemeral container | TR-DB-002 |
| **Defense Evasion** | IDS poisoned to ignore one class; adversarial inputs crafted to evade it; `--rm` destroys forensic residue | TR-AI-001, TR-AI-002, TR-AI-003, TR-DB-002 |
| **Impact** | NGAP replay flood against the AMF; user-plane desynchronisation; RAN signalling storm | TR-N2-001, TR-N3-002, TR-RAN-002 |

The chain is notable for how short it is. Credential Access (`TR-DB-001`) requires only network
reachability, and network reachability is universal (`TR-VIRT-004`). There is no step in this
chain that depends on exploiting a software vulnerability — every one is a configuration or
design property.

---

## Technique coverage

### ATT&CK (31 techniques)

| Technique | Name | Threats |
|---|---|---|
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | TR-AI-004, TR-OPS-001 |
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | TR-VIRT-004 |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | TR-VIRT-005 |
| [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | TR-N2-002, TR-N3-001, TR-N4-001, TR-OPS-001, TR-SUB-001, TR-SUB-002, TR-SUB-003, TR-SUB-004, TR-VIRT-004 |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | TR-N3-001, TR-N4-003 |
| [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal | TR-VIRT-005 |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Indicator Removal: File Deletion | TR-DB-002 |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | TR-SUB-003 |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | TR-RAN-001 |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Valid Accounts: Default Accounts | TR-DB-001 |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | TR-VIRT-002 |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | TR-OPS-002 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | TR-N4-002 |
| [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | TR-AI-004, TR-DB-002, TR-OPS-001, TR-SUB-004 |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | TR-DB-001, TR-DB-002, TR-SUB-001 |
| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | TR-N2-001, TR-RAN-002 |
| [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | TR-N3-002, TR-N4-002 |
| [T1499.001](https://attack.mitre.org/techniques/T1499/001/) | Endpoint DoS: OS Exhaustion Flood | TR-RAN-002 |
| [T1499.002](https://attack.mitre.org/techniques/T1499/002/) | Endpoint DoS: Service Exhaustion Flood | TR-N2-001 |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | TR-VIRT-001, TR-VIRT-002 |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | TR-DB-001, TR-DB-002, TR-SUB-001 |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | TR-AI-001, TR-AI-002 |
| [T1565](https://attack.mitre.org/techniques/T1565/) | Data Manipulation | TR-N4-002 |
| [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | Data Manipulation: Stored Data Manipulation | TR-AI-001 |
| [T1565.002](https://attack.mitre.org/techniques/T1565/002/) | Data Manipulation: Transmitted Data Manipulation | TR-N2-001, TR-N4-001 |
| [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | TR-N2-001, TR-N4-003, TR-OPS-002 |
| [T1608](https://attack.mitre.org/techniques/T1608/) | Stage Capabilities | TR-N4-003, TR-OPS-002 |
| [T1609](https://attack.mitre.org/techniques/T1609/) | Container Administration Command | TR-VIRT-001, TR-VIRT-003 |
| [T1610](https://attack.mitre.org/techniques/T1610/) | Deploy Container | TR-DB-002, TR-OPS-002, TR-RAN-001 |
| [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | TR-VIRT-001, TR-VIRT-003 |
| [T1613](https://attack.mitre.org/techniques/T1613/) | Container and Resource Discovery | TR-VIRT-001, TR-VIRT-002, TR-VIRT-003 |

### ATLAS (16 techniques)

| Technique | Name | Threats |
|---|---|---|
| [AML.T0010.002](https://atlas.mitre.org/techniques/AML.T0010.002) | AI Supply Chain Compromise: Data | TR-AI-004 |
| [AML.T0013](https://atlas.mitre.org/techniques/AML.T0013) | Discover AI Model Ontology | TR-AI-003 |
| [AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) | Evade AI Model | TR-AI-002, TR-AI-003 |
| [AML.T0016.001](https://atlas.mitre.org/techniques/AML.T0016.001) | Obtain Capabilities: Software Tools | TR-OPS-002 |
| [AML.T0018.000](https://atlas.mitre.org/techniques/AML.T0018.000) | Manipulate AI Model: Poison AI Model | TR-AI-001 |
| [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) | Training Data Poisoning | TR-AI-001 |
| [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) | Exfiltration via Cyber Means | TR-AI-004 |
| [AML.T0031](https://atlas.mitre.org/techniques/AML.T0031) | Erode AI Model Integrity | TR-AI-001, TR-AI-003 |
| [AML.T0035](https://atlas.mitre.org/techniques/AML.T0035) | AI Artifact Collection | TR-AI-004 |
| [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037) | Data from Local System | TR-AI-004 |
| [AML.T0042](https://atlas.mitre.org/techniques/AML.T0042) | Verify Attack | TR-AI-001, TR-AI-002 |
| [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043) | Craft Adversarial Data | TR-AI-002 |
| [AML.T0043.000](https://atlas.mitre.org/techniques/AML.T0043.000) | Craft Adversarial Data: White-Box Optimization | TR-AI-002 |
| [AML.T0043.003](https://atlas.mitre.org/techniques/AML.T0043.003) | Craft Adversarial Data: Manual Modification | TR-AI-002 |
| [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044) | Full AI Model Access | TR-AI-002 |
| [AML.T0046](https://atlas.mitre.org/techniques/AML.T0046) | Spamming AI System with Chaff Data | TR-AI-003 |

### FiGHT (36 techniques)

| Technique | Name | Threats |
|---|---|---|
| [FGT1020.001](https://fight.mitre.org/techniques/FGT1020.001) | Automated Exfiltration: Traffic Duplication | TR-OPS-001 |
| [FGT1040](https://fight.mitre.org/techniques/FGT1040) | Network Sniffing | TR-OPS-001, TR-SUB-004 |
| [FGT1040.502](https://fight.mitre.org/techniques/FGT1040.502) | Network Sniffing: Eavesdrop On U Plane Data | TR-N3-001 |
| [FGT1195.501](https://fight.mitre.org/techniques/FGT1195.501) | Supply Chain Compromise: SIM Credentials Theft | TR-DB-001, TR-RAN-001, TR-SUB-001 |
| [FGT1498.501](https://fight.mitre.org/techniques/FGT1498.501) | Network DoS: Flooding Core Network Component | TR-N2-001 |
| [FGT1498.503](https://fight.mitre.org/techniques/FGT1498.503) | Network DoS: Malicious Packets To Network Functions | TR-N2-001, TR-N4-002, TR-N4-003 |
| [FGT1499](https://fight.mitre.org/techniques/FGT1499) | Endpoint Denial of Service | TR-RAN-002 |
| [FGT1499.503](https://fight.mitre.org/techniques/FGT1499.503) | Endpoint DoS: DOS A UE Via gNB Or NF Signaling | TR-N3-002, TR-N4-002 |
| [FGT1499.504](https://fight.mitre.org/techniques/FGT1499.504) | Endpoint DoS: DOS A UE Via Established GTP-U Tunnel | TR-N3-002 |
| [FGT1557.503](https://fight.mitre.org/techniques/FGT1557.503) | Adversary-in-the-Middle: Non-SBI | TR-N2-002, TR-N4-001, TR-VIRT-004 |
| [FGT1557.504](https://fight.mitre.org/techniques/FGT1557.504) | Adversary-in-the-Middle: Service Based Interface | TR-SUB-003, TR-VIRT-004 |
| [FGT1572.501](https://fight.mitre.org/techniques/FGT1572.501) | Protocol Tunneling: UE Access Via GTP-U | TR-N3-001 |
| [FGT1583.502](https://fight.mitre.org/techniques/FGT1583.502) | Acquire Infrastructure: Programmable UE Devices | TR-RAN-001 |
| [FGT1587.004](https://fight.mitre.org/techniques/FGT1587.004) | Develop Capabilities: Exploits | TR-N4-003 |
| [FGT1588.002](https://fight.mitre.org/techniques/FGT1588.002) | Obtain Capabilities: Tool | TR-OPS-002 |
| [FGT1599.501](https://fight.mitre.org/techniques/FGT1599.501) | Network Boundary Bridging: Malicious Co-Tenancy Exploit Of NFVI | TR-VIRT-004, TR-VIRT-005 |
| [FGT1600.502](https://fight.mitre.org/techniques/FGT1600.502) | Weaken Encryption: Network Interfaces | TR-N2-002, TR-N4-001, TR-SUB-001, TR-SUB-003 |
| [FGT1609](https://fight.mitre.org/techniques/FGT1609) | Container Administration Command | TR-VIRT-001, TR-VIRT-003 |
| [FGT1611](https://fight.mitre.org/techniques/FGT1611) | Escape to Host | TR-VIRT-001 |
| [FGT1611.501](https://fight.mitre.org/techniques/FGT1611.501) | Malicious Privileged container-VNF Shared Resource Access | TR-VIRT-001, TR-VIRT-002 |
| [FGT1613](https://fight.mitre.org/techniques/FGT1613) | Container and Resource Discovery | TR-VIRT-003 |
| [FGT1642.501](https://fight.mitre.org/techniques/FGT1642.501) | Endpoint DoS: Transmit Spoofed Broadcast Message | TR-RAN-002 |
| [FGT1642.503](https://fight.mitre.org/techniques/FGT1642.503) | Endpoint DoS: AMF | TR-N2-001 |
| [FGT5003](https://fight.mitre.org/techniques/FGT5003) | Network Function Service Discovery | TR-SUB-003 |
| [FGT5009.002](https://fight.mitre.org/techniques/FGT5009.002) | Weaken Integrity: Network Interfaces | TR-N2-002, TR-N4-001 |
| [FGT5012.004](https://fight.mitre.org/techniques/FGT5012.004) | Locate UE: Core Network Function Signaling | TR-SUB-002, TR-SUB-004 |
| [FGT5013](https://fight.mitre.org/techniques/FGT5013) | Malicious VNF Instantiation | TR-DB-002 |
| [FGT5014](https://fight.mitre.org/techniques/FGT5014) | Shared Resource Discovery | TR-VIRT-002, TR-VIRT-004 |
| [FGT5019.001](https://fight.mitre.org/techniques/FGT5019.001) | Subscriber Profile Identifier Discovery: Intercept Home Network Via SUCI | TR-SUB-002 |
| [FGT5019.003](https://fight.mitre.org/techniques/FGT5019.003) | Subscriber Profile Identifier Discovery: Obtain Subscriber Identifier Via NF | TR-SUB-003, TR-SUB-004 |
| [FGT5019.004](https://fight.mitre.org/techniques/FGT5019.004) | Subscriber Profile Identifier Discovery: Intercept Unencrypted SUPI | TR-SUB-002 |
| [FGT5020](https://fight.mitre.org/techniques/FGT5020) | Retrieve UE Subscription Data | TR-DB-001, TR-DB-002, TR-SUB-001 |
| [FGT5021](https://fight.mitre.org/techniques/FGT5021) | Tunnel ID Uniqueness Failure | TR-N3-002, TR-N4-002, TR-VIRT-005 |
| [FGT5022](https://fight.mitre.org/techniques/FGT5022) | Alter Subscriber Profile | TR-DB-001 |
| [FGT5026](https://fight.mitre.org/techniques/FGT5026) | SIM Cloning | TR-RAN-001, TR-SUB-001 |
| [FGT5031](https://fight.mitre.org/techniques/FGT5031) | Discover Tunnel Endpoint ID (TEID) | TR-N3-001 |

---

## Notes on framework currency

MITRE ATLAS was substantially revised before this analysis and several technique names used in
older literature are now wrong. The identifiers here were verified against `atlas.mitre.org`
rather than recalled. In particular:

- `AML.T0020` is now **Training Data Poisoning** (previously "Poison Training Data").
- The "ML" prefix has been replaced by "AI" throughout: `AML.T0015` is **Evade AI Model**,
  `AML.T0031` is **Erode AI Model Integrity**, `AML.T0044` is **Full AI Model Access**.
- `AML.T0018` **Manipulate AI Model** is the parent of `AML.T0018.000` **Poison AI Model**,
  which is the distinct step of producing a poisoned model from poisoned data.

ATT&CK and FiGHT identifiers were likewise verified against `attack.mitre.org` and
`fight.mitre.org`.

## Gaps

Two things this mapping deliberately does **not** claim:

1. **No Persistence tactic.** Nothing in the dataset shows an implant, a modified image, a cron
   entry or a backdoored account. The container escape (TR-VIRT-001) would make persistence
   trivial, but it was not observed, so it is not mapped.

2. **No Command and Control.** All operator activity arrives over SSH from the management
   network (`10.10.2.10 → 10.10.3.20:22`), which is legitimate administration in this context.
   No covert channel, beaconing or tunnelled C2 appears in any capture.

Both absences are consistent with an authorised exercise rather than an intrusion, and both are
recorded here so that a reader does not mistake the gap for an analysis failure.
