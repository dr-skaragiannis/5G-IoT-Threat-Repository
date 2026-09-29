# Environment

The asset inventory and topology of the NITRO exercise range, reconstructed entirely from
captured traffic. Container names in the dataset are pseudonymised into unreadable strings, so
nothing here is taken from a label — every role is derived from behaviour, and each attribution
records the evidence that produced it.

---

## 1. The two networks

| Network | Range | What it carries |
|---|---|---|
| **5G core fabric** | `172.18.0.0/16` (Docker bridge) | Every 3GPP reference point — N1/N2, N3, N4, and the whole service-based interface — plus the subscriber database, on a single flat L2 segment. |
| **Management / enterprise** | `10.10.0.0/16` | Operator SSH, DNS, Zabbix monitoring, Wazuh logging. The container host sits on both. |

The single most consequential structural fact in this dataset is that the first row has **no
internal segmentation**. N2 signalling, N3 user traffic, N4 session management, SBI service calls
and unauthenticated MongoDB all share one broadcast domain. 3GPP TS 33.501 assumes these are
separable trust domains; here they are not. This is catalogued as **TR-VIRT-004** and it is the
enabling condition for roughly half of the other findings.

---

## 2. 5G core assets (`172.18.0.0/16`)

| Address | Role | How it was identified |
|---|---|---|
| `172.18.0.1` | Docker bridge gateway / container host | Source of the NGAP replay injection in module3; not a 5G function. |
| `172.18.0.2` | **MongoDB** — UDR backing store | TCP/27017; responses contain `open5gs.subscribers`, `admin.$cmd`, and BSON subscriber documents. |
| `172.18.0.3` | Network function (SBI client, role unresolved) | Registers with the SCP on 7777 but emits no distinguishing service payload. Candidate: BSF or NSSF. |
| `172.18.0.4` | **UDR** | Returns `{"authenticationMethod":"5G_AKA","encPermanentKey":...,"encOpcKey":...}` and queries `open5gs.subscribers` on MongoDB directly. |
| `172.18.0.5` | **WebUI / provisioning front end** | Sustained TCP to `172.18.0.2:27017`, no SBI service role, no NF registration payload. |
| `172.18.0.6` | **AUSF** | Emits `{"servingNetworkName":"...","ausfInstanceId":"e3860042-9746-41f1-acee-f5a3b090dc7f"}`. |
| `172.18.0.7` | **UDM** | Receives Nudm_UECM registration: `{"amfInstanceId":"e44528d2-...","pei":"imeisv-...","deregCallbackUri":...}`; returns `subscribedUeAmbr` and `subscribedSnssaiInfos`. |
| `172.18.0.8` | **PCF** | Named in SM policy responses as `{"pcfIpEndPoints":[{"ipv4Address":"172.18.0.8","port":7777}]}`. |
| `172.18.0.9` | **SMF** | `smfInstanceId` `e4266780-9746-41f1-b2f8-d7543eb0bbe1`, callbacks under `/nsmf-callback/v1/`; PFCP peer on UDP/8805. |
| `172.18.0.10` | **SCP** (Service Communication Proxy) | Eight distinct NFs connect *to* it on 7777, and it is the **only** client of the NRF. Indirect-communication model; nothing else fits that graph. |
| `172.18.0.11` | Network function (SBI client, role unresolved) | As `.3`. Candidate: NSSF or BSF. |
| `172.18.0.12` | **UPF** | PFCP peer of the SMF on UDP/8805; GTP-U endpoint on UDP/2152. |
| `172.18.0.13` | **NRF** | Sole SBI server whose only client is the SCP; receives continuous `PATCH [{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]` heartbeats for every NF. |
| `172.18.0.14` | **AMF** | Owns the N2 SCTP association on port 38412; `amfInstanceId` `e44528d2-9746-41f1-bb50-936d1b93cf87`; callbacks under `/namf-callback/v1/`. Target of TR-N2-001. |
| `172.18.0.15` | **gNB** (UERANSIM `nr-gnb`) — later reused | Holds the N2 association to the AMF and the N3 GTP-U tunnel to the UPF; binds UDP/4997. From module5 the same address is reused by an ephemeral tools container (see TR-VIRT-005). |
| `172.18.0.16` | **UE** (UERANSIM `nr-ue`) | Speaks RLS to the gNB on UDP/4997; source of the storm in TR-RAN-002. |
| `172.18.0.17` | Ephemeral `open5gs-tools` container (module0) | Short-lived; queries `172.18.0.2:27017` for `subscribers`, `security`, `subscriber_status`. |

### Reference points observed

| Interface | Transport | Endpoints | Protection observed |
|---|---|---|---|
| N2 (NGAP) | SCTP/38412, PPID 60 | gNB `.15` ↔ AMF `.14` | **None.** No IPsec, no DTLS. |
| N3 (GTP-U) | UDP/2152 | gNB `.15` ↔ UPF `.12` | **None.** |
| N4 (PFCP) | UDP/8805 | SMF `.9` ↔ UPF `.12` | **None.** No IPsec, no PFCP association security. |
| SBI (HTTP/2) | TCP/7777 | all NFs ↔ SCP `.10` ↔ NRF `.13` | **None.** Cleartext `h2c`; JSON bodies fully readable. |
| UDR backing store | TCP/27017 | UDR `.4`, WebUI `.5`, tools `.17`/`.15` ↔ MongoDB `.2` | **None.** No authentication handshake at all. |
| RLS (radio link sim) | UDP/4997 | UE `.16` ↔ gNB `.15` | Not applicable (simulation channel). |

---

## 3. Management assets (`10.10.0.0/16`)

| Address | Role | Evidence |
|---|---|---|
| `10.10.2.10` | Operator workstation | Originates SSH to the capture host; 7,267 packets to `10.10.3.20:22` in module8 alone. |
| `10.10.3.20` | **Container host / capture host** | Runs every `tcpdump -i any -w moduleN.pcap` in the dataset; runs the Docker daemon; source of the `ping 8.8.8.8` used to generate the `ICMP_FLOOD` class. |
| `10.10.3.254` | DNS resolver / gateway | Destination of 1,338–3,989 TCP SYNs to port 53 per capture. |
| `10.10.4.10` | **Zabbix + Wazuh** monitoring | TCP/10051 (Zabbix server) and TCP/1514 (Wazuh agent) from the capture host, continuously across all nine captures. |

The monitoring stack is worth noting: Zabbix and Wazuh are both present and both active
throughout, yet nothing in the dataset indicates that any of the 26 catalogued behaviours raised
an alert. The 5G control plane is simply outside their visibility — they watch hosts, not N2/N4.
That gap is the subject of [DETECTION.md](DETECTION.md).

---

## 4. Subscriber population

Six subscriber records are recoverable from the database response in `module5.pcap` frame 5243,
and three of them are seen registering in the captures.

| IMSI (pseudonym) | Observed UE IPs | Seen registering |
|---|---|---|
| `999702813335208` | `10.45.0.7`, `10.45.0.11`, `10.45.0.12` | yes (module0, module1) |
| `999704314796334` | `10.45.0.6`, `10.45.0.10` | yes (module0, module1) |
| `999705145365381` | `10.45.0.8`, `10.45.0.9`, `10.45.0.13` | yes (module0, module1) |
| `999709275422922` | — | provisioned only |
| `999707253793452` | — | provisioned only |
| `999702047615749` | — | provisioned only |

PLMN is MCC `999` / MNC `70` (a test PLMN). Slice is SST 1, DNN `internet`. UE address pool is
`10.45.0.0/24`.

The IMSI, IMEISV and key values above are pseudonyms; the `172.18.0.0/16` addresses are the
dataset's original RFC 1918 Docker addresses, which the anonymiser deliberately left in place.

**Every one of the six records carries the same `k` and the same `opc`.** That is visible
directly in the database response: `716443940B35EC8A7EDA57F98A9A70E6` and
`A14B42703DEBABBE206D7597D93D65FA` repeat for all six subscribers. In a laboratory this is a
convenience; in production it would mean one compromised SIM compromises the entire subscriber
base. It is recorded as part of TR-SUB-001.

Device identities observed as `pei` values in Nudm_UECM registration:
`imeisv-4370816141361512`, `imeisv-4370816144617407`, `imeisv-4370816162227071`.

---

## 5. Software stack

| Component | Evidence |
|---|---|
| 5G core | Open5GS — `open5gs.subscribers` collection name, `/etc/open5gs/smf.yaml` paths in shell history, port 7777 SBI convention, `ogstun` interface. |
| RAN simulator | UERANSIM — `nr-ue`/`nr-gnb` binaries, `uesimtun0..3` interfaces, `gnbSearchList` config key, RLS on UDP/4997. |
| Subscriber store | MongoDB, accessed by `mongosh 2.4.2` on `Node.js v20.18.3`. |
| Orchestration | Docker Compose — `ngc.yaml` (core), `g1b1.yaml` (RAN), `register_subscriber.sh`. |
| Offensive tooling | Montimage 5GReplay v0.0.1; `arp-scan`; `tshark`; an unrecovered `pfcpExploit.py`. |
| ML pipeline | Python 3, pandas, scikit-learn (`RandomForestClassifier`), Jupyter; scripts `preprocess.py`, `train_ids.py`, `train_poisoned_ids.py`. |
| Monitoring | Zabbix (10051), Wazuh (1514). |

---

## 6. Capture windows

| Capture | Start (UTC) | End (UTC) | Duration | Frames | Theme |
|---|---|---|---|---|---|
| `module0` | 2026-08-26 20:23:18 | 21:04:29 | 41 m | 107,451 | Baseline registration; subscriber DB enumeration |
| `module1` | 2026-08-27 19:18:57 | 20:06:17 | 47 m | 131,027 | PDU sessions; TEID enumeration; user-plane failure |
| `module2` | 2026-08-27 20:22:16 | 22:27:16 | 2 h 05 m | 467,492 | Registration failure analysis; onset of the RAN storm |
| `module3` | *(inferred)* 22:28 | 22:56 | ~28 m | 4,267,925 | **NGAP replay flood** — pcap excluded, NetFlow present |
| `module4` | 2026-08-28 06:39:41 | 06:50:44 | 11 m | 31,478 | Post-flood; container and AppArmor reconnaissance |
| `module5` | 2026-08-28 06:53:41 | 07:00:45 | 7 m | 63,064 | **Bulk subscriber extraction**; SMF config recon |
| `module6` | 2026-09-09 20:24:52 | 22:14:27 | 1 h 50 m | 276,064 | PFCP exploitation attempt; ARP scan; firewall DoS |
| `module7` | 2026-09-09 22:16:16 | 22:52:01 | 36 m | 92,423 | **Container escape to host** |
| `module8` | 2026-09-09 22:53:27 | 23:11:11 | 18 m | 59,699 | IDS dataset construction; **training-data poisoning** |
| `module9` | 2026-09-09 23:25:13 | 23:33:55 | 9 m | 22,347 | **Adversarial evasion**; robustness testing |

Timestamps were shifted by a single constant during anonymisation (19,515,057 µs); all
inter-packet intervals are bit-identical to the originals, so durations and rates are exact.
module3's window is inferred from its NetFlow timestamps (`27/08/2026 10:51:58 PM` onward), which
place it immediately after module2 closes.
