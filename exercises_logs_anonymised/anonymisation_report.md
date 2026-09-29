# Anonymisation report

Generated 2026-09-29T21:16:24Z

Output directory: `C:\Users\bloodraven\Downloads\Temp\NITRO_5G_Exercise_Dataset_v1.0\exercises_logs_anonymised`

Key fingerprint: `51f20a067e76bdb2`

The key itself is not written anywhere. Without it the pseudonyms cannot be
recomputed or reversed.

## 1. What was found

| Severity | Category | Distinct values | Occurrences | From headers |
|---|---|---:|---:|---:|
| CRITICAL | SIM authentication key (K / OPc) | 85 | 1,297 | 0 |
| HIGH | IMSI (subscriber identity) | 39 | 2,270 | 0 |
| HIGH | IMEISV (device identity) | 3 | 686 | 0 |
| HIGH | MSISDN (phone number) | 1 | 1 | 0 |
| MEDIUM | APN / DNN string | 5 | 282,026 | 0 |
| MEDIUM | IPv4 address | 20 | 1,390 | 0 |
| MEDIUM | Account name / home directory | 1 | 2 | 0 |
| low | Container / service name | 1 | 2 | 0 |
| low | Process ID | 1 | 2 | 0 |
| low | Filesystem path | 1 | 2 | 0 |

### Why each one matters

- **SIM authentication key (K / OPc)** — Long-term subscriber authentication secret. Disclosure allows SIM cloning and full subscriber impersonation against the live network.
- **IMSI (subscriber identity)** — International Mobile Subscriber Identity: the permanent, globally unique identifier of a SIM card. Direct personal identifier.
- **IMEISV (device identity)** — Device identity of the handset. Links all activity of one physical device across time and cell sites.
- **MSISDN (phone number)** — Subscriber telephone number in national or E.164 form.
- **APN / DNN string** — Access point name. Reveals operator and, in lab APNs, the network function that generated the traffic.
- **IPv4 address** — Host address. Pseudonymised prefix-preservingly so subnet topology survives.
- **Account name / home directory** — Operator account name, appearing in shell history and file paths.
- **Container / service name** — Docker container or compose service names describing the lab topology.
- **Process ID** — PID of a process on the capture host.
- **Filesystem path** — Directory layout of the capture host.

## 2. What was changed

| File | Packets | Modified | Checksums fixed | Replacements |
|---|---:|---:|---:|---:|
| `module0.pcap` | 107,451 | 343 | 289 | 678 |
| `module1.pcap` | 131,027 | 1,858 | 1,829 | 3,716 |
| `module2.pcap` | 467,492 | 763 | 694 | 1,038 |
| `module3.pcap` | 4,267,925 | 1,875,691 | 1,580,119 | 3,621,459 |
| `module4.pcap` | 31,478 | 4 | 1 | 8 |
| `module5.pcap` | 63,064 | 20 | 9 | 69 |
| `module6.pcap` | 276,064 | 124 | 64 | 248 |
| `module7.pcap` | 92,423 | 27 | 1 | 54 |
| `module8.pcap` | 59,699 | 5 | 0 | 10 |
| `module9.pcap` | 22,347 | 6 | 0 | 12 |

Timestamps were shifted by a single constant (19,515,057 µs). Every inter-packet
interval is therefore bit-identical; only the absolute position on the clock moved.

| History file | Lines | Lines changed | Replacements |
|---|---:|---:|---:|
| `bash_history_v1` | 501 | 256 | 302 |
| `bash_history_v2` | 490 | 127 | 146 |

## 3. Verification

Result: **FAIL**

| Check | Result | Detail |
|---|---|---|
| no original identifier survives | **FAIL** | msisdn: 2 leak(s) e.g. 0000000001... in module0.pcap |
| no original address in any header | **FAIL** | 240036 occurrence(s) of 22 distinct original address(es) survive, e.g. ['module0.pcap: 172.18.0.14', 'module0.pcap: 172.18.0.2', 'module1.pcap: 172.18.0.14'] |
| pseudonyms are not real identifiers | PASS | 265 pseudonyms, none present in the original value set |
| mapping preserves cardinality | PASS | no non-injective category detected |
| generated values keep their format | PASS | IMSI/IMEI/IP all still parse as their types |
| IP subnet topology preserved | PASS | 2258 address(es) keep their subnet grouping |
| key material absent from output | PASS | no key material in any encoding found in 12 artefact(s) |
| different key yields different pseudonyms | PASS | 173 rewritten value(s) map to disjoint pseudonyms under two independent keys (2 value(s) are deliberately left unchanged by the keyring) |
| capture structure preserved | PASS | byte size, packet count and every frame length identical in 10 file(s) |
| relative timing preserved | PASS | every inter-packet interval identical; only a constant offset applied |
| IPv4 header checksums valid | PASS | 20000 sampled packets verify |
| output re-scan finds no residual identifiers | PASS | no unaccounted high-severity identifier shape remains in the redacted payloads |

### Properties being asserted

- **Identifiability** — no original identifier survives in the output, and no
  pseudonym equals a real value. Proven by exhaustive byte search, not sampling.
- **Linkability** — the mapping is consistent inside this release so the dataset
  remains analysable, but it is not invertible and not portable to any other
  release, because a second key yields a disjoint pseudonym space.
- **Usability** — packet count, every frame length, the 84 CICFlow feature
  semantics and all inter-packet timing are unchanged; subnet topology is
  preserved by construction, so topology-dependent features still work.

## 5. Residual risk

Known and accepted:

1. **Edited packets are distinguishable.** Modified frames had their checksums
   recomputed, so someone holding the original file can tell which packets
   contained an identifier. This reveals *that* a value was present, never its
   content.
2. **Operational structure survives.** Counts, packet sizes, timing patterns,
   ports and protocol mix are all preserved on purpose: that is what makes the
   dataset analysable. An attacker who already knows the lab's topology can
   still recognise which host role a flow belongs to.
3. **Transport key-exchange blobs are left intact.** They are not reversible to
   a credential, but they do fingerprint a session. Removing them would damage
   TLS/SSH structure, so they are documented rather than removed.
