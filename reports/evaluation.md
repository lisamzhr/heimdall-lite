# Evaluation: rules vs ML on CTU-13

**Data:** CTU-13 scenario 42 (Neris) and 44 (Rbot). Labels: `From-Botnet` = positive, `Normal` = negative; `Background` flows are unlabelled and excluded. Labels are host-based (every flow of the infected machine counts as botnet).
**Reproduce:** `python ml/prepare.py ...`, `python ml/train_eval.py`, `python ml/sanity.py`, `scripts/replay_pcap.sh` (see README).

## Results
| Detector | Neris (scenario 42) | Rbot (scenario 44) |
|---|---|---|
| Suricata, ET Open signatures (botnet-only pcap) | Infection not detected (0 flows with an ET alert; only protocol-anomaly alerts) | Infection detected via IRC C2 (3 flows with ET alerts) |
| Random Forest trained on the *other* scenario (flow level) | precision 1.000, recall 0.317 | precision 0.977, recall 0.997 |
| Single threshold: distinct destinations per source per minute >= 26 | precision 0.940, recall 0.962 | precision 0.918, recall 0.992 |

Threshold and model are fitted on the other scenario only. Suricata flow counts and Argus flow counts are not the same unit, so the Suricata row is not numerically comparable.

## Findings
1. **ML generalisation depends on direction.** Train 42 -> test 44 reaches recall 0.997; train 44 -> test 42 reaches only 0.317 (27,992 of 40,961 botnet flows missed).
2. **A one-line fan-out rule matches or beats the Random Forest** across scenarios (recall 0.962 vs 0.317 on Neris), at the cost of some precision. The same threshold (26) came out of both training scenarios.
3. **Ports are not a shortcut.** Removing port features leaves results unchanged (42 -> 44: 0.972 / 0.994).
4. **A random split inside one scenario gives 1.000 / 1.000**, which shows why it is a misleading benchmark.
5. **Rules and behaviour fail differently.** ET detects the plaintext IRC C2 of Rbot but not Neris; the fan-out feature sees both, and also matches the SMB sweep and port-scan behaviour seen in incident 01 and 02.
6. Host level: the infected machine (147.32.84.165 in scenario 44) was flagged in both directions. Two normal hosts were flagged with the loose "10 flows" rule (333 of 4,580 and 287 of 108,807 flows), so a ratio-based host rule would be fairer.

## Limitations
- Only one infected machine per scenario and 19-23 normal hosts, so false-positive estimates are weak and host-level numbers cannot be quoted as rates.
- Host-based labels reward models that learn "this machine is infected" rather than "this flow is malicious".
- Background traffic (97% of flows) is excluded; on a real network, precision would be lower.
- CTU-13 is from 2011; results say little about modern encrypted traffic.
- The explanation that infected machines simply contact many destinations is a hypothesis, not tested.
