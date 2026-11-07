# Incident 03: SSH brute force (own lab, known ground truth)

**Setup:** attacker = Windows host `192.168.56.1` (Python + paramiko), target = sensor VM `192.168.56.111`, account `bruteforcetest` created for this test only. Capture: `tcpdump -i enp0s8 host 192.168.56.1 and port 22` on the target (`lab-sshbrute.pcap`, 253 packets, 37,820 bytes).
**Ground truth:** 6 login attempts, wordlist `password, 123456, admin, letmein, qwerty, Str0ngP@ss2026!`, 0.3 s between attempts, run between 15:19:40 and 15:20:45 UTC. First 5 fail, 6th succeeds (correct password placed last on purpose).
**Reproduce:** `scripts/replay_pcap.sh pcaps/lab-sshbrute.pcap`

## Detection results
| Configuration | Alerts |
|---|---|
| Default ET Open rules | 0 |
| Custom rule `HEIMDALL` (`rules/heimdall.rules`, sid 9000002: 5+ new connections to port 22 from one source in 60s) | 1, at 15:20:25 UTC (the 6th connection, the moment the threshold was crossed) |

Suricata's `ssh` event records the client/server banner (`paramiko_5.1.0` / `OpenSSH_9.6p1`) for every attempt, but nothing about which password was tried or whether it succeeded: SSH encrypts the authentication exchange, so payload-based rules cannot see that even in principle.

## False-positive check
0 `HEIMDALL` alerts on the incident-01 malware capture (one negative sample, not proof of no false positives).

## Findings
- No default rule matched 6 attempts in ~65 seconds; a connection-count rule was needed, the same approach as the port-scan custom rule (incident 02).
- The rule flags *connection volume*, not success or failure, since that information is not visible in the traffic. It fired exactly once, on the attempt that happened to succeed, which is a coincidence of the timing, not something the rule can tell apart.
- A real attacker using a slower rate (e.g. one attempt every few minutes) would stay under this threshold, same limitation as the port-scan rule.

## Relevance to ML
Features that would help here: distinct new SSH connections per source per time window (same family as the fan-out feature used in incident 01/02), and attempt rate over time, since content-based features are unavailable for encrypted protocols.
