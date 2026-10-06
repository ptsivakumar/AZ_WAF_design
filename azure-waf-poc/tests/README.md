# Tests

| File | Objective | Runbook step |
|---|---|---|
| `bypass-test.sh` | 2 — origin lockdown | 4.1 |
| `traffic-gen.sh` | 5 — Detection to Prevention | 4.3 |
| `kql/01-what-matched.kql` | 5 — blocked vs merely matched | 4.3 |
| `kql/02-would-block.kql` | 5 — pre-flip check | before 4.5 |
| `kql/03-block-rate-detection.kql` | 6 — detections | 4.7 |
| `kql/04-policy-tampering.kql` | 6 — detections | 4.7 |

Run `bypass-test.sh` **twice** — once unlocked, once locked. The pair is the evidence.
