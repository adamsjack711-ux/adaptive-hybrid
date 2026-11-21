# Recovery load results — 2026-11-21

Environment: one macOS arm64 host, Python 3.15.2, liboqs 0.16.0, NATS Server 2.15.3. Each run used a disposable loopback JetStream broker, three real SLH-DSA voters, real three-rail KEM handshakes, durable peer and subscriber files, and ChaCha20-Poly1305 packets. All nodes ran in one Python process. Run output: [baseline](recovery-load-baseline.txt), [20 nodes](recovery-load-heavy.txt), [40 nodes](recovery-load-peak.txt), [retained-history loss](recovery-loss-results.txt).

| Workload | Seed | Recovered gaps | Hard broker restarts | Encrypted packets | Timed workload | Deliveries/s | Median step | P95 step | Slowest recovery |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 nodes, 30 epochs, gap every 7 | 1 | 4 | 2 | 260 | 4.222 s | 35.5 | 49.1 ms | 1336.1 ms | 1505.6 ms |
| 20 nodes, 100 epochs, gap every 7 | 17 | 14 | 7 | 3440 | 55.962 s | 35.7 | 190.9 ms | 4816.2 ms | 6581.9 ms |
| 40 nodes, 120 epochs, gap every 5 | 42 | 23 | 11 | 7760 | 157.696 s | 30.4 | 380.0 ms | 10374.8 ms | 12491.6 ms |

All three runs completed with no cursor left behind, no unresolved deferred certificate, and no traffic key reused by a node. The separate loss check deleted a deferred certificate from the disposable stream. Both subscribers stopped recovery and, after restart, retained no traffic key.

The timer starts after certificate signing and initial KEM setup. A step includes publication, delivery, recovery, key derivation, and packet checks; crash steps include broker and peer reconstruction. Deliveries/s counts expected subscriber deliveries divided by timed workload duration. The peak run also has a denser gap schedule than the other two, so its rate is not a like-for-like scale comparison. These are single-host lab measurements, not multi-host capacity or production latency claims. The tested ceiling is 40 nodes and 120 epochs; larger scales and process-per-node isolation remain untested.
