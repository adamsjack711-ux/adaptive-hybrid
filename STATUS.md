# Status — 2026-11-21

Canonical checkout: `~/Documents/GitHub/adaptive-hybrid`, branch `feat/recovery-load-stress`. Integration target: `main`. The merged recovery baseline is [PR #2](https://github.com/adamsjack711-ux/adaptive-hybrid/pull/2), merge commit `288af89`. The stress-test code and evidence were tested at commit `f27f645` and are in [PR #3](https://github.com/adamsjack711-ux/adaptive-hybrid/pull/3), which is ready for review but not merged.

## Current result

- The opt-in durable subscriber on `main` records a stream cursor and deferred certificate sequence numbers, replays retained history after missing epochs arrive, and offers strict boundary gating. It remains a loopback research prototype.
- The stress branch adds a configurable real-crypto JetStream load runner, a retained-history deletion check, and stronger checking against reuse of any prior traffic key for each node.
- On one macOS arm64 host with Python 3.15.2, liboqs 0.16.0 and NATS Server 2.15.3, the 5-node/30-epoch, 20-node/100-epoch and 40-node/120-epoch runs passed. The peak run recovered 23 gaps across 11 hard broker restarts and checked 7,760 encrypted packets. The slowest recovery step took 12.5 seconds. [Measurements, commands and limits](verification/recovery-load-results.md).
- Deleting a deferred certificate from the disposable stream blocked recovery and new traffic-key activation after restart. [Run output](verification/recovery-loss-results.txt).
- The original five-node recovery run, Python compilation, and `git diff --check` passed locally. [GitHub CI](https://github.com/adamsjack711-ux/adaptive-hybrid/actions/runs/44941235867) passed Python, ProVerif and fast Tamarin at `f27f645`.

## Limits and next step

The load measurements exclude initial certificate signing and KEM setup and use one host, one broker and one subscriber process. They do not establish distributed throughput, production latency, or cryptographic security. A lost retained certificate stops recovery; it cannot be reconstructed from the local cursor. No revision has been deployed or accepted by a user.

PR #3 remains ready for review; merging it into `main` is pending Jack's approval. After that, the next technical milestone is independent protocol review and multi-host testing with protected deployment identities and key storage.
