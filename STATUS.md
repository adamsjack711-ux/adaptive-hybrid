# Status — 2026-11-21

Canonical checkout: `~/Documents/GitHub/adaptive-hybrid`, branch `feat/recovery-load-stress`. Integration target: `main`. The merged recovery baseline is [PR #2](https://github.com/adamsjack711-ux/adaptive-hybrid/pull/2), merge commit `288af89`. [PR #3](https://github.com/adamsjack711-ux/adaptive-hybrid/pull/3) was checked open and mergeable on 2026-11-21; it is not merged.

## Current result

- The opt-in durable subscriber on `main` records a stream cursor and deferred certificate sequence numbers, replays retained history after missing epochs arrive, and offers strict boundary gating. It remains a loopback research prototype.
- The stress branch adds a configurable real-crypto JetStream load runner, a retained-history deletion check, and stronger checking against reuse of any prior traffic key for each node.
- On one macOS arm64 host with Python 3.15.2, liboqs 0.16.0 and NATS Server 2.15.3, the 5-node/30-epoch, 20-node/100-epoch, 40-node/120-epoch and 50-node/160-epoch runs passed. The largest run recovered 31 gaps across 15 hard broker restarts and checked 12,900 encrypted packets. The slowest recovery step took 16.88 seconds. [Measurements, commands and limits](verification/recovery-load-results.md).
- Deleting a deferred certificate from the disposable stream blocked recovery and new traffic-key activation after restart. [Run output](verification/recovery-loss-results.txt).
- The original five-node recovery run, Python compilation, and `git diff --check` passed locally. [GitHub CI](https://github.com/adamsjack711-ux/adaptive-hybrid/actions/runs/44941235867) passed Python, ProVerif and fast Tamarin at `f27f645`.
- The fail-closed availability stall at 33 deferred future certificates was fixed at code commit `ebd0139`. A 2026-11-21 adversarial run rejected 3,072 malformed, tampered, and oversized publications, then recovered 256 valid future epochs after the missing epoch and a hard broker restart. Deleting overflow history still blocked new key activation. [Threat conditions and evidence](verification/adversarial-recovery-results.md).
- A separate-process sensor lab used mutual TLS, real three-rail KEM exchange, SLH-DSA-certified lattice advisories and each endpoint's own durable subscriber. Both refused the epoch 3 boundary while epoch 2 was withheld, then recovered after broker and endpoint restarts and exchanged encrypted sensor packets. [Run output](verification/recovery-network-results.txt). This is a local integration, not a multi-host deployment.
- The full Python unit and Hypothesis suite passed locally: 47 tests. Python compilation and `git diff --check` passed. The existing retained-history deletion check and 5-node/30-epoch regression load run also passed after the fix. The tested source is code commit `ebd0139`; new CI has not run yet.

## Limits and next step

The load measurements exclude initial certificate signing and KEM setup and use one host, one broker and one subscriber process. They do not establish distributed throughput, production latency, or cryptographic security. A lost retained certificate stops recovery; it cannot be reconstructed from the local cursor. No revision has been deployed or accepted by a user.

PR #3 is open, targeting `main`, and its remote head was `5a96a59` when checked on 2026-11-21. Local commits `ebd0139` and `1eb97bd` contain the fix, integration lab and verification evidence, but have not been pushed. Automatic approval review rejected `git push origin feat/recovery-load-stress` because explicit authorization to publish repository contents was not established. The next step requires Jack's explicit approval to push the local branch, followed by CI review. Merging into `main` remains a separate approval. Independent protocol review and multi-host testing with protected deployment identities and key storage remain later milestones.
