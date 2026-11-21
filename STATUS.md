# Status — 2026-11-21

Canonical checkout: `~/Documents/GitHub/adaptive-hybrid`, branch `main`.
Tested code commit: `4344f48`; integrated through [PR #1](https://github.com/adamsjack711-ux/adaptive-hybrid/pull/1) at merge commit `5fc7d45`.

## Implemented

- Optional atomic, owner-only peer policy and signer-key state. A restored peer has no traffic key until a fresh handshake and boundary; old certificates remain rejected and current-epoch forks remain sticky.
- A loopback mutual-TLS flow with independent client and server processes, real three-rail KEM exchange, signed lattice advisories, encrypted packets over successive boundaries, a hard server crash, and fresh peer processes after restart. Evidence: `verification/durable-results.txt`.
- `RepeatedBoundaries.pv` checks a fixed four-boundary schedule with reused rail secrets and disclosed X25519. The ProVerif runner checks its secrecy, agreement, distinct-key and reachability results. Evidence: `verification/repeated-results.txt`.

## Fresh verification

- `HYPOTHESIS_PROFILE=ci python -m pytest -q tests`: 45 passed using the project's dependencies.
- `python -m verification.durable_session`: passed with liboqs 0.16.0, real SLH-DSA and loopback mutual TLS.
- `python -m verification.live_checks`: passed against NATS Server 2.15.3, including broker crash and traffic-key rotation.
- `python -m verification.network_examples --runs 1 --link internal`: passed, including delayed-advisory fallback.
- `verification/crosscheck.sh`: passed with ProVerif 2.05 for both models.
- Python compilation and `git diff --check`: passed.

Tamarin theories were unchanged and were not rerun locally. The new repeated-boundary model is a fixed symbolic schedule; it does not cover adaptive compromise or computational security. The restart flow uses a temporary lab CA and local key files. A deployment still needs provisioned identities, protected key storage, a durable broker cursor, and a recovery protocol for missing epochs. No revision was deployed or accepted by a user.

PR #1 was reviewed locally, marked ready, and squash-merged into `main` on 2026-11-21. GitHub CI passed at the final PR head `4195b5b` (Python, ProVerif, and fast Tamarin). The local `main` checkout matches the remote merge commit. The merge has not been deployed or accepted by a user.

Next milestone: design and implement deployment identities, protected key storage, a durable broker cursor, and recovery from missing epochs before any production rollout.
