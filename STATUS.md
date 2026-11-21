# Status — 2026-11-21

Canonical checkout: `~/Documents/GitHub/adaptive-hybrid`. Integration target: `main`.
Working branch: `feat/authenticated-durable-sessions`. Tested code commit: `4344f48`.

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

The branch was pushed to `origin/feat/authenticated-durable-sessions`. A draft PR could not be opened: the connected GitHub app returned 403, the local `gh` login is invalid, and automatic approval review rejected retrieving a saved Git credential to create the PR. No PR was created.

Next integration step: use a GitHub connection with pull-request write access to open a draft PR, then review and merge into `main`. Design the deployment components as a separate milestone.
