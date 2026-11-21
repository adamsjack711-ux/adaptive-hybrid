# Adaptive hybrid key exchange

Adaptive Hybrid is a research prototype for changing a session’s cryptographic policy after its initial handshake. It explores whether endpoints can pay the cost of a backup key exchange up front, then switch primitives at a scheduled epoch boundary without another KEM exchange.

## Live demo

Run from the repository root with Python 3.12+, `nats-server`, and the matching liboqs build described below. [Local setup](#run-locally)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
./demo.sh --pause 2
```

The demo starts and stops its own loopback JetStream broker. The peers start on X25519 and ML-KEM-768, reject a two-vote proposal, and stage the swap when the third signed vote arrives. The live transcript shows what happens at the epoch boundary. [Full live transcript](verification/demo-results.txt)

```text
  JetStream seq 2  3/5 votes accepted, epoch 1 staged on both peers
  Traffic key      Unchanged while the policy is staged
  Epoch boundary   Both peers switched using secrets from the initial exchange
  Active rails     X25519 + Classic-McEliece-348864
  Client sent      46ed5cdbfa2bf2cde8daf3a2… (37 bytes of ciphertext and tag)
  Server decrypted "After the policy swap"
  New key rejected the packet encrypted before the swap
```

The demo then disconnects the server's subscriber. Both peers use all three rails until the subscriber reconnects and catches up.

The detector reads scripted lab signals. The KEM exchanges, Ed25519 and SLH-DSA signatures, JetStream deliveries, and ChaCha20-Poly1305 encryption all execute live. The two peers pass application packets and boundary offers in process. Set `--pause` to the number of seconds between stages, or omit it for an uninterrupted run.

## Planned benchmark

Compare two ways to handle the same signed lattice swap. One preloads the McEliece backup during the initial handshake. The other starts with X25519 and ML-KEM-768 and runs a fresh X25519 and McEliece exchange at the swap.

The benchmark measures bytes sent at setup and at the swap, plus the time from the scheduled boundary to the first successfully decrypted message. The loopback results cover delay and bandwidth. Testing network packet loss and measuring CPU, memory, and power on physical IoT devices are follow-up work.

### Loopback network examples

Run the examples with the live demo dependencies installed.

```sh
.venv/bin/python -m verification.network_examples
.venv/bin/python -m verification.network_examples --link iot
```

Separate client and server processes exchange real KEM material and encrypted sensor readings over mutual TLS on loopback. The lab emulates link delay and bandwidth for internal, branch-office, remote, and IoT gateway scenarios. Timing starts after TLS setup and measures the interval to the first decrypted reading at each phase. Each scenario also delays one peer's signed JetStream advisory. The client decrypts a pump reading during all-rail fallback and another after catch-up. [Measured run](verification/network-results.txt)

### Authenticated session and restart

Run the multi-boundary lab flow with the same KEM dependencies:

```sh
.venv/bin/python -m verification.durable_session
```

Two independent processes exchange all three KEM rails and boundary offers over mutual TLS. They verify signed lattice advisories and exchange encrypted packets at epochs 0, 1 and 2. The harness then hard-kills the server. New client and server processes restore peer policy and the signers' identity keys and last-voted epoch, perform a **fresh** three-rail handshake, and exchange packets at epochs 2 and 3. The restored peer starts with no traffic key until its first authenticated boundary. State files use atomic replacement and owner-only permissions; they contain policy and signer keys, but no KEM secrets or traffic keys. This is a loopback lab with a temporary CA and local files, not a deployment key store. [Run output](verification/durable-results.txt)

## Architecture

The handshake establishes three independent secrets. Normal operation combines X25519 and ML-KEM-768 in HKDF. A certified lattice swap replaces ML-KEM with Classic McEliece-348864. A classical swap uses both post-quantum rails.

```text
 research, quantum and anomaly signals
                  |
                  v
          [ Policy detector ]
                  | proposed advisory
                  v
          [ Five voters, quorum of three ]
                  | signed certificate
                  v
          [ NATS JetStream advisory stream ]
                  |                      |
                  v                      v
          [ Client policy ]      [ Server policy ]
                  |                      |
                  +---- epoch offers ---+
                         at boundary
                  |                      |
                  v                      v
          [ HKDF on client ]     [ HKDF on server ]
                  ^                      ^
                  +--- shared secrets --+
                    X25519 + ML-KEM-768
                    + Classic McEliece
```

Each peer stages only the next signed epoch. Certificates carry Ed25519 votes from three distinct roster identities. Lattice advisories also require an SLH-DSA signature from each of those voters. At a handshake boundary, both peers compare the scheduled epoch with their accepted history and the other peer’s offer. Matching, undisputed offers activate the policy. A missed epoch, differing history, or observed fork selects all three rails. An agreed hash swap or a policy with fewer than two healthy rails suspends key derivation.

The message parser rejects duplicate fields, unknown fields and mismatched subjects before staging policy. A certificate can be up to 192 KiB to accommodate five SLH-DSA shares. Boundary offers are capped at 256 bytes.

## Threat model

An adversary can delay, reorder, replay, withhold or alter advisory traffic. Peers provision voter public keys ahead of time and validate signed bodies locally. Two three-vote quorums can share as few as one voter, so one voter signing both proposals can enable conflicting certificates. The formal fork witness exercises a case with two compromised voters. An honest peer remembers a valid conflict it observes at its current epoch.

The fleet demo trusts its initial in-process exchange to supply matching secrets and a common transcript. The separate-process lab uses mutual TLS for that exchange and for genuine offers, with a common boundary schedule supplied by the lab harness. An operational deployment still needs provisioned identities, protected persistent keys, a durable delivery cursor, and a recovery protocol for missing epochs.

## Run locally

Use Python 3.12 or later, a matching liboqs 0.16.0 shared library with ML-KEM-768, Classic McEliece-348864 and SLH-DSA-SHA2-128f enabled, NATS Server with JetStream, Tamarin 1.12.0 with Maude 3.5.1, and ProVerif 2.05. The Python wrapper can build liboqs on first use with Git, CMake and a C compiler. Set `OQS_INSTALL_PATH` to the prefix of an existing matching build if needed. [liboqs-python setup](https://github.com/open-quantum-safe/liboqs-python#installation)

On macOS with Homebrew and the command-line developer tools installed:

```sh
brew install cmake nats-server ocaml tamarin-prover/tap/tamarin-prover
tools_dir=$(mktemp -d)
curl -fsSL https://proverif.inria.fr/proverif2.05.tar.gz -o "$tools_dir/proverif.tar.gz"
tar -xzf "$tools_dir/proverif.tar.gz" -C "$tools_dir"
(cd "$tools_dir/proverif2.05" && ./build -nointeract)
export PATH="$tools_dir/proverif2.05:$PATH"
```

The CI workflow gives the corresponding Ubuntu prover setup. [GitHub Actions workflow](.github/workflows/verify.yml)

From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
./run_all.sh
```

The script starts a loopback broker with an isolated temporary store, runs Python tests, live JetStream checks, the live demo, a smoke test for all four network examples, Tamarin and ProVerif, then stops the broker and prints a pass/fail summary. Run the next two commands in separate terminals for the five-node demo and KEM measurements.

```sh
nats-server -js -a 127.0.0.1 -sd ./jetstream-data
```

```sh
.venv/bin/python combiner.py --interval 0.1 --nats-url nats://127.0.0.1:4222
```

## Verification results

| Check | Result |
| --- | --- |
| Python unit and Hypothesis tests | Generated crash, withhold, replay and competing-certificate schedules kept both peers in agreement. Each emitted key included post-quantum input. Fuzzed advisory, certificate and offer inputs were rejected without state changes. |
| Live JetStream | Five sessions exercised quorum loss, replay and fork detection with real signatures and KEMs. A separate session checked encrypted traffic in both directions through repeated rekeying, split delivery, a hard broker restart, and suspension and recovery. [Run output](verification/live-results.txt) |
| Tamarin 1.12.0 | 30 maintained lemmas and reachability checks verified across the advisory, boundary and two-compromised-signer theories. [Results](verification/results.txt) |
| ProVerif 2.05 | The original one-boundary model and a four-boundary fixed schedule each passed two traffic-key secrecy queries and one injective key-agreement query. The repeated model also checked distinct keys across boundaries. Each reached normal, lattice swap, classical swap and all-rail fallback. The repeated model reuses the same rail secrets and discloses X25519 throughout. [Results](verification/proverif-results.txt), [repeated results](verification/repeated-results.txt) |
| Timing checks | The boundary key comparison calls `hmac.compare_digest`. Tests check delegation to the native Ed25519 and SLH-DSA verifiers. The live run samples timings with equal-length inputs. |

Pushes run bounded Hypothesis tests, ProVerif and the fast Tamarin theories. Manual dispatch adds the maintained fork theory and can optionally run the larger exploratory fork search. [Proof scope and composition](verification/README.md)

## Scope and limitations

- The original ProVerif model covers **one completed boundary per fresh session**, with at least one selected post-quantum secret assumed private. The repeated-boundary model covers one fixed four-boundary schedule with the same rail secrets and a disclosed X25519 secret; both post-quantum secrets remain private. Adaptive schedules and later disclosure of either post-quantum secret are outside that model.
- Successive traffic keys depend on the original rail secrets. Disclosure of all three rail secrets and the round inputs exposes traffic keys from that session. Recovering after that disclosure requires a fresh key exchange.
- An agreed hash swap suspends key derivation. During split delivery, all-rail fallback still depends on HKDF-SHA256.
- The fork result uses **reachability with two compromised signers** and a composition argument across the certificate, peer-state and boundary theories. It applies when a valid conflicting certificate reaches a peer while the conflicting epoch is current. A late conflict can arrive after a peer has advanced.
- **Signed epoch and history checks provide replay protection.** JetStream supplies delivery and persistence. A signed replay can have fresh broker metadata, and a hard broker restart can roll back consumer acknowledgments.
- **Classic McEliece is a dormant backup with a 261 KB payload** exchanged up front. It adds 261,216 bytes to the raw handshake, which totals 263,552 bytes before framing. It is used for swaps that need it and for all-rail fallback.
- The prototype assumes genuine offers and a common schedule. Its symbolic results do not establish computational secrecy, correctness of native crypto libraries or timing properties. Signature checks use library verifiers on public inputs, and the timing samples describe one run.
- The generated schedules use a second Ed25519 key to exercise the dual-signature logic deterministically. The live tests cover actual SLH-DSA and the actual KEMs. The test scenarios retain the in-memory peers and voters across broker restart.
- The authenticated restart lab persists signer keys and peer policy in owner-only files, then performs a fresh KEM exchange. It does not resume an interrupted traffic session, protect keys from a compromised host, or authenticate a production boundary scheduler.

## Future work

Add a provisioned identity and protected key store, recovery from missing epochs, and a refresh mechanism for long-lived sessions. Extend the repeated-boundary symbolic model to adversarial schedules and evolving compromise, and measure the backup payload and broker failure behavior across a distributed deployment.

Released under the [MIT License](LICENSE).
