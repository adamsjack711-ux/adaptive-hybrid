# Adaptive hybrid key exchange

Adaptive Hybrid is a research prototype for changing a session’s cryptographic policy after its initial handshake. It explores whether endpoints can pay the cost of a backup key exchange up front, then switch primitives at a scheduled epoch boundary without another KEM exchange.

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

An adversary can delay, reorder, replay, withhold or alter advisory traffic. Peers provision voter public keys ahead of time and validate signed bodies locally. The fork witness allows two compromised voters to sign competing proposals, each alongside a different honest voter. An honest peer remembers a valid conflict it observes at its current epoch.

The demo trusts the initial in-process exchange to supply matching secrets and a common transcript. It also trusts the in-process exchange of genuine offers and the shared boundary schedule. An operational deployment would need an authenticated network handshake, authenticated offers and a durable record of peer and signer state.

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

The script starts a loopback broker with an isolated temporary store, runs Python tests, live JetStream checks, Tamarin and ProVerif, then stops the broker and prints a pass/fail summary. For the five-node demo and KEM payload/timing output, run these commands in separate terminals:

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
| Live JetStream | Five sessions exercised quorum loss, replay and fork detection with real signatures and KEMs. Two independently fed peers fell back during out-of-order or split delivery, then converged after a hard broker restart and catch-up. [Run output](verification/live-results.txt) |
| Tamarin 1.12.0 | 30 maintained lemmas and reachability checks verified across the advisory, boundary and two-compromised-signer theories. [Results](verification/results.txt) |
| ProVerif 2.05 | Two traffic-key secrecy queries and one injective key-agreement query passed. Four reachability queries exercised normal, lattice swap, classical swap and all-rail fallback. [Results](verification/proverif-results.txt) |
| Timing checks | The boundary key comparison calls `hmac.compare_digest`. Tests check delegation to the native Ed25519 and SLH-DSA verifiers. The live run samples timings with equal-length inputs. |

Pushes run bounded Hypothesis tests, ProVerif and the fast Tamarin theories. Manual dispatch adds the maintained fork theory and can optionally run the larger exploratory fork search. [Proof scope and composition](verification/README.md)

## Scope and limitations

- ProVerif covers **one completed boundary per fresh session**, with at least one selected post-quantum secret assumed private. Disclosure across multiple boundaries that reuse KEM secrets is outside that model.
- The fork result uses **reachability with two compromised signers** and a composition argument across the certificate, peer-state and boundary theories. It applies when a valid conflicting certificate reaches a peer while the conflicting epoch is current. A late conflict can arrive after a peer has advanced.
- **Signed epoch and history checks provide replay protection.** JetStream supplies delivery and persistence. A signed replay can have fresh broker metadata, and a hard broker restart can roll back consumer acknowledgments.
- **Classic McEliece is a dormant backup with a 261 KB payload** exchanged up front. It adds 261,216 bytes to the raw handshake, which totals 263,552 bytes before framing. It is used for swaps that need it and for all-rail fallback.
- The prototype assumes genuine offers and a common schedule. Its symbolic results do not establish computational secrecy, correctness of native crypto libraries or timing properties. Signature checks use library verifiers on public inputs, and the timing samples describe one run.
- The generated schedules use a second Ed25519 key to exercise the dual-signature logic deterministically. The live tests cover actual SLH-DSA and the actual KEMs. The test scenarios retain the in-memory peers and voters across broker restart.

## Future work

Add authenticated transport and offers, persistent vote and fork state, recovery from missing epochs, and a refresh mechanism for long-lived sessions. Extend the symbolic models to multiple boundaries per session and measure the backup payload and broker failure behavior across a distributed deployment.

Released under the [MIT License](LICENSE).
