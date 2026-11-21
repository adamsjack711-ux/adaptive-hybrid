# Adaptive hybrid key exchange verification

`crosscheck.sh` runs two ProVerif models. `Combiner.pv` checks one completed boundary per fresh session. `RepeatedBoundaries.pv` checks four successive boundaries using the same three secrets: normal, lattice swap, classical swap, then all-rail fallback. It discloses X25519 at the start while keeping both post-quantum secrets private. Its secrecy, injective agreement and distinct-key queries pass within that fixed schedule. It does not model adaptive compromise or policy delivery. [Repeated model output](repeated-results.txt)

From the repository root, run `./verification/verify.sh` for all 30 maintained lemmas. Pass `--fast` for Advisory and Boundary or `--slow` for the two-signer fork reachability theory. The fast theories each have a 120-second timeout. The reference run used Tamarin 1.12.0 and Maude 3.5.1. [Tool setup](../README.md#run-locally)

`./verification/verify.sh --exploratory` runs the older, unconstrained fork witness search in `ForkWitness.spthy`. It has a separate 900-second budget and can be inconclusive. The maintained fork argument uses `ForkReachability.spthy` below.

## Results

| Property | Result and scope |
|---|---|
| Quorum | Every accepted certificate has endorsements from at least three distinct members of the five-voter roster on the same body. Lattice certificates require both ideal signature checks for each of three identities, including for recovery. |
| Policy epoch | Every post-bootstrap activation of an agreed policy has an earlier valid certificate. A successful staging step increments the local epoch by exactly one. Old or duplicate certificates cannot advance it. |
| Fail-safe | At a completed boundary with different offers, a disputed history, or a missed scheduled epoch, the combiner selects all three inputs. This contains every rail from any previous active combination. An observed same-epoch fork sets a sticky flag. |
| Key agreement | Given the same established session, genuine exchanged offers, round and scheduled epoch, both completed endpoint computations select the same ordered inputs and produce identical key terms, including on lattice swaps and fallback. |
| Downgrade | Every emitted key includes the lattice secret, the code secret, or both in the actual HKDF input term. An agreed lattice swap selects X25519 and McEliece. Suspension emits no key. |
| Fallback label and agreement | At traffic epoch 3, two peers that last accepted epoch 2 derive the same all-secret key with the label `all-rails-fallback-v1|traffic=3|policy=2,2`. For unequal accepted epochs the label binds both in canonical order. |

The old unconditional epoch-equality lemma still has a four-step counterexample. Withholding an advisory deliberately leaves policy behind traffic. Its replacements check the epochs in the actual HKDF label and the key and rails selected by both peers. A real-KEM reproduction staged signed watch and warn certificates, withheld epoch 3, and confirmed both calls to HKDF used the label above and produced equal keys.

## What the theories model

**Advisory.spthy** models the certificate checks and the local state in `Peer.receive`. The public network can replay, reorder, delay or withhold signed bodies and recombine individual signatures. The private constructors model unforgeability for a given scheme, voter and message. A voter can endorse arbitrary proposals and can equivocate. This broadens the possible detector outputs beyond the real threshold and hysteresis logic. The proof establishes signer provenance and quorum size. It does not establish the truth of a signal or the honesty of a quorum.

A linear fact carries one peer's epoch, history head, last body and fork bit. Only the successor certificate advances it. A different valid body at the current epoch preserves the accepted history and sets the bit. Discarding an old advisory or an exact duplicate is represented by leaving state untouched. Tamarin's naturals start at one, so the policy theory represents Python epoch zero by one. The persistent entry records the body installed at that head. The policy-boundary rule additionally requires the current linear state to match. The matching-offer input overapproximates when a boundary may occur for this provenance proof.

**Boundary.spthy** checks the combiner at an arbitrary boundary. It admits arbitrary snapshots, including histories unreachable through the certificate rules. The proof therefore covers the snapshot supplied after any accepted transition. The effective policy in a snapshot summarizes the Python per-assumption map. The history head commits to the advisory sequence, which determines that map.

| Effective policy or observation | Inputs used for a key |
|---|---|
| Genesis, normal, watch, warn, or recovery with both primaries healthy | X25519 + ML-KEM. The backup was exchanged at handshake time. |
| Lattice swap, other rails healthy | X25519 + McEliece |
| Classical swap, other rails healthy | ML-KEM + McEliece |
| Different offers, detected fork, or wrong scheduled epoch | X25519 + ML-KEM + McEliece |
| Agreed hash swap or fewer than two healthy rails | Suspended |

Each endpoint builds its own context from its local and remote offers. Canonical client/server order represents Python's sorting of the two genuine offers. The fresh round token stands for the session and its unique round ID. The symbolic HKDF binds ordered secrets, context, label, epoch and rail identities. An independently executed server rule uses the reverse local/remote view. Reachability checks exercise warning, backup activation and fallback, including a concrete withheld-epoch trace.

## Limits of the claims

- Fail-safe applies at a boundary where the session observes a disagreement. It does not promise immediate rekeying on receipt, eventual message delivery, or agreement across different sessions whose peers have never compared histories. Python rejects a stale conflicting certificate before checking its signatures. It can therefore miss evidence of an old fork after it advances. The fork bit records observed, current-epoch conflicts.
- The trusted boundary is the one in the PoC. Its in-process offer exchange supplies genuine peer offers and a common round schedule. The fixed-suite handshake supplies three equal per-rail secrets and the same transcript to the endpoints. The key-agreement result cannot be transferred to an unauthenticated network handshake with an active intermediary.
- NATS and JetStream are abstracted as hostile advisory delivery. Broker timestamps, consumer persistence, availability and catch-up latency are outside the proof. Key agreement is a safety result for completed transitions. An adversary can prevent progress by withholding messages.
- HKDF, history hashing and signatures have ideal symbolic semantics. The results concern rail inclusion, state transitions and key equality. They do not prove computational secrecy after compromise, KEM or library correctness, byte encoding correctness, or equivalence of the Python implementation to the models.

## Proof audit

[results.txt](results.txt) records the verification run. The runner rejects unfinished proofs, well-formedness warnings and unexpected counterexamples.

**Fork reachability.** `ForkReachability.spthy` fixes one epoch and one initial roster. Two signing keys are disclosed. Each remaining voter can sign once. Two distinct honest voters can receive different proposals. Each contributes both signature schemes to a different certificate alongside the two compromised voters. Tamarin verified a trace in which one honest peer receives the swap certificate followed by the conflicting normal certificate. The certificate-sources lemma traces the honest dual share to its signing event. Precomputation reported 11 refined source cases and complete deconstructions.

The fork property follows by composition. The witness reaches the current-epoch comparison in `Advisory.spthy`. Its verified conflict and preservation lemmas set and retain the flag. At the next completed boundary, `fork_uses_all` in `Boundary.spthy` selects all secrets. This argument uses the shared certificate-body and offer semantics of the three models. The witness search used a 900-second timeout, four capabilities and an 8 GiB heap limit.

### Composition theorem for the current-epoch fork

Let E be the current epoch, let P be an honest peer and let A and B be distinct lattice advisory bodies for E. Assume an uninterrupted peer session, genuine boundary offers, an established common transcript, and delivery of B before P advances past E.

1. **Certificate interface.** Map the five fresh signer identities of `ForkReachability` bijectively to the five roster entries of `Advisory`. Map each witness body to a concrete advisory with the same assumption, epoch and tier and a fixed valid score/source encoding. This map preserves inequality of A and B. Each witness certificate has distinct shares from the two disclosed signers and one eligible honest signer. Its Ed and SLH terms cover the same body. Each share can therefore be consumed by `CheckLattice`, and `Threshold` can produce `Cert(A)` and `Cert(B)`. The advisory model permits equivocation by the two disclosed identities. The live test instantiates the certificates with voter sets {1,2,3} and {1,2,4}.
2. **Peer state.** Choose a reachable prefix with P clear at E−1. For E=3, two successive quorum-certified watch and warn advisories provide that prefix. Abstract `Waiting(P)` by this state. Delivering A through `Advance` gives P epoch E, last body A and a history head incorporating A. This represents `Holding(P,A)`. Delivering B now enables `Conflict`: the epoch matches, the certificate validates and A differs from B. The `Compared` event satisfies `conflict_sets_fork`. The accepted body and head survive this step. Induction on subsequent state steps, using `fork_preserved_each_step` and stuttering for discarded packets, preserves the fork bit for P.
3. **Boundary interface.** Map P's epoch, history and fork bit to its offered snapshot. At a completed boundary, unequal offers imply all rails by `disagreement_uses_all`. For equal forked offers, either their epoch is the scheduled epoch (`fork_uses_all`) or it differs (`missed_epoch_uses_all`). Both cases select all rails. The role symmetry of the genuine offer pair and `agreement` give the same key at both completed peers.

Thus there exists a two-certificate delivery reaching a fork, and every subsequent completed boundary of that session uses all three rails. This is a compositional argument over machine-checked component lemmas. Delivery, boundary completion, and continuity of the peer state are hypotheses; a stale conflict arriving after an advance falls outside the theorem.
