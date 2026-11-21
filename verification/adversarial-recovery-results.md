# Adversarial recovery results — 2026-11-21

Command:

```sh
.venv/bin/python -m verification.adversarial_recovery --hostile-rounds 1024 --future-certificates 256 --timeout 600
```

Environment: one macOS arm64 host, Python 3.15.2, liboqs 0.16.0, and NATS Server 2.15.3. The script uses three disposable loopback JetStream brokers in sequence, one durable subscriber with two real KEM peers per scenario, and three Ed25519 voters. All checks run with Python assertions enabled. The larger run is a local stress check, not a distributed capacity measurement.

| Probe | Observed result |
| --- | --- |
| 3,072 publications comprising malformed JSON, a changed signed epoch, and oversized payloads | Delivery cursor advanced without advancing peer policy. A later valid epoch 1 activated normally. The hostile publication loop took 3.718 seconds. |
| Epoch 2 withheld while 256 quorum-certified future epochs were published, with malformed messages interspersed | The subscriber kept at most 32 deferred sequence numbers locally and persisted an overflow replay cursor. No future boundary activated while epoch 2 was absent. The publication loop took 3.809 seconds. |
| Epoch 2 published, then the broker hard-restarted and the subscriber was reconstructed | All 256 future certificates were recovered from retained stream history. The epoch 258 boundary activated with matching peer keys. Catch-up after reconnection took 1.544 seconds. |
| Control run with exactly 32 deferred future epochs, followed by epoch 2 | The subscriber replayed all 32 certificates and activated the epoch 34 boundary. |
| An overflow certificate deleted from retained history before epoch 2 was delivered | Recovery raised a missing-message error and restored peers did not activate a traffic key. |

Observed output:

```text
PASS 3072 malformed, forged, and oversized publications did not advance policy (3.718 s)
PASS 256 deferred certificates recovered after missing epoch and hard broker restart (flood 3.809 s; recovery 1.544 s)
PASS 32 deferred certificates recovered when missing epoch arrived
PASS deleted overflow history blocked recovery and new key activation
```

Before the fix, the 33rd valid future certificate exhausted the 32-entry deferred list and blocked the durable consumer, even after epoch 2 arrived. The subscriber now persists the first overflow stream sequence, acknowledges later deliveries, and replays the retained range after gaps close. Its local deferred list remains bounded. The replay cursor is accepted from the old state-file schema on restart and validated on load.

The future-certificate probe assumes a publisher can obtain quorum-certified future epochs and deliver them ahead of a missing epoch, or can otherwise control stream order. An unauthenticated publisher cannot forge those signatures. The test does not establish protection against broker or host compromise, distributed throughput, or cryptographic security. Retained history loss still causes a deliberate fail-closed stop.
