"""Show a live policy swap and encrypted traffic between two in-process peers."""
import argparse
import asyncio
from contextlib import AsyncExitStack, ExitStack
import json
import math
import os
from pathlib import Path
import signal
from tempfile import TemporaryDirectory

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from combiner import Peer, STREAM, SUBJECTS, Subscriber, boundary, load_nats, publish
from detector import SLH, WEIGHTS, Detector, Voter
from handshake import ALGORITHMS, RAILS, handshake, keys_match, require_kems
from verification.broker import broker


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def show_traffic(pair, message, rails, *, fallback=False):
    client, server = pair
    check(all(peer.rails == rails and peer.fallback == fallback for peer in pair),
          "Peers did not select the expected rails")
    check(client.key is not None and keys_match(client.key, server.key),
          "Peers did not derive a common traffic key")
    nonce = os.urandom(12)
    plaintext = message.encode()
    ciphertext = ChaCha20Poly1305(client.key).encrypt(nonce, plaintext, None)
    recovered = ChaCha20Poly1305(server.key).decrypt(nonce, ciphertext, None)
    check(recovered == plaintext, "Server recovered a different message")
    print(f"  Active rails     {' + '.join(ALGORITHMS[rail] for rail in client.rails)}")
    print(f"  Client sent      {ciphertext[:12].hex()}… ({len(ciphertext)} bytes of ciphertext and tag)")
    print(f'  Server decrypted "{recovered.decode()}"')
    return nonce, ciphertext


async def run(url, pause):
    print("Adaptive Hybrid live demo")
    print("Two in-process peers, five voting identities, one temporary JetStream broker")
    print("ChaCha20-Poly1305 application messages")
    oqs = require_kems()
    check(SLH in oqs.get_enabled_sig_mechanisms(), f"Enable {SLH} in liboqs")
    nats, api = load_nats()

    with ExitStack() as stack, TemporaryDirectory(prefix="adaptive-signals-") as tmp:
        voters = [Voter(f"voter-{i}", oqs, stack) for i in range(1, 6)]
        roster = {voter.name: voter.public for voter in voters}
        verifier = stack.enter_context(oqs.Signature(SLH))
        detector = Detector()
        signals = Path(tmp) / "signals.json"

        async with AsyncExitStack() as connections:
            nc = await nats.connect(url, allow_reconnect=False)
            connections.push_async_callback(nc.close)
            js = nc.jetstream()
            await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)

            print("\n[1/5] Establish the session")
            metrics = []
            pair = [Peer(name, roster, verifier, state)
                    for name, state in zip(("client", "server"), handshake(metrics))]
            client, server = pair
            nodes = [Subscriber([peer], peer.name, 1, url) for peer in pair]
            for node in nodes:
                connections.push_async_callback(node.disconnect)
                await node.connect()
            initial_key = client.key
            print(f"  Initial exchange {sum(metric.size for metric in metrics):,} raw bytes, "
                  f"including {metrics[-1].size:,} bytes for the McEliece backup")
            initial_packet = show_traffic(pair, "Before the policy swap", RAILS[:2])
            await asyncio.sleep(pause)

            print("\n[2/5] Reject a proposal with two votes")
            signals.write_text(json.dumps([
                {"assumption": "lattice", "type": source, "confidence": 1.0} for source in WEIGHTS
            ]))
            swap, = detector.poll(signals)
            print(f"  Lab signals      {', '.join(swap.sources)} -> {swap.assumption} {swap.tier} "
                  f"(score {swap.score:.2f}, epoch {swap.epoch})")
            votes = [voter.vote(swap) for voter in voters[:2]]
            seq = await publish(js, swap, votes, nodes)
            check(all(peer.epoch == 0 and keys_match(peer.key, initial_key) for peer in pair),
                  "A proposal without quorum changed peer state")
            print(f"  JetStream seq {seq}  2/5 Ed25519 + SLH-DSA votes rejected by both peers")
            await asyncio.sleep(pause)

            print("\n[3/5] Activate the signed swap")
            votes.append(voters[2].vote(swap))
            seq = await publish(js, swap, votes, nodes)
            check(all(peer.epoch == swap.epoch and keys_match(peer.key, initial_key) for peer in pair),
                  "Peers did not stage the certificate while keeping the current traffic key")
            print(f"  JetStream seq {seq}  3/5 votes accepted, epoch {swap.epoch} staged on both peers")
            print("  Traffic key      Unchanged while the policy is staged")
            boundary(pair, swap.epoch)
            print("  Epoch boundary   Both peers switched using secrets from the initial exchange")
            show_traffic(pair, "After the policy swap", ("classical", "code"))
            try:
                nonce, ciphertext = initial_packet
                ChaCha20Poly1305(server.key).decrypt(nonce, ciphertext, None)
            except InvalidTag:
                print("  New key rejected the packet encrypted before the swap")
            else:
                raise RuntimeError("The new key accepted a packet from before the swap")
            await asyncio.sleep(pause)

            print("\n[4/5] Fall back when delivery is split")
            signals.write_text("[]")
            recovery, = detector.poll(signals)
            print(f"  Lab signals      Cleared -> {recovery.assumption} {recovery.tier} (epoch {recovery.epoch})")
            await nodes[1].disconnect()
            seq = await publish(js, recovery, [voter.vote(recovery) for voter in voters[:3]], nodes[:1])
            check((client.epoch, server.epoch) == (recovery.epoch, swap.epoch),
                  "The delivery gap did not leave the peers on different policy epochs")
            print(f"  JetStream seq {seq}  Server subscriber offline "
                  f"(client epoch {client.epoch}, server epoch {server.epoch})")
            boundary(pair, recovery.epoch)
            show_traffic(pair, "Delivered during the gap", RAILS, fallback=True)
            await asyncio.sleep(pause)

            print("\n[5/5] Reconnect and return to the normal rails")
            await nodes[1].connect()
            await nodes[1].through(seq)
            check(client.offer() == server.offer() and server.epoch == recovery.epoch,
                  "The reconnected peer did not catch up to the published policy")
            print(f"  JetStream seq {seq}  Server caught up to epoch {server.epoch}")
            boundary(pair, recovery.epoch)
            show_traffic(pair, "Delivered after recovery", RAILS[:2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pause", type=float, default=0, metavar="SECONDS",
                        help="pause between stages for a live walkthrough")
    args = parser.parse_args()
    if not math.isfinite(args.pause) or args.pause < 0:
        parser.error("--pause must be a finite, nonnegative number")

    signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        with broker() as instance:
            asyncio.run(run(instance.url, args.pause))
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"Demo failed: {exc}") from None
    print("\nPASS  Encrypted traffic verified before the swap, after the swap, during fallback, and after recovery.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
