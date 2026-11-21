"""Probe hostile JetStream publications and deferred-history exhaustion."""

import argparse
import asyncio
from contextlib import ExitStack
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from combiner import STREAM, SUBJECTS, Subscriber, load_nats
from detector import Advisory, Voter
from handshake import require_kems
from verification.broker import broker
from verification.recovery_stress import make_nodes, traffic
from wire import MAX_CERTIFICATE_BYTES, encode_certificate


async def exercise(instance, directory, roster, certificates, *, hostile_rounds, future_certificates):
    nats, api = load_nats()
    nc = await nats.connect(instance.url, allow_reconnect=False)
    js = nc.jetstream()
    await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
    node = make_nodes(directory, roster, None, instance.url, 1)[0]

    async def publish(data):
        ack = await js.publish("advisories.classical", data, stream=STREAM)
        return ack.seq

    try:
        await node.connect()
        valid_first = certificates[1]
        # A syntactically valid certificate with a changed signed advisory.
        tampered = valid_first.replace(b'"epoch":1', b'"epoch":2', 1)
        assert tampered != valid_first
        hostile = (b"not JSON", tampered, b"x" * (MAX_CERTIFICATE_BYTES + 1))
        started = perf_counter()
        logging.disable(logging.WARNING)
        try:
            for _ in range(hostile_rounds):
                for payload in hostile:
                    await node.through(await publish(payload))
        finally:
            logging.disable(logging.NOTSET)
        elapsed = perf_counter() - started
        hostile_count = 3 * hostile_rounds
        assert node.cursor == hostile_count and not node.ready_for(1)
        assert all(peer.epoch == 0 for peer in node.pair)

        await node.through(await publish(valid_first))
        assert node.ready_for(1)
        traffic([node], 1, {})
        print(f"PASS {hostile_count} malformed, forged, and oversized publications did not advance policy ({elapsed:.3f} s)")

        # A publisher able to deliver quorum-certified future epochs can fill
        # the bounded deferred list while epoch 2 is withheld.
        last_epoch = future_certificates + 2
        flood_started = perf_counter()
        for epoch in range(3, last_epoch + 1):
            await node.through(await publish(certificates[epoch]))
            if epoch % 8 == 0:
                logging.disable(logging.WARNING)
                try:
                    await node.through(await publish(b"not JSON"))
                finally:
                    logging.disable(logging.NOTSET)
        assert len(node.deferred) == Subscriber.MAX_DEFERRED
        flood_elapsed = perf_counter() - flood_started
        assert not node.ready_for(last_epoch)
        assert node.overflow_next is not None
        assert len(node.deferred) == Subscriber.MAX_DEFERRED
        try:
            node.boundary(last_epoch)
        except ValueError:
            pass
        else:
            raise AssertionError("boundary activated with missing policy history")

        missing_seq = await publish(certificates[2])
        await node.disconnect()
        await nc.close()
        old_pid = instance.proc.pid
        instance.restart()
        assert instance.proc.pid != old_pid
        nc = await nats.connect(instance.url, allow_reconnect=False)
        js = nc.jetstream()
        node = make_nodes(directory, roster, None, instance.url, 1)[0]
        assert all(peer.key is None for peer in node.pair)
        assert len(node.deferred) == Subscriber.MAX_DEFERRED
        assert node.overflow_next is not None
        await node.connect()
        recovery_started = perf_counter()
        await node.through(missing_seq)
        recovery_elapsed = perf_counter() - recovery_started
        assert node.ready_for(last_epoch) and not node.deferred and node.overflow_next is None
        traffic([node], last_epoch, {})
        print(f"PASS {future_certificates} deferred certificates recovered after missing epoch and hard broker restart "
              f"(flood {flood_elapsed:.3f} s; recovery {recovery_elapsed:.3f} s)")
    finally:
        await node.disconnect()
        await nc.close()


async def exercise_at_limit(instance, directory, roster, certificates):
    directory.mkdir()
    nats, api = load_nats()
    nc = await nats.connect(instance.url, allow_reconnect=False)
    js = nc.jetstream()
    await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
    node = make_nodes(directory, roster, None, instance.url, 1)[0]

    async def publish(epoch):
        ack = await js.publish("advisories.classical", certificates[epoch], stream=STREAM)
        await node.through(ack.seq)

    try:
        await node.connect()
        await publish(1)
        for epoch in range(3, 3 + Subscriber.MAX_DEFERRED):
            await publish(epoch)
        assert len(node.deferred) == Subscriber.MAX_DEFERRED
        await publish(2)
        assert node.ready_for(34) and not node.deferred
        traffic([node], 34, {})
        print("PASS 32 deferred certificates recovered when missing epoch arrived")
    finally:
        await node.disconnect()
        await nc.close()


async def exercise_overflow_loss(instance, directory, roster, certificates):
    directory.mkdir()
    nats, api = load_nats()
    nc = await nats.connect(instance.url, allow_reconnect=False)
    js = nc.jetstream()
    await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
    node = make_nodes(directory, roster, None, instance.url, 1)[0]

    async def publish(epoch):
        ack = await js.publish("advisories.classical", certificates[epoch], stream=STREAM)
        await node.through(ack.seq)

    try:
        await node.connect()
        await publish(1)
        for epoch in range(3, 36):
            await publish(epoch)
        overflow_seq = node.overflow_next
        assert overflow_seq is not None and len(node.deferred) == Subscriber.MAX_DEFERRED
        assert await js.delete_msg(STREAM, overflow_seq)
        missing = await js.publish("advisories.classical", certificates[2], stream=STREAM)
        await node.disconnect()
        node = make_nodes(directory, roster, None, instance.url, 1)[0]
        assert all(peer.key is None for peer in node.pair)
        await node.connect()
        try:
            await node.through(missing.seq)
        except nats.js.errors.NotFoundError:
            pass
        else:
            raise AssertionError("recovery proceeded after overflow history was deleted")
        assert not node.ready_for(35)
        assert all(peer.key is None for peer in node.pair)
        print("PASS deleted overflow history blocked recovery and new key activation")
    finally:
        await node.disconnect()
        await nc.close()


def main():
    if not __debug__:
        raise RuntimeError("run without -O so assertions are enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostile-rounds", type=int, default=32)
    parser.add_argument("--future-certificates", type=int, default=64)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.hostile_rounds <= 5000:
        parser.error("hostile-rounds must be 1..5000")
    if not 33 <= args.future_certificates <= 1000:
        parser.error("future-certificates must be 33..1000")
    if args.timeout < 1:
        parser.error("timeout must be positive")
    oqs = require_kems()
    with TemporaryDirectory(prefix="adaptive-adversarial-") as tmp, ExitStack() as stack:
        directory = Path(tmp)
        voters = [Voter(str(i), oqs, stack, directory / f"voter-{i}.state") for i in range(3)]
        roster = {v.name: v.public for v in voters}
        certificates = {}
        for epoch in range(1, max(35, args.future_certificates + 2) + 1):
            advisory = Advisory(epoch, "classical", "normal", 0, ())
            certificates[epoch] = encode_certificate(advisory, [v.vote(advisory) for v in voters])
        with broker() as instance:
            asyncio.run(asyncio.wait_for(exercise(
                instance, directory, roster, certificates,
                hostile_rounds=args.hostile_rounds,
                future_certificates=args.future_certificates), args.timeout))
        with broker() as instance:
            asyncio.run(asyncio.wait_for(exercise_at_limit(
                instance, directory / "at-limit", roster, certificates), args.timeout))
        with broker() as instance:
            asyncio.run(asyncio.wait_for(exercise_overflow_loss(
                instance, directory / "overflow-loss", roster, certificates), args.timeout))


if __name__ == "__main__":
    main()
