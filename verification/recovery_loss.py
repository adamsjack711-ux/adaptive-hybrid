"""Delete retained policy history and check that recovery fails closed."""

import asyncio
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory

from combiner import STREAM, SUBJECTS, load_nats
from detector import Advisory, SLH, Voter
from handshake import require_kems
from verification.broker import broker
from verification.recovery_stress import make_nodes, traffic
from wire import encode_certificate


async def exercise(instance, directory, roster, verifier, certificates):
    nats, api = load_nats()
    nc = await nats.connect(instance.url, allow_reconnect=False)
    js = nc.jetstream()
    await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
    nodes = make_nodes(directory, roster, verifier, instance.url, 2)

    async def publish(epoch):
        advisory, votes = certificates[epoch]
        ack = await js.publish("advisories.lattice", encode_certificate(advisory, votes),
                               stream=STREAM)
        return ack.seq

    try:
        await asyncio.gather(*(node.connect() for node in nodes))
        first = await publish(1)
        await asyncio.gather(*(node.through(first) for node in nodes))
        traffic(nodes, 1, {})

        future = await publish(3)
        await asyncio.gather(*(node.through(future) for node in nodes))
        assert all(node.deferred == [future] and not node.ready_for(3) for node in nodes)
        assert await js.delete_msg(STREAM, future)
        missing = await publish(2)
        errors = await asyncio.gather(*(node.through(missing) for node in nodes),
                                      return_exceptions=True)
        assert all(isinstance(error, nats.js.errors.NotFoundError) for error in errors), errors
        assert all(node.deferred == [future] and not node.ready_for(3) for node in nodes)

        await asyncio.gather(*(node.disconnect() for node in nodes))
        nodes = make_nodes(directory, roster, verifier, instance.url, 2)
        assert all(peer.key is None for node in nodes for peer in node.pair)
        await asyncio.gather(*(node.connect() for node in nodes))
        errors = await asyncio.gather(*(node.through(missing) for node in nodes),
                                      return_exceptions=True)
        assert all(isinstance(error, nats.js.errors.NotFoundError) for error in errors), errors
        for node in nodes:
            try:
                node.boundary(3)
            except ValueError:
                pass
            else:
                raise AssertionError("traffic key activated after retained history was deleted")
        assert all(peer.key is None for node in nodes for peer in node.pair)
        print("PASS deleted deferred certificate stopped recovery and key activation after restart")
    finally:
        await asyncio.gather(*(node.disconnect() for node in nodes))
        await nc.close()


def main():
    if not __debug__:
        raise RuntimeError("run without -O so assertions are enabled")
    oqs = require_kems()
    if SLH not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError(f"Enable {SLH} in liboqs")
    with TemporaryDirectory(prefix="adaptive-loss-") as tmp, ExitStack() as stack, broker() as instance:
        directory = Path(tmp)
        voters = [Voter(str(i), oqs, stack) for i in range(3)]
        roster = {v.name: v.public for v in voters}
        verifier = stack.enter_context(oqs.Signature(SLH))
        certificates = {}
        for epoch in range(1, 4):
            advisory = Advisory(epoch, "lattice", "normal", 0, ())
            certificates[epoch] = advisory, [v.vote(advisory) for v in voters]
        asyncio.run(exercise(instance, directory, roster, verifier, certificates))


if __name__ == "__main__":
    main()
