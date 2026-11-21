"""Five-node JetStream recovery lab with real KEMs, signatures, and crash replay."""

import asyncio
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from combiner import Peer, STREAM, SUBJECTS, Subscriber, load_nats
from detector import Advisory, SLH, Voter
from handshake import handshake, keys_match, require_kems
from verification.broker import broker
from wire import encode_certificate


COUNT = 5
EPOCHS = 12


def make_nodes(directory, roster, verifier, url):
    nodes = []
    for i in range(COUNT):
        pair = [Peer(f"node-{i}/{side}", roster, verifier, session,
                     directory / f"node-{i}-{side}.state")
                for side, session in zip(("client", "server"), handshake())]
        nodes.append(Subscriber(pair, f"recovery-{i}", 1, url,
                                directory / f"node-{i}-cursor.state"))
    return nodes


def traffic(nodes, epoch, previous):
    for i, node in enumerate(nodes):
        node.boundary(epoch)
        left, right = node.pair
        assert left.key is not None and keys_match(left.key, right.key)
        assert left.key != previous.get(i), f"node {i} reused a traffic key"
        previous[i] = left.key
        for direction, sender in enumerate(node.pair):
            receiver = node.pair[1 - direction]
            nonce = (epoch * COUNT * 2 + i * 2 + direction).to_bytes(12, "big")
            plaintext = f"node {i} epoch {epoch} direction {direction}".encode()
            encrypted = ChaCha20Poly1305(sender.key).encrypt(nonce, plaintext, None)
            assert ChaCha20Poly1305(receiver.key).decrypt(nonce, encrypted, None) == plaintext


async def exercise(instance, directory, roster, verifier, certificates):
    nats, api = load_nats()
    nc = await nats.connect(instance.url, allow_reconnect=False)
    js = nc.jetstream()
    await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
    nodes = make_nodes(directory, roster, verifier, instance.url)
    previous = {}
    packets = 0

    async def connect_all():
        await asyncio.gather(*(node.connect() for node in nodes))

    async def deliver(epoch, recipients):
        advisory, votes = certificates[epoch]
        ack = await js.publish("advisories." + advisory.assumption,
                               encode_certificate(advisory, votes), stream=STREAM)
        await asyncio.gather(*(node.through(ack.seq) for node in recipients))
        return ack.seq

    async def restart():
        nonlocal nc, js, nodes
        await asyncio.gather(*(node.disconnect() for node in nodes))
        await nc.close()
        old_pid = instance.proc.pid
        instance.restart()
        assert instance.proc.pid != old_pid
        nc = await nats.connect(instance.url, allow_reconnect=False)
        js = nc.jetstream()
        nodes = make_nodes(directory, roster, verifier, instance.url)
        assert all(peer.key is None for node in nodes for peer in node.pair)
        await connect_all()

    try:
        await connect_all()
        for epoch in (1, 2):
            await deliver(epoch, nodes)
            traffic(nodes, epoch, previous)
            packets += COUNT * 2

        await asyncio.gather(*(node.disconnect() for node in nodes[3:]))
        await deliver(4, nodes[:3])
        assert all(node.deferred for node in nodes[:3])
        for node in nodes:
            try:
                node.boundary(4)
            except ValueError:
                pass
            else:
                raise AssertionError("boundary activated before missing epoch 3")
        await restart()
        assert all(not node.ready_for(4) for node in nodes)
        for node in nodes:
            try:
                node.boundary(4)
            except ValueError:
                pass
            else:
                raise AssertionError("restored peer activated before recovering epoch 3")
        assert all(peer.key is None for node in nodes for peer in node.pair)
        await deliver(3, nodes)
        assert all(node.ready_for(4) and not node.deferred for node in nodes)
        traffic(nodes, 4, previous)
        packets += COUNT * 2
        print("PASS epoch 4 before 3: five cursors and policies recovered across broker and peer restart")

        for epoch in (5, 6):
            await deliver(epoch, nodes)
            traffic(nodes, epoch, previous)
            packets += COUNT * 2

        await asyncio.gather(*(node.disconnect() for node in nodes[3:]))
        await deliver(8, nodes[:3])
        assert all(not node.ready_for(8) for node in nodes)
        await deliver(7, nodes[:3])
        await asyncio.gather(*(node.connect() for node in nodes[3:]))
        target = (await js.stream_info(STREAM)).state.last_seq
        await asyncio.gather(*(node.through(target) for node in nodes[3:]))
        assert all(node.ready_for(8) for node in nodes)
        traffic(nodes, 8, previous)
        packets += COUNT * 2
        print("PASS epoch 8 before 7: offline nodes replayed retained certificates in order")

        for epoch in (9, 10):
            await deliver(epoch, nodes)
            traffic(nodes, epoch, previous)
            packets += COUNT * 2
        await restart()
        for epoch in (11, 12):
            await deliver(epoch, nodes)
            traffic(nodes, epoch, previous)
            packets += COUNT * 2
        assert all(node.cursor == EPOCHS for node in nodes)
        print(f"PASS {COUNT} nodes, {EPOCHS} signed epochs, two hard broker restarts, "
              f"{packets} encrypted packets, no repeated traffic keys")
    finally:
        await asyncio.gather(*(node.disconnect() for node in nodes))
        await nc.close()


def main():
    oqs = require_kems()
    if SLH not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError(f"Enable {SLH} in liboqs")
    with TemporaryDirectory(prefix="adaptive-recovery-") as tmp, ExitStack() as stack, broker() as instance:
        directory = Path(tmp)
        voters = [Voter(str(i), oqs, stack, directory / f"voter-{i}.state") for i in range(3)]
        roster = {v.name: v.public for v in voters}
        verifier = stack.enter_context(oqs.Signature(SLH))
        certificates = {}
        for epoch in range(1, EPOCHS + 1):
            tier = "swap" if epoch % 4 == 0 else "normal"
            advisory = Advisory(epoch, "lattice", tier, .85 if tier == "swap" else 0,
                                ("paper", "quantum") if tier == "swap" else ())
            certificates[epoch] = advisory, [v.vote(advisory) for v in voters]
        asyncio.run(exercise(instance, directory, roster, verifier, certificates))


if __name__ == "__main__":
    main()
