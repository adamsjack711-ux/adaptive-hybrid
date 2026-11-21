"""Two-process mTLS sensor link with durable JetStream policy recovery."""

import argparse
import asyncio
from contextlib import ExitStack
from dataclasses import dataclass
import multiprocessing
from pathlib import Path
import socket
from tempfile import TemporaryDirectory

from combiner import STREAM, SUBJECTS, Subscriber, load_nats
from detector import Advisory, SLH, Voter
from handshake import require_kems
from verification.broker import broker
from verification.durable_session import establish, send_frames
from verification.network_examples import (make_certificates, packet, read_frame,
                                           tls_context, verify_packet)
from wire import MAX_OFFER_BYTES, encode_certificate, encode_offer


TIMEOUT = 60


@dataclass(frozen=True)
class Phase:
    directory: Path
    identities: tuple
    broker_url: str
    first_seq: int | None = None
    future_seq: int | None = None
    missing_seq: int | None = None


def exchange_boundary(conn, reader, node, epoch, role):
    peer = node.pair[0]
    if role == "client":
        send_frames(conn, encode_offer(peer.offer()))
        remote = read_frame(reader, MAX_OFFER_BYTES)
        if not node.activate(remote, epoch, peer.round + 1) or peer.key is None:
            raise RuntimeError("client rejected policy-gated boundary")
        verify_packet(peer, read_frame(reader, 256), f"server reading at epoch {epoch}".encode())
        send_frames(conn, packet(peer, f"client receipt at epoch {epoch}".encode()))
    else:
        remote = read_frame(reader, MAX_OFFER_BYTES)
        send_frames(conn, encode_offer(peer.offer()))
        if not node.activate(remote, epoch, peer.round + 1) or peer.key is None:
            raise RuntimeError("server rejected policy-gated boundary")
        send_frames(conn, packet(peer, f"server reading at epoch {epoch}".encode()))
        verify_packet(peer, read_frame(reader, 256), f"client receipt at epoch {epoch}".encode())
    return peer.rails


async def run_node(conn, reader, peer, phase, role):
    node = Subscriber([peer], f"network-{role}", 1, phase.broker_url,
                      phase.directory / f"{role}-cursor.state")
    try:
        await node.connect()
        if phase.missing_seq is None:
            await node.through(phase.first_seq)
            if not node.ready_for(1):
                raise RuntimeError("initial policy did not arrive")
            rails = exchange_boundary(conn, reader, node, 1, role)
            key, round_id = peer.key, peer.round
            await node.through(phase.future_seq)
            if node.ready_for(3) or node.deferred != [phase.future_seq]:
                raise RuntimeError("future policy was not held")
            try:
                node.activate(b"", 3, round_id + 1)
            except ValueError:
                pass
            else:
                raise AssertionError("traffic boundary activated before epoch 2")
            if peer.key != key or peer.round != round_id:
                raise AssertionError("blocked boundary changed the traffic session")
            return rails, peer.epoch, node.cursor

        if peer.key is not None:
            raise AssertionError("process restart retained a traffic key")
        if node.deferred != [phase.future_seq]:
            raise AssertionError("process restart lost deferred policy history")
        await node.through(phase.missing_seq)
        if not node.ready_for(3) or node.deferred or node.overflow_next is not None:
            raise RuntimeError("policy did not recover through epoch 3")
        rails = exchange_boundary(conn, reader, node, 3, role)
        return rails, peer.epoch, node.cursor
    finally:
        await node.disconnect()


def serve(phase, channel):
    with channel, socket.create_server(("127.0.0.1", 0)) as listener, ExitStack() as stack:
        listener.settimeout(TIMEOUT)
        channel.send(listener.getsockname()[1])
        raw, _ = listener.accept()
        raw.settimeout(TIMEOUT)
        with raw, tls_context(phase.directory, "server").wrap_socket(raw, server_side=True) as conn:
            with conn.makefile("rb") as reader:
                peer = establish(conn, reader, phase, "server", stack)
                asyncio.run(run_node(conn, reader, peer, phase, "server"))


def connect(phase, port):
    with socket.create_connection(("127.0.0.1", port), TIMEOUT) as raw, ExitStack() as stack:
        with tls_context(phase.directory, "client").wrap_socket(
                raw, server_hostname="server.adaptive.test") as conn:
            with conn.makefile("rb") as reader:
                peer = establish(conn, reader, phase, "client", stack)
                return asyncio.run(run_node(conn, reader, peer, phase, "client"))


def connect_worker(phase, port, channel):
    with channel:
        channel.send(connect(phase, port))


def run_phase(phase):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    result_parent, result_child = context.Pipe(duplex=False)
    server = context.Process(target=serve, args=(phase, child))
    client = None
    server.start()
    child.close()
    try:
        if not parent.poll(TIMEOUT):
            raise TimeoutError("server did not start")
        port = parent.recv()
        client = context.Process(target=connect_worker, args=(phase, port, result_child))
        client.start()
        result_child.close()
        client.join(TIMEOUT)
        if client.exitcode != 0 or not result_parent.poll(1):
            raise RuntimeError("client did not finish the authenticated session")
        result = result_parent.recv()
        server.join(TIMEOUT)
        if server.exitcode != 0:
            raise RuntimeError("server did not finish the authenticated session")
        return result
    finally:
        parent.close()
        result_parent.close()
        result_child.close()
        for worker in (client, server):
            if worker is None:
                continue
            if worker.is_alive():
                worker.terminate()
                worker.join(5)
            worker.close()


async def seed_stream(url, certificates):
    nats, api = load_nats()
    nc = await nats.connect(url, allow_reconnect=False)
    try:
        js = nc.jetstream()
        await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
        first = await js.publish("advisories.lattice", certificates[1], stream=STREAM)
        future = await js.publish("advisories.lattice", certificates[3], stream=STREAM)
        return first.seq, future.seq
    finally:
        await nc.close()


async def publish_missing(url, certificate):
    nats, _ = load_nats()
    nc = await nats.connect(url, allow_reconnect=False)
    try:
        ack = await nc.jetstream().publish("advisories.lattice", certificate, stream=STREAM)
        return ack.seq
    finally:
        await nc.close()


def main():
    require_kems()
    with TemporaryDirectory(prefix="adaptive-network-recovery-") as tmp, ExitStack() as stack, broker() as instance:
        directory = Path(tmp)
        make_certificates(directory)
        oqs = require_kems()
        if SLH not in oqs.get_enabled_sig_mechanisms():
            raise RuntimeError(f"Enable {SLH} in liboqs")
        voters = [Voter(str(i), oqs, stack, directory / f"voter-{i}.state") for i in range(3)]
        identities = tuple((v.name, v.public[0].public_bytes_raw(), v.public[1])
                           for v in voters)
        certificates = {}
        for epoch in range(1, 4):
            advisory = Advisory(epoch, "lattice", "normal", 0, ())
            certificates[epoch] = encode_certificate(advisory, [v.vote(advisory) for v in voters])

        first, future = asyncio.run(seed_stream(instance.url, certificates))
        before = run_phase(Phase(directory, identities, instance.url, first, future))
        if before[1:] != (1, future):
            raise RuntimeError(f"unexpected pre-recovery policy state: {before}")
        old_pid = instance.proc.pid
        instance.restart()
        if instance.proc.pid == old_pid:
            raise AssertionError("broker did not hard-restart")
        missing = asyncio.run(publish_missing(instance.url, certificates[2]))
        after = run_phase(Phase(directory, identities, instance.url,
                                future_seq=future, missing_seq=missing))
        if after[1:] != (3, missing):
            raise RuntimeError(f"unexpected recovered policy state: {after}")
        print("PASS two mutually authenticated processes withheld epoch 2 and blocked a new traffic boundary")
        print("PASS hard broker and endpoint restarts recovered signed epochs 2 and 3 from JetStream")
        print("PASS fresh three-rail KEM session exchanged encrypted sensor data at epoch 3")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    main()
