"""Authenticated two-process, multi-boundary lab session with process restart.

The lab CA and signer keys live in a private temporary directory. Each process
owns only its peer policy file. Restart performs a fresh three-rail exchange;
session secrets and traffic keys never enter the durable state files.
"""

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import multiprocessing
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from time import sleep

from detector import Advisory, SLH, Voter
from handshake import RAILS, require_kems
from verification.network_examples import (KeyExchange, make_certificates, make_peer,
                                           packet, read_frame, tls_context, transcript,
                                           verify_packet)
from wire import MAX_CERTIFICATE_BYTES, MAX_OFFER_BYTES, encode_certificate, encode_offer


TIMEOUT = 25


def send_frames(conn, *frames):
    conn.sendall(b"".join(len(frame).to_bytes(4, "big") + frame for frame in frames))


@dataclass(frozen=True)
class Phase:
    directory: Path
    identities: tuple
    epochs: tuple
    certificates: tuple
    crash_server: bool = False


def establish(conn, reader, phase, role, stack):
    oqs = require_kems()
    exchange = KeyExchange(RAILS, oqs, stack)
    if role == "client":
        public = exchange.public_frames()
        send_frames(conn, *public)
        replies = exchange.read(reader, "ciphertext")
        secrets = exchange.finish(replies)
    else:
        public = exchange.read(reader, "public_key")
        replies, secrets = exchange.respond(public)
        send_frames(conn, *replies)
    verifier = stack.enter_context(oqs.Signature(SLH))
    return make_peer(role, phase.identities, verifier, secrets,
                     transcript(RAILS, public, replies), phase.directory / f"{role}.state")


def run_boundary(conn, reader, peer, epoch, certificate, role):
    subject = b"advisories.lattice" if certificate else b""
    if role == "client":
        if certificate and not peer.receive_certificate(certificate, subject.decode()):
            raise RuntimeError("client rejected signed certificate")
        send_frames(conn, epoch.to_bytes(8, "big"), subject, certificate,
                    encode_offer(peer.offer()))
        offer = read_frame(reader, MAX_OFFER_BYTES)
        if not peer.activate(offer, epoch, peer.round + 1) or peer.key is None:
            raise RuntimeError("client rejected authenticated boundary offer")
        message = read_frame(reader, 256)
        verify_packet(peer, message, f"server epoch {epoch}".encode())
        send_frames(conn, packet(peer, f"client epoch {epoch}".encode()))
    else:
        remote_epoch = read_frame(reader, 8)
        if len(remote_epoch) != 8 or int.from_bytes(remote_epoch, "big") != epoch:
            raise RuntimeError("wrong scheduled boundary")
        remote_subject = read_frame(reader, 64)
        remote_certificate = read_frame(reader, MAX_CERTIFICATE_BYTES)
        if remote_subject != subject or remote_certificate != certificate:
            raise RuntimeError("unexpected certificate delivery")
        if certificate and not peer.receive_certificate(certificate, subject.decode()):
            raise RuntimeError("server rejected signed certificate")
        offer = read_frame(reader, MAX_OFFER_BYTES)
        if not peer.activate(offer, epoch, peer.round + 1) or peer.key is None:
            raise RuntimeError("server rejected authenticated boundary offer")
        send_frames(conn, encode_offer(peer.offer()),
                    packet(peer, f"server epoch {epoch}".encode()))
        verify_packet(peer, read_frame(reader, 256), f"client epoch {epoch}".encode())
    return peer.rails, peer.fallback


def serve(phase, channel):
    with channel, socket.create_server(("127.0.0.1", 0)) as listener, ExitStack() as stack:
        listener.settimeout(TIMEOUT)
        channel.send(listener.getsockname()[1])
        raw, _ = listener.accept()
        raw.settimeout(TIMEOUT)
        with raw, tls_context(phase.directory, "server").wrap_socket(raw, server_side=True) as conn:
            with conn.makefile("rb") as reader:
                peer = establish(conn, reader, phase, "server", stack)
                for epoch, certificate in zip(phase.epochs, phase.certificates):
                    run_boundary(conn, reader, peer, epoch, certificate, "server")
        if phase.crash_server:
            # The parent kills this process after the client has completed.
            # Every policy update was durably written before its packet reply.
            while True:
                sleep(60)


def connect(phase, port):
    with socket.create_connection(("127.0.0.1", port), TIMEOUT) as raw, ExitStack() as stack:
        with tls_context(phase.directory, "client").wrap_socket(
                raw, server_hostname="server.adaptive.test") as conn:
            with conn.makefile("rb") as reader:
                peer = establish(conn, reader, phase, "client", stack)
                if phase.epochs[0] > 0 and peer.key is not None:
                    raise RuntimeError("restored policy allowed traffic before a fresh boundary")
                results = []
                for epoch, certificate in zip(phase.epochs, phase.certificates):
                    results.append(run_boundary(conn, reader, peer, epoch, certificate, "client"))
                return results


def connect_worker(phase, port, channel):
    with channel:
        channel.send(connect(phase, port))


def run_phase(phase):
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    result_parent, result_child = ctx.Pipe(duplex=False)
    server = ctx.Process(target=serve, args=(phase, child))
    client = None
    server.start()
    child.close()
    try:
        if not parent.poll(TIMEOUT):
            raise TimeoutError("server did not start")
        port = parent.recv()
        client = ctx.Process(target=connect_worker, args=(phase, port, result_child))
        client.start()
        result_child.close()
        client.join(TIMEOUT)
        if client.exitcode != 0 or not result_parent.poll(1):
            raise RuntimeError("client did not finish the authenticated session")
        results = result_parent.recv()
        if phase.crash_server:
            server.kill()
        server.join(TIMEOUT)
        if (phase.crash_server and server.exitcode == 0) or (
                not phase.crash_server and server.exitcode != 0):
            raise RuntimeError("server did not finish the authenticated session")
        return results
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


def main():
    require_kems()
    with TemporaryDirectory(prefix="adaptive-durable-") as tmp:
        directory = Path(tmp)
        make_certificates(directory)
        with ExitStack() as stack:
            oqs = require_kems()
            if SLH not in oqs.get_enabled_sig_mechanisms():
                raise RuntimeError(f"Enable {SLH} in liboqs")
            voters = [Voter(str(i), oqs, stack, directory / f"voter-{i}.state")
                      for i in range(3)]
            identities = tuple((v.name, v.public[0].public_bytes_raw(), v.public[1])
                               for v in voters)
            watch = Advisory(1, "lattice", "watch", .4, ("paper",))
            swap = Advisory(2, "lattice", "swap", .85, ("paper", "quantum"))
            first = (b"", encode_certificate(watch, [v.vote(watch) for v in voters]),
                     encode_certificate(swap, [v.vote(swap) for v in voters]))
        phase = Phase(directory, identities, (0, 1, 2), first, crash_server=True)
        first_results = run_phase(phase)
        if first_results != [(RAILS[:2], False), (RAILS[:2], False),
                             (("classical", "code"), False)]:
            raise RuntimeError(f"unexpected first-session rails: {first_results}")

        with ExitStack() as stack:
            voters = [Voter(str(i), require_kems(), stack, directory / f"voter-{i}.state")
                      for i in range(3)]
            if tuple((v.name, v.public[0].public_bytes_raw(), v.public[1])
                     for v in voters) != identities or any(v.last != 2 for v in voters):
                raise RuntimeError("signer identity or vote floor changed on restart")
            normal = Advisory(3, "lattice", "normal", 0, ())
            third = encode_certificate(normal, [v.vote(normal) for v in voters])
        second_results = run_phase(Phase(directory, identities, (2, 3), (b"", third)))
        if second_results != [(("classical", "code"), False), (RAILS[:2], False)]:
            raise RuntimeError(f"unexpected restarted-session rails: {second_results}")
        print("PASS two authenticated processes completed three policy epochs")
        print("PASS hard server crash and new peer processes retained signer identity, vote floor and policy")
        print("PASS fresh three-rail handshake resumed encrypted traffic at a new boundary")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    main()
