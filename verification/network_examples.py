"""Compare two swap strategies over loopback mTLS with emulated link conditions."""
import argparse
import asyncio
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import ssl
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter, sleep

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from combiner import Peer, STREAM, SUBJECTS, Subscriber, load_nats, publish
from detector import Advisory, SLH, Voter
from handshake import ALGORITHMS, RAILS, derive, require_kems
from verification.broker import broker
from verification.demo import check
from wire import MAX_OFFER_BYTES, encode_offer


NORMAL = RAILS[:2]
SWAP = ("classical", "code")
TIMEOUT = 20
INITIAL_READING = b'{"sensor":"pump-07","sample":1,"temperature_c":32.4}'
BOUNDARY_READING = b'{"sensor":"pump-07","sample":2,"temperature_c":32.5}'
CATCH_UP_READING = b'{"sensor":"pump-07","sample":3,"temperature_c":32.6}'


@dataclass(frozen=True)
class Link:
    name: str
    rtt_ms: int
    mbps: float

    def send(self, conn, *frames):
        encoded = b"".join(len(frame).to_bytes(4, "big") + frame for frame in frames)
        sleep(self.rtt_ms / 2000 + len(encoded) * 8 / (self.mbps * 1_000_000))
        conn.sendall(encoded)


LINKS = {
    "internal": Link("Internal", 2, 100),
    "branch": Link("Branch office", 50, 10),
    "remote": Link("Constrained remote", 150, 2),
    "iot": Link("IoT gateway", 150, .512),
}


def read_frame(reader, maximum):
    header = reader.read(4)
    check(len(header) == 4, "Missing frame header")
    size = int.from_bytes(header, "big")
    check(size <= maximum, "Oversized frame")
    data = reader.read(size)
    check(len(data) == size, "Truncated frame")
    return data


def make_certificates(directory):
    now = datetime.now(timezone.utc)
    ca_key = Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Adaptive Hybrid lab CA")])

    def builder(name, key):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1)))

    ca = builder(ca_name, ca_key).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
    (directory / "ca.pem").write_bytes(ca.sign(ca_key, None).public_bytes(Encoding.PEM))
    for role, purpose in (("server", ExtendedKeyUsageOID.SERVER_AUTH), ("client", ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{role}.adaptive.test")])
        leaf = (builder(name, key).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([purpose]), False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(f"{role}.adaptive.test")]), False))
        (directory / f"{role}.pem").write_bytes(leaf.sign(ca_key, None).public_bytes(Encoding.PEM))
        (directory / f"{role}.key").write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))


def tls_context(directory, role):
    protocol = ssl.PROTOCOL_TLS_CLIENT if role == "client" else ssl.PROTOCOL_TLS_SERVER
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(directory / "ca.pem")
    context.load_cert_chain(directory / f"{role}.pem", directory / f"{role}.key")
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class KeyExchange:
    """Run one side of the fixed-suite exchange across the lab connection."""

    def __init__(self, rails, oqs, stack):
        self.keys = {rail: X25519PrivateKey.generate() if rail == "classical" else
                     stack.enter_context(oqs.KeyEncapsulation(ALGORITHMS[rail])) for rail in rails}

    def public_frames(self):
        return [key.public_key().public_bytes_raw() if rail == "classical" else key.generate_keypair()
                for rail, key in self.keys.items()]

    def read(self, reader, direction):
        sizes = [32 if rail == "classical" else key.details[f"length_{direction}"]
                 for rail, key in self.keys.items()]
        frames = [read_frame(reader, size) for size in sizes]
        check(all(len(frame) == size for frame, size in zip(frames, sizes)), "Wrong exchange field length")
        return frames

    def respond(self, public):
        replies, secrets = [], {}
        for (rail, key), frame in zip(self.keys.items(), public):
            if rail == "classical":
                reply = key.public_key().public_bytes_raw()
                secret = key.exchange(X25519PublicKey.from_public_bytes(frame))
            else:
                reply, secret = key.encap_secret(frame)
            replies.append(reply)
            secrets[rail] = secret
        return replies, secrets

    def finish(self, replies):
        return {rail: key.exchange(X25519PublicKey.from_public_bytes(frame)) if rail == "classical" else
                key.decap_secret(frame) for (rail, key), frame in zip(self.keys.items(), replies)}


def transcript(rails, public, replies):
    payloads = [frame for pair in zip(public, replies) for frame in pair]
    return hashlib.sha256("|".join(ALGORITHMS[rail] for rail in rails).encode() + b"".join(payloads)).digest()


def make_peer(role, identity_keys, verifier, secrets, digest, state_path=None):
    roster = {name: (Ed25519PublicKey.from_public_bytes(ed), slh) for name, ed, slh in identity_keys}
    key = derive(secrets, NORMAL, digest, b"initial-v1", 0)
    return Peer(role, roster, verifier, (secrets, digest, key), state_path)


def packet(peer, message):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(peer.key).encrypt(nonce, message, None)


def verify_packet(peer, received, expected):
    plaintext = ChaCha20Poly1305(peer.key).decrypt(received[:12], received[12:], None)
    check(plaintext == expected, "Unexpected application message")


async def stage(peer, durable, url, sequence):
    node = Subscriber([peer], durable, sequence, url)
    try:
        await node.connect()
        await node.through(sequence)
    finally:
        await node.disconnect()
    check(peer.epoch == 1, f"{peer.name} did not stage the signed advisory")


def activate(peer, offer, rails, fallback):
    check(peer.activate(offer, 1, peer.round + 1), "Invalid boundary offer")
    check(peer.rails == rails and peer.fallback == fallback and peer.key is not None,
          f"{peer.name} selected unexpected rails")


@dataclass(frozen=True)
class Scenario:
    link: Link
    preload: bool
    advisory_gap: bool
    label: str
    directory: Path
    broker_url: str
    sequence: int
    identity_keys: tuple


def server(scenario, control):
    link = scenario.link
    oqs = require_kems()
    context = tls_context(scenario.directory, "server")
    rails = RAILS if scenario.preload else NORMAL
    with control, socket.create_server(("127.0.0.1", 0)) as listener, ExitStack() as stack:
        listener.settimeout(TIMEOUT)
        control.send(listener.getsockname()[1])
        raw, _ = listener.accept()
        raw.settimeout(TIMEOUT)
        with raw, context.wrap_socket(raw, server_side=True) as conn, conn.makefile("rb") as reader:
            control.send("tls-ready")
            exchange = KeyExchange(rails, oqs, stack)
            public = exchange.read(reader, "public_key")
            replies, secrets = exchange.respond(public)
            verifier = stack.enter_context(oqs.Signature(SLH))
            peer = make_peer("server", scenario.identity_keys, verifier, secrets, transcript(rails, public, replies))
            link.send(conn, *replies, packet(peer, INITIAL_READING))

            if not scenario.advisory_gap:
                asyncio.run(stage(peer, scenario.label + "-server", scenario.broker_url, scenario.sequence))
            control.send(peer.epoch)
            offer = read_frame(reader, MAX_OFFER_BYTES)
            replies = []
            if not scenario.preload:
                exchange = KeyExchange(SWAP, oqs, stack)
                public = exchange.read(reader, "public_key")
                replies, secrets = exchange.respond(public)
                peer.secrets.update(secrets)
                peer.transcript = hashlib.sha256(peer.transcript + transcript(SWAP, public, replies)).digest()
            activate(peer, offer, RAILS if scenario.advisory_gap else SWAP, scenario.advisory_gap)
            link.send(conn, encode_offer(peer.offer()), *replies, packet(peer, BOUNDARY_READING))

            if scenario.advisory_gap:
                asyncio.run(stage(peer, scenario.label + "-server", scenario.broker_url, scenario.sequence))
                control.send(peer.epoch)
                activate(peer, read_frame(reader, MAX_OFFER_BYTES), SWAP, False)
                link.send(conn, encode_offer(peer.offer()), packet(peer, CATCH_UP_READING))


def receive_control(pipe):
    check(pipe.poll(TIMEOUT), "Server did not reach its checkpoint")
    return pipe.recv()


def client(scenario, control, port):
    link = scenario.link
    oqs = require_kems()
    context = tls_context(scenario.directory, "client")
    rails = RAILS if scenario.preload else NORMAL
    with ExitStack() as stack, socket.create_connection(("127.0.0.1", port), TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname="server.adaptive.test") as conn, conn.makefile("rb") as reader:
            check(receive_control(control) == "tls-ready", "Server did not authenticate the connection")
            verifier = stack.enter_context(oqs.Signature(SLH))
            started = perf_counter()
            exchange = KeyExchange(rails, oqs, stack)
            public = exchange.public_frames()
            link.send(conn, *public)
            replies = exchange.read(reader, "ciphertext")
            digest = transcript(rails, public, replies)
            peer = make_peer("client", scenario.identity_keys, verifier, exchange.finish(replies), digest)
            verify_packet(peer, read_frame(reader, 128), INITIAL_READING)
            setup_ms = 1000 * (perf_counter() - started)
            setup_bytes = sum(map(len, public + replies))

            asyncio.run(stage(peer, scenario.label + "-client", scenario.broker_url, scenario.sequence))
            check(receive_control(control) == (0 if scenario.advisory_gap else 1), "Incorrect server policy epoch")
            started = perf_counter()
            public, replies = [], []
            if not scenario.preload:
                exchange = KeyExchange(SWAP, oqs, stack)
                public = exchange.public_frames()
            link.send(conn, encode_offer(peer.offer()), *public)
            offer = read_frame(reader, MAX_OFFER_BYTES)
            if not scenario.preload:
                replies = exchange.read(reader, "ciphertext")
                peer.secrets.update(exchange.finish(replies))
                peer.transcript = hashlib.sha256(peer.transcript + transcript(SWAP, public, replies)).digest()
            activate(peer, offer, RAILS if scenario.advisory_gap else SWAP, scenario.advisory_gap)
            verify_packet(peer, read_frame(reader, 128), BOUNDARY_READING)
            swap_ms = 1000 * (perf_counter() - started)
            swap_bytes = sum(map(len, public + replies))

            if scenario.advisory_gap:
                check(receive_control(control) == 1, "Server did not catch up")
                link.send(conn, encode_offer(peer.offer()))
                activate(peer, read_frame(reader, MAX_OFFER_BYTES), SWAP, False)
                verify_packet(peer, read_frame(reader, 128), CATCH_UP_READING)
    return setup_bytes, setup_ms, swap_bytes, swap_ms


def run_case(scenario):
    ctx = multiprocessing.get_context("spawn")
    with ExitStack() as stack:
        parent, child = ctx.Pipe(duplex=False)
        stack.enter_context(parent)
        stack.enter_context(child)
        worker = ctx.Process(target=server, args=(scenario, child))
        worker.start()
        child.close()
        try:
            result = client(scenario, parent, receive_control(parent))
            worker.join(TIMEOUT)
            check(worker.exitcode == 0, "Server did not complete the scenario")
            return result
        finally:
            if worker.is_alive():
                worker.terminate()
                worker.join(5)
            if worker.is_alive():
                worker.kill()
                worker.join()
            worker.close()


async def publish_swap(url, votes, advisory):
    nats, api = load_nats()
    conn = await nats.connect(url, allow_reconnect=False)
    try:
        js = conn.jetstream()
        await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
        return await publish(js, advisory, votes, [])
    finally:
        await conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5, help="samples per strategy and link")
    parser.add_argument("--link", choices=LINKS, help="run only this link profile")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    oqs = require_kems()
    check(SLH in oqs.get_enabled_sig_mechanisms(), f"Enable {SLH} in liboqs")
    with ExitStack() as stack, TemporaryDirectory(prefix="adaptive-network-") as tmp, broker() as instance:
        directory = Path(tmp)
        make_certificates(directory)
        advisory = Advisory(1, "lattice", "swap", 1.0, ("paper", "quantum", "anomaly"))
        voters = [Voter(str(i), oqs, stack) for i in range(5)]
        identities = tuple((v.name, v.public[0].public_bytes_raw(), v.public[1]) for v in voters)
        sequence = asyncio.run(publish_swap(instance.url, [v.vote(advisory) for v in voters[:3]], advisory))
        print(f"Authenticated loopback, emulated RTT and throughput, {args.runs} samples per strategy and link.", flush=True)
        print("Median ms to decrypted telemetry. Byte counts include only exchange payloads.", flush=True)
        print(f"{'Link (RTT / Mbit/s)':34} {'Strategy':10} {'Setup B':>9} {'Setup ms':>9} {'Swap B':>8} {'Swap ms':>8}", flush=True)
        selected = (args.link,) if args.link else LINKS
        for link_name in selected:
            link = LINKS[link_name]
            samples = {True: [], False: []}
            for run in range(args.runs):
                for preload in (True, False) if run % 2 == 0 else (False, True):
                    scenario = Scenario(link, preload, False, f"lab-{link_name}-{run}-{int(preload)}", directory,
                                        instance.url, sequence, identities)
                    samples[preload].append(run_case(scenario))
            for preload, measurements in samples.items():
                setup_bytes, setup_ms, swap_bytes, swap_ms = map(median, zip(*measurements))
                name = f"{link.name} ({link.rtt_ms} ms / {link.mbps:g})"
                strategy = "Preloaded" if preload else "Fresh"
                print(f"{name:34} {strategy:10} {setup_bytes:9,.0f} {setup_ms:9.1f} {swap_bytes:8,.0f} {swap_ms:8.1f}", flush=True)

        for link_name in selected:
            link = LINKS[link_name]
            gap = Scenario(link, True, True, f"lab-gap-{link_name}", directory, instance.url, sequence, identities)
            _, _, _, fallback_ms = run_case(gap)
            print(f"PASS delayed advisory on {link.name}: decrypted in {fallback_ms:.1f} ms on all rails, "
                  "then decrypted again after catch-up.", flush=True)
        print(f"  Client decrypted during fallback: {BOUNDARY_READING.decode()}")
        print(f"  Client decrypted after catch-up:   {CATCH_UP_READING.decode()}")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
