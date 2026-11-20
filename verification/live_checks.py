"""Run the fleet against an ephemeral, loopback-only JetStream instance."""
import asyncio
from contextlib import AsyncExitStack, ExitStack, contextmanager
from dataclasses import replace
import json
import multiprocessing
from pathlib import Path
import shutil
import subprocess
from statistics import median
import sys
import tempfile
import time
from timeit import repeat
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from combiner import Peer, Subscriber, STREAM, SUBJECTS, boundary, load_nats, publish
from detector import Advisory, SLH, Voter
from handshake import RAILS, handshake, keys_match, require_kems
from wire import encode_certificate


class Broker:
    def __init__(self, binary, directory):
        self.binary, self.directory = binary, Path(directory)
        self.port, self.proc = -1, None

    def start(self):
        self.proc = subprocess.Popen([
            self.binary, "-js", "-sd", str(self.directory / "store"), "-a", "127.0.0.1",
            "-p", str(self.port), "-ports_file_dir", str(self.directory),
        ], stderr=subprocess.DEVNULL)
        ports = self.directory / f"nats-server_{self.proc.pid}.ports"
        for _ in range(100):
            if self.proc.poll() is not None:
                raise RuntimeError("test broker exited during startup")
            try:
                url = json.loads(ports.read_text())["nats"][0]
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(.05)
                continue
            self.port = urlsplit(url).port
            self.url = url
            return
        raise TimeoutError("no broker ports file")

    def stop(self, *, crash=False):
        if self.proc is None or self.proc.poll() is not None:
            return
        if crash:
            self.proc.kill()
        else:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def restart(self):
        self.stop(crash=True)
        self.start()


@contextmanager
def broker():
    binary = shutil.which("nats-server")
    if binary is None:
        local = Path.home() / "go/bin/nats-server"
        if not local.is_file():
            raise FileNotFoundError("Install nats-server and add it to PATH")
        binary = str(local)
    with tempfile.TemporaryDirectory(prefix="adaptive-hybrid-") as tmp:
        instance = Broker(binary, tmp)
        try:
            instance.start()
            yield instance
        finally:
            instance.stop()


def signer_worker(pipe):
    with ExitStack() as stack:
        voter = Voter("5", require_kems(), stack)
        pipe.send((voter.public[0].public_bytes_raw(), voter.public[1]))
        advisory = pipe.recv()
        share = voter.vote(advisory)
        pipe.send(("prepared", advisory.epoch))
        pipe.recv()  # Deterministic failure point before delivery.
        pipe.send(share)


def receive(pipe):
    if not pipe.poll(10):
        raise TimeoutError("signer did not reach its checkpoint")
    return pipe.recv()


async def exercise(url, stack, pipe, worker, oqs):
    voters = [Voter(str(i), oqs, stack) for i in range(1, 5)]
    roster = {v.name: v.public for v in voters}
    public, slh = receive(pipe)
    roster["5"] = Ed25519PublicKey.from_public_bytes(public), slh
    verifier = stack.enter_context(oqs.Signature(SLH))
    nats, api = load_nats()
    async with AsyncExitStack() as cleanup:
        nc = await nats.connect(url)
        cleanup.push_async_callback(nc.close)
        js = nc.jetstream()
        try:
            await js.stream_info(STREAM)
        except nats.js.errors.NotFoundError:
            await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE)
        nodes = []
        for i in range(5):
            pair = [Peer(f"{i}/{side}", roster, verifier, session)
                    for side, session in zip(("client", "server"), handshake())]
            node = Subscriber(pair, f"test-{i}", 1, url)
            cleanup.push_async_callback(node.disconnect)
            await node.connect()
            nodes.append(node)
        peers = [p for node in nodes for p in node.pair]

        def snapshot():
            return [(p.offer(), p.rails, p.key, dict(p.states)) for p in peers]

        def activate(epoch, expected):
            for node in nodes:
                boundary(node.pair, epoch)
            assert all(p.rails == expected and p.key is not None for p in peers)

        first = Advisory(1, "lattice", "watch", .4, ("paper",))
        first_votes = [v.vote(first) for v in voters[:3]]
        await publish(js, first, first_votes, nodes)
        warn = replace(first, epoch=2, tier="warn", score=.64, sources=("paper", "quantum"))
        await publish(js, warn, [v.vote(warn) for v in voters[:3]], nodes)
        activate(2, RAILS[:2])
        swap = replace(warn, epoch=3, tier="swap", score=.85)
        activate(3, RAILS)
        assert all(p.epoch == 2 for p in peers)
        print("PASS withheld epoch 3: all rails, accepted policy 2, matching keys")

        partial = [v.vote(swap) for v in voters[:2]]
        pipe.send(swap)
        assert receive(pipe) == ("prepared", 3)
        worker.kill()
        worker.join(10)
        assert worker.exitcode is not None and worker.exitcode != 0
        before = snapshot()
        await publish(js, swap, partial, nodes)
        assert snapshot() == before
        await publish(js, swap, partial + [voters[2].vote(swap)], nodes)
        activate(3, ("classical", "code"))
        assert all(p.epoch == 3 for p in peers)
        print("PASS signer lost before share delivery: two rejected, surviving quorum activated")

        before = snapshot()
        await publish(js, first, first_votes, nodes)
        assert snapshot() == before
        print("PASS republished epoch 1: fresh stream sequence, policy and keys preserved")

        alternative = replace(swap, tier="normal")
        body = alternative.encode()
        competing = [(v.name, v.ed.sign(body), v.slh.sign(body)) for v in voters[:2]]
        await publish(js, alternative, competing + [voters[3].vote(alternative)], nodes)
        assert all(p.fork and p.key == old[2] and p.states == old[3] and p.epoch == 3
                   for p, old in zip(peers, before))
        activate(3, RAILS)
        recovery = replace(warn, epoch=4)
        await publish(js, recovery, [v.vote(recovery) for v in voters[:3]], nodes)
        activate(4, RAILS)
        assert all(p.fork and p.epoch == 4 for p in peers)
        print("PASS conflicting valid epoch 3: fork latched through epoch 4, all rails")


def run_live(instance):
    if not __debug__:
        raise RuntimeError("run without -O so assertions are enabled")
    # Finish a possible first-import liboqs build before the worker imports it too.
    oqs = require_kems()
    if SLH not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError(f"The live checks require {SLH} in liboqs")
    with ExitStack() as stack:
        ctx = multiprocessing.get_context("spawn")
        parent, child = ctx.Pipe()
        worker = ctx.Process(target=signer_worker, args=(child,))
        worker.start()
        child.close()
        try:
            asyncio.run(exercise(instance.url, stack, parent, worker, oqs))
        finally:
            if worker.is_alive():
                worker.kill()
            worker.join(10)
            parent.close()
    asyncio.run(chaos(instance))
    timing_check()


async def chaos(instance):
    oqs = require_kems()
    nats, _ = load_nats()
    with ExitStack() as stack:
        voters = [Voter(str(i), oqs, stack) for i in range(1, 4)]
        roster = {v.name: v.public for v in voters}
        verifier = stack.enter_context(oqs.Signature(SLH))
        pair = [Peer(name, roster, verifier, session)
                for name, session in zip(("left", "right"), handshake())]
        async with AsyncExitStack() as cleanup:
            async def publisher():
                nc = await nats.connect(instance.url, allow_reconnect=False)
                cleanup.push_async_callback(nc.close)
                return nc, nc.jetstream()

            nc, js = await publisher()
            start = (await js.stream_info(STREAM)).state.last_seq + 1
            nodes = [Subscriber([peer], f"chaos-{peer.name}", start, instance.url) for peer in pair]
            left, right = nodes
            for node in nodes:
                cleanup.push_async_callback(node.disconnect)
                await node.connect()

            first = Advisory(1, "lattice", "watch", .4, ("paper",))
            later = replace(first, epoch=2, score=.85, tier="swap", sources=("paper", "quantum"))
            first_votes, later_votes = ([v.vote(a) for v in voters] for a in (first, later))
            await publish(js, later, later_votes, nodes)
            assert all(peer.epoch == 0 for peer in pair)
            boundary(pair, 2)
            assert all(peer.fallback and peer.rails == RAILS for peer in pair)
            print("PASS out-of-order epoch 2: rejected over the gap, both peers fell back")

            first_seq = await publish(js, first, first_votes, [left])
            assert (pair[0].epoch, pair[1].epoch) == (1, 0)
            boundary(pair, 1)
            assert all(peer.fallback and peer.rails == RAILS for peer in pair)
            await asyncio.sleep(.05)
            await right.through(first_seq)
            boundary(pair, 1)
            assert all(not peer.fallback and peer.rails == RAILS[:2] for peer in pair)
            print("PASS delayed peer: fallback during split delivery, active keys after catch-up")

            second_seq = await publish(js, later, later_votes, [left])
            assert (pair[0].epoch, pair[1].epoch) == (2, 1)
            boundary(pair, 2)
            assert all(peer.fallback for peer in pair)
            pid = instance.proc.pid
            instance.restart()
            assert instance.proc.pid != pid
            await nc.close()
            _, js = await publisher()
            state = (await js.stream_info(STREAM)).state
            print(f"  recovered stream last sequence {state.last_seq}, latest publish {second_seq}")
            for node in nodes:
                await node.disconnect()
                await node.connect()
                consumer = await js.consumer_info(STREAM, node.durable)
                # Consumer metadata may lag a hard crash. Redelivery behind the
                # in-memory cursor must be harmless, and pending traffic must survive.
                assert consumer.ack_floor.stream_seq <= node.cursor
                print(f"  {node.durable}: persisted ack floor {consumer.ack_floor.stream_seq}, "
                      f"application cursor {node.cursor}, pending {consumer.num_pending}, "
                      f"ack pending {consumer.num_ack_pending}")
            await right.through(second_seq)
            boundary(pair, 2)
            assert keys_match(pair[0].key, pair[1].key) and pair[0].key is not None
            assert all(peer.epoch == 2 and not peer.fallback and peer.rails == ("classical", "code")
                       for peer in pair)
            print("PASS hard broker restart mid-epoch: pending traffic recovered, peers converged on epoch 2")

            before = [(peer.offer(), peer.key, dict(peer.states)) for peer in pair]
            for a, votes in ((first, first_votes), (later, later_votes), (later, later_votes)):
                await publish(js, a, votes, nodes)
            successor = replace(later, epoch=3, tier="normal")
            successor_votes = [v.vote(successor) for v in voters]
            malformed = encode_certificate(successor, successor_votes)
            duplicate = b'{"votes":[],' + malformed[1:]
            ack = await js.publish("advisories.lattice", duplicate, stream=STREAM)
            await asyncio.gather(*(node.through(ack.seq) for node in nodes))
            assert before == [(peer.offer(), peer.key, dict(peer.states)) for peer in pair]
            print("PASS duplicate and malformed publications after restart: policy and keys preserved")
            await publish(js, successor, successor_votes, nodes)
            boundary(pair, 3)
            assert all(peer.epoch == 3 and not peer.fallback and peer.rails == RAILS[:2] for peer in pair)


def timing_check():
    # Check the real backends using public inputs of the same length. Timings are
    # descriptive because scheduling and backend choice make thresholds flaky.
    with ExitStack() as stack:
        oqs = require_kems()
        voter = Voter("timing", oqs, stack)
        slh = stack.enter_context(oqs.Signature(SLH))
        advisory = Advisory(1, "lattice", "swap", .85, ("paper", "quantum"))
        _, ed_sig, slh_sig = voter.vote(advisory)
        ed_public, slh_public = voter.public
        valid, altered = advisory.encode(), replace(advisory, tier="warn").encode()

        def verify_ed(body):
            try:
                ed_public.verify(ed_sig, body)
            except InvalidSignature:
                return False
            return True

        def verify_slh(body):
            return slh.verify(body, slh_sig, slh_public)

        def microseconds(function, number):
            elapsed = repeat(function, number=number, repeat=9)
            return f"{median(elapsed) * 1e6 / number:.3f}"

        same, first, last = bytes(32), b"\x01" + bytes(31), bytes(31) + b"\x01"
        key_times = [microseconds(lambda: keys_match(same, other), 10_000) for other in (same, first, last)]
        print(f"Key comparison median µs (equal / first-byte / last-byte mismatch): {' / '.join(key_times)}")
        for name, verify in (("Ed25519", verify_ed), ("SLH-DSA", verify_slh)):
            assert verify(valid) and not verify(altered)
            print(f"{name} verification median µs (valid / altered body): "
                  f"{microseconds(lambda: verify(valid), 10)} / {microseconds(lambda: verify(altered), 10)}")


if __name__ == "__main__":
    with broker() as instance:
        run_live(instance)
