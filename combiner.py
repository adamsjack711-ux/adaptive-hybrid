"""Five-node quorum and epoch-activation demonstration."""
import argparse
import asyncio
import uuid
import hashlib
import json
import logging
import tempfile
import time
from contextlib import AsyncExitStack, ExitStack
from dataclasses import replace
from pathlib import Path

from detector import ASSUMPTIONS, GENESIS, SLH, TIERS, Detector, Voter, quorum
from handshake import RAILS, derive, handshake, keys_match, require_kems
from wire import decode_certificate, decode_offer, encode_certificate, encode_offer, valid_epoch, valid_offer


class Peer:
    def __init__(self, name, roster, verifier, session):
        self.name, self.roster, self.verifier = name, roster, verifier
        self.secrets, self.transcript, self.key = session
        self.states = dict.fromkeys(ASSUMPTIONS, "normal")
        self.epoch, self.head, self.last_digest = 0, GENESIS, None
        self.round, self.fork, self.fallback = 0, False, False
        self.rails = RAILS[:2]

    def receive(self, advisory, votes):
        # Stage certified policy until the next handshake boundary.
        epoch = advisory.epoch
        digest = hashlib.sha256(advisory.encode()).digest()
        if epoch < self.epoch:
            reason = "stale epoch"
        elif epoch == self.epoch and digest == self.last_digest:
            reason = "replay"
        elif advisory.assumption not in self.states or advisory.tier not in TIERS:
            reason = "invalid advisory"
        elif not quorum(advisory, votes, self.roster, self.verifier):
            reason = "insufficient valid distinct votes"
        elif epoch == self.epoch:
            self.fork = True
            reason = "conflicting certified advisory"
        elif epoch != self.epoch + 1:
            reason = "missing earlier epoch"
        else:
            self.epoch, self.last_digest = epoch, digest
            self.head = hashlib.sha256(self.head + digest).digest()
            self.states[advisory.assumption] = advisory.tier
            logging.info("%s staged epoch=%d %s=%s", self.name, epoch,
                         advisory.assumption, advisory.tier)
            return True
        logging.info("%s rejected epoch=%d current=%d reason=%s", self.name, epoch, self.epoch, reason)
        return False

    def receive_certificate(self, data, subject):
        try:
            advisory, votes = decode_certificate(data, subject)
        except ValueError as exc:
            logging.warning("%s rejected malformed certificate: %s", self.name, exc)
            return False
        return self.receive(advisory, votes)

    def offer(self):
        return self.epoch, self.head, self.fork

    def activate(self, remote, expected, round_id):
        # Both peers use the scheduled epoch even if neither received its certificate.
        if isinstance(remote, bytes):
            try:
                remote = decode_offer(remote)
            except ValueError:
                return False
        if not valid_offer(remote) or not valid_epoch(expected):
            return False
        if not valid_epoch(round_id, 1) or round_id != self.round + 1:
            raise ValueError("out-of-order handshake round")
        local = self.offer()
        epoch_ok = local == remote and self.epoch == expected and not self.fork
        rails = RAILS
        reason = "offline, epoch mismatch or disputed history"
        if epoch_ok:
            rails = tuple(r for r in RAILS if self.states[r] != "swap")[:2]
            if self.states["hash"] == "swap" or len(rails) < 2:
                rails = ()
            reason = "agreed policy"
        # Sorted offers bind both views; fallback labels name traffic + both policy epochs.
        offers = sorted((e, h.hex(), f) for e, h, f in (local, remote))
        context = hashlib.sha256(self.transcript + json.dumps(
            [round_id, expected, offers]).encode()).digest()
        label = b"rail-swap-v1" if epoch_ok else b"all-rails-fallback-v1|traffic=%d|policy=%d,%d" % (
            expected, offers[0][0], offers[1][0])
        self.key = derive(self.secrets, rails, context, label, expected) if rails else None
        self.round, self.rails, self.fallback = round_id, rails, not epoch_ok
        logging.info("%s round=%d traffic=%d policy local=%d peer=%d rails=%s reason=%s label=%s",
                     self.name, round_id, expected, self.epoch, remote[0],
                     "+".join(rails) or "suspended", reason, label.decode())
        return True


def boundary(pair, epoch):
    left, right = pair
    offers = encode_offer(left.offer()), encode_offer(right.offer())
    round_id = left.round + 1
    if not valid_epoch(epoch) or right.round != left.round:
        raise ValueError("invalid boundary schedule")
    if not left.activate(offers[1], epoch, round_id) or not right.activate(offers[0], epoch, round_id):
        raise ValueError("invalid boundary offer")
    if not keys_match(left.key, right.key) or left.rails != right.rails:
        raise RuntimeError("peer divergence")


STREAM = "ADAPTIVE_ADVISORIES"
SUBJECTS = ["advisories." + assumption for assumption in ASSUMPTIONS]


def load_nats():
    try:
        import nats
        from nats.js import api
    except ImportError:
        raise SystemExit("Install the NATS client with python -m pip install -r requirements.txt") from None
    return nats, api


class Subscriber:
    """One durable pull consumer and one real NATS connection per fleet node."""
    def __init__(self, pair, durable, start, url):
        self.pair, self.durable, self.start, self.url = pair, durable, start, url
        self.cursor, self.nc = start - 1, None

    async def connect(self):
        nats, api = load_nats()
        self.nc = await nats.connect(self.url, max_reconnect_attempts=2)
        # A recovered pending acknowledgment can block the next pull.
        # Allow redelivery within the five-second fetch window.
        config = api.ConsumerConfig(durable_name=self.durable, ack_policy=api.AckPolicy.EXPLICIT,
                                    deliver_policy=api.DeliverPolicy.BY_START_SEQUENCE,
                                    opt_start_seq=self.start, max_ack_pending=1, ack_wait=2,
                                    inactive_threshold=86400)
        self.sub = await self.nc.jetstream().pull_subscribe("advisories.*", durable=self.durable,
                                                           stream=STREAM, config=config)
        logging.info("%s connected cursor=%d", self.durable, self.cursor)

    async def disconnect(self):
        if self.nc and not self.nc.is_closed:
            await self.nc.close()
            logging.info("%s disconnected cursor=%d", self.durable, self.cursor)

    async def through(self, target):
        # The publish ack is a test barrier. All payloads come from the durable consumer.
        while self.cursor < target:
            msg, = await self.sub.fetch(1, timeout=5)
            seq = msg.metadata.sequence.stream
            age = time.time() - msg.metadata.timestamp.timestamp()
            logging.info("%s delivery seq=%d age=%.3fs", self.durable, seq, age)
            if seq > self.cursor + 1:
                raise RuntimeError(f"{self.durable} lost stream history before {seq}")
            if seq <= self.cursor or not -5 <= age <= 3600:
                logging.warning("%s rejected duplicate sequence or stale broker timestamp", self.durable)
            else:
                # Republishing gets fresh metadata. Verify the signed epoch too.
                for peer in self.pair:
                    peer.receive_certificate(msg.data, msg.subject)
            self.cursor = max(self.cursor, seq)
            await msg.ack_sync()


async def publish(js, a, votes, online):
    data = encode_certificate(a, votes)
    ack = await js.publish("advisories." + a.assumption, data, stream=STREAM)
    await asyncio.gather(*(node.through(ack.seq) for node in online))
    return ack.seq


async def demo(delay, stack, connections, url):
    nats, api = load_nats()
    nc = await nats.connect(url, max_reconnect_attempts=1)
    connections.push_async_callback(nc.close)
    js = nc.jetstream()
    # File storage and limits retention preserve messages across individual acknowledgments.
    try:
        stream = await js.stream_info(STREAM)
    except nats.js.errors.NotFoundError:
        stream = await js.add_stream(name=STREAM, subjects=SUBJECTS, storage=api.StorageType.FILE,
                                     max_age=86400)
    if (set(stream.config.subjects) != set(SUBJECTS) or stream.config.storage != api.StorageType.FILE
            or stream.config.retention != api.RetentionPolicy.LIMITS):
        raise SystemExit("Incompatible ADAPTIVE_ADVISORIES stream configuration")
    start, run = stream.state.last_seq + 1, uuid.uuid4().hex[:12]
    oqs = require_kems()
    voters = [Voter(f"voter-{i}", oqs, stack) for i in range(1, 6)]
    roster = {v.name: v.public for v in voters}
    verifier = stack.enter_context(oqs.Signature(SLH)) if voters[0].slh else None
    detectors = [Detector() for _ in voters]
    fleet, metrics = [], []
    for i in range(1, 6):
        rows = []
        pair = [Peer(f"node-{i}/{side}", roster, verifier, session)
                for side, session in zip(("client", "server"), handshake(rows))]
        if not keys_match(pair[0].key, pair[1].key):
            raise RuntimeError("initial keys differ")
        fleet.append(pair)
        metrics.append(rows)
    nodes = [Subscriber(pair, f"fleet-{run}-{i}", start, url) for i, pair in enumerate(fleet, 1)]
    for node in nodes:
        connections.push_async_callback(node.disconnect)
        await node.connect()
    first = None
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "signals.json"
        for samples in [(), (1,), (.9, .8), (1, 1, 1), (.9, .8), (.8,), ()]:
            path.write_text(json.dumps([dict(assumption="lattice", type=k, confidence=v)
                            for k, v in zip(("paper", "quantum", "anomaly"), samples)]))
            proposals = [d.poll(path) for d in detectors]
            for a in proposals[0]:
                committee = voters[:3] if a.epoch == 3 else voters
                votes = [v.vote(a) for v, local in zip(committee, proposals) if a in local]
                votes = [vote for vote in votes if vote is not None]
                if a.epoch == 1:
                    first = a, votes[:3]
                    await publish(js, replace(a, tier="swap"), votes[:3], nodes)
                    assert all(p.epoch == 0 for pair in fleet for p in pair)
                if a.epoch == 2:
                    await nodes[-1].disconnect()
                online = nodes[:-1] if a.epoch in (2, 3) else nodes
                if a.epoch == 3:
                    logging.info("coordinator withholds epoch 3 at scheduled activation")
                    for pair in fleet:
                        boundary(pair, 3)
                        assert pair[0].rails == RAILS
                seq = await publish(js, a, votes[:3], online)
                if a.epoch == 3:
                    assert seq - nodes[-1].cursor == 2
                    await nodes[-1].connect()
                    await nodes[-1].through(seq)
                for node in online if a.epoch == 2 else nodes:
                    boundary(node.pair, a.epoch)
                    if verifier:
                        assert node.pair[0].epoch == a.epoch
                        if a.tier == "swap":
                            assert node.pair[0].rails == ("classical", "code")
                if a.epoch == 3 and verifier:
                    snapshots = [(p.offer(), p.key) for pair in fleet for p in pair]
                    await publish(js, *first, nodes)
                    await publish(js, a, votes[:3], nodes)
                    for peer, (offer, key) in zip((p for pair in fleet for p in pair), snapshots):
                        assert peer.offer() == offer and keys_match(peer.key, key)
                    # Two alternate voters plus one equivocator certify a competing view.
                    alternate = replace(a, tier="normal")
                    alternate_votes = [v.vote(alternate) for v in voters[3:]]
                    faulty, body = voters[2], alternate.encode()
                    alternate_votes.append((faulty.name, faulty.ed.sign(body), faulty.slh.sign(body)))
                    await publish(js, alternate, alternate_votes, nodes)
                    for pair in fleet:
                        assert all(p.fork for p in pair)
                        boundary(pair, 3)
                        assert pair[0].rails == RAILS
            await asyncio.sleep(delay)
    print("Raw exchange payloads (bytes) and parallel-rail wall times (ms)")
    print("Node  Algorithm                  Public   Reply   Total    Keygen     Encap     Decap")
    for i, rows in enumerate(metrics, 1):
        for m in rows:
            print(f"{i:4}  {m.algorithm:25} {m.public:7} {m.reply:7} {m.size:7}"
                  f" {m.keygen:9.3f} {m.encap:9.3f} {m.decap:9.3f}")
        total = sum(m.size for m in rows)
        backup = rows[-1].size
        print(f"      Handshake {total:,} B = active {total-backup:,} B + dormant {backup:,} B")
    print("X25519 encap includes sender ephemeral keygen and DH. Size excludes transport framing.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=0.1, help="seconds between polls")
    parser.add_argument("--nats-url", default="nats://127.0.0.1:4222")
    args = parser.parse_args()
    if args.interval < 0:
        parser.error("interval must be nonnegative")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    async def run():
        nats, _ = load_nats()
        try:
            async with AsyncExitStack() as connections:
                with ExitStack() as stack:
                    await demo(args.interval, stack, connections, args.nats_url)
        except nats.errors.Error as exc:
            raise SystemExit(f"NATS error ({type(exc).__name__}): {exc}. Start nats-server -js.") from None
    asyncio.run(run())
