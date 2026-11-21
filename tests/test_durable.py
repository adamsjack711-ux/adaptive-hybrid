import hashlib
import hmac
import os
import asyncio
from contextlib import ExitStack
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from combiner import Peer, Subscriber, boundary
from detector import Advisory, Voter
from handshake import RAILS, derive
from wire import encode_certificate


class LabSignature:
    def __init__(self, _algorithm, secret_key=None):
        self.secret = secret_key or os.urandom(32)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def generate_keypair(self):
        return hashlib.sha256(self.secret).digest()

    def export_secret_key(self):
        return self.secret

    def sign(self, body):
        return hmac.digest(self.secret, body, "sha256")


class LabOQS:
    Signature = LabSignature

    @staticmethod
    def get_enabled_sig_mechanisms():
        return ["SLH_DSA_PURE_SHA2_128F"]


def fresh_session():
    seed = os.urandom(32)
    secrets = {rail: hashlib.sha256(seed + rail.encode()).digest() for rail in RAILS}
    transcript = hashlib.sha256(b"fresh transcript" + seed).digest()
    return secrets, transcript, derive(secrets, RAILS[:2], transcript, b"initial-v1", 0)


def signed(advisory, voters):
    return [voter.vote(advisory) for voter in voters]


def test_signer_keys_and_vote_floor_survive_restart(tmp_path):
    path = tmp_path / "voter.json"
    first = Advisory(1, "lattice", "watch", .4, ("paper",))
    second = Advisory(2, "lattice", "warn", .75, ("paper", "quantum"))
    with ExitStack() as stack:
        voter = Voter("one", LabOQS, stack, path)
        public = voter.public
        vote = voter.vote(first)
        assert vote[1] and vote[2]
    assert path.stat().st_mode & 0o777 == 0o600
    with ExitStack() as stack:
        restored = Voter("one", LabOQS, stack, path)
        assert restored.public[0].public_bytes_raw() == public[0].public_bytes_raw()
        assert restored.public[1] == public[1]
        with pytest.raises(ValueError, match="already voted"):
            restored.vote(first)
        assert restored.vote(second)[0] == "one"
    with ExitStack() as stack:
        assert Voter("one", LabOQS, stack, path).last == 2


def test_policy_and_fork_survive_restart_with_fresh_session(tmp_path):
    with ExitStack() as stack:
        voters = [Voter(str(i), LabOQS, stack, tmp_path / f"voter-{i}.json") for i in range(3)]
        roster = {v.name: v.public for v in voters}
        verifier = type("Verifier", (), {"details": {"length_signature": 32},
                                         "verify": lambda self, body, sig, public: True})()

        def peers():
            session = fresh_session()
            return [Peer(name, roster, verifier, session, tmp_path / f"{name}.json")
                    for name in ("left", "right")]

        pair = peers()
        watch = Advisory(1, "classical", "watch", .4, ("paper",))
        swap = Advisory(2, "classical", "swap", .85, ("paper", "quantum"))
        recovery = Advisory(3, "classical", "normal", 0, ())
        watch_votes, swap_votes = signed(watch, voters), signed(swap, voters)
        for peer in pair:
            assert peer.receive(watch, watch_votes)
        boundary(pair, 1)
        assert pair[0].rails == RAILS[:2]
        first_key = pair[0].key

        assert pair[0].receive(swap, swap_votes)
        boundary(pair, 2)
        assert pair[0].fallback and pair[0].rails == RAILS
        fallback_key = pair[0].key
        assert pair[1].receive(swap, swap_votes)
        boundary(pair, 2)
        assert pair[0].rails == ("lattice", "code")
        old_key = pair[0].key
        assert len({first_key, fallback_key, old_key}) == 3

        pair = peers()
        assert all(p.key is None and p.epoch == 2 and p.round == 0 for p in pair)
        for peer in pair:
            assert not peer.receive(watch, watch_votes)
        boundary(pair, 2)
        assert pair[0].key == pair[1].key != old_key
        assert pair[0].rails == ("lattice", "code")
        recovery_votes = signed(recovery, voters)
        for peer in pair:
            assert peer.receive(recovery, recovery_votes)
        boundary(pair, 3)
        assert pair[0].rails == RAILS[:2]

        alternate = Advisory(3, "classical", "swap", .85, ("paper", "quantum"))
        # A valid conflict at the current epoch is durably sticky.
        conflicting_votes = [(v.name, v.ed.sign(alternate.encode()), b"") for v in voters]
        for peer in pair:
            assert not peer.receive(alternate, conflicting_votes)
        pair = peers()
        assert all(p.fork and p.key is None for p in pair)
        boundary(pair, 3)
        assert pair[0].rails == RAILS


def test_state_file_rejects_loose_permissions_and_wrong_roster(tmp_path):
    with ExitStack() as stack:
        voter = Voter("one", LabOQS, stack, tmp_path / "voter.json")
        path = tmp_path / "peer.json"
        Peer("left", {"one": voter.public}, None, fresh_session(), path)
        path.chmod(0o644)
        with pytest.raises(ValueError, match="permissions"):
            Peer("left", {"one": voter.public}, None, fresh_session(), path)
        path.chmod(0o600)
        with pytest.raises(ValueError, match="roster"):
            Peer("left", {}, None, fresh_session(), path)


def test_failed_durable_write_does_not_issue_vote_or_stage_policy(tmp_path, monkeypatch):
    def disk_full(_):
        raise OSError("disk full")

    with ExitStack() as stack:
        voters = [Voter(str(i), LabOQS, stack, tmp_path / f"voter-{i}.json")
                  for i in range(3)]
        advisory = Advisory(1, "classical", "watch", .4, ("paper",))
        voter = voters[0]
        original_save = voter.state_file.save
        monkeypatch.setattr(voter.state_file, "save", disk_full)
        with pytest.raises(OSError, match="disk full"):
            voter.vote(advisory)
        assert voter.last == 0
        monkeypatch.setattr(voter.state_file, "save", original_save)
        votes = signed(advisory, voters)

        path = tmp_path / "peer.json"
        peer = Peer("left", {v.name: v.public for v in voters}, None, fresh_session(), path)
        original_save = peer.state_file.save
        monkeypatch.setattr(peer.state_file, "save", disk_full)
        with pytest.raises(OSError, match="disk full"):
            peer.receive(advisory, votes)
        assert peer.epoch == 0 and peer.last_digest is None and peer.states["classical"] == "normal"
        monkeypatch.setattr(peer.state_file, "save", original_save)
        assert peer.receive(advisory, votes)


def test_subscriber_retries_after_cursor_write_failure(tmp_path, monkeypatch):
    with ExitStack() as stack:
        voters = [Voter(str(i), LabOQS, stack) for i in range(3)]
        roster = {v.name: v.public for v in voters}
        peer = Peer("left", roster, None, fresh_session(), tmp_path / "peer.state")
        advisory = Advisory(1, "classical", "watch", .4, ("paper",))
        data = encode_certificate(advisory, signed(advisory, voters))
        subscriber = Subscriber([peer], "cursor-test", 1, "nats://unused",
                                tmp_path / "cursor.state")
        acknowledgments = []

        class Message:
            metadata = SimpleNamespace(sequence=SimpleNamespace(stream=1),
                                       timestamp=datetime.now(timezone.utc))
            subject = "advisories.classical"

            async def ack_sync(self):
                acknowledgments.append(1)

        message = Message()
        message.data = data

        class Subscription:
            async def fetch(self, count, timeout):
                return [message]

        subscriber.sub = Subscription()
        original_save = subscriber.state_file.save

        def disk_full(_):
            raise OSError("disk full")

        monkeypatch.setattr(subscriber.state_file, "save", disk_full)
        with pytest.raises(OSError, match="disk full"):
            asyncio.run(subscriber.through(1))
        assert peer.epoch == 1 and subscriber.cursor == 0 and not acknowledgments
        assert Subscriber([peer], "cursor-test", 1, "nats://unused",
                          tmp_path / "cursor.state").cursor == 0

        monkeypatch.setattr(subscriber.state_file, "save", original_save)
        asyncio.run(subscriber.through(1))
        assert subscriber.cursor == 1 and acknowledgments == [1]
