import hashlib
import hmac
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import example, given, strategies as st
import pytest

import handshake
from combiner import Peer, boundary
from detector import ASSUMPTIONS, TIERS, Advisory, quorum
from handshake import RAILS


def session():
    secrets = {rail: hashlib.sha256(rail.encode()).digest() for rail in RAILS}
    transcript = hashlib.sha256(b"test transcript").digest()
    return secrets, transcript, handshake.derive(secrets, RAILS[:2], transcript, b"initial-v1", 0)


def committee():
    return [Ed25519PrivateKey.generate() for _ in range(5)]


def roster(keys):
    return {str(i): (key.public_key(), None) for i, key in enumerate(keys)}


def certificate(advisory, keys, voters=range(3)):
    return [(str(i), keys[i].sign(advisory.encode()), b"") for i in voters]


def snapshot(peer):
    return peer.offer(), dict(peer.states), peer.last_digest, peer.key, peer.rails, peer.round, peer.fallback


def test_native_comparison_at_boundary(monkeypatch):
    compare = Mock(wraps=hmac.compare_digest)
    monkeypatch.setattr(handshake.hmac, "compare_digest", compare)
    pair = [Peer(name, {}, None, session()) for name in ("left", "right")]
    boundary(pair, 0)
    compare.assert_called_once_with(pair[0].key, pair[1].key)
    assert not handshake.keys_match(bytes(32), b"\x01" + bytes(31))
    assert not handshake.keys_match(bytes(32), bytes(31) + b"\x01")
    assert handshake.keys_match(None, None)
    assert not handshake.keys_match(None, bytes(32))


def test_native_signature_verifiers_and_distinct_votes():
    advisory = Advisory(1, "lattice", "watch", .4, ("paper",))
    keys = committee()
    ed_verifiers = [Mock(wraps=key.public_key()) for key in keys]
    members = {str(i): (ed, bytes([i])) for i, ed in enumerate(ed_verifiers)}
    slh = Mock(details={"length_signature": 4})
    slh.verify.return_value = True
    valid = [(name, ed, b"sign") for name, ed, _ in certificate(advisory, keys)]
    assert not quorum(advisory, [valid[0]] * 3, members, slh)
    assert not quorum(advisory, valid, members, None)
    slh.reset_mock()
    assert quorum(advisory, valid, members, slh)
    assert slh.verify.call_count == 3
    for name, ed, sig in valid:
        ed_verifiers[int(name)].verify.assert_called_with(ed, advisory.encode())
        slh.verify.assert_any_call(advisory.encode(), sig, bytes([int(name)]))
    slh.verify.return_value = False
    assert not quorum(advisory, valid, members, slh)
    bad_ed = [("0", bytes(64), b"sign"), *valid[1:]]
    slh.reset_mock()
    slh.verify.return_value = True
    assert not quorum(advisory, bad_ed, members, slh)
    assert slh.verify.call_count == 2


def test_derive_rejects_classical_only():
    secrets, transcript, _ = session()
    with pytest.raises(ValueError, match="post-quantum"):
        handshake.derive(secrets, ("classical",), transcript, b"test", 0)


def test_suspension_keeps_peers_agreed():
    keys = committee()
    pair = [Peer(name, roster(keys), None, session()) for name in ("left", "right")]
    advisory = Advisory(1, "hash", "swap", 1, ("paper", "anomaly"))
    for peer in pair:
        assert peer.receive(advisory, certificate(advisory, keys))
    boundary(pair, 1)
    assert all(peer.key is None and not peer.rails and not peer.fallback for peer in pair)


class DualVerifier:
    """A second Ed25519 key stands in for SLH-DSA in generated schedules."""

    details = {"length_signature": 64}

    def verify(self, body, signature, public_key):
        try:
            public_key.verify(signature, b"second scheme|" + body)
        except InvalidSignature:
            return False
        return True


voter_ids = st.lists(st.integers(0, 4), unique=True, max_size=5).map(tuple)
recipients = st.sampled_from(("left", "right", "both", "neither"))
proposals = st.tuples(st.sampled_from(("advisory", "conflict")), st.sampled_from(ASSUMPTIONS),
                      st.sampled_from(TIERS), voter_ids, recipients)
replays = st.tuples(st.just("replay"), st.integers(0, 30), recipients)
crashes = st.tuples(st.sampled_from(("crash", "restart")), st.integers(0, 4))
withholds = st.tuples(st.just("withhold"))


@given(st.lists(st.one_of(proposals, replays, crashes, withholds), min_size=1, max_size=30))
@example([
    ("advisory", "lattice", "swap", (0, 1, 2), "left"),
    ("conflict", "lattice", "normal", (0, 1, 3), "right"),
    ("replay", 0, "right"),
    ("crash", 2), ("crash", 3), ("crash", 4),
    ("advisory", "lattice", "warn", (0, 1, 2, 3, 4), "both"),
    ("withhold",), ("restart", 4), ("advisory", "code", "swap", (0, 1, 4), "both"),
])
def test_generated_advisory_schedules(actions):
    keys, second_keys = committee(), committee()
    members = {str(i): (key.public_key(), second.public_key())
               for i, (key, second) in enumerate(zip(keys, second_keys))}
    initial = session()
    pair = [Peer(name, members, DualVerifier(), initial) for name in ("left", "right")]
    online = set(range(5))
    honest_last = dict.fromkeys(range(2, 5), 0)
    issued = []
    traffic = 0

    def deliver(advisory, votes, target):
        for peer in pair:
            if target in (peer.name, "both"):
                peer.receive(advisory, votes)

    for kind, *args in actions:
        current = max(peer.epoch for peer in pair)
        if kind in ("advisory", "conflict"):
            assumption, tier, selected, target = args
            epoch = max(current, 1) if kind == "conflict" else current + 1
            advisory = Advisory(epoch, assumption, tier, .85, ("paper", "quantum"))
            eligible = []
            for signer in selected:
                if signer not in online or epoch <= honest_last.get(signer, 0):
                    continue
                eligible.append(signer)
                if signer in honest_last:
                    honest_last[signer] = epoch
            votes = [(name, ed, second_keys[int(name)].sign(b"second scheme|" + advisory.encode())
                      if assumption == "lattice" else b"")
                     for name, ed, _ in certificate(advisory, keys, eligible)]
            issued.append((advisory, votes))
            traffic = max(traffic, epoch)
            deliver(advisory, votes, target)
        elif kind == "replay" and issued:
            index, target = args
            deliver(*issued[index % len(issued)], target)
        elif kind == "crash":
            online.discard(args[0])
        elif kind == "restart":
            online.add(args[0])
        elif kind == "withhold":
            traffic = max(traffic, current + 1)

        left, right = pair
        fallback = left.offer() != right.offer() or left.epoch != traffic or left.fork
        # Inspect the actual bytes entering HKDF while still deriving the real key.
        native_hkdf = handshake.HKDF
        inputs = []

        def capture_hkdf(**parameters):
            kdf = native_hkdf(**parameters)

            def checked_derive(material):
                inputs.append(material)
                return kdf.derive(material)

            return SimpleNamespace(derive=checked_derive)

        with patch.object(handshake, "HKDF", side_effect=capture_hkdf):
            assert left.activate(right.offer(), traffic, left.round + 1)
            assert right.activate(left.offer(), traffic, right.round + 1)

        assert left.fallback == right.fallback == fallback
        # Even when a disagreement permits fallback, both endpoints must
        # complete this genuine-offer round with the same key and rails.
        assert left.key == right.key
        assert left.rails == right.rails
        if fallback:
            assert left.rails == RAILS
        if left.key is not None:
            selected_pq = set(left.rails) & {"lattice", "code"}
            assert selected_pq
            material = b"".join(left.secrets[rail] for rail in left.rails)
            assert inputs == [material, material]
            assert all(left.secrets[rail] in material for rail in selected_pq)
        else:
            assert not inputs and not left.rails
