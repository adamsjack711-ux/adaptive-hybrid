import json

from hypothesis import given, strategies as st
import pytest

from combiner import Peer, SUBJECTS
from detector import Advisory
from wire import (MAX_ADVISORY_BYTES, MAX_CERTIFICATE_BYTES, MAX_OFFER_BYTES, decode_advisory,
                  decode_certificate, decode_offer, encode_certificate, encode_offer)
from test_protocol import certificate, committee, roster, session, snapshot

ADVISORY = Advisory(1, "classical", "swap", .85, ("paper", "quantum"))
SUBJECT = "advisories.classical"


def peer_and_certificate():
    keys = committee()
    return Peer("left", roster(keys), None, session()), encode_certificate(ADVISORY, certificate(ADVISORY, keys))


@given(st.binary(max_size=4096), st.sampled_from(SUBJECTS))
def test_arbitrary_wire_bytes_leave_state_untouched(data, subject):
    peer, _ = peer_and_certificate()
    before = snapshot(peer)
    with pytest.raises(ValueError):
        decode_advisory(data)
    assert not peer.receive_certificate(data, subject)
    assert not peer.activate(data, 1, 1)
    assert snapshot(peer) == before


@given(st.integers(min_value=0, max_value=1000))
def test_truncations_leave_state_untouched(offset):
    peer, cert = peer_and_certificate()
    advisory = ADVISORY.encode()
    offer = encode_offer(peer.offer())
    before = snapshot(peer)

    def truncate(data):
        return data[:offset % len(data)]

    with pytest.raises(ValueError):
        decode_advisory(truncate(advisory))
    assert not peer.receive_certificate(truncate(cert), SUBJECT)
    assert not peer.activate(truncate(offer), 1, 1)
    assert snapshot(peer) == before


@given(st.sampled_from(("epoch", "assumption", "tier", "score", "sources")))
def test_duplicate_nested_field_rejected(name):
    peer, cert = peer_and_certificate()
    advisory = ADVISORY.encode()
    value = json.dumps(json.loads(advisory)[name]).encode()
    duplicate = advisory[:-1] + b',"' + name.encode() + b'":' + value + b"}"
    before = snapshot(peer)
    with pytest.raises(ValueError):
        decode_advisory(duplicate)
    assert not peer.receive_certificate(cert.replace(advisory, duplicate), SUBJECT)
    assert snapshot(peer) == before


@pytest.mark.parametrize("extra", [
    b'"votes":[],',
    b'"advisory":null,',
    b'"extra":1,',
])
def test_duplicate_or_unknown_certificate_field_rejected(extra):
    peer, cert = peer_and_certificate()
    before = snapshot(peer)
    assert not peer.receive_certificate(b"{" + extra + cert[1:], SUBJECT)
    assert snapshot(peer) == before


@pytest.mark.parametrize(("field", "value"), [
    ("epoch", b"true"), ("epoch", b"-1"), ("epoch", b"18446744073709551616"),
    ("score", b"NaN"), ("score", b"1e9999"), ("score", b"false"),
    ("tier", b"{}"), ("sources", b'["paper","paper"]'), ("sources", b'[{}]'),
])
def test_invalid_advisory_field(field, value):
    peer, cert = peer_and_certificate()
    before = snapshot(peer)
    payload = json.loads(cert)
    payload["advisory"][field] = None
    malformed = json.dumps(payload).encode().replace(b'"' + field.encode() + b'": null',
                                                     b'"' + field.encode() + b'": ' + value)
    assert not peer.receive_certificate(malformed, SUBJECT)
    assert snapshot(peer) == before


@pytest.mark.parametrize("mutation", ["duplicate signer", "shape", "id", "ed hex", "slh hex", "too many"])
def test_malformed_signature_shares(mutation):
    peer, cert = peer_and_certificate()
    before = snapshot(peer)
    payload = json.loads(cert)
    votes = payload["votes"]
    bad_share = {
        "duplicate signer": votes[0],
        "shape": [],
        "id": [[], "00" * 64, ""],
        "ed hex": ["3", " " * 128, ""],
        "slh hex": ["3", "00" * 64, "ab"],
        "too many": ["3", "00" * 64, ""],
    }[mutation]
    votes.extend([bad_share] * (3 if mutation == "too many" else 1))
    assert not peer.receive_certificate(json.dumps(payload).encode(), SUBJECT)
    assert snapshot(peer) == before


@pytest.mark.parametrize("field", [b'"epoch":0', b'"head":null', b'"fork":false'])
def test_duplicate_offer_field_rejected(field):
    peer, _ = peer_and_certificate()
    before = snapshot(peer)
    offer = encode_offer(peer.offer())
    assert not peer.activate(b"{" + field + b"," + offer[1:], 0, 1)
    assert snapshot(peer) == before


@pytest.mark.parametrize("malformed", [
    (), (0, b"x" * 31, False), (False, b"x" * 32, False), (0, b"x" * 32, 0),
    (1 << 63, b"x" * 32, False), b"[[[[[[[[[[", b"\xff",
])
def test_invalid_offer_rejected(malformed):
    peer, _ = peer_and_certificate()
    before = snapshot(peer)
    assert not peer.activate(malformed, 0, 1)
    assert snapshot(peer) == before


@given(st.integers(min_value=1, max_value=4096))
def test_resource_limits_and_wrong_subject_leave_state_untouched(excess):
    peer, cert = peer_and_certificate()
    before = snapshot(peer)
    offer = encode_offer(peer.offer())
    def oversized(data, limit):
        return data + b" " * (limit + excess - len(data))

    with pytest.raises(ValueError):
        decode_advisory(oversized(ADVISORY.encode(), MAX_ADVISORY_BYTES))
    assert not peer.receive_certificate(oversized(cert, MAX_CERTIFICATE_BYTES), SUBJECT)
    assert not peer.receive_certificate(b"[" * 5000 + b"0" + b"]" * 5000, SUBJECT)
    assert not peer.receive_certificate(cert, "advisories.code")
    assert not peer.activate(oversized(offer, MAX_OFFER_BYTES), 0, 1)
    assert snapshot(peer) == before


def test_valid_messages_round_trip_and_change_state():
    peer, cert = peer_and_certificate()
    assert decode_advisory(ADVISORY.encode()) == ADVISORY
    assert decode_certificate(cert, SUBJECT)[0] == ADVISORY
    assert decode_offer(encode_offer(peer.offer())) == peer.offer()
    assert peer.receive_certificate(cert, SUBJECT)
    assert peer.activate(encode_offer(peer.offer()), 1, 1)
    assert peer.rails == ("lattice", "code") and not peer.fallback
