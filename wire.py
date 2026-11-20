"""Bounded JSON codecs for policy messages and in-process boundary offers."""
import json
import re

from detector import ASSUMPTIONS, TIERS, WEIGHTS, Advisory

MAX_EPOCH = (1 << 63) - 1
MAX_ADVISORY_BYTES = 1024
MAX_CERTIFICATE_BYTES = 192 * 1024
MAX_OFFER_BYTES = 256
ED_SIGNATURE_BYTES = 64
SLH_SIGNATURE_BYTES = 17_088  # SLH-DSA-SHA2-128f (FIPS 205)


def unique_object(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise ValueError("duplicate JSON field")
        obj[name] = value
    return obj


def reject_constant(_):
    raise ValueError("non-finite JSON number")


def decode_json(data, limit):
    if not isinstance(data, bytes) or len(data) > limit:
        raise ValueError("invalid message type or size")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise ValueError("malformed JSON message") from None


def has_fields(obj, *fields):
    return isinstance(obj, dict) and obj.keys() == set(fields)


def valid_epoch(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_EPOCH


def parse_advisory(obj):
    if not has_fields(obj, "epoch", "assumption", "tier", "score", "sources"):
        raise ValueError("invalid advisory fields")
    epoch, assumption, tier = obj["epoch"], obj["assumption"], obj["tier"]
    score, sources = obj["score"], obj["sources"]
    if (not valid_epoch(epoch, 1) or assumption not in ASSUMPTIONS or tier not in TIERS
            or type(score) not in (int, float) or not 0 <= score <= 1
            or not isinstance(sources, list) or len(sources) > len(WEIGHTS)
            or any(not isinstance(source, str) or source not in WEIGHTS for source in sources)
            or len(set(sources)) != len(sources)):
        raise ValueError("invalid advisory values")
    return Advisory(epoch, assumption, tier, score, tuple(sources))


def decode_advisory(data):
    return parse_advisory(decode_json(data, MAX_ADVISORY_BYTES))


def decode_hex(value, size):
    if not isinstance(value, str) or len(value) != size * 2:
        raise ValueError("invalid hex field length")
    decoded = bytes.fromhex(value)
    if len(decoded) != size:
        raise ValueError("invalid hex field")
    return decoded


def encode_certificate(advisory, votes):
    return json.dumps({"advisory": json.loads(advisory.encode()),
                       "votes": [(name, ed.hex(), slh.hex()) for name, ed, slh in votes]},
                      separators=(",", ":")).encode()


def decode_certificate(data, subject):
    obj = decode_json(data, MAX_CERTIFICATE_BYTES)
    if not has_fields(obj, "advisory", "votes"):
        raise ValueError("invalid certificate fields")
    advisory = parse_advisory(obj["advisory"])
    if subject != "advisories." + advisory.assumption:
        raise ValueError("certificate subject mismatch")
    shares = obj["votes"]
    if not isinstance(shares, list) or not 1 <= len(shares) <= 5:
        raise ValueError("invalid share count")
    slh_size = SLH_SIGNATURE_BYTES if advisory.assumption == "lattice" else 0
    votes, seen = [], set()
    for share in shares:
        if not isinstance(share, list) or len(share) != 3:
            raise ValueError("invalid signature share")
        name, ed, slh = share
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
                or name in seen):
            raise ValueError("invalid or duplicate voter ID")
        seen.add(name)
        votes.append((name, decode_hex(ed, ED_SIGNATURE_BYTES), decode_hex(slh, slh_size)))
    return advisory, votes


def encode_offer(offer):
    epoch, head, fork = offer
    return json.dumps({"epoch": epoch, "head": head.hex(), "fork": fork},
                      separators=(",", ":")).encode()


def valid_offer(offer):
    if not isinstance(offer, tuple) or len(offer) != 3:
        return False
    epoch, head, fork = offer
    return valid_epoch(epoch) and type(head) is bytes and len(head) == 32 and type(fork) is bool


def decode_offer(data):
    obj = decode_json(data, MAX_OFFER_BYTES)
    if not has_fields(obj, "epoch", "head", "fork"):
        raise ValueError("invalid offer fields")
    offer = obj["epoch"], decode_hex(obj["head"], 32), obj["fork"]
    if not valid_offer(offer):
        raise ValueError("invalid offer values")
    return offer
