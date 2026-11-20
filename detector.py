"""Poll complete JSON snapshots. Missing observations have confidence zero."""
import json
import logging
import math
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SLH = "SLH_DSA_PURE_SHA2_128F"
GENESIS = bytes(32)


ASSUMPTIONS = ("classical", "lattice", "hash", "code")
WEIGHTS = {"paper": 0.40, "quantum": 0.35, "anomaly": 0.25}
TIERS = ("normal", "watch", "warn", "swap")


@dataclass(frozen=True)
class Advisory:
    epoch: int
    assumption: str
    tier: str
    score: float
    sources: tuple

    def encode(self):
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode()


class Voter:
    def __init__(self, name, oqs, stack):
        self.name = name
        self.ed = Ed25519PrivateKey.generate()
        self.slh = None
        if SLH in oqs.get_enabled_sig_mechanisms():
            self.slh = stack.enter_context(oqs.Signature(SLH))
        self.public = (self.ed.public_key(), self.slh.generate_keypair() if self.slh else None)
        self.last = 0

    def vote(self, advisory):
        if advisory.epoch <= self.last:
            raise ValueError("voter already voted at or beyond this epoch")
        body = advisory.encode()
        lattice = advisory.assumption == "lattice"
        # Fail closed when SLH is unavailable: the committee cannot certify
        # any lattice status, even a return to normal, with Ed25519 alone.
        if lattice and not self.slh:
            logging.warning("%s abstained epoch=%d: SLH-DSA unavailable", self.name, advisory.epoch)
            return None
        self.last = advisory.epoch
        logging.info("%s voted epoch=%d tier=%s", self.name, self.last, advisory.tier)
        return self.name, self.ed.sign(body), self.slh.sign(body) if lattice else b""


def quorum(advisory, votes, roster, verifier):
    # A threshold certificate carries independent signatures. Count distinct
    # provisioned identities only; the signed assumption selects the scheme.
    valid = set()
    body = advisory.encode()
    for name, ed, slh in votes:
        if name not in roster or name in valid:
            logging.info("ignored unknown or duplicate vote %s", name)
            continue
        ed_pk, slh_pk = roster[name]
        try:
            ed_pk.verify(ed, body)
        except InvalidSignature:
            logging.info("rejected invalid Ed25519 vote %s", name)
            continue
        if advisory.assumption == "lattice" and not (
            verifier and slh_pk and len(slh) == verifier.details["length_signature"]
            and verifier.verify(body, slh, slh_pk)
        ):
            logging.info("rejected invalid or unavailable SLH-DSA vote %s", name)
            continue
        valid.add(name)
    logging.info("certificate epoch=%d valid=%d required=3", advisory.epoch, len(valid))
    return len(valid) >= 3


class Detector:
    def __init__(self):
        self.states = dict.fromkeys(ASSUMPTIONS, "normal")
        self.epoch = 0

    def poll(self, path):
        rows = json.loads(Path(path).read_text())
        values = {a: dict.fromkeys(WEIGHTS, 0.0) for a in ASSUMPTIONS}
        for row in rows:
            assumption, kind, confidence = row["assumption"], row["type"], row["confidence"]
            if kind not in WEIGHTS or assumption not in values:
                raise ValueError("unknown signal type or assumption")
            if type(confidence) not in (float, int) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise ValueError("confidence must be a number in [0,1]")
            # Repeated reports of one type cannot count as independent evidence.
            values[assumption][kind] = max(values[assumption][kind], confidence)

        events = []
        for assumption, samples in values.items():
            score = round(sum(WEIGHTS[k] * v for k, v in samples.items()), 6)
            sources = tuple(k for k, v in samples.items() if v >= 0.40)
            old = self.states[assumption]
            # Enter swap at .80, retain it down to .55. Both high tiers
            # require two distinct types each passing the confidence floor.
            swap_floor = 0.55 if old == "swap" else 0.80
            if len(sources) >= 2 and score >= swap_floor:
                tier = "swap"
            elif len(sources) >= 2 and score >= 0.50:
                tier = "warn"
            else:
                tier = "watch" if score >= 0.25 else "normal"
            logging.info("detector %s score=%.3f corroborators=%s %s -> %s",
                         assumption, score, sources, old, tier)
            if tier != old:
                self.epoch += 1
                advisory = Advisory(self.epoch, assumption, tier, score, sources)
                events.append(advisory)
                self.states[assumption] = tier
        return events
