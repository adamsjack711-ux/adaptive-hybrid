"""In-process, unauthenticated fixed-suite exchange with raw binary wire payloads."""
import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from time import perf_counter_ns

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHMS = {"classical": "X25519", "lattice": "ML-KEM-768",
              "code": "Classic-McEliece-348864"}
RAILS = tuple(ALGORITHMS)
SUITE = "|".join(ALGORITHMS.values()).encode()
INSTALL = ("Run python -m pip install -r requirements.txt. Install matching shared "
           "liboqs with ML-KEM-768 and Classic-McEliece-348864 enabled. "
           "See https://github.com/open-quantum-safe/liboqs-python#installation")


def require_kems():
    try:
        import oqs
        enabled = oqs.get_enabled_kem_mechanisms()
    except (ImportError, AttributeError, OSError, RuntimeError, SystemExit) as exc:
        raise SystemExit(INSTALL) from exc
    missing = set(ALGORITHMS.values()) - {"X25519"} - set(enabled)
    if missing:
        raise SystemExit(f"Disabled KEMs: {', '.join(sorted(missing))}. {INSTALL}")
    return oqs


def timed(function, *args):
    start = perf_counter_ns()
    value = function(*args)
    return value, (perf_counter_ns() - start) / 1e6


@dataclass
class Measurement:
    algorithm: str
    public: int
    reply: int
    keygen: float
    encap: float
    decap: float

    @property
    def size(self):
        return self.public + self.reply


def exchange(rail, oqs):
    algorithm = ALGORITHMS[rail]
    if rail == "classical":
        recipient, kg = timed(X25519PrivateKey.generate)
        sender, ephemeral = timed(X25519PrivateKey.generate)
        rp, sp = recipient.public_key(), sender.public_key()
        public, reply = (k.public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw) for k in (rp, sp))
        sent, enc = timed(sender.exchange, rp)
        enc += ephemeral
        received, dec = timed(recipient.exchange, sp)
    else:
        with oqs.KeyEncapsulation(algorithm) as recipient, oqs.KeyEncapsulation(algorithm) as sender:
            # generate_keypair retains the private key in recipient. encap_secret
            # returns (ciphertext, shared secret). Only ciphertext goes on wire.
            public, kg = timed(recipient.generate_keypair)
            (reply, sent), enc = timed(sender.encap_secret, public)
            received, dec = timed(recipient.decap_secret, reply)
    if not hmac.compare_digest(sent, received):
        raise RuntimeError(f"{algorithm} secret mismatch")
    metric = Measurement(algorithm, len(public), len(reply), kg, enc, dec)
    return public + reply, sent, received, metric


def keys_match(left, right):
    if left is None or right is None:
        return left is right
    return hmac.compare_digest(left, right)


def derive(secrets, rails, transcript, label, epoch):
    if "lattice" not in rails and "code" not in rails:
        raise ValueError("a post-quantum rail is required")
    info = b"|".join((label, str(epoch).encode(), ",".join(rails).encode(), transcript))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript,
                info=info).derive(b"".join(secrets[r] for r in rails))


def handshake(measurements=None):
    oqs = require_kems()
    with ThreadPoolExecutor(3) as pool:
        futures = [pool.submit(exchange, rail, oqs) for rail in RAILS]
        results = [future.result() for future in futures]
    digest = hashlib.sha256(SUITE)
    for wire, _, _, metric in results:
        # The fixed suite defines each field length. Hash the full binary
        # payload directly, including every byte of the McEliece public key.
        digest.update(wire)
        if measurements is not None:
            measurements.append(metric)
    transcript = digest.digest()
    peers = []
    for side in (1, 2):
        secrets = {r: result[side] for r, result in zip(RAILS, results)}
        key = derive(secrets, RAILS[:2], transcript, b"initial-v1", 0)
        peers.append((secrets, transcript, key))
    return peers
