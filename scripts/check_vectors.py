"""Check v0.2 transcript vectors independently with Python's standard library."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = dict(
    line.split("=", 1)
    for line in (ROOT / "tests/fixtures/vectors.txt").read_text().splitlines()
)
POINTS = {key: bytes.fromhex(value) for key, value in VECTORS.items()}
ORDER = 2**252 + 27742317777372353535851937790883648493

def transcript(domain, fields):
    framed = bytearray()
    for label, value in [(b"domain", domain), *fields]:
        framed += len(label).to_bytes(8, "little") + label
        framed += len(value).to_bytes(8, "little") + value
    return int.from_bytes(hashlib.sha512(framed).digest(), "little") % ORDER

def scalar(data):
    return int.from_bytes(data, "little")

def check(condition, name):
    if not condition:
        raise ValueError(f"Vector check failed: {name}")

def main():
    p = POINTS["schnorr"]
    c = transcript(b"zk-proofs/v0.2/schnorr-nizk/ristretto255", [
        (b"generator", POINTS["g"]), (b"public-key", POINTS["public_a"]),
        (b"commitment", p[:32]), (b"context", b"vector"),
    ])
    check(scalar(p[32:]) == (13 + 7 * c) % ORDER, "Schnorr response")
    p = POINTS["pedersen_proof"]
    c = transcript(b"zk-proofs/v0.2/pedersen-opening/ristretto255", [
        (b"value-generator", POINTS["g"]), (b"blinding-generator", POINTS["h"]),
        (b"commitment", POINTS["pedersen_commitment"]), (b"announcement", p[:32]),
        (b"context", b"vector"),
    ])
    check(scalar(p[32:64]) == (13 + 42 * c) % ORDER, "Pedersen value response")
    check(scalar(p[64:]) == (13 + 13 * c) % ORDER, "Pedersen blinding response")
    c = transcript(b"zk-proofs/v0.2/schnorr-or-ring/ristretto255", [
        (b"generator", POINTS["g"]), (b"ring-size", (2).to_bytes(4, "little")),
        (b"public-key", POINTS["public_a"]), (b"public-key", POINTS["public_b"]),
        (b"context", b"vector"), (b"message", b"message"),
        (b"announcement", POINTS["ring_t_a"]), (b"announcement", POINTS["ring_t_b"]),
    ])
    p = POINTS["ring_signature"]
    check(scalar(p[:4]) == 2, "ring size")
    check(scalar(p[4:36]) == (c - 13) % ORDER, "ring real challenge")
    check(scalar(p[36:68]) == (13 + (c - 13) * 7) % ORDER, "ring real response")
    check(scalar(p[68:100]) == 13, "ring simulated challenge")
    check(scalar(p[100:132]) == 13, "ring simulated response")
    print("Independent transcript/scalar checks passed for all three protocols.")

if __name__ == "__main__":
    main()
