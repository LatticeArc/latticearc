#!/usr/bin/env python3
"""Regenerate public test vectors independently with OpenSSL 3.5+ (never production keys).

Usage: OPENSSL=/path/to/openssl python3 scripts/generate-detached-fixtures.py
The transcript below implements the published v1 contract without calling LatticeArc.
"""
import base64
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

OPENSSL = os.environ.get("OPENSSL", "openssl")
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PREFIX = b"LatticeArc-Detached-Signature\0"
DOMAIN = "example.com/claims"
CLAIMS = b'{"sub":"alice","role":"reader","exp":2000000000}'


def transcript(claims, domain, algorithm_id=1):
    domain = domain.encode("ascii")
    return (PREFIX + bytes([1, algorithm_id]) + len(domain).to_bytes(2, "big") + domain
            + len(claims).to_bytes(8, "big") + claims)


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    key = root / "key.der"
    # RFC 8410 PKCS#8 wrapping of the public RFC 8032 test seed.
    key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + SEED)
    public = subprocess.check_output([
        OPENSSL, "pkey", "-inform", "DER", "-in", str(key), "-pubout", "-outform", "DER"
    ])[-32:]

    def sign(message):
        message_file = root / "message.bin"
        message_file.write_bytes(message)
        return subprocess.check_output([
            OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", str(key),
            "-keyform", "DER", "-in", str(message_file)
        ])

    def vector(name, claims=CLAIMS, domain=DOMAIN):
        message = transcript(claims, domain)
        return {
            "name": name, "claims_hex": claims.hex(), "public_key_hex": public.hex(),
            "expected_domain": domain, "valid": True, "transcript_hex": message.hex(),
            "record": {"version": 1, "algorithm": "ed25519", "domain": domain,
                       "signature": base64.b64encode(sign(message)).decode("ascii")},
        }

    base = vector("valid-claims")
    vectors = [base, vector("valid-empty-claims", b""),
               vector("valid-binary-claims", bytes(range(256))),
               vector("valid-max-domain", b"boundary", "a" * 255)]

    def invalid(name):
        result = copy.deepcopy(base)
        result.update(name=name, valid=False)
        vectors.append(result)
        return result

    invalid("altered-claims")["claims_hex"] = CLAIMS.replace(b"reader", b"admin").hex()
    invalid("reserialized-claims")["claims_hex"] = CLAIMS.replace(b",", b", ").hex()
    invalid("wrong-key")["public_key_hex"] = (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    invalid("wrong-expected-domain")["expected_domain"] = "example.com/other"
    rebound = invalid("relabeled-domain")
    rebound["record"]["domain"] = rebound["expected_domain"] = "example.com/other"
    invalid("unsupported-version")["record"]["version"] = 2
    invalid("unsupported-algorithm")["record"]["algorithm"] = "ed25519ph"
    invalid("malformed-base64")["record"]["signature"] = "!" * 88
    signature = base64.b64decode(base["record"]["signature"])
    invalid("truncated-signature")["record"]["signature"] = base64.b64encode(signature[:-1]).decode()
    invalid("extended-signature")["record"]["signature"] = base64.b64encode(signature + b"\0").decode()
    invalid("unpadded-base64")["record"]["signature"] = base["record"]["signature"].rstrip("=")
    invalid("invalid-signature")["record"]["signature"] = base64.b64encode(b"\xff" * 64).decode()
    invalid("raw-ed25519-is-not-detached")["record"]["signature"] = base64.b64encode(sign(CLAIMS)).decode()
    digest = hashlib.sha512(b"LatticeArc-Sig-ed25519-v1\0" + CLAIMS).digest()
    invalid("unified-envelope-is-not-detached")["record"]["signature"] = base64.b64encode(sign(digest)).decode()

    fixture = {
        "description": "Public RFC 8032 seed; independent OpenSSL Ed25519 vectors for detached v1",
        "generator": subprocess.check_output([OPENSSL, "version"], text=True).strip(),
        "seed_hex": SEED.hex(), "vectors": vectors,
    }
    output = Path(__file__).resolve().parents[1] / "latticearc/tests/fixtures/detached-v1.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    print(output)

# Pure FIPS 204 fixtures use a public seed and deterministic signing for
# reproducibility only. Production LatticeArc signing remains randomized.
pq_sets = []
for parameter, algorithm_id, pk_size, sk_size in [(44, 2, 1312, 2560), (65, 3, 1952, 4032), (87, 4, 2592, 4896)]:
    algorithm = f"ml-dsa-{parameter}"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        key = root / "key.pem"
        wrong_key = root / "wrong-key.pem"
        for key_file, seed in [(key, bytes(range(32))), (wrong_key, bytes(reversed(range(32))))]:
            subprocess.run([OPENSSL, "genpkey", "-algorithm", algorithm.upper(),
                            "-pkeyopt", f"hexseed:{seed.hex()}", "-out", str(key_file)], check=True)

        def raw_key(key_file, label):
            text = subprocess.check_output([OPENSSL, "pkey", "-in", str(key_file), "-text", "-noout"], text=True)
            block = re.search(r"(?m)^" + label + r":\n((?: +[0-9a-f:]+\n)+)", text).group(1)
            return bytes.fromhex(block.replace(":", ""))

        public = raw_key(key, "pub")
        secret = raw_key(key, "priv")
        wrong_public = raw_key(wrong_key, "pub")
        assert len(public) == pk_size and len(secret) == sk_size

        def sign_pq(message, context=None):
            message_file = root / "message.bin"
            message_file.write_bytes(message)
            options = [] if context is None else ["-pkeyopt", f"context-string:{context}"]
            return subprocess.check_output([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", str(key),
                                            "-in", str(message_file), "-pkeyopt", "deterministic:1", *options])

        def pq_vector(name, claims=CLAIMS, domain=DOMAIN):
            message = transcript(claims, domain, algorithm_id)
            return {"name": name, "claims_hex": claims.hex(), "expected_domain": domain,
                    "wrong_key": False, "valid": True, "transcript_hex": message.hex(),
                    "record": {"version": 1, "algorithm": algorithm, "domain": domain,
                               "signature": base64.b64encode(sign_pq(message)).decode()}}

        base = pq_vector("valid-claims")
        vectors = [base, pq_vector("valid-empty-claims", b""), pq_vector("valid-binary-claims", bytes(range(256))),
                   pq_vector("valid-max-domain", b"boundary", "a" * 255)]

        def pq_invalid(name):
            value = copy.deepcopy(base)
            value.update(name=name, valid=False)
            vectors.append(value)
            return value

        pq_invalid("altered-claims")["claims_hex"] = CLAIMS.replace(b"reader", b"admin").hex()
        pq_invalid("reserialized-claims")["claims_hex"] = CLAIMS.replace(b",", b", ").hex()
        pq_invalid("wrong-key")["wrong_key"] = True
        pq_invalid("wrong-domain")["expected_domain"] = "example.com/other"
        rebound = pq_invalid("relabeled-domain")
        rebound["expected_domain"] = rebound["record"]["domain"] = "example.com/other"
        pq_invalid("unsupported-version")["record"]["version"] = 2
        pq_invalid("algorithm-substitution")["record"]["algorithm"] = "ml-dsa-87" if parameter != 87 else "ml-dsa-65"
        signature = base64.b64decode(base["record"]["signature"])
        pq_invalid("truncated-signature")["record"]["signature"] = base64.b64encode(signature[:-1]).decode()
        pq_invalid("extended-signature")["record"]["signature"] = base64.b64encode(signature + b"\0").decode()
        pq_invalid("malformed-base64")["record"]["signature"] = "!" * len(base["record"]["signature"])
        pq_invalid("invalid-signature")["record"]["signature"] = base64.b64encode(b"\xff" * len(signature)).decode()
        pq_invalid("raw-ml-dsa-is-not-detached")["record"]["signature"] = base64.b64encode(sign_pq(CLAIMS)).decode()
        pq_invalid("wrong-native-context")["record"]["signature"] = base64.b64encode(sign_pq(transcript(CLAIMS, DOMAIN, algorithm_id), "other-context")).decode()
        pq_sets.append({"algorithm": algorithm, "public_key_hex": public.hex(), "secret_key_hex": secret.hex(),
                        "wrong_public_key_hex": wrong_public.hex(), "vectors": vectors})

output = Path(__file__).resolve().parents[1] / "latticearc/tests/fixtures/detached-pq-v1.json"
output.write_text(json.dumps({"description": "Public test keys and deterministic OpenSSL ML-DSA vectors; never deploy these keys",
                             "generator": subprocess.check_output([OPENSSL, "version"], text=True).strip(),
                             "sets": pq_sets}, indent=2) + "\n", encoding="utf-8")
print(output)
