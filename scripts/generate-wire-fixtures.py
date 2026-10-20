#!/usr/bin/env python3
"""Regenerate the binary wire-format v1 known-answer vectors without calling LatticeArc.

Usage: python3 scripts/generate-wire-fixtures.py
Writes latticearc/tests/fixtures/wire-v1.json. The layout below implements
docs/WIRE_FORMAT.md independently of the Rust encoder; latticearc/tests/wire_format_kat.rs
checks that the Rust encoder and decoder agree with these bytes on every platform.
Component bytes are deterministic filler, not real keys: the format is structural.
"""
import json
from pathlib import Path

MAGIC = b"LA"
VERSION = 1

KEM = {1: ("ML-KEM-512", 800, 768), 3: ("ML-KEM-768", 1184, 1088), 5: ("ML-KEM-1024", 1568, 1568)}
DSA = {2: ("ML-DSA-44", 1312, 2420), 3: ("ML-DSA-65", 1952, 3309), 5: ("ML-DSA-87", 2592, 4627)}


def filler(length, seed):
    out, b = bytearray(), seed
    for _ in range(length):
        b = (b * 29 + 7) & 0xFF
        out.append(b)
    return bytes(out)


def vector(name, type_tag, alg_id, fields, length_prefixed=None):
    body = b""
    for field in fields:
        data = filler(field["len"], field["seed"])
        if field["name"] == length_prefixed:
            body += len(data).to_bytes(4, "big")
        body += data
    wire = MAGIC + bytes([VERSION, type_tag, alg_id]) + body
    return {"name": name, "type_tag": type_tag, "algorithm_id": alg_id, "fields": fields,
            "wire_hex": wire.hex()}


def f(name, length, seed):
    return {"name": name, "len": length, "seed": seed}


vectors = []
for alg_id, (label, pk_len, ct_len) in KEM.items():
    vectors.append(vector(f"hybrid_kem_public_key/{label}", 0x01, alg_id,
                          [f("ml_kem_pk", pk_len, 1), f("ecdh_pk", 32, 2)]))
for alg_id, (label, pk_len, ct_len) in KEM.items():
    vectors.append(vector(f"encapsulated_key/{label}", 0x02, alg_id,
                          [f("ml_kem_ct", ct_len, 3), f("ecdh_pk", 32, 4)]))
for (alg_id, (label, pk_len, ct_len)), sym_len in zip(KEM.items(), (0, 13, 64)):
    vectors.append(vector(f"hybrid_ciphertext/{label}/sym{sym_len}", 0x03, alg_id,
                          [f("kem_ciphertext", ct_len, 5), f("ecdh_ephemeral_pk", 32, 6),
                           f("nonce", 12, 8), f("tag", 16, 9),
                           f("symmetric_ciphertext", sym_len, 7)],
                          length_prefixed="symmetric_ciphertext"))
for alg_id, (label, pk_len, sig_len) in DSA.items():
    vectors.append(vector(f"hybrid_sig_public_key/{label}", 0x04, alg_id,
                          [f("ml_dsa_pk", pk_len, 10), f("ed25519_pk", 32, 11)]))
for alg_id, (label, pk_len, sig_len) in DSA.items():
    vectors.append(vector(f"hybrid_signature/{label}", 0x05, alg_id,
                          [f("ml_dsa_sig", sig_len, 12), f("ed25519_sig", 64, 13)]))

doc = {
    "format": "LatticeArc binary wire format v1 (docs/WIRE_FORMAT.md)",
    "filler": "each field: b = seed; repeat len times: b = (b * 29 + 7) mod 256, emit b",
    "fields_order": "wire order; symmetric_ciphertext is preceded by its u32 big-endian length",
    "vectors": vectors,
}
output = Path(__file__).resolve().parents[1] / "latticearc/tests/fixtures/wire-v1.json"
output.write_text(json.dumps(doc, indent=1) + "\n")
print(f"wrote {len(vectors)} vectors to {output}")
