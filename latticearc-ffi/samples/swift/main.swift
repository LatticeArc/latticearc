// LatticeArc Swift sample: round-trips every API the `latticearc-ffi` crate
// exposes, against the generated `LatticeArc` module. Runs on macOS, iOS and
// the iOS simulator (CryptoKit supplies the SHA-512 for the pre-hashed
// signatures). Exits non-zero on the first failed check, so it doubles as
// the CI test for the Swift bindings. Build and run it with
// `scripts/ffi/run-swift-sample.sh`.

import CryptoKit
import Foundation
import LatticeArc

var checks = 0

func check(_ condition: Bool, _ what: String, file: StaticString = #file, line: UInt = #line) {
    checks += 1
    if !condition {
        print("FAIL (\(line)): \(what)")
        exit(1)
    }
}

/// Runs `body` and checks that it throws exactly `expected`.
func expectError(_ expected: LatticeArcError, _ what: String, line: UInt = #line, _ body: () throws -> Void) {
    do {
        try body()
        check(false, "\(what): no error thrown", line: line)
    } catch let error as LatticeArcError {
        check(error == expected, "\(what): got \(error), expected \(expected)", line: line)
    } catch {
        check(false, "\(what): unexpected \(error)", line: line)
    }
}

/// Runs `body` and checks that it throws the given case (payload ignored).
func expectErrorCase(_ what: String, line: UInt = #line, _ matches: (LatticeArcError) -> Bool, _ body: () throws -> Void) {
    do {
        try body()
        check(false, "\(what): no error thrown", line: line)
    } catch let error as LatticeArcError {
        check(matches(error), "\(what): got \(error)", line: line)
    } catch {
        check(false, "\(what): unexpected \(error)", line: line)
    }
}

func bytes(_ value: UInt8, _ count: Int) -> Data { Data([UInt8](repeating: value, count: count)) }
func utf8(_ s: String) -> Data { Data(s.utf8) }

// --- Library status ---------------------------------------------------------
let ver = version()
check(!ver.isEmpty, "version string")
let lock = memoryLockStatus()
check(lock.featureEnabled == lock.supported || !lock.supported, "memory lock status is consistent")

// --- SecretBytes ------------------------------------------------------------
let imported = SecretBytes.import(bytes: utf8("correct horse battery staple"))
check(imported.len() == 28 && !imported.isEmpty(), "import length")
check(imported.exportBytes() == utf8("correct horse battery staple"), "explicit export round-trip")
let random = try SecretBytes.random(len: 32)
check(random.len() == 32 && random.exportBytes() != bytes(0, 32), "random bytes")
_ = random.isLocked()
expectErrorCase("random(0)", { if case .InvalidInput = $0 { return true }; return false }) { _ = try SecretBytes.random(len: 0) }

// --- Argon2id ---------------------------------------------------------------
let defaults = argon2DefaultParams()
check(defaults.memoryKib == 65536 && defaults.iterations == 3 && defaults.outputLen == 32, "default Argon2 profile")
let calibrated = try argon2Calibrate(targetMs: 20, maxMemoryKib: 2048)
check(calibrated.memoryKib <= 2048, "calibrate honours the memory bound")
let small = Argon2Params(memoryKib: 1024, iterations: 1, parallelism: 1, outputLen: 32)
let salt = bytes(0x5a, 16)
let k1 = try argon2id(password: imported, salt: salt, params: small)
let k2 = try argon2id(password: imported, salt: salt, params: small)
check(k1.exportBytes() == k2.exportBytes() && k1.len() == 32, "Argon2id deterministic")
expectErrorCase("Argon2 bad params", { if case .InvalidParams = $0 { return true }; return false }) {
    _ = try argon2id(password: imported, salt: salt, params: Argon2Params(memoryKib: 1024, iterations: 0, parallelism: 1, outputLen: 32))
}

// --- HKDF and SP 800-108 ----------------------------------------------------
let okm = try hkdf(ikm: k1, salt: bytes(1, 8), context: utf8("app/v1/hkdf"), length: 42)
check(okm.len() == 42, "HKDF length")
expectErrorCase("HKDF empty context", { if case .InvalidContext = $0 { return true }; return false }) {
    _ = try hkdf(ikm: k1, salt: nil, context: Data(), length: 32)
}
let ck = try counterKdf(key: k1, label: utf8("label"), context: utf8("app/v1/kdf"), length: 32)
check(ck.len() == 32, "counter KDF length")

// --- Committing key wrap ----------------------------------------------------
let kek = try SecretBytes.random(len: 32)
let fileKey = try SecretBytes.random(len: 32)
let wrapped = try wrapKey(kek: kek, key: fileKey, context: utf8("app/v1/file-key/42"))
let unwrapped = try unwrapKey(kek: kek, wrapped: wrapped, context: utf8("app/v1/file-key/42"))
check(unwrapped.exportBytes() == fileKey.exportBytes(), "wrap/unwrap round-trip")
expectError(.AuthenticationFailed, "unwrap with wrong KEK") {
    _ = try unwrapKey(kek: random, wrapped: wrapped, context: utf8("app/v1/file-key/42"))
}
expectError(.AuthenticationFailed, "unwrap with wrong context") {
    _ = try unwrapKey(kek: kek, wrapped: wrapped, context: utf8("app/v1/other"))
}
let padded = try wrapKeyPadded(kek: kek, key: fileKey, context: utf8("app/v1/root/epoch-1"), totalLen: 4096)
check(padded.count == 4096, "padded wrap is exactly totalLen")
check(try unwrapKey(kek: kek, wrapped: padded, context: utf8("app/v1/root/epoch-1")).exportBytes() == fileKey.exportBytes(), "padded unwrap")

// --- Streaming AEAD ---------------------------------------------------------
let streamKey = try SecretBytes.random(len: 32)
let enc = try StreamEncryptor(key: streamKey, aad: utf8("app/v1/file/7"), segmentSize: 1024)
let first = bytes(0xa1, Int(enc.firstPlaintextSegmentSize()))
let middle = bytes(0xb2, Int(enc.plaintextSegmentSize()))
let tail = bytes(0xc3, 100)
check(try enc.nextIndex() == 0, "first index is 0")
let s0 = try enc.sealSegment(plaintext: first)
let s1 = try enc.sealSegment(plaintext: middle)
let s2 = try enc.finish(lastPlaintext: tail)
// Tink layout: every ciphertext segment is `segmentSize` bytes except the
// first, which is shorter by the 40-byte Tink header so segments stay aligned.
check(s1.count == Int(enc.segmentSize()) && s0.count == Int(enc.firstPlaintextSegmentSize()) + 16, "ciphertext segment sizes")
expectError(.StreamExhausted, "seal after finish") { _ = try enc.sealSegment(plaintext: middle) }
let header = enc.header()
let dec = try StreamDecryptor(key: streamKey, aad: utf8("app/v1/file/7"), header: header)
check(try dec.openSegment(index: 1, segment: s1, isLast: false) == middle, "random access to segment 1")
check(try dec.openNext(segment: s0, isLast: false) == first, "sequential segment 0")
check(try dec.openNext(segment: s1, isLast: false) == middle, "sequential segment 1")
check(!dec.isFinished() && dec.nextIndex() == 2, "decryptor position")
check(try dec.openNext(segment: s2, isLast: true) == tail, "last segment")
check(dec.isFinished(), "decryptor finished")
expectError(.AuthenticationFailed, "segment misdescribed as last") { _ = try dec.openSegment(index: 1, segment: s1, isLast: true) }
expectError(.AuthenticationFailed, "wrong stream key") {
    _ = try StreamDecryptor(key: random, aad: utf8("app/v1/file/7"), header: header)
}
let wrongAad = try StreamDecryptor(key: streamKey, aad: utf8("app/v1/file/8"), header: header)
expectError(.AuthenticationFailed, "wrong aad") { _ = try wrongAad.openSegment(index: 0, segment: s0, isLast: false) }

// --- Hybrid KEM and encryption ---------------------------------------------
for level in [MlKemSecurityLevel.mlKem512, .mlKem768, .mlKem1024] {
    let sk = try HybridKemSecretKey.generate(level: level)
    check(sk.securityLevel() == level, "KEM level")
    let pkWire = try sk.publicKey().toWire()
    let pk = try HybridKemPublicKey.fromWire(bytes: pkWire)
    check(try pk.toWire() == pkWire && pk.securityLevel() == level, "KEM public key wire round-trip")
    let encap = try encapsulate(publicKey: pk, context: utf8("app/v1/transfer"))
    let ss = try decapsulate(secretKey: sk, encapsulatedKey: encap.encapsulatedKey, context: utf8("app/v1/transfer"))
    check(ss.exportBytes() == encap.sharedSecret.exportBytes() && ss.len() == 64, "KEM shared secret agrees")
    let wrongKey = try HybridKemSecretKey.generate(level: level)
    let implicit = try decapsulate(secretKey: wrongKey, encapsulatedKey: encap.encapsulatedKey, context: utf8("app/v1/transfer"))
    check(implicit.exportBytes() != ss.exportBytes(), "implicit rejection: wrong key gives another secret, no error")
    let parts = try sk.exportParts()
    let restored = try HybridKemSecretKey.fromParts(parts: parts)
    check(try restored.publicKey().toWire() == pkWire, "KEM secret key parts round-trip")
    let ct = try encryptHybrid(publicKey: pk, plaintext: utf8("hello"), aad: utf8("hdr"))
    check(try decryptHybrid(secretKey: restored, ciphertext: ct, aad: utf8("hdr")) == utf8("hello"), "hybrid encrypt/decrypt")
    expectError(.AuthenticationFailed, "hybrid decrypt wrong aad") { _ = try decryptHybrid(secretKey: sk, ciphertext: ct, aad: utf8("other")) }
}
expectErrorCase("KEM empty context", { if case .InvalidContext = $0 { return true }; return false }) {
    _ = try encapsulate(publicKey: try HybridKemSecretKey.generate(level: .mlKem768).publicKey(), context: Data())
}
expectErrorCase("KEM garbage wire", { if case .WireFormat = $0 { return true }; return false }) {
    _ = try HybridKemPublicKey.fromWire(bytes: bytes(0, 5))
}

// --- Hybrid signatures ------------------------------------------------------
let seed = SecretBytes.import(bytes: bytes(0x42, 32))
for set in [MlDsaParameterSet.mlDsa44, .mlDsa65, .mlDsa87] {
    let a = try HybridSigningKey.fromSeed(seed: seed, parameterSet: set)
    let b = try HybridSigningKey.fromSeed(seed: seed, parameterSet: set)
    check(try a.publicKey().toWire() == b.publicKey().toWire() && a.parameterSet() == set, "seed-derived keys are identical")
    let pk = try HybridSigPublicKey.fromWire(bytes: a.publicKey().toWire())
    let sig = try a.sign(message: utf8("manifest"), context: utf8("app/v1/manifest"))
    check(try verify(publicKey: pk, message: utf8("manifest"), signature: sig, context: utf8("app/v1/manifest")), "hybrid verify")
    check(try !verify(publicKey: pk, message: utf8("manifest!"), signature: sig, context: utf8("app/v1/manifest")), "hybrid verify rejects other message")
    check(try !verify(publicKey: pk, message: utf8("manifest"), signature: sig, context: utf8("app/v2/manifest")), "hybrid verify rejects other context")
    let digest = Data(SHA512.hash(data: bytes(0xee, 1 << 20)))
    let psig = try a.signPrehashed(digest: digest, context: utf8("app/v1/root-sig"))
    check(try verifyPrehashed(publicKey: pk, digest: digest, signature: psig, context: utf8("app/v1/root-sig")), "hybrid pre-hashed verify")
    check(try !verify(publicKey: pk, message: digest, signature: psig, context: utf8("app/v1/root-sig")), "modes are separated")
    let parts = a.exportParts()
    let restored = try HybridSigningKey.fromParts(parts: parts)
    check(try verify(publicKey: pk, message: utf8("x"), signature: restored.sign(message: utf8("x"), context: utf8("c")), context: utf8("c")), "signing key parts round-trip")
}
let generated = try HybridSigningKey.generate(parameterSet: .mlDsa65)
check(generated.parameterSet() == .mlDsa65, "generated hybrid key")
expectErrorCase("hybrid sign empty context", { if case .InvalidContext = $0 { return true }; return false }) {
    _ = try generated.sign(message: utf8("m"), context: Data())
}
expectErrorCase("hybrid bad digest length", { if case .InvalidInput = $0 { return true }; return false }) {
    _ = try generated.signPrehashed(digest: bytes(0, 32), context: utf8("c"))
}
expectErrorCase("zero seed", { if case .InvalidInput = $0 { return true }; return false }) {
    _ = try HybridSigningKey.fromSeed(seed: SecretBytes.import(bytes: bytes(0, 32)), parameterSet: .mlDsa65)
}

// --- ML-DSA -----------------------------------------------------------------
let mlSk = try MlDsaSigningKey.fromSeed(seed: seed, parameterSet: .mlDsa65)
let mlPk = try MlDsaPublicKey.fromBytes(bytes: mlSk.publicKey().toBytes(), parameterSet: .mlDsa65)
let mlSig = try mlSk.sign(message: utf8("msg"), context: utf8("ctx"))
check(try mlPk.verify(message: utf8("msg"), signature: mlSig, context: utf8("ctx")), "ML-DSA verify")
check(try !mlPk.verify(message: utf8("msg"), signature: mlSig, context: utf8("other")), "ML-DSA verify rejects other context")
let mlDigest = Data(SHA512.hash(data: utf8("big content")))
let mlPsig = try mlSk.signPrehashed(digest: mlDigest, hash: .sha512, context: utf8("ctx"))
check(try mlPk.verifyPrehashed(digest: mlDigest, hash: .sha512, signature: mlPsig, context: utf8("ctx")), "HashML-DSA verify")
let mlRestored = try MlDsaSigningKey.fromParts(secretKey: mlSk.exportSecretKey(), publicKey: mlPk.toBytes(), parameterSet: .mlDsa65)
check(try mlPk.verify(message: utf8("m"), signature: mlRestored.sign(message: utf8("m"), context: Data()), context: Data()), "ML-DSA parts round-trip")
let mlGen = try MlDsaSigningKey.generate(parameterSet: .mlDsa44)
check(mlGen.parameterSet() == .mlDsa44 && mlGen.publicKey().parameterSet() == .mlDsa44, "generated ML-DSA key")
expectErrorCase("SHA-256 not allowed at ML-DSA-65", { if case .InvalidParams = $0 { return true }; return false }) {
    _ = try mlSk.signPrehashed(digest: bytes(0, 32), hash: .sha256, context: utf8("ctx"))
}
expectErrorCase("HashML-DSA verify rejects a wrong digest length", { if case .InvalidInput = $0 { return true }; return false }) {
    _ = try mlPk.verifyPrehashed(digest: bytes(0, 16), hash: .sha512, signature: mlPsig, context: utf8("ctx"))
}

print("latticearc-ffi Swift sample: \(checks) checks passed (library \(ver))")
