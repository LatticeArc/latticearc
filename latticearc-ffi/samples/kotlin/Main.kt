// LatticeArc Kotlin sample: round-trips every API the `latticearc-ffi` crate
// exposes, against the generated `com.latticearc.ffi` bindings loaded through
// JNA. Plain Kotlin/JVM so it runs on a developer machine and in CI; the same
// calls work unchanged in an Android module. Exits non-zero on the first failed
// check. Build and run it with `scripts/ffi/run-kotlin-sample.sh`.

import com.latticearc.ffi.*
import java.security.MessageDigest
import kotlin.system.exitProcess

var checks = 0

fun check(condition: Boolean, what: String) {
    checks += 1
    if (!condition) {
        println("FAIL: $what")
        exitProcess(1)
    }
}

inline fun <reified E : LatticeArcException> expect(what: String, body: () -> Unit) {
    try {
        body()
        check(false, "$what: no exception thrown")
    } catch (e: LatticeArcException) {
        check(e is E, "$what: got ${e::class.simpleName}: ${e.message}")
    }
}

fun bytes(value: Int, count: Int) = ByteArray(count) { value.toByte() }
fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)
fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)

fun main() {
    // --- Library status -----------------------------------------------------
    val ver = version()
    check(ver.isNotEmpty(), "version string")
    val lock = memoryLockStatus()
    check(!lock.supported || lock.featureEnabled, "memory lock status is consistent")

    // --- SecretBytes --------------------------------------------------------
    val imported = SecretBytes.import(utf8("correct horse battery staple"))
    check(imported.len() == 28u && !imported.isEmpty(), "import length")
    check(imported.exportBytes().contentEquals(utf8("correct horse battery staple")), "explicit export round-trip")
    val random = SecretBytes.random(32u)
    check(random.len() == 32u && !random.exportBytes().contentEquals(bytes(0, 32)), "random bytes")
    random.isLocked()
    expect<LatticeArcException.InvalidInput>("random(0)") { SecretBytes.random(0u) }

    // --- Argon2id -----------------------------------------------------------
    val defaults = argon2DefaultParams()
    check(defaults.memoryKib == 65536u && defaults.iterations == 3u && defaults.outputLen == 32u, "default Argon2 profile")
    val calibrated = argon2Calibrate(20u, 2048u)
    check(calibrated.memoryKib <= 2048u, "calibrate honours the memory bound")
    val small = Argon2Params(memoryKib = 1024u, iterations = 1u, parallelism = 1u, outputLen = 32u)
    val salt = bytes(0x5a, 16)
    val k1 = argon2id(imported, salt, small)
    val k2 = argon2id(imported, salt, small)
    check(k1.exportBytes().contentEquals(k2.exportBytes()) && k1.len() == 32u, "Argon2id deterministic")
    expect<LatticeArcException.InvalidParams>("Argon2 bad params") {
        argon2id(imported, salt, Argon2Params(memoryKib = 1024u, iterations = 0u, parallelism = 1u, outputLen = 32u))
    }

    // --- HKDF and SP 800-108 ------------------------------------------------
    val okm = hkdf(k1, bytes(1, 8), utf8("app/v1/hkdf"), 42u)
    check(okm.len() == 42u, "HKDF length")
    expect<LatticeArcException.InvalidContext>("HKDF empty context") { hkdf(k1, null, ByteArray(0), 32u) }
    val ck = counterKdf(k1, utf8("label"), utf8("app/v1/kdf"), 32u)
    check(ck.len() == 32u, "counter KDF length")

    // --- Committing key wrap ------------------------------------------------
    val kek = SecretBytes.random(32u)
    val fileKey = SecretBytes.random(32u)
    val wrapped = wrapKey(kek, fileKey, utf8("app/v1/file-key/42"))
    val unwrapped = unwrapKey(kek, wrapped, utf8("app/v1/file-key/42"))
    check(unwrapped.exportBytes().contentEquals(fileKey.exportBytes()), "wrap/unwrap round-trip")
    expect<LatticeArcException.AuthenticationFailed>("unwrap with wrong KEK") { unwrapKey(random, wrapped, utf8("app/v1/file-key/42")) }
    expect<LatticeArcException.AuthenticationFailed>("unwrap with wrong context") { unwrapKey(kek, wrapped, utf8("app/v1/other")) }
    val padded = wrapKeyPadded(kek, fileKey, utf8("app/v1/root/epoch-1"), 4096u)
    check(padded.size == 4096, "padded wrap is exactly totalLen")
    check(unwrapKey(kek, padded, utf8("app/v1/root/epoch-1")).exportBytes().contentEquals(fileKey.exportBytes()), "padded unwrap")

    // --- Streaming AEAD -----------------------------------------------------
    val streamKey = SecretBytes.random(32u)
    val enc = StreamEncryptor(streamKey, utf8("app/v1/file/7"), 1024u)
    val first = bytes(0xa1, enc.firstPlaintextSegmentSize().toInt())
    val middle = bytes(0xb2, enc.plaintextSegmentSize().toInt())
    val tail = bytes(0xc3, 100)
    check(enc.nextIndex() == 0u, "first index is 0")
    val s0 = enc.sealSegment(first)
    val s1 = enc.sealSegment(middle)
    val s2 = enc.finish(tail)
    // Tink layout: every ciphertext segment is `segmentSize` bytes except the
    // first, which is shorter by the 40-byte Tink header so segments stay aligned.
    check(s1.size == enc.segmentSize().toInt() && s0.size == enc.firstPlaintextSegmentSize().toInt() + 16, "ciphertext segment sizes")
    expect<LatticeArcException.StreamExhausted>("seal after finish") { enc.sealSegment(middle) }
    val header = enc.header()
    val dec = StreamDecryptor(streamKey, utf8("app/v1/file/7"), header)
    check(dec.openSegment(1u, s1, false).contentEquals(middle), "random access to segment 1")
    check(dec.openNext(s0, false).contentEquals(first), "sequential segment 0")
    check(dec.openNext(s1, false).contentEquals(middle), "sequential segment 1")
    check(!dec.isFinished() && dec.nextIndex() == 2u, "decryptor position")
    check(dec.openNext(s2, true).contentEquals(tail), "last segment")
    check(dec.isFinished(), "decryptor finished")
    expect<LatticeArcException.AuthenticationFailed>("segment misdescribed as last") { dec.openSegment(1u, s1, true) }
    expect<LatticeArcException.AuthenticationFailed>("wrong stream key") { StreamDecryptor(random, utf8("app/v1/file/7"), header) }
    val wrongAad = StreamDecryptor(streamKey, utf8("app/v1/file/8"), header)
    expect<LatticeArcException.AuthenticationFailed>("wrong aad") { wrongAad.openSegment(0u, s0, false) }

    // --- Hybrid KEM and encryption -----------------------------------------
    for (level in listOf(MlKemSecurityLevel.ML_KEM512, MlKemSecurityLevel.ML_KEM768, MlKemSecurityLevel.ML_KEM1024)) {
        val sk = HybridKemSecretKey.generate(level)
        check(sk.securityLevel() == level, "KEM level")
        val pkWire = sk.publicKey().toWire()
        val pk = HybridKemPublicKey.fromWire(pkWire)
        check(pk.toWire().contentEquals(pkWire) && pk.securityLevel() == level, "KEM public key wire round-trip")
        val encap = encapsulate(pk, utf8("app/v1/transfer"))
        val ss = decapsulate(sk, encap.encapsulatedKey, utf8("app/v1/transfer"))
        check(ss.exportBytes().contentEquals(encap.sharedSecret.exportBytes()) && ss.len() == 64u, "KEM shared secret agrees")
        val wrongKey = HybridKemSecretKey.generate(level)
        val implicit = decapsulate(wrongKey, encap.encapsulatedKey, utf8("app/v1/transfer"))
        check(!implicit.exportBytes().contentEquals(ss.exportBytes()), "implicit rejection: wrong key gives another secret, no error")
        val parts = sk.exportParts()
        val restored = HybridKemSecretKey.fromParts(parts)
        check(restored.publicKey().toWire().contentEquals(pkWire), "KEM secret key parts round-trip")
        val ct = encryptHybrid(pk, utf8("hello"), utf8("hdr"))
        check(decryptHybrid(restored, ct, utf8("hdr")).contentEquals(utf8("hello")), "hybrid encrypt/decrypt")
        expect<LatticeArcException.AuthenticationFailed>("hybrid decrypt wrong aad") { decryptHybrid(sk, ct, utf8("other")) }
    }
    expect<LatticeArcException.InvalidContext>("KEM empty context") {
        encapsulate(HybridKemSecretKey.generate(MlKemSecurityLevel.ML_KEM768).publicKey(), ByteArray(0))
    }
    expect<LatticeArcException.WireFormat>("KEM garbage wire") { HybridKemPublicKey.fromWire(bytes(0, 5)) }

    // --- Hybrid signatures --------------------------------------------------
    val seed = SecretBytes.import(bytes(0x42, 32))
    for (set in listOf(MlDsaParameterSet.ML_DSA44, MlDsaParameterSet.ML_DSA65, MlDsaParameterSet.ML_DSA87)) {
        val a = HybridSigningKey.fromSeed(seed, set)
        val b = HybridSigningKey.fromSeed(seed, set)
        check(a.publicKey().toWire().contentEquals(b.publicKey().toWire()) && a.parameterSet() == set, "seed-derived keys are identical")
        val pk = HybridSigPublicKey.fromWire(a.publicKey().toWire())
        val sig = a.sign(utf8("manifest"), utf8("app/v1/manifest"))
        check(verify(pk, utf8("manifest"), sig, utf8("app/v1/manifest")), "hybrid verify")
        check(!verify(pk, utf8("manifest!"), sig, utf8("app/v1/manifest")), "hybrid verify rejects other message")
        check(!verify(pk, utf8("manifest"), sig, utf8("app/v2/manifest")), "hybrid verify rejects other context")
        val digest = sha512(bytes(0xee, 1 shl 20))
        val psig = a.signPrehashed(digest, utf8("app/v1/root-sig"))
        check(verifyPrehashed(pk, digest, psig, utf8("app/v1/root-sig")), "hybrid pre-hashed verify")
        check(!verify(pk, digest, psig, utf8("app/v1/root-sig")), "modes are separated")
        val restored = HybridSigningKey.fromParts(a.exportParts())
        check(verify(pk, utf8("x"), restored.sign(utf8("x"), utf8("c")), utf8("c")), "signing key parts round-trip")
    }
    val generated = HybridSigningKey.generate(MlDsaParameterSet.ML_DSA65)
    check(generated.parameterSet() == MlDsaParameterSet.ML_DSA65, "generated hybrid key")
    expect<LatticeArcException.InvalidContext>("hybrid sign empty context") { generated.sign(utf8("m"), ByteArray(0)) }
    expect<LatticeArcException.InvalidInput>("hybrid bad digest length") { generated.signPrehashed(bytes(0, 32), utf8("c")) }
    expect<LatticeArcException.InvalidInput>("zero seed") {
        HybridSigningKey.fromSeed(SecretBytes.import(bytes(0, 32)), MlDsaParameterSet.ML_DSA65)
    }

    // --- ML-DSA -------------------------------------------------------------
    val mlSk = MlDsaSigningKey.fromSeed(seed, MlDsaParameterSet.ML_DSA65)
    val mlPk = MlDsaPublicKey.fromBytes(mlSk.publicKey().toBytes(), MlDsaParameterSet.ML_DSA65)
    val mlSig = mlSk.sign(utf8("msg"), utf8("ctx"))
    check(mlPk.verify(utf8("msg"), mlSig, utf8("ctx")), "ML-DSA verify")
    check(!mlPk.verify(utf8("msg"), mlSig, utf8("other")), "ML-DSA verify rejects other context")
    val mlDigest = sha512(utf8("big content"))
    val mlPsig = mlSk.signPrehashed(mlDigest, PrehashAlgorithm.SHA512, utf8("ctx"))
    check(mlPk.verifyPrehashed(mlDigest, PrehashAlgorithm.SHA512, mlPsig, utf8("ctx")), "HashML-DSA verify")
    val mlRestored = MlDsaSigningKey.fromParts(mlSk.exportSecretKey(), mlPk.toBytes(), MlDsaParameterSet.ML_DSA65)
    check(mlPk.verify(utf8("m"), mlRestored.sign(utf8("m"), ByteArray(0)), ByteArray(0)), "ML-DSA parts round-trip")
    val mlGen = MlDsaSigningKey.generate(MlDsaParameterSet.ML_DSA44)
    check(mlGen.parameterSet() == MlDsaParameterSet.ML_DSA44 && mlGen.publicKey().parameterSet() == MlDsaParameterSet.ML_DSA44, "generated ML-DSA key")
    expect<LatticeArcException.InvalidParams>("SHA-256 not allowed at ML-DSA-65") {
        mlSk.signPrehashed(bytes(0, 32), PrehashAlgorithm.SHA256, utf8("ctx"))
    }
    expect<LatticeArcException.InvalidInput>("HashML-DSA verify rejects a wrong digest length") {
        mlPk.verifyPrehashed(bytes(0, 16), PrehashAlgorithm.SHA512, mlPsig, utf8("ctx"))
    }

    println("latticearc-ffi Kotlin sample: $checks checks passed (library $ver)")
}
