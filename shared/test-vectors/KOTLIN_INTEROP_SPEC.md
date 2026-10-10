# VaultSync Kotlin / Android Interoperability Specification

This document provides exact guidelines for implementing compatible cryptography in Kotlin on Android to interoperate with the VaultSync protocol and pass the shared test vectors.

---

## 1. Golden Vectors Reference

- `shared/test-vectors/vectors_v1.json`: Contains deterministic intermediate and final values for key derivation, key wrapping, and record encryption.
- `shared/test-vectors/malformed_vectors_v1.json`: Contains adversarial test cases (corrupted tags, bit flips, relocated record IDs, invalid parameters).

---

## 2. Cryptographic Construction Mapping (Python to Kotlin)

### 2.1 Password Normalization and Encoding
- **Kotlin**:
  ```kotlin
  import java.text.Normalizer
  import java.nio.charset.StandardCharsets

  val normalizedPassword = Normalizer.normalize(password, Normalizer.Form.NFC)
  val passwordBytes = normalizedPassword.toByteArray(StandardCharsets.UTF_8)
  ```

### 2.2 Argon2id Key Derivation
- **Parameters**:
  - Algorithm: Argon2id
  - Memory: $65,536$ KiB (64 MiB)
  - Time Cost / Iterations: $3$
  - Parallelism: $4$ lanes
  - Output Key Length: $32$ bytes (256 bits)
  - Salt: $16$ bytes
- **Kotlin Implementation (BouncyCastle or Native NDK)**:
  ```kotlin
  import org.bouncycastle.crypto.generators.Argon2BytesGenerator
  import org.bouncycastle.crypto.params.Argon2Parameters

  val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
      .withVersion(Argon2Parameters.ARGON2_VERSION_13)
      .withMemoryAsKB(65536)
      .withIterations(3)
      .withParallelism(4)
      .withSalt(saltBytes)
      .build()

  val generator = Argon2BytesGenerator()
  generator.init(params)
  val masterSecret = ByteArray(32)
  generator.generateBytes(passwordBytes, masterSecret)
  ```

### 2.3 HKDF Domain Separation
- **Parameters**:
  - PRF: HMAC-SHA256
  - Info string for KEK: `"vaultsync:kek:v1".toByteArray(StandardCharsets.UTF_8)`
  - Output Length: $32$ bytes
- **Kotlin Implementation**:
  ```kotlin
  import org.bouncycastle.crypto.digests.SHA256Digest
  import org.bouncycastle.crypto.generators.HKDFBytesGenerator
  import org.bouncycastle.crypto.params.HKDFParameters

  // HKDF-Expand with masterSecret as IKM (PRK)
  val hkdf = HKDFBytesGenerator(SHA256Digest())
  hkdf.init(HKDFParameters.skipExtractParameters(masterSecret, "vaultsync:kek:v1".toByteArray(StandardCharsets.UTF_8)))
  val kek = ByteArray(32)
  hkdf.generateBytes(kek, 0, 32)
  ```

### 2.4 Authenticated Encryption: AES-256-GCM
- **Java / Android JCE**:
  - Transformation: `"AES/GCM/NoPadding"`
  - Nonce Length: $12$ bytes (96 bits)
  - Tag Length: $128$ bits ($16$ bytes)
  - Layout: `ciphertext` field in the envelope contains raw AES ciphertext directly followed by the $16$-byte tag. This directly matches the byte array returned by `Cipher.doFinal(plaintext)` in Android Java/Kotlin!
- **Associated Data (AAD)**:
  - For Wrapped Key: `"vaultsync:key-wrap:v1:Argon2id".toByteArray(StandardCharsets.UTF_8)`
  - For Record: `"vaultsync:record:v1:$recordId".toByteArray(StandardCharsets.UTF_8)`
- **Kotlin Implementation**:
  ```kotlin
  import javax.crypto.Cipher
  import javax.crypto.spec.GCMParameterSpec
  import javax.crypto.spec.SecretKeySpec

  val cipher = Cipher.getInstance("AES/GCM/NoPadding")
  val keySpec = SecretKeySpec(vaultKeyBytes, "AES")
  val gcmSpec = GCMParameterSpec(128, nonceBytes) // 128-bit tag

  // Encrypt
  cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
  cipher.updateAAD(aadBytes)
  val ciphertextWithTag = cipher.doFinal(plaintextBytes)

  // Decrypt
  cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
  cipher.updateAAD(aadBytes)
  val decryptedPlaintext = cipher.doFinal(ciphertextWithTag)
  ```

---

## 3. Verification Roadmap

- **Status**: The protocol, data formats, and golden vectors are fully specified and verified against Python unit and regression tests.
- **Android Phase (Phase 5)**: The Android Jetpack Compose client will execute against these exact test fixtures using native unit tests (`./gradlew test`) to guarantee bidirectional cryptographic parity.
