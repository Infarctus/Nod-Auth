package io.github.infarctus.nodauth

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** Portable password backup, including Android API 24/25. No device-bound key. */
object BackupCrypto {
    private val magic = "AA-BACKUP-1\n".toByteArray(Charsets.US_ASCII)
    private const val saltSize = 16
    private const val nonceSize = 12
    private const val iterations = 1_300_000
    const val maxPlaintext = 16 * 1024 * 1024
    const val maxArchive = maxPlaintext + 128

    fun isEncrypted(data: ByteArray): Boolean = data.size >= magic.size &&
        magic.indices.all { data[it] == magic[it] }

    private fun key(password: String, salt: ByteArray): SecretKeySpec {
        val chars = password.toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, 256)
        chars.fill('\u0000')
        val bytes = try { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).encoded }
                    finally { spec.clearPassword() }
        return try { SecretKeySpec(bytes, "AES") } finally { bytes.fill(0) }
    }

    /** An empty password exports the original setup ZIP without encryption. */
    fun encode(plaintext: ByteArray, password: String): ByteArray {
        require(plaintext.size <= maxPlaintext)
        return if (password.isEmpty()) plaintext.copyOf() else encrypt(plaintext, password)
    }

    fun encrypt(plaintext: ByteArray, password: String): ByteArray {
        require(plaintext.size <= maxPlaintext)
        val random = SecureRandom()
        val salt = ByteArray(saltSize).also { random.nextBytes(it) }
        val nonce = ByteArray(nonceSize).also { random.nextBytes(it) }
        val header = magic + salt + nonce
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(password, salt), GCMParameterSpec(128, nonce))
        cipher.updateAAD(header)
        return header + cipher.doFinal(plaintext)
    }

    fun decrypt(archive: ByteArray, password: String): ByteArray {
        val headerSize = magic.size + saltSize + nonceSize
        require(isEncrypted(archive) && archive.size in (headerSize + 16)..maxArchive)
        val salt = archive.copyOfRange(magic.size, magic.size + saltSize)
        val nonce = archive.copyOfRange(magic.size + saltSize, headerSize)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(password, salt), GCMParameterSpec(128, nonce))
        cipher.updateAAD(archive.copyOfRange(0, headerSize))
        return cipher.doFinal(archive, headerSize, archive.size - headerSize)
    }
}
