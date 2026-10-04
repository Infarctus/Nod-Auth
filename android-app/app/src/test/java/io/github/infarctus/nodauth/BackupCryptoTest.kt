package io.github.infarctus.nodauth

import org.junit.Assert.*
import org.junit.Test

class BackupCryptoTest {
    @Test fun emptyPasswordExportsAnIndependentUnencryptedCopy() {
        val original = byteArrayOf(0x50, 0x4b, 0x03, 0x04, 1, 2, 3)
        val backup = BackupCrypto.encode(original, "")
        assertFalse(BackupCrypto.isEncrypted(backup))
        assertArrayEquals(original, backup)
        val expected = original.clone()
        original.fill(0)
        assertArrayEquals(expected, backup)
        assertThrows(Exception::class.java) { BackupCrypto.encode(ByteArray(BackupCrypto.maxPlaintext + 1), "") }
    }
    @Test fun passwordsHaveNoLengthOrCharacterRestrictions() {
        val original = "synthetic enrollment data".toByteArray()
        for (password in listOf("a", " ", "é🔑", "p".repeat(1025))) {
            val backup = BackupCrypto.encode(original, password)
            assertTrue(BackupCrypto.isEncrypted(backup))
            assertArrayEquals(original, BackupCrypto.decrypt(backup, password))
        }
    }
    @Test fun passwordRoundTripAndRandomizedArchives() {
        val original = "synthetic enrollment data".toByteArray()
        val a = BackupCrypto.encrypt(original, "sample-password-2026")
        val b = BackupCrypto.encrypt(original, "sample-password-2026")
        assertTrue(BackupCrypto.isEncrypted(a))
        assertFalse(a.contentEquals(b))
        assertArrayEquals(original, BackupCrypto.decrypt(a, "sample-password-2026"))
    }
    @Test fun wrongPasswordAndTamperingAreRejected() {
        val archive = BackupCrypto.encrypt("synthetic".toByteArray(), "sample-password-2026")
        for (index in listOf(15, archive.lastIndex)) {
            val damaged = archive.clone()
            damaged[index] = (damaged[index].toInt() xor 1).toByte()
            assertThrows(Exception::class.java) { BackupCrypto.decrypt(damaged, "sample-password-2026") }
        }
        assertThrows(Exception::class.java) { BackupCrypto.decrypt(archive, "different-password") }
    }
    @Test fun oversizedAndMalformedArchivesAreRejected() {
        assertThrows(Exception::class.java) { BackupCrypto.decrypt(ByteArray(128), "sample-password-2026") }
        assertThrows(Exception::class.java) { BackupCrypto.encrypt(ByteArray(BackupCrypto.maxPlaintext + 1), "sample-password-2026") }
    }
}
