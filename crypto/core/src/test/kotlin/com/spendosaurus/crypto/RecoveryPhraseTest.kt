package com.spendosaurus.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RecoveryPhraseTest {

    @Test
    fun `generated phrase has 24 words all drawn from the BIP-39 wordlist`() {
        val phrase = RecoveryPhrase.generate()
        assertEquals(24, phrase.words.size)
        // Round-tripping through fromPhrase re-validates the checksum.
        assertEquals(phrase.words, RecoveryPhrase.fromPhrase(phrase.phrase).words)
    }

    @Test
    fun `recovers the exact household key it sealed`() {
        val key = HouseholdKey.generate()
        val phrase = RecoveryPhrase.generate()

        val sealed = phrase.seal(key, "household_x")
        val recoveredKey = phrase.unseal(sealed, "household_x")

        val ciphertext = key.cipher().encrypt("family data", "households/household_x/items/1")
        assertEquals(
            "family data",
            recoveredKey.cipher().decrypt(ciphertext, "households/household_x/items/1")
        )
    }

    @Test
    fun `matches the published BIP-39 test vector for all-zero entropy`() {
        // Independently verifiable against the reference Python/JS BIP-39
        // implementations' test vectors for 32 zero bytes of entropy -- not
        // just internally self-consistent, but checkable against the spec.
        val vector = "abandon ".repeat(23) + "art"
        val phrase = RecoveryPhrase.fromPhrase(vector)
        assertEquals(24, phrase.words.size)
        assertEquals("art", phrase.words.last())
    }

    @Test
    fun `a mistyped word fails the checksum instead of silently succeeding`() {
        // Same 24 words as the valid all-zero vector above, but with the
        // checksum word swapped for another entropy word -- a stand-in for a
        // real typo, with a deterministically wrong checksum rather than a
        // randomly-generated one that has a 1-in-256 chance of still passing.
        val corrupted = "abandon ".repeat(24).trim()
        assertFailsWith<IllegalArgumentException> { RecoveryPhrase.fromPhrase(corrupted) }
    }

    @Test
    fun `wrong phrase cannot unseal another household's key`() {
        val key = HouseholdKey.generate()
        val realPhrase = RecoveryPhrase.generate()
        val wrongPhrase = RecoveryPhrase.generate()

        val sealed = realPhrase.seal(key, "household_x")

        assertFailsWith<Exception> { wrongPhrase.unseal(sealed, "household_x") }
    }
}
