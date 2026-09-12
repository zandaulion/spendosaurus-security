package com.spendosaurus.crypto

import com.google.crypto.tink.subtle.AesGcmJce
import com.google.crypto.tink.subtle.Random
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.spec.KeySpec
import java.text.Normalizer
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * An optional, opt-in 24-word recovery phrase (BIP-39, the same standard
 * used by cryptocurrency wallets) that can also unwrap a household's key.
 *
 * This exists for the one case device-to-device key sharing can't cover: a
 * single-person household, one device, no other member's phone to re-wrap
 * the key from. Anyone in a multi-device household can already recover by
 * having another member's device re-seal the key for a replacement device --
 * this phrase is only needed when there is no one else to ask.
 *
 * It is generated on-device, shown to the user exactly once, and never
 * stored anywhere by us in any form -- not the words, not a hash of them,
 * not the key they derive. Losing the phrase *and* every device in a
 * single-person household means the data is gone; that is the honest cost
 * of a key we genuinely never hold, not a bug.
 *
 * The mnemonic encoding and the mnemonic-to-seed derivation both follow the
 * public BIP-39 specification exactly (SHA-256 checksum, PBKDF2-HMAC-SHA512,
 * 2048 rounds, salt "mnemonic") so the math is independently checkable
 * against BIP-39 test vectors -- we are repurposing a well-known, published
 * derivation, not inventing one.
 */
class RecoveryPhrase private constructor(val words: List<String>) {

    val phrase: String get() = words.joinToString(" ")

    /** Seals a household key's raw keyset bytes under this phrase. */
    fun seal(key: HouseholdKey, householdId: String): ByteArray =
        aead().encrypt(key.exportRawForRecovery(), householdId.toAad())

    /** Recovers a household key from a blob produced by [seal]. */
    fun unseal(sealed: ByteArray, householdId: String): HouseholdKey =
        HouseholdKey.fromRaw(aead().decrypt(sealed, householdId.toAad()))

    private fun aead(): AesGcmJce {
        CryptoConfig.register()
        // BIP-39 mnemonic-to-seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt
        // "mnemonic" (+ optional passphrase, unused here), 64-byte output.
        // We only need 32 bytes for AES-256, taken from the front of the seed.
        val normalized = Normalizer.normalize(phrase, Normalizer.Form.NFKD)
        val salt = Normalizer.normalize("mnemonic", Normalizer.Form.NFKD)
        val spec: KeySpec = PBEKeySpec(
            normalized.toCharArray(),
            salt.toByteArray(StandardCharsets.UTF_8),
            2048,
            64 * 8
        )
        val seed = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).encoded
        return AesGcmJce(seed.copyOf(32))
    }

    private fun String.toAad(): ByteArray = toByteArray(StandardCharsets.UTF_8)

    companion object {
        private const val WORD_COUNT = 24
        private const val ENTROPY_BYTES = 32 // 256 bits -> 24 words with an 8-bit checksum

        private val wordlist: List<String> by lazy {
            RecoveryPhrase::class.java.getResourceAsStream("/bip39/english.txt")
                ?.bufferedReader(StandardCharsets.UTF_8)
                ?.readLines()
                ?.filter { it.isNotBlank() }
                ?: error("bip39/english.txt wordlist resource is missing")
        }

        init {
            check(wordlist.size == 2048) { "BIP-39 wordlist must have exactly 2048 words" }
        }

        fun generate(): RecoveryPhrase {
            CryptoConfig.register()
            val entropy = Random.randBytes(ENTROPY_BYTES)
            return RecoveryPhrase(entropyToWords(entropy))
        }

        /** Parses and validates a phrase a user typed back in, e.g. during recovery. */
        fun fromPhrase(phrase: String): RecoveryPhrase {
            val words = Normalizer.normalize(phrase.trim(), Normalizer.Form.NFKD)
                .lowercase()
                .split(Regex("\\s+"))
            require(words.size == WORD_COUNT) { "Recovery phrase must be $WORD_COUNT words" }

            val indices = words.map { word ->
                wordlist.indexOf(word).also {
                    require(it >= 0) { "'$word' is not a recovery-phrase word" }
                }
            }
            val bits = indices.flatMap { index -> (10 downTo 0).map { bit -> (index shr bit) and 1 == 1 } }

            val entropyBits = bits.subList(0, ENTROPY_BYTES * 8)
            val checksumBits = bits.subList(ENTROPY_BYTES * 8, bits.size)
            val entropy = bitsToBytes(entropyBits)

            require(checksumBits == checksumBitsOf(entropy)) {
                "Recovery phrase failed its checksum -- check for a mistyped or reordered word"
            }
            return RecoveryPhrase(words)
        }

        private fun entropyToWords(entropy: ByteArray): List<String> {
            val bits = bytesToBits(entropy) + checksumBitsOf(entropy)
            return bits.chunked(11).map { chunk ->
                val index = chunk.fold(0) { acc, bit -> (acc shl 1) or (if (bit) 1 else 0) }
                wordlist[index]
            }
        }

        private fun checksumBitsOf(entropy: ByteArray): List<Boolean> {
            val hash = MessageDigest.getInstance("SHA-256").digest(entropy)
            val checksumBitCount = entropy.size * 8 / 32 // 8 bits for 256-bit entropy
            return bytesToBits(hash).subList(0, checksumBitCount)
        }

        private fun bytesToBits(bytes: ByteArray): List<Boolean> =
            bytes.flatMap { byte -> (7 downTo 0).map { bit -> (byte.toInt() shr bit) and 1 == 1 } }

        private fun bitsToBytes(bits: List<Boolean>): ByteArray {
            require(bits.size % 8 == 0)
            return ByteArray(bits.size / 8) { i ->
                var value = 0
                for (b in 0 until 8) {
                    value = (value shl 1) or (if (bits[i * 8 + b]) 1 else 0)
                }
                value.toByte()
            }
        }
    }
}
