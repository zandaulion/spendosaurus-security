package com.spendosaurus.crypto

import com.google.crypto.tink.Aead
import java.nio.charset.StandardCharsets

/**
 * Encrypts/decrypts the JSON payload of a single Firestore document under a
 * household's [HouseholdKey]. The document's path (e.g.
 * `households/{hid}/items/{itemId}`) is always passed in as associated data,
 * so a ciphertext blob copied to a different document -- a different item,
 * or a different household entirely -- fails to decrypt instead of silently
 * being accepted there.
 *
 * The output of [Aead.encrypt] is a single self-contained blob (Tink embeds
 * the nonce and auth tag); there is no separate IV field to manage or to
 * accidentally reuse.
 */
class ContentCipher internal constructor(private val aead: Aead) {

    fun encrypt(plaintextJson: String, documentPath: String): ByteArray =
        aead.encrypt(plaintextJson.toByteArray(StandardCharsets.UTF_8), documentPath.asAad())

    fun decrypt(ciphertext: ByteArray, documentPath: String): String =
        String(aead.decrypt(ciphertext, documentPath.asAad()), StandardCharsets.UTF_8)

    private fun String.asAad(): ByteArray = toByteArray(StandardCharsets.UTF_8)
}
