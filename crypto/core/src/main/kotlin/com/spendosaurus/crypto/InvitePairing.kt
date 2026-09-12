package com.spendosaurus.crypto

import com.google.crypto.tink.subtle.AesGcmJce
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.Random
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Authenticates who gets to join a household, independent of whether the
 * server can be trusted.
 *
 * An invite link looks like `.../join?code=ABCDE-12345#s=<fragment>`. The
 * `code` is looked up server-side to find, rate-limit, and expire the
 * invite, same as before. The `#s=...` fragment is a URL fragment: browsers
 * and HTTP clients never send it to any server, so it only ever travels
 * through whatever channel the invite link itself travels through (a text
 * message, an email, AirDrop).
 *
 * That fragment secret is what lets the inviting device trust the new
 * member's public key without asking the server to vouch for it. Without
 * this step, a server that wanted to (or was compelled to) substitute a
 * different public key for "the new member" could get the household key
 * wrapped for an attacker instead -- the inviter has no other way to verify
 * a bare public key belongs to the person they actually invited. Requiring
 * the join announcement to be sealed with a key derived from the fragment
 * secret means only someone who received the real link can produce an
 * announcement the inviter will accept.
 *
 * [sealJoinAnnouncement] / [openJoinAnnouncement] use HKDF (RFC 5869) and
 * AES-256-GCM from Tink's `subtle` package -- the same audited
 * implementations `HouseholdKey` and `DeviceIdentity` use elsewhere, not a
 * separate hand-rolled scheme.
 */
object InvitePairing {
    private const val HKDF_INFO = "spendosaurus-invite-pairing-v1"
    private const val SECRET_SIZE_BYTES = 32

    /** Generates the secret that goes in the invite link's `#s=` fragment. */
    fun generateSecret(): ByteArray {
        CryptoConfig.register()
        return Random.randBytes(SECRET_SIZE_BYTES)
    }

    fun encodeForFragment(secret: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(secret)

    fun decodeFromFragment(fragment: String): ByteArray =
        Base64.getUrlDecoder().decode(fragment)

    /**
     * Called on the joining device: seals its freshly generated public key so
     * only someone holding [secret] (i.e. someone who received this exact
     * invite link) can read it. [inviteCode] is bound in as associated data
     * so the announcement can't be replayed against a different invite.
     */
    fun sealJoinAnnouncement(secret: ByteArray, publicKeyBytes: ByteArray, inviteCode: String): ByteArray =
        pairingAead(secret).encrypt(publicKeyBytes, inviteCode.toAad())

    /**
     * Called on the inviting device: recovers the joining device's public key
     * from the announcement it uploaded via the server. Throws if [secret]
     * doesn't match, [inviteCode] doesn't match, or the ciphertext was
     * tampered with -- there is no partial success.
     */
    fun openJoinAnnouncement(secret: ByteArray, ciphertext: ByteArray, inviteCode: String): ByteArray =
        pairingAead(secret).decrypt(ciphertext, inviteCode.toAad())

    private fun pairingAead(secret: ByteArray): AesGcmJce {
        CryptoConfig.register()
        val derivedKey = Hkdf.computeHkdf(
            "HMACSHA256",
            secret,
            /* salt = */ ByteArray(0),
            HKDF_INFO.toByteArray(StandardCharsets.UTF_8),
            32
        )
        return AesGcmJce(derivedKey)
    }

    private fun String.toAad(): ByteArray = toByteArray(StandardCharsets.UTF_8)
}
