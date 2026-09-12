package com.spendosaurus.crypto

import com.google.crypto.tink.Aead
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.aead.PredefinedAeadParameters
import java.nio.charset.StandardCharsets

/**
 * The single AES-256-GCM key shared by every member of one household. Every
 * item, cost entry, and audit-log entry in that household is encrypted with
 * this key before it is written to Firestore. The server never sees it in
 * any form -- only [sealForMember] output (an HPKE ciphertext only the target
 * device's private key can open) is ever written to `households/{id}/members`.
 *
 * Binding [sealForMember]/[unseal] and every [cipher] operation to the
 * household id as associated data/context is deliberate: it stops a sealed
 * key or a ciphertext document from being copied into a different household
 * and silently accepted there.
 */
class HouseholdKey private constructor(private val handle: KeysetHandle) {

    /** Wraps this key so only [member]'s private key can recover it. */
    fun sealForMember(member: RemoteIdentity, householdId: String): ByteArray =
        member.seal(exportRaw(), householdId.toContext())

    /** An [Aead] scoped to this household's content -- see [ContentCipher]. */
    fun cipher(): ContentCipher = ContentCipher(handle.getPrimitive(Aead::class.java))

    private fun exportRaw(): ByteArray =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get())

    /** Used only by [RecoveryPhrase] to seal this key with a passphrase-derived AEAD. */
    internal fun exportRawForRecovery(): ByteArray = exportRaw()

    companion object {
        fun generate(): HouseholdKey {
            CryptoConfig.register()
            return HouseholdKey(KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM))
        }

        /** Recovers the household key from a blob produced by [sealForMember]. */
        fun unseal(sealed: ByteArray, identity: DeviceIdentity, householdId: String): HouseholdKey {
            CryptoConfig.register()
            val raw = identity.unwrap(sealed, householdId.toContext())
            return HouseholdKey(TinkProtoKeysetFormat.parseKeyset(raw, InsecureSecretKeyAccess.get()))
        }

        /** Recovers the household key from raw keyset bytes, e.g. via [RecoveryPhrase]. */
        internal fun fromRaw(raw: ByteArray): HouseholdKey {
            CryptoConfig.register()
            return HouseholdKey(TinkProtoKeysetFormat.parseKeyset(raw, InsecureSecretKeyAccess.get()))
        }
    }
}

private fun String.toContext(): ByteArray = toByteArray(StandardCharsets.UTF_8)
