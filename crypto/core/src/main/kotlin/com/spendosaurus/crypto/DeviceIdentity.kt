package com.spendosaurus.crypto

import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.hybrid.HpkeParameters

/**
 * X25519-HPKE (RFC 9180) with AES-128-GCM, TINK key-prefix variant.
 *
 * Built directly from [HpkeParameters] rather than the
 * `PredefinedHybridParameters.HPKE_X25519_HKDF_SHA256_AES_128_GCM` constant,
 * because that convenience constant lands in Tink Java after 1.23.0; this
 * builds the exact same parameters by hand against the published API.
 */
private val HPKE_X25519_PARAMS: HpkeParameters = HpkeParameters.builder()
    .setVariant(HpkeParameters.Variant.TINK)
    .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
    .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
    .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
    .build()

/**
 * A device or account's personal HPKE (RFC 9180) keypair, X25519-based.
 *
 * The private half never leaves the device it was generated on. This class
 * itself does not persist anything -- [exportPrivateForLocalStorage] hands
 * back cleartext key bytes that the caller (the Android layer, via
 * `AndroidKeystoreStorage`) is responsible for encrypting at rest under a
 * hardware-backed key before writing them anywhere. Nothing in this module
 * ever sends those bytes over the network; only [publicKeyBytes] is meant to
 * be uploaded.
 */
class DeviceIdentity private constructor(private val handle: KeysetHandle) {

    /** Safe to upload: identifies this device/account for key-wrapping. */
    val publicKeyBytes: ByteArray
        get() = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle.publicKeysetHandle)

    /**
     * Cleartext private keyset bytes. Callers MUST encrypt this before
     * persisting it anywhere -- see `AndroidKeystoreStorage` in the
     * `crypto-android` module, which wraps it with a Keystore-backed AEAD via
     * `TinkProtoKeysetFormat.serializeEncryptedKeyset`.
     */
    fun exportPrivateForLocalStorage(): ByteArray =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get())

    /** Unwraps a household key that was sealed to this identity's public key. */
    internal fun unwrap(wrapped: ByteArray, contextInfo: ByteArray): ByteArray =
        handle.getPrimitive(HybridDecrypt::class.java).decrypt(wrapped, contextInfo)

    companion object {
        fun generate(): DeviceIdentity {
            CryptoConfig.register()
            return DeviceIdentity(KeysetHandle.generateNew(HPKE_X25519_PARAMS))
        }

        /** Restores an identity from bytes produced by [exportPrivateForLocalStorage]. */
        fun restore(exportedPrivate: ByteArray): DeviceIdentity {
            CryptoConfig.register()
            return DeviceIdentity(
                TinkProtoKeysetFormat.parseKeyset(exportedPrivate, InsecureSecretKeyAccess.get())
            )
        }
    }
}

/**
 * Someone else's public identity -- the household member (or the device
 * you're inviting) you want to seal a secret to. Constructed from the bytes
 * they published (or that arrived, authenticated, via [InvitePairing]).
 */
class RemoteIdentity private constructor(private val publicHandle: KeysetHandle) {

    /** Seals [secret] so that only the holder of the matching private key can read it. */
    internal fun seal(secret: ByteArray, contextInfo: ByteArray): ByteArray =
        publicHandle.getPrimitive(HybridEncrypt::class.java).encrypt(secret, contextInfo)

    companion object {
        fun fromPublicKeyBytes(bytes: ByteArray): RemoteIdentity {
            CryptoConfig.register()
            return RemoteIdentity(TinkProtoKeysetFormat.parseKeysetWithoutSecret(bytes))
        }
    }
}
