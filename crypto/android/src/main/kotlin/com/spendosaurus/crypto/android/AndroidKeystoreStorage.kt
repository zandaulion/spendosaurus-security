package com.spendosaurus.crypto.android

import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.spendosaurus.crypto.DeviceIdentity
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Persists a [DeviceIdentity]'s private key on-device, encrypted at rest
 * under a key that lives in the Android Keystore and is hardware-backed
 * where the device supports it (StrongBox / TEE). The private key material
 * is never written to disk, SharedPreferences, or anywhere else in
 * cleartext -- not even briefly -- and it never leaves the device at all.
 *
 * The master key itself is managed entirely by `AndroidKeysetManager`
 * (which wires up `AndroidKeystoreKmsClient` internally given an
 * `android-keystore://` URI) -- Tink's own documented pattern for Android
 * at-rest protection, not a custom scheme layered on top of it. Only the
 * resulting *encrypted*
 * keyset bytes (via `TinkProtoKeysetFormat.serializeEncryptedKeyset`) are
 * ever written to disk.
 */
class AndroidKeystoreStorage(context: Context, keysetFileName: String = "spendosaurus_identity.tink") {

    private val appContext = context.applicationContext
    private val file = File(appContext.filesDir, keysetFileName)
    private val associatedData = ASSOCIATED_DATA.toByteArray(StandardCharsets.UTF_8)

    init {
        AeadConfig.register()
    }

    /** True if a device identity has already been generated and stored. */
    fun hasStoredIdentity(): Boolean = file.exists()

    /** Loads the previously stored identity, decrypting it via the Keystore master key. */
    fun load(): DeviceIdentity {
        check(hasStoredIdentity()) { "No stored identity -- call save() with a freshly generated one first" }
        val encrypted = file.readBytes()
        val plaintextHandle = TinkProtoKeysetFormat.parseEncryptedKeyset(encrypted, masterKeyAead(), associatedData)
        val cleartext = TinkProtoKeysetFormat.serializeKeyset(plaintextHandle, InsecureSecretKeyAccess.get())
        return DeviceIdentity.restore(cleartext)
    }

    /** Encrypts [identity]'s private key under the Keystore master key and writes it to disk. */
    fun save(identity: DeviceIdentity) {
        val cleartext = identity.exportPrivateForLocalStorage()
        val handle = TinkProtoKeysetFormat.parseKeyset(cleartext, InsecureSecretKeyAccess.get())
        val encrypted = TinkProtoKeysetFormat.serializeEncryptedKeyset(handle, masterKeyAead(), associatedData)
        file.writeBytes(encrypted)
    }

    /** Removes the stored identity, e.g. on sign-out. Does not affect other members' access. */
    fun clear() {
        file.delete()
    }

    /**
     * The Keystore-backed AEAD used only to encrypt/decrypt the identity
     * keyset file above -- never to touch household or content keys
     * directly. `AndroidKeysetManager` auto-generates this master key inside
     * the Keystore the first time it's needed and reuses it after that; the
     * key material itself never leaves the Keystore/TEE.
     */
    private fun masterKeyAead(): Aead {
        val manager = AndroidKeysetManager.Builder()
            .withSharedPref(appContext, MASTER_KEYSET_NAME, MASTER_KEYSET_PREF_FILE)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(MASTER_KEY_URI)
            .build()
        return manager.keysetHandle.getPrimitive(Aead::class.java)
    }

    companion object {
        private const val MASTER_KEY_URI = "android-keystore://spendosaurus_identity_master_key"
        private const val MASTER_KEYSET_NAME = "spendosaurus_master_keyset"
        private const val MASTER_KEYSET_PREF_FILE = "spendosaurus_crypto_prefs"
        private const val ASSOCIATED_DATA = "spendosaurus-identity-v1"
    }
}
