package com.spendosaurus.crypto

import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.hybrid.HybridConfig

/**
 * One-time registration of the Tink primitives this module uses.
 *
 * Everything downstream (household content encryption, identity keypairs,
 * key wrapping) is built entirely out of primitives Tink itself implements
 * and has published; this module never implements a cipher or a KDF from
 * scratch. [Hkdf] and [AesGcmJce] used by [InvitePairing] are Tink's own
 * `subtle` package, not a local reimplementation.
 *
 * Call this once, before touching anything else in this module.
 */
object CryptoConfig {
    @Volatile
    private var registered = false

    @Synchronized
    fun register() {
        if (registered) return
        AeadConfig.register()
        HybridConfig.register()
        registered = true
    }
}
