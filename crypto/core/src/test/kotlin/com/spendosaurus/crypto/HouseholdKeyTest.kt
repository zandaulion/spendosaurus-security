package com.spendosaurus.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class HouseholdKeyTest {

    @Test
    fun `sealed key can only be recovered by the intended member`() {
        val household = "household_abc"
        val key = HouseholdKey.generate()

        val member = DeviceIdentity.generate()
        val stranger = DeviceIdentity.generate()
        val memberPublic = RemoteIdentity.fromPublicKeyBytes(publicKeyOf(member))

        val sealed = key.sealForMember(memberPublic, household)

        // The intended member recovers it and can decrypt content sealed with it.
        val recovered = HouseholdKey.unseal(sealed, member, household)
        val plaintext = recovered.cipher().decrypt(
            key.cipher().encrypt("hello", "households/$household/items/1"),
            "households/$household/items/1"
        )
        assertEquals("hello", plaintext)

        // Someone else's private key cannot open it.
        assertFailsWith<Exception> { HouseholdKey.unseal(sealed, stranger, household) }
    }

    @Test
    fun `sealed key is bound to its household id`() {
        val key = HouseholdKey.generate()
        val member = DeviceIdentity.generate()
        val memberPublic = RemoteIdentity.fromPublicKeyBytes(publicKeyOf(member))

        val sealed = key.sealForMember(memberPublic, "household_a")

        // Copying the sealed blob into a different household's context fails.
        assertFailsWith<Exception> { HouseholdKey.unseal(sealed, member, "household_b") }
    }

    @Test
    fun `content ciphertext is bound to its document path`() {
        val key = HouseholdKey.generate()
        val cipher = key.cipher()
        val ciphertext = cipher.encrypt("""{"title":"Roof repair"}""", "households/h1/items/item1")

        // Decrypting under the right path works.
        assertEquals("""{"title":"Roof repair"}""", cipher.decrypt(ciphertext, "households/h1/items/item1"))

        // The same ciphertext moved to a different document fails to decrypt --
        // this is what stops a copied blob being silently accepted elsewhere.
        assertFailsWith<Exception> { cipher.decrypt(ciphertext, "households/h1/items/item2") }
    }

    @Test
    fun `tampering with ciphertext is detected`() {
        val key = HouseholdKey.generate()
        val cipher = key.cipher()
        val ciphertext = cipher.encrypt("sensitive amount", "households/h1/items/item1").copyOf()
        ciphertext[ciphertext.size - 1] = (ciphertext[ciphertext.size - 1] + 1).toByte()

        assertFailsWith<Exception> { cipher.decrypt(ciphertext, "households/h1/items/item1") }
    }

    @Test
    fun `two households never generate the same key`() {
        val a = HouseholdKey.generate().cipher().encrypt("x", "p")
        val b = HouseholdKey.generate().cipher().encrypt("x", "p")
        assertNotEquals(a.toList(), b.toList())
    }

    private fun publicKeyOf(identity: DeviceIdentity): ByteArray = identity.publicKeyBytes
}
