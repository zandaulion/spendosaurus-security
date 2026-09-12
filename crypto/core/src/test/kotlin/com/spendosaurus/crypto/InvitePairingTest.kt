package com.spendosaurus.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class InvitePairingTest {

    @Test
    fun `join announcement round-trips for the holder of the fragment secret`() {
        val secret = InvitePairing.generateSecret()
        val newDevice = DeviceIdentity.generate()

        val announcement = InvitePairing.sealJoinAnnouncement(secret, newDevice.publicKeyBytes, "ABCDE-12345")
        val recovered = InvitePairing.openJoinAnnouncement(secret, announcement, "ABCDE-12345")

        assertEquals(newDevice.publicKeyBytes.toList(), recovered.toList())
    }

    @Test
    fun `a server that never saw the fragment cannot forge or read the announcement`() {
        val secret = InvitePairing.generateSecret()
        val wrongSecret = InvitePairing.generateSecret()
        val newDevice = DeviceIdentity.generate()

        val announcement = InvitePairing.sealJoinAnnouncement(secret, newDevice.publicKeyBytes, "ABCDE-12345")

        assertFailsWith<Exception> {
            InvitePairing.openJoinAnnouncement(wrongSecret, announcement, "ABCDE-12345")
        }
    }

    @Test
    fun `an announcement cannot be replayed against a different invite code`() {
        val secret = InvitePairing.generateSecret()
        val newDevice = DeviceIdentity.generate()

        val announcement = InvitePairing.sealJoinAnnouncement(secret, newDevice.publicKeyBytes, "ABCDE-12345")

        assertFailsWith<Exception> {
            InvitePairing.openJoinAnnouncement(secret, announcement, "ZZZZZ-99999")
        }
    }

    @Test
    fun `fragment encoding round-trips and contains no padding characters`() {
        val secret = InvitePairing.generateSecret()
        val encoded = InvitePairing.encodeForFragment(secret)

        assertEquals(secret.toList(), InvitePairing.decodeFromFragment(encoded).toList())
        assertEquals(false, encoded.contains('='))
    }
}
