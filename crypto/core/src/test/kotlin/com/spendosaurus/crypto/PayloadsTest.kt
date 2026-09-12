package com.spendosaurus.crypto

import kotlin.test.Test
import kotlin.test.assertEquals

class PayloadsTest {

    @Test
    fun `item payload round-trips through encryption exactly`() {
        val cipher = HouseholdKey.generate().cipher()
        val path = "households/h1/items/item1"
        val item = ItemPayload(
            title = "Roof repair",
            category = "home",
            currency = "RON",
            estimatedMinor = 340_00,
            targetDate = "2026-11-01",
            notes = "Get a second quote",
            recurrence = null,
            currentCycle = null,
            createdByLabel = "Alex's Phone"
        )

        val ciphertext = cipher.encryptItem(item, path)
        val recovered = cipher.decryptItem(ciphertext, path)

        assertEquals(item, recovered)
    }

    @Test
    fun `cost and audit payloads round-trip exactly`() {
        val cipher = HouseholdKey.generate().cipher()

        val cost = CostPayload(amountMinor = 15_00, currency = "RON", note = "First installment", date = "2026-09-12")
        val costPath = "households/h1/items/item1/costs/c1"
        assertEquals(cost, cipher.decryptCost(cipher.encryptCost(cost, costPath), costPath))

        val audit = AuditPayload(action = "cost_added", summary = "Added 15.00 RON to Roof repair")
        val auditPath = "households/h1/auditLog/a1"
        assertEquals(audit, cipher.decryptAudit(cipher.encryptAudit(audit, auditPath), auditPath))
    }
}
