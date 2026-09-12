package com.spendosaurus.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * The plaintext shape of one household item, exactly as it exists on-device
 * after decryption. Everything here is opaque to the server -- it only ever
 * sees the [ContentCipher] output of `Json.encodeToString(this)`.
 *
 * Deliberately not encrypted, and not part of this payload: the document id,
 * `createdAt`/`updatedAt` timestamps, and `status`. Those stay as plain
 * Firestore fields because the app needs to sort and filter by them without
 * decrypting every document first, and none of them reveal what a family is
 * spending money on or how much.
 */
@Serializable
data class ItemPayload(
    val title: String,
    val category: String,
    val currency: String,
    val estimatedMinor: Long,
    val targetDate: String? = null,
    val notes: String? = null,
    val recurrence: String? = null,
    val currentCycle: String? = null,
    val createdByLabel: String? = null
)

@Serializable
data class CostPayload(
    val amountMinor: Long,
    val currency: String,
    val note: String? = null,
    val date: String,
    val cycle: String? = null,
    val deviceLabel: String? = null
)

@Serializable
data class AuditPayload(
    val action: String,
    val summary: String,
    val detailsJson: String? = null
)

private val json = Json { ignoreUnknownKeys = true }

fun ContentCipher.encryptItem(payload: ItemPayload, documentPath: String): ByteArray =
    encrypt(json.encodeToString(payload), documentPath)

fun ContentCipher.decryptItem(ciphertext: ByteArray, documentPath: String): ItemPayload =
    json.decodeFromString(ItemPayload.serializer(), decrypt(ciphertext, documentPath))

fun ContentCipher.encryptCost(payload: CostPayload, documentPath: String): ByteArray =
    encrypt(json.encodeToString(payload), documentPath)

fun ContentCipher.decryptCost(ciphertext: ByteArray, documentPath: String): CostPayload =
    json.decodeFromString(CostPayload.serializer(), decrypt(ciphertext, documentPath))

fun ContentCipher.encryptAudit(payload: AuditPayload, documentPath: String): ByteArray =
    encrypt(json.encodeToString(payload), documentPath)

fun ContentCipher.decryptAudit(ciphertext: ByteArray, documentPath: String): AuditPayload =
    json.decodeFromString(AuditPayload.serializer(), decrypt(ciphertext, documentPath))
