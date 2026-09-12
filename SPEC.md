# Spendosaurus Encryption Spec

This document describes exactly how Spendosaurus encrypts household data,
so the claim "Spendosaurus cannot read your expenses" is something you can
check, not something you have to take on faith. Everything described here
is implemented in [`/crypto`](./crypto) and enforced server-side by
[`/backend/firestore.rules`](./backend/firestore.rules) and
[`/backend/functions`](./backend/functions) — all public in this repo.

If you find a place where the code doesn't match this document, or a way
around what this document claims, please open an issue.

## In plain language

Every phone in a household generates its own private key that never leaves
that phone. The household's expenses are encrypted with a separate key that
only household members' phones ever hold, in a form our servers can read.
When you add an expense, your phone encrypts it before it's sent anywhere;
when another family member's phone receives it, their phone decrypts it.
Our server, and Firebase/Google underneath it, only ever sees encrypted
bytes, sizes, and timestamps — never a title, category, amount, or note.

Two things follow from this that we want to be upfront about, not bury:

- **We cannot help you recover data from your account.** If you're in a
  single-person household and you lose your phone without ever writing
  down the recovery phrase we offer you at setup, that household's data is
  gone. We don't have a back door, which also means we don't have a back
  door for you.
- **We cannot see your data to debug it.** If something looks wrong, we can
  look at metadata (when a write happened, how large it was, whether it
  succeeded) but not at what it says. Screenshots help us far more than
  most support requests, in this app specifically.

## Threat model

What this design protects against:
- Anyone with read access to the Firestore database or its backups
  (including us, an attacker who breaches our project, or a legal demand
  served on us for data we hold) sees ciphertext, not expense content.
- A network intermediary or a compromised CDN/hosting layer sees ciphertext
  in transit and at rest.
- A server that wanted to (or was compelled to) impersonate a new household
  member during an invite cannot get the household key wrapped for a key
  it controls (see "Invite pairing" below) — this is a real, not
  theoretical, gap in simpler "server relays public keys" designs.

What it does not protect against:
- A compromised or malicious *device* that is already a legitimate member
  of the household — it has the household key, by design, because it
  needs to display your expenses.
- Weaknesses in Android's Keystore/TEE implementation on a given device.
- A user who loses every device in a single-person household and never
  recorded the recovery phrase (see above — this is a deliberate trade-off,
  not an oversight).
- Metadata: household size, roughly how often a household is active, and
  approximate item/cost counts are visible to the server, because Firestore
  needs some plaintext fields (ids, timestamps) to sort and sync documents.

## Primitives

Everything here is built from [Google Tink](https://developers.google.com/tink)
primitives — audited, widely reviewed implementations — never a hand-rolled
cipher or KDF:

| Purpose | Primitive |
|---|---|
| Per-device/account identity keypair | HPKE (RFC 9180), X25519 KEM, HKDF-SHA256, AES-128-GCM AEAD — via `com.google.crypto.tink.hybrid.HpkeParameters` |
| Household content key | AES-256-GCM — `PredefinedAeadParameters.AES256_GCM` |
| Invite-pairing key derivation | HKDF-HMAC-SHA256 (RFC 5869) — `com.google.crypto.tink.subtle.Hkdf` |
| Invite-pairing encryption | AES-256-GCM — `com.google.crypto.tink.subtle.AesGcmJce` |
| Recovery phrase | BIP-39 (SHA-256 checksum, PBKDF2-HMAC-SHA512, 2048 rounds) — the published Bitcoin BIPs spec, repurposed as a key-derivation mechanism, not a wallet |

Source: [`/crypto/core`](./crypto/core). Tests: same directory, run with
`./gradlew :crypto:core:test`.

## Data model

```
users/{uid}                              publicKey, pushTokens, createdAt
households/{hid}/members/{uid}           wrappedKey, role, joinedAt
households/{hid}/invites/{id}            codeHash, expiresAt, revoked   (bookkeeping only)
households/{hid}/joinAnnouncements/{id}  ciphertext                    (opaque; see Invite pairing)
households/{hid}/items/{itemId}          ciphertext, createdAt, updatedAt
households/{hid}/items/{id}/costs/{cid}  ciphertext, createdAt
households/{hid}/auditLog/{id}           ciphertext, createdAt, actorUid
inviteLookup/{codeHash}                  householdId, inviteId, expiresAt (server-only, never client-readable)
```

Encrypted (inside `ciphertext`): item title, category, currency, amount,
target date, notes, recurrence; cost amount, note, date; audit summary and
details. See [`Payloads.kt`](./crypto/core/src/main/kotlin/com/spendosaurus/crypto/Payloads.kt)
for the exact plaintext shape.

Left as plaintext Firestore fields, and why: `createdAt`/`updatedAt`
(sorting), item/cost/household/user ids (routing and access control),
`actorUid` on audit entries (so entries can be attributed without
decryption). None of these reveal what a household spends money on or how
much.

Every ciphertext is produced with the full document path as AEAD
associated data (see [`ContentCipher.kt`](./crypto/core/src/main/kotlin/com/spendosaurus/crypto/ContentCipher.kt)),
and every wrapped household key is produced with the household id as HPKE
context info (see [`HouseholdKey.kt`](./crypto/core/src/main/kotlin/com/spendosaurus/crypto/HouseholdKey.kt)).
Both mean a ciphertext or wrapped key copied to a different document or
household fails to decrypt there instead of silently being accepted.

## Key lifecycle

**1. Identity.** On first launch, a device generates an HPKE keypair
(`DeviceIdentity.generate()`). The private half is exported once
(`exportPrivateForLocalStorage()`) and immediately re-encrypted by the
Android layer under a hardware-backed Keystore key before it touches disk
(`AndroidKeystoreStorage`, using Tink's own documented
`AndroidKeysetManager` + `AndroidKeystoreKmsClient` pattern). The public
half (`publicKeyBytes`) is uploaded to `users/{uid}`.

**2. Household creation.** A device generates a random household key
(`HouseholdKey.generate()`), wraps it for its own public key
(`sealForMember`), and calls the `createHousehold` Cloud Function with that
wrapped blob. The function stores it in `members/{uid}` but has no path to
decrypt it — see [`households.ts`](./backend/functions/src/households.ts).

**3. Invite pairing — the part a naive design gets wrong.** An invite link
is `.../join?code=ABCDE-12345#s=<secret>`. The `code` is registered
server-side (`createInvite`) for lookup, rate-limiting, and expiry, same as
any invite system. The `#s=...` fragment is a URL fragment: browsers and
HTTP clients never transmit it to a server, so it only ever travels through
whatever channel carried the link itself (a text message, an email).

If the server alone matched a joining device's public key to a pending
invite, a server that wanted to (or was compelled to) substitute a
different public key could get the household key wrapped for an attacker
instead — the inviting device has no independent way to verify a bare
public key belongs to the person they actually invited. The fragment
secret closes that gap: the joining device seals its public key with a key
derived from the fragment (`InvitePairing.sealJoinAnnouncement`) before
uploading it; only someone holding the same fragment — i.e. someone who
received the real link — can produce an announcement the inviter's device
will accept (`InvitePairing.openJoinAnnouncement`). The server relays the
announcement but cannot forge or read it.

Once the inviting device opens the announcement, it wraps the household
key for that now-authenticated public key
(`HouseholdKey.sealForMember`) and writes it to
`members/{newUid}`, completing the join. This requires the inviter's
device to be online at some point after the invitee redeems the code — in
practice, seconds, since a Cloud Function can wake it with a push.

**4. Content.** Every item/cost/audit write encrypts its JSON payload with
the household's `ContentCipher` before the write reaches Firestore, and
decrypts on read. Firestore's realtime listeners sync the ciphertext
exactly as they would any other document — sync doesn't require the server
to understand what it's syncing.

**5. Notifications.** A Cloud Function trigger fires on writes to
`items`/`costs` and sends a content-free FCM data message (just a
household id) — see [`notifications.ts`](./backend/functions/src/notifications.ts).
The receiving app decrypts locally and raises the real notification
itself; the function never has anything to put in the notification text
even if it wanted to.

**6. Losing a device.** Any other current member's device can re-seal the
household key for a replacement device, the same mechanism as adding a new
member (`HouseholdKey.sealForMember` again, this time to your own new
device's public key). A single-person household has no one else to ask —
for that case, an optional 24-word recovery phrase
(`RecoveryPhrase.generate()`) is offered at household creation, sealing the
household key under a key derived the same way a BIP-39 wallet derives its
seed. This phrase is shown once, never transmitted anywhere, and never
stored by us in any form.

## Verifying this yourself

- `./gradlew :crypto:core:test` runs the full test suite, including
  tamper-detection (flip a byte in a ciphertext, decryption throws),
  cross-household binding (a sealed key or ciphertext moved to a different
  household fails to open there), and a test against the published
  BIP-39 test vector for all-zero entropy — not just internal
  self-consistency, but checkable against an external spec.
- `backend/firestore.rules` has no rule that reads or depends on the
  content of any `ciphertext` field — access control here is entirely
  about who may read/write a document, never about what it contains.
- `backend/functions/src` has no code path that constructs a `HouseholdKey`,
  a `DeviceIdentity`, or anything else from `/crypto` — grep for imports
  from that module and there are none.

## Roadmap for making this more verifiable, not just documented

1. ✅ Open-source the crypto module (this repo).
2. ✅ Build on vetted, published primitives only (Tink), documented above.
3. ✅ Publish the Firestore rules and Cloud Functions source (this repo).
4. Reproducible builds — a way to confirm the Play Store APK matches this
   source, not just that *some* source looks clean.
5. An independent third-party cryptography audit of this design and its
   implementation, published in full.
6. A bug bounty program for ongoing adversarial pressure.

We're starting at 1–3. 4–6 are next, gated on the app having real users and
revenue to fund an audit properly rather than a token one.
