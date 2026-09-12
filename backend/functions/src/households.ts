import * as crypto from "node:crypto";
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { FieldValue } from "firebase-admin/firestore";
import { db } from "./admin";

/**
 * None of the functions in this file ever see a decryption key or plaintext
 * expense content. Every "key" parameter accepted here is opaque, already-
 * sealed ciphertext produced on-device (see /crypto/core); these functions
 * only decide *whether* a write is allowed to happen and *where* it's
 * stored, never what it means. See ../../SPEC.md.
 */

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no 0/O/1/I

function randomCode(length = 10): string {
  const bytes = crypto.randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  }
  return `${out.slice(0, 5)}-${out.slice(5)}`;
}

function hashCode(code: string): string {
  return crypto.createHash("sha256").update(code.toUpperCase().replace(/[^A-Z0-9]/g, "")).digest("hex");
}

async function requireMember(householdId: string, uid: string): Promise<void> {
  const memberDoc = await db.doc(`households/${householdId}/members/${uid}`).get();
  if (!memberDoc.exists) {
    throw new HttpsError("permission-denied", "Not a member of this household");
  }
}

/**
 * Creates a household and its creator's own membership entry atomically.
 *
 * `householdId` is generated *client-side* (Firestore client SDKs can mint a
 * valid random document id locally, with no server round trip) rather than
 * here, because `wrappedKey` must already be sealed with the household id as
 * HPKE context (HouseholdKey.sealForMember) before this function is ever
 * called -- the client can't seal a key to an id it doesn't have yet, so the
 * id has to come from whoever seals first.
 */
export const createHousehold = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const householdId = request.data?.householdId;
  if (typeof householdId !== "string" || !/^[A-Za-z0-9_-]{10,64}$/.test(householdId)) {
    throw new HttpsError("invalid-argument", "householdId is required");
  }

  const wrappedKey = request.data?.wrappedKey;
  if (typeof wrappedKey !== "string" || wrappedKey.length === 0) {
    throw new HttpsError("invalid-argument", "wrappedKey is required");
  }

  const householdRef = db.collection("households").doc(householdId);
  await db.runTransaction(async (tx) => {
    const existing = await tx.get(householdRef);
    if (existing.exists) {
      throw new HttpsError("already-exists", "householdId collision -- generate a new client-side id and retry");
    }
    tx.set(householdRef, {
      createdAt: FieldValue.serverTimestamp(),
      createdBy: uid,
    });
    tx.set(householdRef.collection("members").doc(uid), {
      wrappedKey,
      role: "owner",
      joinedAt: FieldValue.serverTimestamp(),
    });
  });

  return { householdId: householdRef.id };
});

/**
 * Registers an invite for lookup, rate-limiting, and expiry. Returns only
 * the server-side `code` used to find this invite. The invite *link* the
 * client builds around this code additionally carries a `#s=` fragment --
 * a secret this function never sees -- which is what actually authenticates
 * the joining device's public key later. See InvitePairing.kt / SPEC.md for
 * why that step can't live here.
 */
export const createInvite = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const householdId = request.data?.householdId;
  if (typeof householdId !== "string") {
    throw new HttpsError("invalid-argument", "householdId is required");
  }
  await requireMember(householdId, uid);

  // TODO(production): rate-limit invite creation per household/uid.
  const code = randomCode();
  const expiresAt = Date.now() + INVITE_TTL_MS;
  const inviteRef = db.collection(`households/${householdId}/invites`).doc();

  await db.runTransaction(async (tx) => {
    tx.set(inviteRef, {
      codeHash: hashCode(code),
      createdBy: uid,
      createdAt: FieldValue.serverTimestamp(),
      expiresAt,
      usedAt: null,
      revoked: false,
    });
    // A flat lookup table keyed by code hash, since a bare code doesn't say
    // which household's invites subcollection to search. Never client-
    // readable (see firestore.rules) -- functions reach it via the Admin SDK.
    tx.set(db.doc(`inviteLookup/${hashCode(code)}`), {
      householdId,
      inviteId: inviteRef.id,
      expiresAt,
    });
  });

  return { code, expiresInDays: INVITE_TTL_MS / 86_400_000 };
});

/**
 * Resolves an invite code to a household so the joining device knows where
 * to post its sealed join announcement. Marks the invite used immediately
 * to prevent two people racing the same code -- this is a bookkeeping
 * lock, not the trust boundary; the trust boundary is the fragment secret
 * the caller must separately have to actually get the household key.
 */
export const redeemInvite = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const code = request.data?.code;
  if (typeof code !== "string") {
    throw new HttpsError("invalid-argument", "code is required");
  }

  const lookupRef = db.doc(`inviteLookup/${hashCode(code)}`);
  const lookup = await lookupRef.get();
  if (!lookup.exists) {
    throw new HttpsError("not-found", "Invite not found or already used");
  }
  const { householdId, inviteId, expiresAt } = lookup.data() as {
    householdId: string;
    inviteId: string;
    expiresAt: number;
  };
  if (Date.now() > expiresAt) {
    throw new HttpsError("deadline-exceeded", "Invite has expired");
  }

  const inviteRef = db.doc(`households/${householdId}/invites/${inviteId}`);
  await db.runTransaction(async (tx) => {
    const invite = await tx.get(inviteRef);
    if (!invite.exists || invite.get("revoked") || invite.get("usedAt")) {
      throw new HttpsError("not-found", "Invite not found or already used");
    }
    tx.update(inviteRef, { usedAt: FieldValue.serverTimestamp(), usedBy: uid });
    tx.delete(lookupRef);
  });

  return { householdId, inviteId };
});
