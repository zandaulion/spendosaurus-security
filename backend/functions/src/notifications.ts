import { onDocumentWritten } from "firebase-functions/v2/firestore";
import { db, messaging } from "./admin";

/**
 * Wakes other household members' devices when something changes, without
 * ever knowing what changed. The push payload below is deliberately
 * content-free -- a `data` message carrying only the household id -- because
 * this function has no household key and could not put real content in a
 * notification if it wanted to. The receiving app decrypts the actual
 * change locally and raises the real, detailed notification itself. This is
 * the same pattern Signal/WhatsApp use for E2E-encrypted push.
 */
async function notifyHousehold(householdId: string, excludeUid?: string): Promise<void> {
  const members = await db.collection(`households/${householdId}/members`).get();
  const uids = members.docs.map((d) => d.id).filter((uid) => uid !== excludeUid);
  if (uids.length === 0) return;

  const userDocs = await db.getAll(...uids.map((uid) => db.doc(`users/${uid}`)));
  const tokens = userDocs.flatMap((doc) => (doc.get("pushTokens") as string[] | undefined) ?? []);
  if (tokens.length === 0) return;

  const response = await messaging.sendEachForMulticast({
    tokens,
    data: {
      type: "household_update",
      householdId,
    },
    android: { priority: "high" },
  });

  // TODO(production): prune tokens messaging reports as unregistered.
  if (response.failureCount > 0) {
    console.warn(`household_update push: ${response.failureCount}/${tokens.length} deliveries failed`);
  }
}

export const onItemWritten = onDocumentWritten(
  "households/{householdId}/items/{itemId}",
  async (event) => {
    await notifyHousehold(event.params.householdId);
  }
);

export const onCostWritten = onDocumentWritten(
  "households/{householdId}/items/{itemId}/costs/{costId}",
  async (event) => {
    await notifyHousehold(event.params.householdId);
  }
);
