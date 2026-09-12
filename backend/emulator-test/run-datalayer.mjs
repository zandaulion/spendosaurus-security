// Exercises the REAL web/js/firebase-bundle.js (built from web/src/firebase-entry.js)
// against the emulators -- not a reimplementation like run.mjs, the actual
// production module. Node has no `window`/Capacitor, so a fake native
// plugin is installed globally before import, shaped exactly like
// CryptoPlugin.kt's real methods (same method names, same {field} return
// shapes) so this also acts as a contract check between native-crypto.js
// and the plugin it expects.
//
// This covers one device's full solo path: identity, household creation,
// item/cost CRUD, and realtime sync. The two-device invite/join mechanics
// (createInvite/redeemInvite/join announcements/membership) are already
// covered thoroughly by run.mjs against the same rules and functions;
// firebase-entry.js's createInviteLink/redeemInviteLink/watchPendingJoins
// call the identical collections and fields, just from one process, which
// is why they aren't re-verified with a second simulated device here.

import { randomBytes } from 'node:crypto';

function fakeCryptoPlugin() {
  const identity = { publicKey: null };
  const householdKeys = new Map(); // householdId -> fake key material (just a tag)

  const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
  const unb64 = (s) => Buffer.from(s, 'base64').toString('utf8');

  return {
    hasIdentity: async () => ({ hasIdentity: identity.publicKey !== null }),
    generateIdentity: async () => {
      identity.publicKey = b64(`pubkey-${randomBytes(6).toString('hex')}`);
      return { publicKey: identity.publicKey };
    },
    getPublicKey: async () => ({ publicKey: identity.publicKey }),
    createHouseholdKey: async ({ householdId }) => {
      householdKeys.set(householdId, `key-${householdId}`);
      return { wrappedKeyForSelf: b64(`wrapped(${householdId},${identity.publicKey})`) };
    },
    unsealHouseholdKey: async ({ householdId }) => {
      householdKeys.set(householdId, `key-${householdId}`);
      return {};
    },
    isHouseholdKeyUnlocked: async ({ householdId }) => ({ unlocked: householdKeys.has(householdId) }),
    encryptContent: async ({ householdId, documentPath, plaintextJson }) => {
      if (!householdKeys.has(householdId)) throw new Error(`household key for ${householdId} not unlocked`);
      return { ciphertext: b64(`${documentPath}::${plaintextJson}`) };
    },
    decryptContent: async ({ householdId, documentPath, ciphertext }) => {
      if (!householdKeys.has(householdId)) throw new Error(`household key for ${householdId} not unlocked`);
      const [path, json] = unb64(ciphertext).split('::');
      if (path !== documentPath) throw new Error('path mismatch -- wrong document');
      return { plaintextJson: json };
    }
  };
}

globalThis.window = globalThis;
globalThis.Capacitor = { Plugins: { SpendosaurusCrypto: fakeCryptoPlugin() } };

// Imported from the bundle itself, not a separately-loaded copy of the SDK
// -- a second `firebase/auth` import from this file's own node_modules
// would initialize an unrelated app instance with no signed-in user, since
// the bundle's internal `app`/`auth` aren't reachable from outside it.
const { DataLayer, useEmulators } = await import('../../../web/js/firebase-bundle.js');

let passed = 0, failed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`❌ ${name}\n   ${e.stack || e}`);
    failed++;
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function main() {
  useEmulators();
  await DataLayer.signInForDevelopment();

  let householdId;
  await check('ensureIdentity + createHousehold', async () => {
    await DataLayer.ensureIdentity();
    householdId = await DataLayer.createHousehold();
    assert(typeof householdId === 'string' && householdId.length > 0, 'expected a household id');
  });

  let itemId;
  await check('createItem then watchItems sees it decrypted correctly', async () => {
    itemId = await DataLayer.createItem(householdId, { title: 'Roof repair', estimatedMinor: 340000, category: 'home' });
    const items = await new Promise((resolve, reject) => {
      const unsub = DataLayer.watchItems(householdId, (list) => {
        if (list.length > 0) { unsub(); resolve(list); }
      }, reject);
    });
    assert(items.length === 1, `expected 1 item, got ${items.length}`);
    assert(items[0].title === 'Roof repair', `title mismatch: ${JSON.stringify(items[0])}`);
    assert(items[0].id === itemId, 'id should match the created item');
  });

  await check('updateItem changes what watchItems reports', async () => {
    await DataLayer.updateItem(householdId, itemId, { title: 'Roof repair (revised)', estimatedMinor: 400000, category: 'home' });
    const items = await new Promise((resolve, reject) => {
      const unsub = DataLayer.watchItems(householdId, (list) => {
        if (list[0]?.title === 'Roof repair (revised)') { unsub(); resolve(list); }
      }, reject);
    });
    assert(items[0].estimatedMinor === 400000, 'expected the updated amount');
  });

  await check('addCost then watchCosts sees it decrypted correctly', async () => {
    await DataLayer.addCost(householdId, itemId, { amountMinor: 15000, currency: 'RON', date: '2026-09-12' });
    const costs = await new Promise((resolve, reject) => {
      const unsub = DataLayer.watchCosts(householdId, itemId, (list) => {
        if (list.length > 0) { unsub(); resolve(list); }
      }, reject);
    });
    assert(costs.length === 1, `expected 1 cost, got ${costs.length}`);
    assert(costs[0].amountMinor === 15000, 'cost amount mismatch');
  });

  await check('deleteItem removes it from watchItems', async () => {
    await DataLayer.deleteItem(householdId, itemId);
    const items = await new Promise((resolve, reject) => {
      const unsub = DataLayer.watchItems(householdId, (list) => {
        unsub(); resolve(list);
      }, reject);
    });
    assert(items.length === 0, `expected the item to be gone, got ${items.length}`);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('Test runner crashed:', e);
  process.exit(1);
});
