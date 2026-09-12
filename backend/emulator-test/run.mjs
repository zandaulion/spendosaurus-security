// Integration test against the Firebase Local Emulator Suite -- exercises
// firestore.rules and the Cloud Functions in ../functions exactly the way
// the real Android app will, using the same client SDK calls. No Blaze
// billing and no live Google Sign-In needed: the emulators don't require
// either.
//
// The one thing this can't exercise is the real crypto module (Kotlin/
// Android-only) -- everywhere the real app would call NativeCrypto, this
// uses a clearly-labeled FAKE_CRYPTO stand-in that produces distinguishable
// placeholder strings instead of real ciphertext. That's a deliberate
// boundary: the crypto module already has its own 12 passing unit tests in
// spendosaurus-security/crypto/core; what THIS test verifies is everything
// around it -- rules enforcement, function correctness, the household
// create/invite/join data flow -- independent of that.

import { initializeApp } from 'firebase/app';
import {
  getAuth, connectAuthEmulator, signInAnonymously, signOut
} from 'firebase/auth';
import {
  getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, getDocs,
  updateDoc, deleteDoc, collection, serverTimestamp
} from 'firebase/firestore';
import { getFunctions, connectFunctionsEmulator, httpsCallable } from 'firebase/functions';

const CONFIG = {
  apiKey: 'demo-key',
  authDomain: 'spendosaurus-app.firebaseapp.com',
  projectId: 'spendosaurus-app',
  storageBucket: 'spendosaurus-app.firebasestorage.app',
  messagingSenderId: '255031619343',
  appId: '1:255031619343:web:749a038497cbd04b17987a'
};

const FAKE_CRYPTO = {
  publicKey: (label) => `FAKE-PUBKEY(${label})`,
  wrap: (label, householdId) => `FAKE-WRAPPED(${label},${householdId})`,
  encrypt: (label, plaintext) => `FAKE-CIPHERTEXT(${label}:${plaintext})`
};

let passed = 0;
let failed = 0;

async function check(name, fn) {
  try {
    await fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`❌ ${name}\n   ${e.message || e}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function assertDenied(promise, message) {
  try {
    await promise;
  } catch (e) {
    if (e.code === 'permission-denied' || /PERMISSION_DENIED/i.test(e.message || '')) return;
    throw new Error(`${message} -- rejected for the wrong reason: ${e.message}`);
  }
  throw new Error(`${message} -- expected permission-denied, but it succeeded`);
}

function newClient() {
  // Each "device" gets its own app instance so their auth states don't clash.
  const app = initializeApp(CONFIG, `client-${Math.random().toString(36).slice(2)}`);
  const auth = getAuth(app);
  const db = getFirestore(app);
  const functions = getFunctions(app);
  connectAuthEmulator(auth, 'http://127.0.0.1:9099', { disableWarnings: true });
  connectFirestoreEmulator(db, '127.0.0.1', 8080);
  connectFunctionsEmulator(functions, '127.0.0.1', 5001);
  return { auth, db, functions };
}

async function main() {
  const alice = newClient();
  const bob = newClient();

  await (await signInAnonymously(alice.auth));
  await (await signInAnonymously(bob.auth));
  const aliceUid = alice.auth.currentUser.uid;
  const bobUid = bob.auth.currentUser.uid;

  await check('users/{uid} public key: a user can write their own, another user can read it', async () => {
    await setDoc(doc(alice.db, `users/${aliceUid}`), { publicKey: FAKE_CRYPTO.publicKey('alice') });
    const seenByBob = await getDoc(doc(bob.db, `users/${aliceUid}`));
    assert(seenByBob.exists(), 'bob should be able to read alice\'s public key doc');
  });

  await check('users/{uid} public key: a user cannot write someone else\'s', async () => {
    await assertDenied(
      setDoc(doc(bob.db, `users/${aliceUid}`), { publicKey: 'evil' }),
      'bob writing to alice\'s user doc should be denied'
    );
  });

  let householdId;
  await check('createHousehold: client-generated id, sealed key stored, household readable by its creator', async () => {
    householdId = doc(collection(alice.db, 'households')).id;
    const wrappedKey = FAKE_CRYPTO.wrap('alice', householdId);
    const createHousehold = httpsCallable(alice.functions, 'createHousehold');
    const result = await createHousehold({ householdId, wrappedKey });
    assert(result.data.householdId === householdId, 'function should echo back the same id');

    const memberDoc = await getDoc(doc(alice.db, `households/${householdId}/members/${aliceUid}`));
    assert(memberDoc.exists(), 'creator should have a members/{uid} doc');
    assert(memberDoc.data().wrappedKey === wrappedKey, 'wrapped key should be stored as-is (opaque to the server)');
  });

  await check('createHousehold: colliding id is rejected, not silently overwritten', async () => {
    const createHousehold = httpsCallable(alice.functions, 'createHousehold');
    await assertRejectsWith(
      () => createHousehold({ householdId, wrappedKey: 'anything' }),
      'already-exists'
    );
  });

  let itemPath;
  await check('a member can write and read household content (ciphertext, opaque to us)', async () => {
    const itemRef = doc(collection(alice.db, `households/${householdId}/items`));
    itemPath = itemRef.path;
    await setDoc(itemRef, {
      ciphertext: FAKE_CRYPTO.encrypt('alice', JSON.stringify({ title: 'Roof repair', estimatedMinor: 340000 })),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    });
    const readBack = await getDoc(itemRef);
    assert(readBack.exists(), 'alice should be able to read the item back');
  });

  await check('a non-member cannot read household items', async () => {
    await assertDenied(
      getDocs(collection(bob.db, `households/${householdId}/items`)),
      'bob (not yet a member) reading items should be denied'
    );
  });

  await check('a non-member cannot write household items either', async () => {
    await assertDenied(
      setDoc(doc(collection(bob.db, `households/${householdId}/items`)), { ciphertext: 'evil' }),
      'bob (not yet a member) writing an item should be denied'
    );
  });

  let inviteCode;
  await check('createInvite: a member can create one, a non-member cannot', async () => {
    const createInvite = httpsCallable(alice.functions, 'createInvite');
    const result = await createInvite({ householdId });
    inviteCode = result.data.code;
    assert(typeof inviteCode === 'string' && inviteCode.length > 0, 'expected an invite code');

    const createInviteAsBob = httpsCallable(bob.functions, 'createInvite');
    await assertRejectsWith(() => createInviteAsBob({ householdId }), 'permission-denied');
  });

  await check('redeemInvite: resolves the code to the right household, exactly once', async () => {
    const redeemInvite = httpsCallable(bob.functions, 'redeemInvite');
    const result = await redeemInvite({ code: inviteCode });
    assert(result.data.householdId === householdId, 'redeeming should resolve to the household the code was made for');

    await assertRejectsWith(() => redeemInvite({ code: inviteCode }), 'not-found');
  });

  await check('join announcement: bob (pre-membership) can post one; alice completes the join', async () => {
    const announcementRef = doc(collection(bob.db, `households/${householdId}/joinAnnouncements`));
    await setDoc(announcementRef, { ciphertext: FAKE_CRYPTO.encrypt('bob-pubkey', 'announcement') });

    // Alice's device "processes" it: seals the household key for bob and
    // writes his members/{uid} doc. In the real app this happens after
    // InvitePairing.openJoinAnnouncement() authenticates bob's public key.
    const wrappedForBob = FAKE_CRYPTO.wrap('bob', householdId);
    await setDoc(doc(alice.db, `households/${householdId}/members/${bobUid}`), {
      wrappedKey: wrappedForBob,
      role: 'member',
      joinedAt: serverTimestamp()
    });
    await deleteDoc(announcementRef);
  });

  await check('bob is now a member and can read the household\'s content', async () => {
    const readBack = await getDoc(doc(bob.db, itemPath));
    assert(readBack.exists(), 'bob should now be able to read the item alice created before he joined');
    assert(readBack.data().ciphertext.includes('alice'), 'content is still alice\'s ciphertext, unmodified');
  });

  await check('audit log: an entry must be attributed to its real author', async () => {
    const auditRef = doc(collection(bob.db, `households/${householdId}/auditLog`));
    await assertDenied(
      setDoc(auditRef, { action: 'item_added', summary: 'x', actorUid: aliceUid, createdAt: serverTimestamp() }),
      'bob writing an audit entry attributed to alice should be denied'
    );
    await setDoc(auditRef, { action: 'item_added', summary: 'x', actorUid: bobUid, createdAt: serverTimestamp() });
  });

  await check('audit log is append-only: no update, no delete, even by a member', async () => {
    const entries = await getDocs(collection(bob.db, `households/${householdId}/auditLog`));
    const first = entries.docs[0].ref;
    await assertDenied(updateDoc(first, { summary: 'edited' }), 'updating an audit entry should be denied');
    await assertDenied(deleteDoc(first), 'deleting an audit entry should be denied');
  });

  await Promise.all([signOut(alice.auth), signOut(bob.auth)]);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

async function assertRejectsWith(fn, expectedCode) {
  try {
    await fn();
  } catch (e) {
    if (e.code && e.code.endsWith(expectedCode)) return;
    throw new Error(`expected error code '${expectedCode}', got '${e.code}': ${e.message}`);
  }
  throw new Error(`expected a '${expectedCode}' error, but the call succeeded`);
}

main().catch((e) => {
  console.error('Test runner crashed:', e);
  process.exit(1);
});
