# Emulator integration checks

These checks use synthetic accounts and placeholder ciphertext against the local
Auth, Firestore and Functions emulators. They require a `demo-` project and reject
non-loopback emulator addresses.

With Node.js 22 or newer, Java 21 or newer and the Firebase CLI installed:

```sh
npm --prefix backend/functions ci
npm --prefix backend/functions run build
npm --prefix backend/emulator-test ci
cd backend
firebase emulators:exec --project demo-spendosaurus --only auth,firestore,functions \
  'node emulator-test/run.mjs'
```

The test reads `FIREBASE_AUTH_EMULATOR_HOST` and `FIRESTORE_EMULATOR_HOST` when
provided by the emulator runner. Set `SPENDOS_FUNCTIONS_EMULATOR_HOST` if the
Functions emulator uses a port other than 5001. No production project, credentials
or existing records are needed.

The scoped gRPC override replaces the Firestore test client's older pinned minor
with a patched 1.x release. The integration run exercises authentication, rules,
household creation, invitations, membership and encrypted-record access through
that client. The real cryptography has its own tests in `crypto/core`.

The test package uses the current client SDK and does not install the Admin SDK;
server-side Admin APIs are supplied by the separate Functions package.
