# Spendosaurus Security

This is the public, auditable security core for the Spendosaurus Android app: everything that touches an encryption key, and everything on
the server side that decides who can read or write what. It's a separate
repo, on purpose — the app repo is where product code and secrets live;
this is the part we're asking you to trust, so it's the part anyone can
read, build, and check against the running app.

**Start with [`SPEC.md`](./SPEC.md)** for what's actually encrypted, what
isn't, why, and what "we cannot read your data" does and doesn't protect
against.

## What's here

```
crypto/core/      Pure-JVM Kotlin: household/device key management and
                   content encryption, built on Google Tink. No Android
                   dependency, so the cryptography is testable and
                   reviewable on its own -- ./gradlew :crypto:core:test
crypto/android/    Thin adapter: persists a device's private key encrypted
                   under an Android Keystore-backed master key. This is the
                   only module that touches disk.
backend/           Firestore Security Rules and the Cloud Functions that
                   run against this data. No code path here ever
                   constructs a household or device key -- see SPEC.md
                   for how to verify that yourself.
```

The complete Android product repository is private; this repository is the public
entry point for reviewing the cryptography and backend access rules. The separate
[self-hosted PWA](https://github.com/zandaulion/spendosaurus) uses a different data
model and must not be assumed to inherit this Android encryption design.

## Building

Use JDK 17 for the Kotlin JVM toolchain, the included Gradle wrapper, Android SDK
36 for `crypto/android`, and Node.js 22/npm for Cloud Functions. Supply your own
Android SDK path through the environment or ignored local configuration.
Gradle/npm need network access for their public dependencies on first use.

```bash
./gradlew :crypto:core:test          # crypto unit tests, pure JVM
./gradlew :crypto:android:assemble   # Android library module

cd backend/functions
npm ci
npm run build                        # tsc --noEmit-equivalent build to lib/
```

## How this fits into the app

The Android app (private repo, since it also holds product/UI code and
release signing config) depends on `crypto/core` and `crypto/android` as a
git submodule of this repo, and deploys `backend/firestore.rules` and
`backend/functions` from here via `firebase deploy`. This repo is the
source of truth for both; the app repo does not fork or duplicate them.

## Reporting a problem

If you find a way around what SPEC.md claims, or a mismatch between this
code and that document, please follow [SECURITY.md](SECURITY.md) for private reporting. See SPEC.md's roadmap for
where we are on independent verification (reproducible builds, a paid
third-party audit) — we're not there yet, and we say so rather than imply
otherwise.

## License

Apache 2.0 — see [LICENSE](./LICENSE).


## Support and contributions

Use this repository’s Issues for reproducible bugs and focused feature requests. Include the version, relevant runtime/browser, expected behavior and a minimal synthetic example. Remove credentials, personal records, device identifiers and deployment-specific values before sharing logs or screenshots.

Run `./gradlew :crypto:core:test` for cryptography changes and `npm ci && npm run build` from `backend/functions` for backend changes. Do not test against real households or production Firebase projects.

Keep changes focused and update the affected documentation. Security-sensitive reports should follow [SECURITY.md](SECURITY.md).
