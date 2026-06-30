# M2 — Identity & Control Harness: testing

## What M2 delivers

- **Identity at rest**: `lattice-mobile` generates / recovers a PQ-hybrid identity
  and encrypts the BIP39 mnemonic under a passphrase (age scrypt) to
  `<appSupport>/lattice/identity.age`. The passphrase is a 32-byte random value
  held in the platform keystore (`flutter_secure_storage`), gated by
  `local_auth` (biometric / device credential) where available.
- **Onboarding**: Welcome → Create or Recover → (generate) reveal 24-word phrase
  → confirm 3 words → secure → dashboard. Or recover from a phrase.
- **Dashboard control harness**: fingerprint hero + copyable PeerId, an ONLINE
  power toggle (binds the iroh transport + accepts), a copyable "connect ticket",
  paste-to-connect, a live event console, and a per-peer encrypted send bar.

> Note: a PQ-hybrid ticket carries ML-DSA + ML-KEM public keys (tens of KB), far
> beyond a QR code's ~3 KB ceiling — so ticket exchange is copy/paste text, not
> QR/scan. A multi-frame QR or serverless short-code rendezvous is a future option.

## Fast logic check (no GUI)

The identity round-trip is covered by Rust tests:

```bash
cd flutter/rust && cargo test -p lattice-mobile
# identity_generate_store_load_roundtrip ... ok
# recover_summary_matches_generated ... ok
```

## Linux desktop

Prereq: a running secret service for `flutter_secure_storage`.

```bash
sudo pacman -S --needed libsecret gnome-keyring   # if not already present
cd flutter && flutter run -d linux
```

1. **First run** → Welcome → *Create a new identity* → tap to reveal the phrase →
   *I've saved it* → enter the 3 requested words → lands on the dashboard showing
   your fingerprint + PeerId.
2. Toggle **ONLINE**: the console logs "Online · accepting connections" and the
   mesh background turns teal and pulses. *Share connect ticket* opens the
   copyable ticket text.
3. **Relaunch** the app: you get the **Unlock** screen (Linux has no biometric, so
   it proceeds straight through the keystore) and the **same PeerId** loads —
   confirming persistence.

Note: `local_auth` has no Linux implementation — by design the unlock falls
through to the keystore (graceful fallback), it does not error.

## Two-node P2P test

The app's wire preamble matches the `lattice-net` reference CLI, so the easiest
second peer is the CLI from the Lattice repo:

1. In the app: toggle **ONLINE**, open *Share connect ticket*, copy the text.
2. In `~/Development/Lattice`:
   ```bash
   cargo run -p lattice-chat-example --bin lattice-net -- connect <TICKET>
   ```
3. The app console logs `Secure session up · …`; type in the CLI and it appears
   in the app console as `… » message`; use the app's send bar to reply.

Both ends need outbound internet to reach the n0 relays. This is also the first
real-world exercise of Lattice's relay/holepunch path (untested upstream).

## Android

```bash
flutter devices                 # find your device id
cd flutter && flutter run -d <device-id>
```

- First build cross-compiles the Rust per-ABI via cargo-ndk (slow once).
- Onboarding is identical. On **Unlock**, a biometric / device-credential prompt
  appears if the device has one enrolled.
- Ticket exchange is copy/paste (share the ticket text via any messaging app and
  paste into Connect). Pair a phone against the desktop app (or two phones).

If Gradle complains about the NDK version, install the requested one:
`sdkmanager --list | grep ndk` then `sdkmanager "ndk;<version>"`.

## Reset

To wipe the local identity during testing: delete `<appSupport>/lattice/` and
clear the `lattice_identity_passphrase` keystore entry (re-onboards on next run).
On Linux, `<appSupport>` is `~/.local/share/dev.lattice.lattice_node/`.
