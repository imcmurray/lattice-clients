# Security Policy

> **Lattice Clients is experimental and has not been security-audited.** These
> are Flutter clients over the [Lattice framework](https://github.com/imcmurray/lattice);
> all cryptography and transport live there. Do not use this app to protect
> information whose disclosure would harm you.

## Reporting a vulnerability

Please report security issues **privately** — don't open a public issue or PR.

Use GitHub's private vulnerability reporting: on this repository, go to the
**Security** tab → **Report a vulnerability**. That opens a private advisory
visible only to the maintainer.

If a finding is in the cryptography, handshake, or transport, report it against
the [**Lattice**](https://github.com/imcmurray/lattice/security) repository
instead — that's where the security-relevant code lives. Report client-side
issues (identity storage, key handling in the app, the FFI facade, build/CI
supply chain) here.

This is a personal research project, so responses are best-effort with no
guaranteed timeline. A useful report includes what you found, how to reproduce
it, and the impact you believe it has.

## Scope

**In scope for this repo** — client-side handling of secrets and identity: the
age-encrypted identity file and its passphrase in the platform keystore
(`flutter_secure_storage`), the biometric/credential gate (`local_auth`), the
`lattice-mobile` FFI facade and its wire preamble, and the build/release supply
chain (pinned Actions, CI secrets, artifact integrity).

**Out of scope here** — the cryptographic and transport guarantees of the
framework itself (report those against Lattice), metadata privacy, and anything
documented as a limitation in the README.

## Supported versions

Pre-release: only the latest `main` is supported. The wire protocol may change
without notice before a tagged release.
