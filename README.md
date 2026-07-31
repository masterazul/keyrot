# keyrot

[![CI](https://github.com/masterazul/keyrot/actions/workflows/ci.yml/badge.svg)](https://github.com/masterazul/keyrot/actions/workflows/ci.yml)
[![Security](https://github.com/masterazul/keyrot/actions/workflows/security.yml/badge.svg)](https://github.com/masterazul/keyrot/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-2021-orange.svg)

A small encrypted secrets vault for the command line. Secrets are versioned, can be
rotated, and every action is written to a hash-chained audit log you can verify.

## How it works

- A passphrase is stretched with **Argon2id** into a key-encryption key (KEK).
- The KEK wraps a random 256-bit data-encryption key (DEK) — **envelope encryption**, so
  a passphrase change re-wraps one key instead of re-encrypting every secret.
- Each secret value is sealed with the DEK using **AES-256-GCM** under a fresh random
  nonce; every write adds a new version, so history is preserved and rotation is a write.
- Each operation appends an entry to `<vault>.audit`, chained by SHA-256
  (`hash = sha256(seq || ts || action || target || prev_hash)`), so editing or removing an
  entry mid-log breaks the chain and `keyrot verify` reports the exact sequence; an empty or
  missing log is rejected too, since `init` always writes the first entry.
- The vault file is written atomically (temp file + rename), so an interrupted write can
  never leave a half-written, corrupt vault.

Derived keys live in `Zeroizing` buffers and are wiped on drop. The vault is a single JSON
file; nothing ever leaves the machine.

## Build

```
cargo build --release
```

## Use

```
export KEYROT_PASSPHRASE='correct horse battery staple'
keyrot init
keyrot put db/password 's3cr3t'
keyrot get db/password
keyrot rotate db/password --generate     # replace with a fresh random value
keyrot get db/password --version 1        # earlier versions stay retrievable
keyrot history db/password
keyrot ls
keyrot gen 32                             # print a fresh 32-byte secret
keyrot rm db/password
keyrot audit
keyrot verify
```

Full command list is in `keyrot help`. The passphrase is read from `KEYROT_PASSPHRASE`,
or prompted if unset. The vault path comes from `--vault <path>`, `KEYROT_VAULT`, or
defaults to `./keyrot.vault`.

## Threat model

What keyrot is built to withstand, and what it deliberately does not:

**Protects against**
- **Theft of the vault file at rest.** Values are AES-256-GCM sealed under a DEK that is
  itself encrypted; without the passphrase the file is opaque, and GCM's tag rejects any
  tampering with the ciphertext.
- **Offline passphrase guessing.** Argon2id is memory-hard, making brute force costly.
- **Silent history rewriting.** The audit chain is tamper-evident: editing a past action or
  removing an entry mid-log breaks the SHA-256 links, and an empty or missing log is rejected,
  so `keyrot verify` catches it. Truncating the most recent entries is the one case a single
  local file can't prove against — that needs an external anchor (out of scope here).
- **Interrupted writes.** Atomic save means a crash mid-write leaves the previous good
  vault intact, not a corrupt one.

**Out of scope**
- A compromised host that can read process memory or the passphrase env var while keyrot
  runs — decrypted secrets necessarily exist in memory during an operation.
- A weak passphrase. Argon2id raises the cost of guessing; it does not rescue a guessable
  secret.
- The audit log records that an action happened, not an approval workflow — it is evidence,
  not access control.

## License

MIT
