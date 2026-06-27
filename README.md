# keyrot

A small encrypted secrets vault for the command line. Secrets are versioned, can be
rotated, and every action is written to a hash-chained audit log you can verify.

## How it works

- A passphrase is stretched with **Argon2id** into a key-encryption key (KEK).
- The KEK wraps a random 256-bit data-encryption key (DEK) — envelope encryption.
- Each secret value is sealed with the DEK using **AES-256-GCM**; every write adds a
  new version, so history is preserved.
- Each operation appends an entry to `<vault>.audit`. Entries are chained by SHA-256
  (`hash = sha256(seq || ts || action || target || prev_hash)`), so any edit to a past
  entry breaks the chain and `keyrot verify` reports it.

The vault is a single JSON file; nothing leaves the machine.

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
keyrot history db/password
keyrot ls
keyrot audit
keyrot verify
```

The passphrase is read from `KEYROT_PASSPHRASE`, or prompted if unset. The vault path
comes from `--vault <path>`, `KEYROT_VAULT`, or defaults to `./keyrot.vault`.

## License

MIT
