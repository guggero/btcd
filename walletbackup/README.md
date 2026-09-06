# Wallet backup cryptography experiment

A descriptor is encrypted to the backup public keys of up to five signing
devices. With threshold 1, any one device recovers it. With threshold 2, one
device opens a small summary and any two recover the descriptor.
[`docs/bip-opreturn-backup-v4.md`](../docs/bip-opreturn-backup-v4.md) contains
the exact wire format, the publish and recovery sequences, and the security
limits. [`docs/bip-opreturn-backup-v3.md`](../docs/bip-opreturn-backup-v3.md)
holds the review of v2 that both versions build on.

Start with the runnable example:

```sh
go test ./walletbackup -run '^Example$' -v
go test ./walletbackup -run 'TestV2|TestShamirExplanation|TestPublicKeysCanForge' -v
go test ./walletbackup
```

The example derives separate backup and spending keys from three BIP32 test
seeds and encrypts a 2-of-3 descriptor using only public configuration. It
recovers once with a single device and once with devices one and three. The
test path `m/100000'/0'` is not a proposed BIP assignment. All example seeds
are public.

Read in this order:

| File | What it demonstrates |
| --- | --- |
| [`example_test.go`](example_test.go) | Seed → public configuration → single-device recovery, and summary → two-device recovery |
| [`shamir.go`](shamir.go) | The line through two derived shares, Lagrange interpolation |
| [`crypto.go`](crypto.go) | Raw-x ECDH key derivation, transcript/recipient binding, beacon generation |
| [`backup.go`](backup.go) | Public-key-only publishing, both profiles, bounded parsing, contribution binding |
| [`payload.go`](payload.go) | Binary extended keys, DEFLATE with the preset dictionary, private-key rejection |
| [`explanation_test.go`](explanation_test.go) | V2 key-recovery attack, small-number share example, forgery and GCS discovery |
| [`backup_test.go`](backup_test.go) | All subsets of all shapes, layout and format byte, tampering and vectors |
| [`payload_test.go`](payload_test.go) | Dictionary hash, round trips, malformed payloads |
| [`testdata/vectors.json`](testdata/vectors.json) | Complete 1-of-1, 1-of-3, 2-of-2, 2-of-3 and 2-of-5 vectors with intermediate secrets |

The production-facing `Seal` entry point always uses `crypto/rand`. Deterministic
entropy injection exists only in an unexported helper for tests. Each JSON
vector publishes its complete entropy input, ECDH outputs, masks, shares,
keys, header, ciphertexts and envelope. They are **test secrets**.

The vectors originate in an independent Python implementation, using Python
integer arithmetic, `zlib`, and `cryptography` for secp256k1 ECDH, HKDF and
AEAD. Go tests compare the complete byte streams and intermediate values, and
decode the payloads that `zlib` compressed; Python is not needed to run them.
Go's DEFLATE output differs from `zlib`'s, which the format permits: a reader
only inflates. To regenerate with Python and `cryptography` installed:

```sh
python3 walletbackup/testdata/generate_vectors.py
```

This is experimental code, not a production recovery product or an assigned
BIP implementation.

* The descriptor is treated as a string. It is not parsed or validated.
  Extended private keys and WIF keys are rejected by pattern only.
* There is no compact-filter server or client, transaction publication,
  hardware transport, share-exchange protocol, or sender approval.
* The format exposes its version, participant count and threshold. Public keys
  permit locating and forging backups, but do not supply decryption secrets.
* Temporary publisher secrets must be discarded; neither Go memory erasure nor
  constant-time hardware ECDH is provided here.

Choosing between `Threshold: 1` and `Threshold: 2` is an application privacy
decision. Test both failure and recovery before relying on any eventual
wallet integration.
