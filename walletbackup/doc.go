// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package walletbackup demonstrates encrypted descriptor recovery using
// secp256k1 ECDH. A descriptor is encrypted to the backup public keys of up to
// five participants. With threshold 1 any participant recovers it; with
// threshold 2 one participant opens a summary and any two recover the
// descriptor. It is an experimental companion to
// docs/bip-opreturn-backup-v4.md, not an assigned BIP or a production wallet.
//
// Encryption does not authenticate the publisher. Anyone with the backup
// public keys can create a new backup. Callers must validate recovered wallet
// policies independently and retain competing backups.
//
// The publisher knows the descriptor and the encryption secrets while
// creating a backup. Confidentiality from a later compromise of its public
// configuration requires erasing this ephemeral state. Go does not guarantee
// erasure of all copies. The underlying btcec ECDH uses variable-time curve
// operations; this package is not a hardware-wallet implementation.
package walletbackup
