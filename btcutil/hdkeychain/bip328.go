// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

var (
	// ErrDeriveTweakFromPrivate indicates that tweak-returning public
	// derivation was requested on a private extended key. Neuter the key
	// before calling it.
	ErrDeriveTweakFromPrivate = errors.New(
		"cannot derive a public tweak from a private extended key",
	)
)

// NewMuSig2Key creates the BIP328 synthetic extended public key for an already
// aggregated, untweaked MuSig2 public key. It preserves the full point,
// including its Y parity; callers must not replace it with an x-only-normalized
// point. The result has depth, parent fingerprint and child number zero, the
// BIP328 fixed chain code, and net's public version bytes. It owns its backing
// slices. Nil or invalid keys and nil network parameters return an error.
// Aggregation and signing are deliberately outside this package.
func NewMuSig2Key(pub *btcec.PublicKey, net *chaincfg.Params) (*ExtendedKey,
	error) {

	// A synthetic xpub must commit to a valid full point. Treat nil inputs
	// as errors rather than letting serialization dereference them.
	if pub == nil || !pub.IsOnCurve() {
		return nil, fmt.Errorf("invalid MuSig2 aggregate public key")
	}
	if net == nil {
		return nil, fmt.Errorf("missing network parameters")
	}

	// BIP328 fixes the chain code to SHA256("MuSig2MuSig2MuSig2"). A fresh
	// array per key prevents Zero or caller mutation from affecting others.
	chainCode := sha256.Sum256([]byte("MuSig2MuSig2MuSig2"))
	return NewExtendedKey(
		bytes.Clone(net.HDPublicKeyID[:]), pub.SerializeCompressed(),
		chainCode[:], make([]byte, 4), 0, 0, false,
	), nil
}

// DeriveWithTweak derives an unhardened child of a public extended key and
// returns the exact 32-byte big-endian I_L scalar used in CKDpub. BIP328
// signers apply these scalars in path order as plain, not x-only, MuSig2
// tweaks. It does not aggregate keys or apply Taproot's output-key tweak.
//
// Private parents return ErrDeriveTweakFromPrivate. Otherwise the child and
// errors are identical to Derive, including ErrDeriveHardFromPublic and
// ErrInvalidChild. No indices are skipped automatically. On failure the child
// is nil and the tweak is zero. The returned tweak owns its storage.
func (k *ExtendedKey) DeriveWithTweak(i uint32) (*ExtendedKey, [32]byte,
	error) {

	// Restrict this API to public derivation so it never exposes a tweak
	// computed from private-key material, especially a hardened derivation.
	var tweak [32]byte
	if k.isPrivate {
		return nil, tweak, ErrDeriveTweakFromPrivate
	}
	child, err := k.derive(i, &tweak)
	return child, tweak, err
}
