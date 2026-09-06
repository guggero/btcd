// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/hkdf"
)

const (
	suite = "btcd/walletbackup/v4-experiment/"
)

// taggedHash is BIP340's hash construction with experiment-specific tags.
func taggedHash(label string, parts ...[]byte) [32]byte {
	tag := sha256.Sum256([]byte(suite + label))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	for _, part := range parts {
		h.Write(part)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// epochBytes is the fixed-width encoding used wherever an epoch is hashed.
func epochBytes(epoch uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], epoch)
	return encoded[:]
}

// recipientKeys derives the 16-byte wrap pad w_i and the scalar h_i, binding
// both to the exact header, network, epoch, recipient public key, and
// one-based index. GenerateSharedSecret returns x(e*B) = x(b*E), NOT lnd's
// SHA256(ser_comp(e*B)).
//
// For the two-device profile h_i is the share itself for indexes 1 and 2, and
// the mask of a stored correction for every other index.
func recipientKeys(shared []byte, context [32]byte, recipient []byte,
	index byte) ([wrapSize]byte, btcec.ModNScalar) {

	info := append([]byte(suite+"recipient/"), recipient...)
	info = append(info, index)
	kdf := hkdf.New(sha256.New, shared, context[:], info)
	var material [wrapSize + 32]byte

	// HKDF-SHA256 always supplies this fixed, permitted output length.
	_, _ = io.ReadFull(kdf, material[:])
	defer clear(material[:])
	var wrap [wrapSize]byte
	copy(wrap[:], material[:wrapSize])
	var mask btcec.ModNScalar
	mask.SetByteSlice(material[wrapSize:])
	return wrap, mask
}

// Beacon returns a four-byte discovery hint. Public keys suffice to locate
// backups; this is deliberately not a decryption secret or an authenticity
// check. Network is the genesis hash in wire byte order.
func Beacon(network [32]byte, public [33]byte, epoch uint32) [4]byte {
	digest := taggedHash(
		"beacon", network[:], public[:], epochBytes(epoch),
	)
	var beacon [4]byte
	copy(beacon[:], digest[:4])
	return beacon
}

// randomScalar samples a nonzero scalar by rejection instead of reducing
// random bytes modulo N.
func randomScalar(random io.Reader) (btcec.ModNScalar, error) {
	for {
		var encoded [32]byte
		if _, err := io.ReadFull(random, encoded[:]); err != nil {
			return btcec.ModNScalar{}, err
		}

		var scalar btcec.ModNScalar
		if scalar.SetBytes(&encoded) != 0 || scalar.IsZero() {
			continue
		}

		return scalar, nil
	}
}
