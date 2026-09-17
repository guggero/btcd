// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	// ErrHDKeyIDConflict indicates that an existing HD version registration
	// conflicts with a public/private pair required by
	// RegisterSLIP132KeyIDs.
	ErrHDKeyIDConflict = errors.New(
		"conflicting HD key version registration",
	)
)

// RegisterSLIP132KeyIDs registers Bitcoin's mainnet and testnet SLIP-0132
// public/private version pairs: x/y/z/Y/Z and t/u/v/U/V, respectively. It does
// not register other coins, network parameters or address encodings, nor infer
// script types from keys. The existing x/t pairs are included for consistency.
//
// Identical registrations are left unchanged, making repeated calls safe.
// If either version is already used in a different pair or key role, it returns
// an error wrapping ErrHDKeyIDConflict without changing any registrations.
// Like RegisterHDKeyID, call this during startup, before concurrent registry
// lookups or registrations. It is not called automatically by key parsing.
//
// Reference: https://github.com/satoshilabs/slips/blob/master/slip-0132.md
func RegisterSLIP132KeyIDs() error {
	// Keep the published private-to-public mappings together. These are
	// explicit version bytes, not guesses based on Base58 text prefixes.
	pairs := map[[4]byte][4]byte{
		{0x04, 0x88, 0xad, 0xe4}: {0x04, 0x88, 0xb2, 0x1e}, // xprv/xpub
		{0x04, 0x9d, 0x78, 0x78}: {0x04, 0x9d, 0x7c, 0xb2}, // yprv/ypub
		{0x04, 0xb2, 0x43, 0x0c}: {0x04, 0xb2, 0x47, 0x46}, // zprv/zpub
		{0x02, 0x95, 0xb0, 0x05}: {0x02, 0x95, 0xb4, 0x3f}, // Yprv/Ypub
		{0x02, 0xaa, 0x7a, 0x99}: {0x02, 0xaa, 0x7e, 0xd3}, // Zprv/Zpub
		{0x04, 0x35, 0x83, 0x94}: {0x04, 0x35, 0x87, 0xcf}, // tprv/tpub
		{0x04, 0x4a, 0x4e, 0x28}: {0x04, 0x4a, 0x52, 0x62}, // uprv/upub
		{0x04, 0x5f, 0x18, 0xbc}: {0x04, 0x5f, 0x1c, 0xf6}, // vprv/vpub
		{0x02, 0x42, 0x85, 0xb5}: {0x02, 0x42, 0x89, 0xef}, // Uprv/Upub
		{0x02, 0x57, 0x50, 0x48}: {0x02, 0x57, 0x54, 0x83}, // Vprv/Vpub
	}

	// Validate the entire batch before publishing anything. A custom
	// registration must not be overwritten, or acquire an ambiguous kind
	// merely because an application enables these additional versions.
	for private, public := range pairs {
		for registeredPrivate, registeredPublic := range hdPrivToPubKeyIDs {
			if registeredPrivate == private &&
				bytes.Equal(registeredPublic, public[:]) {

				continue
			}
			if registeredPrivate == private ||
				registeredPrivate == public ||
				bytes.Equal(registeredPublic, private[:]) ||
				bytes.Equal(registeredPublic, public[:]) {

				return fmt.Errorf("%w: SLIP-0132 pair %x/%x",
					ErrHDKeyIDConflict, private, public)
			}
		}
	}

	// Existing identical registrations keep their backing storage. New
	// entries own their bytes, independently of this call's local table.
	for private, public := range pairs {
		if _, exists := hdPrivToPubKeyIDs[private]; !exists {
			hdPrivToPubKeyIDs[private] = bytes.Clone(public[:])
		}
	}
	return nil
}
