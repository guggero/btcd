// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain

import "github.com/btcsuite/btcd/btcec/v2"

// deriveChildKey applies the 32-byte I_L from CKD's HMAC to the parent key.
// Keeping the group arithmetic separate makes the otherwise infeasible zero
// and infinity boundary cases directly testable without replacing HMAC.
func (k *ExtendedKey) deriveChildKey(il []byte) ([]byte, error) {
	// BIP32 rejects I_L >= n, but permits a zero tweak. Only the final
	// child scalar or point must be nonzero. Callers handle invalid child
	// indices; this arithmetic never silently advances to a different
	// index.
	var ilNum btcec.ModNScalar
	if overflow := ilNum.SetByteSlice(il); overflow {
		return nil, ErrInvalidChild
	}

	// The algorithm used to derive the child key depends on whether or not
	// a private or public child is being derived.
	//
	// For private children:
	//   childKey = parse256(Il) + parentKey
	//
	// For public children:
	//   childKey = serP(point(parse256(Il)) + parentKey)
	var childKey []byte
	if k.isPrivate {
		// Add the parent private key to the intermediate private key to
		// derive the final child key, for either hardened or normal
		// CKD.
		//
		// childKey = parse256(Il) + parentKey
		var keyNum btcec.ModNScalar
		if overflow := keyNum.SetByteSlice(k.key); overflow {
			return nil, ErrInvalidChild
		}

		ilNum.Add(&keyNum)
		if ilNum.IsZero() {
			return nil, ErrInvalidChild
		}
		childKeyBytes := ilNum.Bytes()
		childKey = childKeyBytes[:]

		// Retain the historical minimal internal scalar encoding.
		// Serialization and subsequent CKD pad it back to 32 bytes.
		for len(childKey) > 0 && childKey[0] == 0x00 {
			childKey = childKey[1:]
		}
	} else {
		// A zero intermediate point simply leaves the parent unchanged.
		// Checking infinity here would incorrectly reject a zero I_L.
		var ilJ btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&ilNum, &ilJ)

		// Convert the serialized compressed parent public key into X
		// and Y coordinates so it can be added to the intermediate
		// public key.
		pubKey, err := btcec.ParsePubKey(k.key)
		if err != nil {
			return nil, err
		}

		// Convert the public key to jacobian coordinates, as that's
		// what our main add/double methods use.
		var pubKeyJ btcec.JacobianPoint
		pubKey.AsJacobian(&pubKeyJ)

		// Add the intermediate public key to the parent public key to
		// derive the final child key.
		//
		// childKey = serP(point(parse256(Il)) + parentKey)
		var childKeyPubJ btcec.JacobianPoint
		btcec.AddNonConst(&ilJ, &pubKeyJ, &childKeyPubJ)
		if childKeyPubJ.Z.IsZero() {
			return nil, ErrInvalidChild
		}

		// Convert the new child public key back to affine coordinates
		// so we can serialize it in compressed format.
		childKeyPubJ.ToAffine()
		childKeyPub := btcec.NewPublicKey(
			&childKeyPubJ.X, &childKeyPubJ.Y,
		)

		childKey = childKeyPub.SerializeCompressed()
	}

	return childKey, nil
}
