// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// scalarShare is a point (x, y) on the secret line. Zero is forbidden as an
// index because P(0) is the secret, but zero is a valid share value.
type scalarShare struct {
	index byte
	value btcec.ModNScalar
}

// lineShare evaluates the line through (1, first) and (2, second) at index:
// P(i) = first + (i-1)*(second-first). The line is defined by two derived
// values instead of being sampled, so those two participants need no stored
// share. The caller must reject first == second, which makes the line
// constant.
func lineShare(first, second *btcec.ModNScalar, index byte) btcec.ModNScalar {
	var slope, steps btcec.ModNScalar
	slope.Set(first).Negate().Add(second)
	one := new(btcec.ModNScalar).SetInt(1)
	steps.SetInt(uint32(index)).Add(one.Negate())
	slope.Mul(&steps).Add(first)
	steps.Zero()
	return slope
}

// combine interpolates P(0). It cannot detect insufficient shares or a
// dishonest participant: a threshold check and payload AEAD do that above it.
func combine(shares []scalarShare) (btcec.ModNScalar, error) {
	if len(shares) == 0 || len(shares) > MaxParticipants {
		return btcec.ModNScalar{}, fmt.Errorf("invalid share count")
	}

	var seen [MaxParticipants + 1]bool
	for _, share := range shares {
		if share.index == 0 || share.index > MaxParticipants ||
			seen[share.index] {

			return btcec.ModNScalar{}, fmt.Errorf("invalid or " +
				"duplicate share index")
		}
		seen[share.index] = true
	}

	var secret btcec.ModNScalar
	for i := range shares {
		var numerator, denominator, xi btcec.ModNScalar
		numerator.SetInt(1)
		denominator.SetInt(1)
		xi.SetInt(uint32(shares[i].index))
		xi.Negate()
		for j := range shares {
			if i == j {
				continue
			}

			// lambda_i(0) = product_{j != i} x_j / (x_j - x_i).
			var xj btcec.ModNScalar
			xj.SetInt(uint32(shares[j].index))
			numerator.Mul(&xj)
			denominator.Mul(xj.Add(&xi))
		}

		// Only public indexes enter this variable-time inversion.
		denominator.InverseNonConst()
		numerator.Mul(&denominator).Mul(&shares[i].value)
		secret.Add(&numerator)
	}

	return secret, nil
}
