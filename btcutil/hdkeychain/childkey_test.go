// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestBIP32TweakBoundaries exercises CKDpriv and CKDpub at the zero and group
// order boundaries, using supplied I_L values instead of searching for HMAC
// preimages. Ordinary derivation remains covered by all official BIP32 vectors.
func TestBIP32TweakBoundaries(t *testing.T) {
	t.Parallel()
	var vectors []struct {
		Name, Tweak, Private string
		Invalid              bool
	}
	readBIPJSON(t, "testdata/bip32_tweaks.json", &vectors)
	require.Len(t, vectors, 6)
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			// Parent scalar one makes both cancellation and the
			// expected group sum explicit in the portable fixture.
			private := NewExtendedKey(
				chaincfg.MainNetParams.HDPrivateKeyID[:],
				[]byte{
					1,
				}, make([]byte, 32), make([]byte, 4), 0, 0,
				true,
			)
			public, err := private.Neuter()
			require.NoError(t, err)
			tweak := decodeBIPHex(t, vector.Tweak)
			for _, parent := range []*ExtendedKey{private, public} {
				child, err := parent.deriveChildKey(tweak)
				if vector.Invalid {
					require.ErrorIs(t, err, ErrInvalidChild)
					require.Nil(t, child)
					continue
				}
				require.NoError(t, err)
				expected := decodeBIPHex(t, vector.Private)
				if !parent.IsPrivate() {
					_, pub := btcec.PrivKeyFromBytes(
						expected,
					)
					expected = pub.SerializeCompressed()
				}
				require.Equal(t, expected, child)
			}
		})
	}
}
