// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsHDPublicKeyID checks built-in versions and registration replacement.
// Registration is intentionally serial because the registry is initialized
// before use, not mutated concurrently with lookups.
func TestIsHDPublicKeyID(t *testing.T) {
	// Public lookup must not confuse private versions with public versions
	// or accept prefixes of a valid version.
	for _, params := range []*Params{
		&MainNetParams, &TestNet3Params, &TestNet4Params,
		&RegressionNetParams, &SimNetParams,
	} {

		require.True(t, IsHDPublicKeyID(params.HDPublicKeyID[:]))
		require.False(t, IsHDPublicKeyID(params.HDPrivateKeyID[:]))
	}
	require.False(t, IsHDPublicKeyID(nil))
	require.False(t, IsHDPublicKeyID([]byte{1, 2, 3}))
	require.False(t, IsHDPublicKeyID([]byte{1, 2, 3, 4, 5}))

	// Replacing a mapping must remove its old public version from lookup.
	// Restore the registry afterward so this test cannot affect others.
	private := [4]byte{0xfa, 0xfb, 0xfc, 0xfd}
	public := []byte{0xfa, 0xfb, 0xfc, 0xfe}
	previous, existed := hdPrivToPubKeyIDs[private]
	t.Cleanup(func() {
		if existed {
			hdPrivToPubKeyIDs[private] = previous
		} else {
			delete(hdPrivToPubKeyIDs, private)
		}
	})
	require.NoError(t, RegisterHDKeyID(public, private[:]))
	require.True(t, IsHDPublicKeyID(public))
	require.NoError(t, RegisterHDKeyID(
		MainNetParams.HDPublicKeyID[:], private[:],
	))
	require.False(t, IsHDPublicKeyID(public))
}
