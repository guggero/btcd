// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"encoding/hex"
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRegisterSLIP132KeyIDs verifies every Bitcoin version pair and repeatable
// registration. Registry mutation is serial and restored before other tests.
func TestRegisterSLIP132KeyIDs(t *testing.T) {
	original := hdPrivToPubKeyIDs
	hdPrivToPubKeyIDs = maps.Clone(original)
	t.Cleanup(func() { hdPrivToPubKeyIDs = original })

	// Include an unrelated registration to ensure the helper only adds
	// supported pairs and preserves application-specific mappings.
	customPrivate := [4]byte{0xfa, 0xfb, 0xfc, 0xfd}
	customPublic := []byte{0xfa, 0xfb, 0xfc, 0xfe}
	require.NoError(t, RegisterHDKeyID(customPublic, customPrivate[:]))
	require.NoError(t, RegisterSLIP132KeyIDs())
	registered := maps.Clone(hdPrivToPubKeyIDs)
	require.NoError(t, RegisterSLIP132KeyIDs())
	require.Equal(t, registered, hdPrivToPubKeyIDs)
	require.Equal(t, customPublic, hdPrivToPubKeyIDs[customPrivate])

	// Independently transcribed from the Bitcoin mainnet/testnet rows of
	// SLIP-0132. Case matters for the single-signature and multisig pairs.
	for _, pair := range []struct{ name, private, public string }{
		{"x", "0488ade4", "0488b21e"},
		{"y", "049d7878", "049d7cb2"},
		{"z", "04b2430c", "04b24746"},
		{"Y", "0295b005", "0295b43f"},
		{"Z", "02aa7a99", "02aa7ed3"},
		{"t", "04358394", "043587cf"},
		{"u", "044a4e28", "044a5262"},
		{"v", "045f18bc", "045f1cf6"},
		{"U", "024285b5", "024289ef"},
		{"V", "02575048", "02575483"},
	} {

		t.Run(pair.name, func(t *testing.T) {
			private, err := hex.DecodeString(pair.private)
			require.NoError(t, err)
			public, err := hex.DecodeString(pair.public)
			require.NoError(t, err)
			actual, err := HDPrivateKeyToPublicKeyID(private)
			require.NoError(t, err)
			require.Equal(t, public, actual)
			require.True(t, IsHDPublicKeyID(public))
			require.False(t, IsHDPublicKeyID(private))
		})
	}
}

// TestRegisterSLIP132Conflicts checks each possible version collision and the
// all-or-nothing guarantee. A failure involving any pair must leave every other
// mapping untouched.
func TestRegisterSLIP132Conflicts(t *testing.T) {
	original := hdPrivToPubKeyIDs
	t.Cleanup(func() { hdPrivToPubKeyIDs = original })
	private := [4]byte{0x02, 0x57, 0x50, 0x48}
	public := [4]byte{0x02, 0x57, 0x54, 0x83}
	custom := [4]byte{0xfa, 0xfb, 0xfc, 0xfd}
	for _, test := range []struct {
		name            string
		private, public [4]byte
	}{
		{"different public version", private, custom},
		{"different private version", custom, public},
		{"private used as public", custom, private},
		{"public used as private", public, custom},
	} {

		t.Run(test.name, func(t *testing.T) {
			// Start with one conflicting mapping and no other
			// pairs. Equality afterward catches partial
			// registration too.
			hdPrivToPubKeyIDs = map[[4]byte][]byte{
				test.private: test.public[:],
			}
			before := maps.Clone(hdPrivToPubKeyIDs)
			require.ErrorIs(
				t, RegisterSLIP132KeyIDs(), ErrHDKeyIDConflict,
			)
			require.Equal(t, before, hdPrivToPubKeyIDs)
		})
	}
}
