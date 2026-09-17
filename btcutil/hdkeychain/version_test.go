// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestRegisteredKeyVersions checks that stricter BIP32 parsing still supports
// explicitly registered versions rather than hard-coding Bitcoin's xpub/xprv.
func TestRegisteredKeyVersions(t *testing.T) {
	// Registration precedes the parallel tests' lookups. This test itself
	// must remain serial because chaincfg's registry is not synchronized.
	params := chaincfg.MainNetParams
	params.HDPublicKeyID = [4]byte{0xfa, 0xfb, 0xfc, 0xfe}
	params.HDPrivateKeyID = [4]byte{0xfa, 0xfb, 0xfc, 0xfd}
	key, err := NewMaster(make([]byte, 32), &params)
	require.NoError(t, err)

	// Legacy parsing does not need registration. Strict parsing and Neuter
	// use the application-supplied private-to-public version mapping.
	_, err = NewKeyFromString(key.String())
	require.NoError(t, err)
	require.NoError(t, chaincfg.RegisterHDKeyID(
		params.HDPublicKeyID[:], params.HDPrivateKeyID[:],
	))
	public, err := key.Neuter()
	require.NoError(t, err)
	for _, original := range []*ExtendedKey{key, public} {
		decoded, err := NewKeyFromStringStrict(original.String())
		require.NoError(t, err)
		require.Equal(t, original.String(), decoded.String())
		require.Equal(t, original.IsPrivate(), decoded.IsPrivate())
	}
}
