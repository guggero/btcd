package descriptors

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestDerivedKeyOrigins distinguishes known signing ancestry from global xpub
// eligibility, without changing the permissive descriptor parsing contract.
func TestDerivedKeyOrigins(t *testing.T) {
	master, err := hdkeychain.NewMaster(
		make([]byte, 32), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	root, err := master.Neuter()
	require.NoError(t, err)
	rootPub, err := root.ECPubKey()
	require.NoError(t, err)
	fingerprint := fmt.Sprintf("%x", address.Hash160(
		rootPub.SerializeCompressed(),
	)[:4])
	accountPrivate, err := master.Derive(hdkeychain.HardenedKeyStart + 9)
	require.NoError(t, err)
	account, err := accountPrivate.Neuter()
	require.NoError(t, err)
	unknown, err := account.CloneWithVersion([]byte{1, 2, 3, 4})
	require.NoError(t, err)
	tests := []struct {
		name, key string
		path      []uint32
		xpub      bool
		reason    string
	}{
		{"root", root.String() + "/<5;9>/*", []uint32{9, 7}, true, ""},
		{
			"full origin",
			"[" + fingerprint + "/9h]" + account.String() + ("/<5" +
				";9>/*"),
			[]uint32{
				0x80000009, 9, 7,
			}, true, "",
		},
		{
			"unknown ancestry", account.String() + "/<5;9>/*", nil,
			false, "incomplete_origin",
		},
		{
			"intermediate anchor", "[01234567]" + account.String(),
			nil, false, "incomplete_origin",
		},
		{
			"contradictory child",
			"[" + fingerprint + "/8h]" + account.String(), nil,
			false, "inconsistent_origin",
		},
		{
			"unknown version known origin",
			"[" + fingerprint + "/9h]" + unknown.String(),
			[]uint32{
				0x80000009,
			}, false, "invalid_extended_key",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d, err := NewDescriptor("wpkh(" + test.key + ")")
			require.NoError(t, err)
			branch := uint32(0)
			if d.MultipathLen() == 2 {
				branch = 1
			}
			info, err := d.DerivedInfoAt(branch, 7)
			require.NoError(t, err)
			require.Len(t, info.Keys, 1)
			key := info.Keys[0]
			if test.path == nil {
				require.Nil(t, key.Origin)
			} else {
				require.NotNil(t, key.Origin)
				require.Equal(t, test.path, key.Origin.Path)
				require.Equal(t, fingerprint, fmt.Sprintf(
					"%x", key.Origin.Fingerprint,
				))
			}
			require.Equal(t, test.xpub, len(key.ExtendedKey) == 78)
			require.Equal(t, test.reason, key.XPubOmission)
		})
	}

	// Historical hardened steps are fine; a hardened suffix cannot be
	// derived from the public account, nor can an index enter that range.
	d, err := NewDescriptor("wpkh(" + account.String() + "/7h)")
	require.NoError(t, err)
	_, err = d.DerivedInfoAt(0, 0)
	require.Error(t, err)
}
