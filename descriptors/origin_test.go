package descriptors

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestOriginResolution checks that historical hardened steps stay in metadata
// while only the suffix is resolved at the selected coordinates.
func TestOriginResolution(t *testing.T) {
	origin := parseValidatedOrigin("01234567/84h/1'/0")
	require.Equal(t, [4]byte{1, 35, 69, 103}, origin.Fingerprint)
	require.Equal(t, []uint32{0x80000054, 0x80000001, 0}, origin.Path)

	// Branch one means child nine, not child one. Wildcard indexes cannot
	// silently cross into hardened derivation.
	steps, err := parseKeyPath("<5;9>/*")
	require.NoError(t, err)
	key := &descKey{steps: steps, origin: origin}
	path, err := key.resolvePath(1, 17)
	require.NoError(t, err)
	require.Equal(t, []uint32{9, 17}, path)
	_, err = key.resolvePath(2, 17)
	require.Error(t, err)
	_, err = key.resolvePath(0, hdkeychain.HardenedKeyStart)
	require.Error(t, err)

	// Exported origins must not offer a writable reference into the parser.
	clone := cloneOrigin(origin)
	clone.Path[0] = 0
	require.Equal(t, uint32(0x80000054), origin.Path[0])
}

// TestDescriptorPrivateSources checks source provenance even when parsing has
// discarded the secret, and when it is nested inside an aggregate expression.
func TestDescriptorPrivateSources(t *testing.T) {
	root, err := hdkeychain.NewMaster(
		make([]byte, 32), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	pub, err := root.Neuter()
	require.NoError(t, err)
	priv, _ := btcec.PrivKeyFromBytes([]byte{1})
	wif, err := btcutil.NewWIF(priv, &chaincfg.MainNetParams, true)
	require.NoError(t, err)

	// Public descriptors remain usable by all existing consumers; rejecting
	// secrets is a consumer policy rather than a new grammar restriction.
	tests := []struct {
		body            string
		private, ranged bool
	}{
		{"wpkh(" + root.String() + ")", true, false},
		{"wpkh(" + wif.String() + ")", true, false},
		{"wpkh(" + pub.String() + "/<5;9>/*)", false, true},
		{
			"tr(musig(" + pub.String() + "," + wif.String() + "))",
			true, false,
		},
		{
			"tr(musig(" + pub.String() + "," + pub.String() + (")/*)"),
			false, true,
		},
	}
	for i, test := range tests {
		descriptor, err := NewDescriptor(test.body)
		require.NoErrorf(t, err, "case %d", i)
		require.Equal(t, test.private, descriptor.HasPrivateKeys())
		require.Equal(t, test.ranged, descriptor.IsRanged())
	}
}
