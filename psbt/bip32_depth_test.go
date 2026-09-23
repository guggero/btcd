package psbt

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestReadXPubDepthBoundary checks path lengths beyond the uint8 multiplication
// boundary and at BIP32's maximum depth. Valid deep global origins must
// roundtrip.
func TestReadXPubDepthBoundary(t *testing.T) {
	_, pub := btcec.PrivKeyFromBytes([]byte{1})
	for _, depth := range []uint8{0, 62, 63, 64, 254, 255} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			key := hdkeychain.NewExtendedKey(
				chaincfg.MainNetParams.HDPublicKeyID[:],
				pub.SerializeCompressed(), make([]byte, 32),
				make([]byte, 4), depth, 0, false,
			)
			path := make([]uint32, int(depth))
			encoded := SerializeBIP32Derivation(0x67452301, path)
			result, err := ReadXPub(EncodeExtendedKey(key), encoded)
			require.NoError(t, err)
			require.Equal(t, 0x67452301, int(
				result.MasterKeyFingerprint,
			))
			require.Len(t, result.Bip32Path, int(depth))

			// The fix must not weaken the depth/path-count
			// agreement.
			_, err = ReadXPub(EncodeExtendedKey(key), append(
				encoded, 0, 0, 0, 0,
			))
			require.Error(t, err)
		})
	}
}
