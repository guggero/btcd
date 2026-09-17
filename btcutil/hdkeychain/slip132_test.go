// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// TestSLIP132Vectors executes all three published Bitcoin vectors, including
// neutering and /0/0 address derivation. Registration is intentionally serial,
// before the package's parallel tests start accessing the global registry.
func TestSLIP132Vectors(t *testing.T) {
	var vectors []struct{ Path, Private, Public, Address string }
	readBIPJSON(t, "testdata/slip132.json", &vectors)
	require.Len(t, vectors, 3)
	require.NoError(t, chaincfg.RegisterSLIP132KeyIDs())

	for _, vector := range vectors {
		t.Run(vector.Path, func(t *testing.T) {
			// A registered SLIP-0132 pair works in both parsers and
			// Neuter preserves the specified public version bytes.
			private, err := NewKeyFromStringStrict(vector.Private)
			require.NoError(t, err)
			public, err := NewKeyFromStringStrict(vector.Public)
			require.NoError(t, err)
			neutered, err := private.Neuter()
			require.NoError(t, err)
			require.Equal(t, vector.Public, neutered.String())
			for _, encoded := range []string{
				vector.Private, vector.Public,
			} {

				legacy, err := NewKeyFromString(encoded)
				require.NoError(t, err)
				require.Equal(t, encoded, legacy.String())
			}

			// CKDpub must agree with neutered CKDpriv and retain
			// the original version throughout the published /0/0
			// path.
			for range 2 {
				private, err = private.Derive(0)
				require.NoError(t, err)
				public, err = public.Derive(0)
				require.NoError(t, err)
				neutered, err = private.Neuter()
				require.NoError(t, err)
				require.Equal(
					t, public.String(), neutered.String(),
				)
				require.True(t, strings.HasPrefix(
					private.String(), vector.Private[:4],
				))
				require.True(t, strings.HasPrefix(
					public.String(), vector.Public[:4],
				))
			}
			pub, err := public.ECPubKey()
			require.NoError(t, err)
			hash := address.Hash160(pub.SerializeCompressed())

			// The caller, not the parser or registry, selects the
			// output type. The published vectors specify these
			// types.
			var output address.Address
			switch vector.Path {
			case "m/44'/0'/0'":
				output, err = address.NewAddressPubKeyHash(
					hash, &chaincfg.MainNetParams,
				)

			case "m/49'/0'/0'":
				redeem := append([]byte{0x00, 0x14}, hash...)
				output, err = address.NewAddressScriptHash(
					redeem, &chaincfg.MainNetParams,
				)

			case "m/84'/0'/0'":
				output, err = address.NewAddressWitnessPubKeyHash(
					hash, &chaincfg.MainNetParams,
				)
			}
			require.NoError(t, err)
			require.NotNil(t, output)
			require.Equal(t, vector.Address, output.EncodeAddress())
		})
	}
}

// TestStrictSLIP132Metadata ensures enabling extra versions does not relax root
// metadata or key-kind checks, while legacy parsing remains permissive.
func TestStrictSLIP132Metadata(t *testing.T) {
	require.NoError(t, chaincfg.RegisterSLIP132KeyIDs())
	params := chaincfg.MainNetParams
	params.HDPrivateKeyID = [4]byte{0x04, 0x9d, 0x78, 0x78}
	params.HDPublicKeyID = [4]byte{0x04, 0x9d, 0x7c, 0xb2}
	for _, kind := range []string{"private", "public"} {
		for _, defect := range []string{
			"fingerprint", "index", "version",
		} {

			t.Run(kind+"/"+defect, func(t *testing.T) {
				// Corrupt one field of a valid synthetic test
				// root. Serialization recalculates the
				// checksum, isolating strict metadata
				// validation from checksum validation.
				key, err := NewMaster(make([]byte, 32), &params)
				require.NoError(t, err)
				if kind == "public" {
					key, err = key.Neuter()
					require.NoError(t, err)
				}
				expected := ErrInvalidRootMetadata
				switch defect {
				case "fingerprint":
					key.parentFP[0] = 1

				case "index":
					key.childNum = 1

				case "version":
					key.version = params.HDPublicKeyID[:]
					if kind == "public" {
						key.version = params.HDPrivateKeyID[:]
					}
					expected = ErrInvalidKeyVersion
				}

				// The same bytes have intentionally different
				// parsing contracts; neither parser silently
				// repairs the key.
				encoded := key.String()
				legacy, err := NewKeyFromString(encoded)
				require.NoError(t, err)
				require.Equal(t, encoded, legacy.String())
				strict, err := NewKeyFromStringStrict(encoded)
				require.ErrorIs(t, err, expected)
				require.Nil(t, strict)
			})
		}
	}
}
