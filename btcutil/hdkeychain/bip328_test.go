// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// readBIPJSON loads a complete, pinned BIP vector file and rejects unknown
// fields so schema changes cannot silently stop exercising vector contents.
func readBIPJSON(t *testing.T, path string, target any) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(target))
}

// decodeBIPHex decodes fixture bytes without hiding malformed test inputs.
func decodeBIPHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

// TestBIP328Vectors checks every official synthetic xpub, including the odd-Y
// aggregate key that would change if its parity were discarded prematurely.
func TestBIP328Vectors(t *testing.T) {
	t.Parallel()
	var vectors []struct {
		AggregatePubkey string   `json:"aggregate_pubkey"`
		Keys            []string `json:"keys"`
		Xpub            string   `json:"xpub"`
	}
	readBIPJSON(t, "testdata/bip328.json", &vectors)
	require.Len(t, vectors, 3)
	for _, vector := range vectors {
		t.Run(vector.AggregatePubkey, func(t *testing.T) {
			// Aggregation belongs to the MuSig2 package. This suite
			// starts with the BIP's full aggregate point and tests
			// construction and derivation without importing musig2.
			pub, err := btcec.ParsePubKey(decodeBIPHex(
				t, vector.AggregatePubkey,
			))
			require.NoError(t, err)
			key, err := NewMuSig2Key(pub, &chaincfg.MainNetParams)
			require.NoError(t, err)
			require.Equal(t, vector.Xpub, key.String())
			require.False(t, key.IsPrivate())
			require.Equal(
				t,
				decodeBIPHex(t, "868087ca02a6f974c4598924c36b57762d32cb457171"+
					"67e300622c7167e38965"), key.ChainCode(),
			)

			// The constructor must not leave shared mutable chain
			// code storage between synthetic roots.
			other, err := NewMuSig2Key(pub, &chaincfg.MainNetParams)
			require.NoError(t, err)
			other.Zero()
			require.Equal(t, vector.Xpub, key.String())
			for _, index := range []uint32{
				0, 1, 2, HardenedKeyStart - 1,
			} {

				child, tweak, err := key.DeriveWithTweak(index)
				require.NoError(t, err)
				ordinary, err := key.Derive(index)
				require.NoError(t, err)
				require.Equal(
					t, ordinary.String(), child.String(),
				)
				checkPublicTweak(t, key, child, index, tweak)
				key = child
			}
		})
	}
}

// checkPublicTweak independently computes CKDpub's HMAC and verifies the group
// equation, so two public APIs sharing a bug cannot validate each other alone.
func checkPublicTweak(t *testing.T, parent, child *ExtendedKey, index uint32,
	tweak [32]byte) {

	t.Helper()
	pub, err := parent.ECPubKey()
	require.NoError(t, err)
	data := make([]byte, 37)
	copy(data, pub.SerializeCompressed())
	binary.BigEndian.PutUint32(data[33:], index)
	mac := hmac.New(sha512.New, parent.ChainCode())
	_, err = mac.Write(data)
	require.NoError(t, err)
	digest := mac.Sum(nil)
	require.Equal(t, digest[:32], tweak[:])
	require.Equal(t, digest[32:], child.ChainCode())

	// BIP328 uses ordinary addition, without an even-Y normalization of
	// the parent. Test the actual child point as well as serialized xpubs.
	var scalar btcec.ModNScalar
	require.False(t, scalar.SetByteSlice(tweak[:]))
	var original, delta, result btcec.JacobianPoint
	pub.AsJacobian(&original)
	btcec.ScalarBaseMultNonConst(&scalar, &delta)
	btcec.AddNonConst(&original, &delta, &result)
	result.ToAffine()
	expected := btcec.NewPublicKey(&result.X, &result.Y)
	got, err := child.ECPubKey()
	require.NoError(t, err)
	require.True(t, expected.IsEqual(got))
}

// TestBIP328Errors checks public-only derivation and constructor validation.
func TestBIP328Errors(t *testing.T) {
	t.Parallel()
	_, pub := btcec.PrivKeyFromBytes([]byte{1})
	_, err := NewMuSig2Key(nil, &chaincfg.MainNetParams)
	require.Error(t, err)
	_, err = NewMuSig2Key(pub, nil)
	require.Error(t, err)
	_, err = NewMuSig2Key(new(btcec.PublicKey), &chaincfg.MainNetParams)
	require.Error(t, err)

	// Failure must not return a partially computed tweak or child. Also
	// check the existing maximum-depth rule, which the new API must retain.
	key, err := NewMuSig2Key(pub, &chaincfg.MainNetParams)
	require.NoError(t, err)
	child, tweak, err := key.DeriveWithTweak(HardenedKeyStart)
	require.ErrorIs(t, err, ErrDeriveHardFromPublic)
	require.Nil(t, child)
	require.Zero(t, tweak)
	key.depth = 255
	child, tweak, err = key.DeriveWithTweak(0)
	require.ErrorIs(t, err, ErrDeriveBeyondMaxDepth)
	require.Nil(t, child)
	require.Zero(t, tweak)
	private, err := NewMaster(make([]byte, 32), &chaincfg.MainNetParams)
	require.NoError(t, err)
	child, tweak, err = private.DeriveWithTweak(0)
	require.ErrorIs(t, err, ErrDeriveTweakFromPrivate)
	require.Nil(t, child)
	require.Zero(t, tweak)
}

// TestBIP32JSONVectors executes all five official vector groups. Public steps
// additionally exercise DeriveWithTweak, while hardened steps retain Derive.
func TestBIP32JSONVectors(t *testing.T) {
	t.Parallel()
	var vectors struct {
		Valid   []struct{ Seed, Path, Xpub, Xprv string }
		Invalid []struct{ Key, Reason string }
	}
	readBIPJSON(t, "testdata/bip32.json", &vectors)
	require.Len(t, vectors.Valid, 17)
	require.Len(t, vectors.Invalid, 16)
	for _, vector := range vectors.Valid {
		t.Run(vector.Seed[:8]+"/"+vector.Path, func(t *testing.T) {
			key, err := NewMaster(
				decodeBIPHex(t, vector.Seed),
				&chaincfg.MainNetParams,
			)
			require.NoError(t, err)
			for _, step := range strings.Split(
				vector.Path, "/",
			)[1:] {

				index, err := strconv.ParseUint(
					strings.TrimSuffix(step, "'"), 10, 32,
				)
				require.NoError(t, err)
				hardened := strings.HasSuffix(step, "'")
				if hardened {
					index += HardenedKeyStart
				}
				parent, err := key.Neuter()
				require.NoError(t, err)
				key, err = key.Derive(uint32(index))
				require.NoError(t, err)
				if !hardened {
					child, tweak, err := parent.DeriveWithTweak(uint32(index))
					require.NoError(t, err)
					neutered, err := key.Neuter()
					require.NoError(t, err)
					require.Equal(
						t, neutered.String(),
						child.String(),
					)
					checkPublicTweak(
						t, parent, child, uint32(index),
						tweak,
					)
				}
			}
			require.Equal(t, vector.Xprv, key.String())
			pub, err := key.Neuter()
			require.NoError(t, err)
			require.Equal(t, vector.Xpub, pub.String())
		})
	}

	// The existing general-purpose parser accepts arbitrary version bytes
	// and root metadata. Preserve and explicitly identify those
	// pre-existing differences; the other invalid vectors must fail during
	// decoding.
	for _, vector := range vectors.Invalid {
		t.Run(vector.Reason+"/"+vector.Key[:4], func(t *testing.T) {
			_, err := NewKeyFromString(vector.Key)
			legacyAccepted := strings.Contains(vector.Reason, "version") ||
				strings.HasPrefix(vector.Reason, "zero depth")
			if legacyAccepted {
				require.NoError(
					t, err,
					"documented legacy parser behavior",
				)
			} else {
				require.Error(t, err)
			}
		})
	}
}
