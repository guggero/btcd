// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestV2PlaintextGuessRecoversEphemeral demonstrates the broken v2 key
// derivation, not an attack on ECDH. The adversary uses no backup private
// keys and does not evaluate Argon2. An ElligatorSwift encoding would only
// change how the observed x(E) is decoded, not this public equality test.
func TestV2PlaintextGuessRecoversEphemeral(t *testing.T) {
	t.Parallel()
	participants, _ := testParticipants(3)
	var publicKeys []byte
	for _, participant := range participants {
		publicKeys = append(publicKeys, participant.PublicKey[:]...)
	}

	// Use the literal placeholder tags from the unassigned v2 draft.
	v2Hash := func(label string, parts ...[]byte) [32]byte {
		tag := sha256.Sum256([]byte("BIPXXX/" + label))
		h := sha256.New()
		h.Write(tag[:])
		h.Write(tag[:])
		for _, part := range parts {
			h.Write(part)
		}
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest
	}
	ephemeral := func(schema, payload []byte) *btcec.PrivateKey {
		digest := v2Hash("ephemeral", publicKeys, schema, payload)
		key, _ := btcec.PrivKeyFromBytes(digest[:])
		require.False(t, key.Key.IsZero())
		return key
	}
	contentKey := func(e *btcec.PrivateKey) []byte {
		digest := v2Hash("content-key", e.Serialize())
		var scalar btcec.ModNScalar
		scalar.SetByteSlice(digest[:])
		encoded := scalar.Bytes()
		return encoded[:]
	}

	// This schema is predictable from a public-key configuration and the
	// construction height. Turning hints off leaves the rest zero.
	schema := make([]byte, 80)
	binary.BigEndian.PutUint32(schema[:4], 900000)
	schema[4], schema[5] = 2, 3
	walletID := v2Hash("wallet-id", publicKeys)
	copy(schema[8:16], walletID[:8])
	descriptor := []byte(fmt.Sprintf(
		"wsh(sortedmulti(2,%x,%x,%x))",
		testKey(11).PubKey().SerializeCompressed(),
		testKey(12).PubKey().SerializeCompressed(),
		testKey(13).PubKey().SerializeCompressed(),
	))
	actualE := ephemeral(schema, descriptor)
	observedX := actualE.PubKey().SerializeCompressed()[1:]
	aead, err := chacha20poly1305.New(contentKey(actualE))
	require.NoError(t, err)

	// AAD is public; its contents cannot prevent this key-recovery attack.
	aad := []byte("public envelope transcript")
	nonce := make([]byte, 12)
	ciphertext := aead.Seal(nil, nonce, descriptor, aad)

	guesses := [][]byte{[]byte("a different descriptor"), descriptor}
	var recovered []byte
	for _, guess := range guesses {
		candidateE := ephemeral(schema, guess)
		if !bytes.Equal(
			candidateE.PubKey().SerializeCompressed()[1:],
			observedX,
		) {

			continue
		}
		attackerAEAD, err := chacha20poly1305.New(contentKey(
			candidateE,
		))
		require.NoError(t, err)
		recovered, err = attackerAEAD.Open(nil, nonce, ciphertext, aad)
		require.NoError(t, err)
	}
	require.Equal(t, descriptor, recovered)
	t.Log(
		"Recovered the v2 content key with zero participant private " +
			"keys and two plaintext guesses",
	)
}

// TestShamirExplanation gives small, hand-checkable values while performing
// the actual arithmetic in the secp256k1 scalar field. In v4 the line is not
// sampled: it is the one through the first two participants' derived values.
func TestShamirExplanation(t *testing.T) {
	t.Parallel()
	scalar := func(value uint32) *btcec.ModNScalar {
		return new(btcec.ModNScalar).SetInt(value)
	}

	// Suppose the derived values are h_1 = 49 and h_2 = 56.
	first, second := scalar(49), scalar(56)
	var shares []scalarShare
	for index, want := range []uint32{42, 49, 56, 63, 70, 77} {
		value := lineShare(first, second, byte(index))
		require.Equal(t, *scalar(want), value)
		if index > 0 {
			shares = append(shares, scalarShare{
				index: byte(index), value: value,
			})
		}
	}

	// Any two of the five participants interpolate the same P(0).
	for i := range shares {
		for j := i + 1; j < len(shares); j++ {
			recovered, err := combine([]scalarShare{
				shares[j], shares[i],
			})
			require.NoError(t, err)
			require.Equal(t, *scalar(42), recovered)
		}
	}
	t.Log(
		"P(1)=49, P(2)=56 define P(x)=42+7x; shares 1 and 3 give " +
			"3/2*49 - 1/2*63 = 42 mod N",
	)

	// Given only one share, each candidate secret has a compatible line.
	// This holds for a derived share (1) and for a corrected one (3).
	for _, known := range []scalarShare{shares[0], shares[2]} {
		for _, candidate := range []uint32{0, 1, 42, 49, 1000000} {
			// slope = (P(i) - s) / i, then check P(i) = s + slope*i.
			var slope, index, y btcec.ModNScalar
			index.SetInt(uint32(known.index))
			slope.Set(scalar(candidate)).Negate().Add(&known.value)
			slope.Mul(new(btcec.ModNScalar).InverseValNonConst(&index))
			y.Mul2(&slope, &index).Add(scalar(candidate))
			require.Equal(t, known.value, y)
		}
	}
}

func TestV2SortedBeaconDistinguisher(t *testing.T) {
	t.Parallel()
	beacons := make([][4]byte, 16)
	for i := range beacons {
		beacons[i] = Beacon([32]byte{}, [33]byte{byte(i)}, 450)
	}
	sort.Slice(beacons, func(i, j int) bool {
		return bytes.Compare(beacons[i][:], beacons[j][:]) < 0
	})
	for i := 1; i < len(beacons); i++ {
		require.Less(
			t, bytes.Compare(beacons[i-1][:], beacons[i][:]), 0,
		)
	}

	// With n=16 there is no filler and every v2 slot is ordered, however
	// "placed into slots, sorted" is interpreted for smaller key sets.
	t.Log(
		"All 16 v2 beacons are ordered; distinct random slots have " +
			"this order with probability 1/16! (about 4.78e-14)",
	)
}

func TestPublicKeysCanForge(t *testing.T) {
	t.Parallel()
	participants, private := testParticipants(3)
	config := testConfig(2)

	// The publisher API needs only public configuration. AEAD proves that
	// these bytes are internally consistent, not that devices approved
	// them.
	policy := "wpkh(" + testExtendedKey(versionTpub, 66) + "/<0;1>/*)"
	forged, err := Seal(config, participants, policy)
	require.NoError(t, err)
	all := openAll(t, config, forged, private)
	plaintext, err := Recover(config.Network, forged, all[:2]...)
	require.NoError(t, err)
	require.Equal(t, policy, plaintext)
	t.Log(
		"A public-key-only publisher can create a backup every " +
			"recipient can open",
	)
}

// TestChunkDiscovery uses btcd's existing GCS implementation, but a custom
// element set: BIP158 basic filters themselves exclude OP_RETURN outputs.
func TestChunkDiscovery(t *testing.T) {
	t.Parallel()
	participants, private := testParticipants(3)
	config := testConfig(2)
	blob, err := Seal(config, participants, testDescriptor(2, 3))
	require.NoError(t, err)

	// The index covers the five aligned chunks of the beacon area, without
	// parsing the format byte or knowing the participant count.
	var elements [][]byte
	for i := 0; i < BeaconAreaSize; i += 4 {
		elements = append(elements, blob[i:i+4])
	}
	filterKey := [16]byte{1, 2, 3}
	filter, err := gcs.BuildGCSFilter(19, 784931, filterKey, elements)
	require.NoError(t, err)
	for i := range private {
		current := Beacon(
			config.Network, participants[i].PublicKey,
			config.Epoch+1,
		)
		previous := Beacon(
			config.Network, participants[i].PublicKey, config.Epoch,
		)
		match, err := filter.MatchAny(filterKey, [][]byte{
			current[:], previous[:],
		})
		require.NoError(t, err)
		require.True(t, match)
	}
}
