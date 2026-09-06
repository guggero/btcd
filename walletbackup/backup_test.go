// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/address/v2/base58"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func testKey(value uint32) *btcec.PrivateKey {
	var scalar btcec.ModNScalar
	scalar.SetInt(value)
	return btcec.PrivKeyFromScalar(&scalar)
}

func testParticipants(count int) ([]Participant, []*btcec.PrivateKey) {
	participants := make([]Participant, count)
	private := make([]*btcec.PrivateKey, count)
	for i := range participants {
		private[i] = testKey(uint32(i + 1))
		copy(
			participants[i].PublicKey[:],
			private[i].PubKey().SerializeCompressed(),
		)
		binary.BigEndian.PutUint32(
			participants[i].Fingerprint[:], uint32(i+1),
		)
	}
	return participants, private
}

func testConfig(threshold byte) Config {
	return Config{
		WalletID: [16]byte{1}, Revision: 7, Epoch: 450,
		Threshold: threshold,
	}
}

// testExtendedKey returns a structurally valid extended key with public,
// deterministic contents. Version selects xpub, tpub, xprv or tprv.
func testExtendedKey(version [4]byte, id byte) string {
	raw := make([]byte, 0, extendedKeySize)
	raw = append(raw, version[:]...)
	raw = append(raw, 4, 0xaa, 0xbb, 0xcc, id, 0x80, 0, 0, 2)
	chainCode := sha256.Sum256([]byte{id})
	raw = append(raw, chainCode[:]...)
	raw = append(raw, testKey(uint32(id)+100).PubKey().SerializeCompressed()...)
	return base58.CheckEncode(raw[1:], raw[0])
}

// testDescriptor returns a realistic multisig descriptor without checksum.
func testDescriptor(threshold, count int) string {
	keys := make([]string, count)
	for i := range keys {
		keys[i] = fmt.Sprintf(
			"[%08x/48h/1h/0h/2h]%s/<0;1>/*", i+1,
			testExtendedKey(versionTpub, byte(i+1)),
		)
	}
	return fmt.Sprintf(
		"wsh(sortedmulti(%d,%s))", threshold, strings.Join(keys, ","),
	)
}

func openAll(t *testing.T, config Config, blob []byte,
	private []*btcec.PrivateKey) []*Contribution {

	t.Helper()
	contributions := make([]*Contribution, len(private))
	for i, key := range private {
		contribution, err := Open(
			config.Network, config.Epoch*EpochBlocks, blob, key,
		)
		require.NoError(t, err)
		summary := contribution.Summary()
		require.Equal(t, config.Threshold, summary.Threshold)
		require.Equal(t, byte(len(private)), summary.Participants)
		require.Equal(t, config.Epoch, contribution.Epoch())
		if config.Threshold == 2 {
			require.Equal(t, config.WalletID, summary.WalletID)
			require.Equal(t, config.Revision, summary.Revision)
		} else {
			require.Zero(t, summary.WalletID)
		}
		contributions[i] = contribution
	}
	return contributions
}

// TestRecoverySubsets exercises every subset of every supported wallet shape,
// including nonconsecutive indexes and more than the minimum number of
// participants.
func TestRecoverySubsets(t *testing.T) {
	t.Parallel()
	for n := 1; n <= MaxParticipants; n++ {
		for threshold := 1; threshold <= 2 && threshold <= n; threshold++ {
			name := fmt.Sprintf("%d-of-%d", threshold, n)
			t.Run(name, func(t *testing.T) {
				config := testConfig(byte(threshold))
				participants, private := testParticipants(n)
				descriptor := testDescriptor(threshold, n)
				blob, err := Seal(config, participants, descriptor)
				require.NoError(t, err)
				all := openAll(t, config, blob, private)
				for subset := 0; subset < 1<<n; subset++ {
					var selected []*Contribution
					for i := range all {
						if subset&(1<<i) != 0 {
							selected = append(
								selected, all[i],
							)
						}
					}
					recovered, err := Recover(
						config.Network, blob, selected...,
					)
					if bits.OnesCount(uint(subset)) < threshold {
						require.ErrorIs(
							t, err, ErrInsufficientShares,
						)
						continue
					}
					require.NoError(t, err)
					require.Equal(t, descriptor, recovered)
				}
			})
		}
	}
}

// TestLayout pins the sizes and offsets a discovery index relies on.
func TestLayout(t *testing.T) {
	t.Parallel()
	for n := 1; n <= MaxParticipants; n++ {
		for threshold := 1; threshold <= 2 && threshold <= n; threshold++ {
			config := testConfig(byte(threshold))
			participants, _ := testParticipants(n)
			payload := []byte("opaque payload")
			blob, err := seal(rand.Reader, config, participants, payload)
			require.NoError(t, err)

			// 69 + 16n and 41 + 52n bytes before the payload.
			overhead := 69 + 16*n
			if threshold == 2 {
				overhead = 41 + 52*n
			}
			require.Len(t, blob, overhead+len(payload))

			// Beacons sit on four-byte boundaries from offset zero, in
			// canonical key order whatever order the caller used.
			sorted := append([]Participant(nil), participants...)
			for i := range sorted {
				for j := i + 1; j < len(sorted); j++ {
					if bytes.Compare(
						sorted[j].PublicKey[:],
						sorted[i].PublicKey[:],
					) < 0 {

						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
			for i, participant := range sorted {
				beacon := Beacon(
					config.Network, participant.PublicKey,
					config.Epoch,
				)
				require.Equal(t, beacon[:], blob[4*i:4*i+4])
			}
			require.Equal(
				t, byte(0x40|(threshold-1)<<3|n), blob[BeaconAreaSize],
			)
			_, err = schnorr.ParsePubKey(blob[21:53])
			require.NoError(t, err)

			// Unused slots are random filler, not a fixed pattern.
			other, err := seal(rand.Reader, config, participants, payload)
			require.NoError(t, err)
			require.Equal(t, blob[:4*n], other[:4*n])
			if n < MaxParticipants {
				require.NotEqual(
					t, blob[4*n:BeaconAreaSize],
					other[4*n:BeaconAreaSize],
				)
			}
		}
	}
}

func TestRejectMixedDuplicateAndCorruptShares(t *testing.T) {
	t.Parallel()
	config := testConfig(2)
	participants, private := testParticipants(4)
	descriptor := testDescriptor(2, 4)
	blob, err := Seal(config, participants, descriptor)
	require.NoError(t, err)
	all := openAll(t, config, blob, private)
	_, err = Recover(config.Network, blob, all[0], all[0])
	require.ErrorIs(t, err, ErrInvalidBackup)

	// Same wallet, revision and payload still produce independent backups.
	other, err := Seal(config, participants, descriptor)
	require.NoError(t, err)
	require.NotEqual(t, blob, other)
	otherShares := openAll(t, config, other, private)
	_, err = Recover(config.Network, blob, all[0], otherShares[1])
	require.ErrorIs(t, err, ErrInvalidBackup)

	// A wrong share fails at the payload AEAD, whether it is a derived
	// share (indexes 1 and 2) or a corrected one.
	for _, index := range []int{1, 3} {
		corrupt := *all[index]
		corrupt.share.value.Add(new(btcec.ModNScalar).SetInt(1))
		_, err = Recover(config.Network, blob, all[0], &corrupt)
		require.ErrorIs(t, err, ErrInvalidBackup)
	}

	// Three collinear shares are fine; three with one wrong are not.
	_, err = Recover(config.Network, blob, all[0], all[2], all[3])
	require.NoError(t, err)
	corrupt := *all[3]
	corrupt.share.value.Add(new(btcec.ModNScalar).SetInt(1))
	_, err = Recover(config.Network, blob, all[0], all[2], &corrupt)
	require.ErrorIs(t, err, ErrInvalidBackup)

	_, err = Recover(config.Network, blob, all[0], nil)
	require.ErrorIs(t, err, ErrInvalidBackup)
	_, err = Recover(config.Network, blob, nil, all[0])
	require.ErrorIs(t, err, ErrInvalidBackup)
	_, err = Recover([32]byte{9}, blob, all[0], all[1])
	require.ErrorIs(t, err, ErrInvalidBackup)
	_, err = Open(
		config.Network, config.Epoch*EpochBlocks, blob, testKey(99),
	)
	require.ErrorIs(t, err, ErrNotRecipient)
	_, err = Open(config.Network, config.Epoch*EpochBlocks, blob, nil)
	require.ErrorIs(t, err, ErrNotRecipient)

	// A single-device contribution cannot be replayed on another backup.
	config = testConfig(1)
	blob, err = Seal(config, participants, descriptor)
	require.NoError(t, err)
	other, err = Seal(config, participants, descriptor)
	require.NoError(t, err)
	single := openAll(t, config, blob, private)
	_, err = Recover(config.Network, other, single[0])
	require.ErrorIs(t, err, ErrInvalidBackup)
	_, err = Recover(config.Network, blob, single[0], single[0])
	require.ErrorIs(t, err, ErrInvalidBackup)
}

// TestWalletInstances ensures a second account using the same devices remains
// distinguishable, while canonical sorting preserves each fingerprint.
func TestWalletInstances(t *testing.T) {
	t.Parallel()
	participants, private := testParticipants(3)
	participants[0], participants[2] = participants[2], participants[0]
	original := append([]Participant(nil), participants...)
	var ids [2][16]byte
	for i := range ids {
		config := testConfig(2)
		config.WalletID[0] = byte(i + 1)
		blob, err := Seal(config, participants, testDescriptor(2, 3))
		require.NoError(t, err)
		require.Equal(t, original, participants)
		all := openAll(t, config, blob, private)
		ids[i] = all[0].Summary().WalletID
		for j, contribution := range all {
			summary := contribution.Summary()
			fingerprint := summary.Fingerprints[contribution.Index()-1]
			require.Equal(t, uint32(j+1), binary.BigEndian.Uint32(
				fingerprint[:],
			))
		}
	}
	require.NotEqual(t, ids[0], ids[1])
}

func TestTampering(t *testing.T) {
	t.Parallel()
	for _, threshold := range []byte{1, 2} {
		config := testConfig(threshold)
		participants, private := testParticipants(3)
		blob, err := Seal(config, participants, testDescriptor(2, 3))
		require.NoError(t, err)
		height := config.Epoch * EpochBlocks
		contentStart := headerSize + entriesSize(3, int(threshold)) +
			summaryCTSize(3, int(threshold))

		// Flip every byte. For two-device backups, header, entry and
		// summary changes must fail before presenting a summary, and
		// payload changes at quorum decryption. A single-device backup
		// has one AEAD, so every change fails at Open.
		for offset := range blob {
			mutated := bytes.Clone(blob)
			mutated[offset] ^= 1
			first, err := Open(
				config.Network, height, mutated, private[0],
			)
			if threshold == 1 || offset < contentStart {
				require.Error(t, err, "offset %d", offset)
				continue
			}
			require.NoError(t, err)
			second, err := Open(
				config.Network, height, mutated, private[2],
			)
			require.NoError(t, err)
			_, err = Recover(config.Network, mutated, first, second)
			require.ErrorIs(t, err, ErrInvalidBackup)
		}
		for length := 0; length < len(blob); length++ {
			first, err := Open(
				config.Network, height, blob[:length], private[0],
			)
			if err != nil {
				continue
			}
			require.Equal(t, byte(2), threshold)
			second, err := Open(
				config.Network, height, blob[:length], private[2],
			)
			require.NoError(t, err)
			_, err = Recover(
				config.Network, blob[:length], first, second,
			)
			require.ErrorIs(t, err, ErrInvalidBackup)
		}
	}
}

// TestFormatByte rejects every format byte the specification does not list.
func TestFormatByte(t *testing.T) {
	t.Parallel()
	valid := map[byte]bool{
		0x41: true, 0x42: true, 0x43: true, 0x44: true, 0x45: true,
		0x4a: true, 0x4b: true, 0x4c: true, 0x4d: true,
	}
	blob := make([]byte, headerSize+4096)
	copy(blob[pointOffset:], schnorr.SerializePubKey(testKey(1).PubKey()))
	for format := 0; format < 256; format++ {
		blob[formatOffset] = byte(format)
		_, err := parse(blob)
		if valid[byte(format)] {
			require.NoError(t, err, "format %#x", format)
			continue
		}
		require.ErrorIs(t, err, ErrInvalidBackup, "format %#x", format)
	}

	// An X coordinate that is not on the curve, and a correction >= N.
	blob[formatOffset] = 0x4b
	copy(blob[pointOffset:], bytes.Repeat([]byte{0xff}, 32))
	_, err := parse(blob)
	require.ErrorIs(t, err, ErrInvalidBackup)
	copy(blob[pointOffset:], schnorr.SerializePubKey(testKey(1).PubKey()))
	copy(blob[headerSize+3*wrapSize:], bytes.Repeat([]byte{0xff}, 32))
	_, err = parse(blob)
	require.ErrorIs(t, err, ErrInvalidBackup)
}

func TestEpochNetworkAndConfiguration(t *testing.T) {
	t.Parallel()
	participants, private := testParticipants(3)
	descriptor := testDescriptor(2, 3)
	for _, threshold := range []byte{1, 2} {
		for _, epoch := range []uint32{0, 1, 450} {
			config := testConfig(threshold)
			config.Epoch = epoch
			blob, err := Seal(config, participants, descriptor)
			require.NoError(t, err)

			// The epoch is not transmitted. The block's epoch and the
			// preceding one are the only ones tried.
			for _, height := range []uint32{
				epoch * EpochBlocks, (epoch+2)*EpochBlocks - 1,
			} {

				contribution, err := Open(
					config.Network, height, blob, private[0],
				)
				require.NoError(t, err)
				require.Equal(t, epoch, contribution.Epoch())
			}
			_, err = Open(
				config.Network, (epoch+2)*EpochBlocks, blob,
				private[0],
			)
			require.ErrorIs(t, err, ErrNotRecipient)
			if epoch > 0 {
				_, err = Open(
					config.Network, epoch*EpochBlocks-1, blob,
					private[0],
				)
				require.ErrorIs(t, err, ErrNotRecipient)
			}
			_, err = Open(
				[32]byte{99}, epoch*EpochBlocks, blob, private[0],
			)
			require.ErrorIs(t, err, ErrNotRecipient)
		}
	}

	config := testConfig(2)
	_, err := Seal(config, []Participant{
		participants[0], participants[0],
	}, descriptor)
	require.Error(t, err)
	for _, threshold := range []byte{0, 3, 255} {
		config.Threshold = threshold
		_, err = Seal(config, participants, descriptor)
		require.Error(t, err)
	}
	config = testConfig(2)
	_, err = Seal(config, participants[:1], descriptor)
	require.Error(t, err)
	_, err = Seal(config, nil, descriptor)
	require.Error(t, err)
	_, err = Seal(config, make([]Participant, 6), descriptor)
	require.Error(t, err)
	_, err = seal(
		rand.Reader, config, participants, make([]byte, MaxPayloadSize+1),
	)
	require.Error(t, err)
	_, err = Seal(config, participants, "")
	require.ErrorIs(t, err, ErrInvalidDescriptor)

	// The wallet ID lives in the summary, which only two-device backups
	// have.
	config.WalletID = [16]byte{}
	_, err = Seal(config, participants, descriptor)
	require.Error(t, err)
	config.Threshold = 1
	_, err = Seal(config, participants, descriptor)
	require.NoError(t, err)

	config = testConfig(2)
	participants[0].PublicKey = [33]byte{}
	_, err = Seal(config, participants, descriptor)
	require.Error(t, err)
}

func TestEntropyAndScalarEdges(t *testing.T) {
	t.Parallel()
	participants, _ := testParticipants(3)

	// A publication consumes a 32-byte scalar, a 16-byte seed and four
	// bytes per unused beacon slot. Every early exhaustion must fail.
	entropy := make([]byte, 56)
	_, err := rand.Read(entropy)
	require.NoError(t, err)
	entropy[0] = 0x7f
	for length := 0; length < len(entropy); length++ {
		_, err = seal(
			bytes.NewReader(entropy[:length]), testConfig(2),
			participants, nil,
		)
		require.Error(t, err)
	}
	reader := bytes.NewReader(entropy)
	_, err = seal(reader, testConfig(2), participants, nil)
	require.NoError(t, err)
	require.Zero(t, reader.Len())

	_, err = randomScalar(bytes.NewReader(nil))
	require.ErrorIs(t, err, io.EOF)
	_, err = randomScalar(bytes.NewReader(make([]byte, 32)))
	require.ErrorIs(t, err, io.EOF)

	// Reject N itself, then accept 1, rather than silently mapping N to 0.
	order, err := hex.DecodeString(
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036" +
			"4141",
	)
	require.NoError(t, err)
	one := testKey(1).Serialize()
	sampled, err := randomScalar(bytes.NewReader(append(order, one...)))
	require.NoError(t, err)
	require.Equal(t, testKey(1).Key, sampled)

	_, err = combine(nil)
	require.Error(t, err)
	_, err = combine([]scalarShare{{index: 0}})
	require.Error(t, err)
	_, err = combine([]scalarShare{{index: MaxParticipants + 1}})
	require.Error(t, err)
	_, err = combine([]scalarShare{{index: 1}, {index: 1}})
	require.Error(t, err)
}

type vector struct {
	Name         string
	Network      string
	WalletID     string `json:"wallet_id"`
	Epoch        uint32
	Revision     uint32
	Threshold    byte
	Entropy      string
	Ephemeral    string
	Seed         string
	Header       string
	Context      string
	Descriptor   string
	Payload      string
	Secret       string
	Blob         string
	Participants []struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		SharedX    string `json:"shared_x"`
		WrapPad    string `json:"wrap_pad"`
		Mask       string
		Share      string
		Index      byte
	}
}

func unhex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

// TestIndependentVectors compares complete envelopes and intermediate ECDH,
// HKDF and share values against the independent Python implementation, and
// decodes payloads that Python's zlib compressed.
func TestIndependentVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var vectors []vector
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.Len(t, vectors, 5)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			config := Config{
				Epoch:     v.Epoch,
				Revision:  v.Revision,
				Threshold: v.Threshold,
			}
			copy(config.Network[:], unhex(t, v.Network))
			copy(config.WalletID[:], unhex(t, v.WalletID))
			participants := make([]Participant, len(v.Participants))
			private := make([]*btcec.PrivateKey, len(participants))
			for i, p := range v.Participants {
				private[i], _ = btcec.PrivKeyFromBytes(unhex(
					t, p.PrivateKey,
				))
				copy(participants[i].PublicKey[:], unhex(
					t, p.PublicKey,
				))
				copy(
					participants[i].Fingerprint[:],
					private[i].Serialize()[28:],
				)
			}

			// Go's DEFLATE output differs from zlib's, so the envelope
			// is rebuilt around the Python payload bytes.
			blob, err := seal(
				bytes.NewReader(unhex(t, v.Entropy)), config,
				participants, unhex(t, v.Payload),
			)
			require.NoError(t, err)
			require.Equal(t, v.Blob, hex.EncodeToString(blob))
			require.Equal(t, v.Header, hex.EncodeToString(
				blob[:headerSize],
			))

			all := openAll(t, config, blob, private)
			ephemeral, _ := btcec.PrivKeyFromBytes(unhex(
				t, v.Ephemeral,
			))
			var context [32]byte
			copy(context[:], unhex(t, v.Context))
			for i, p := range v.Participants {
				shared := btcec.GenerateSharedSecret(
					private[i], ephemeral.PubKey(),
				)
				require.Equal(t, p.SharedX, hex.EncodeToString(
					shared,
				))
				wrap, mask := recipientKeys(
					shared, context,
					participants[i].PublicKey[:], p.Index,
				)
				require.Equal(t, p.WrapPad, hex.EncodeToString(
					wrap[:],
				))
				encodedMask := mask.Bytes()
				require.Equal(t, p.Mask, hex.EncodeToString(
					encodedMask[:],
				))
				require.Equal(t, p.Index, all[i].Index())
				if v.Threshold == 1 {
					require.Equal(t, v.Seed, hex.EncodeToString(
						all[i].seed[:],
					))
					continue
				}
				share := all[i].share.value.Bytes()
				require.Equal(t, p.Share, hex.EncodeToString(
					share[:],
				))

				// The first two shares are the derived values.
				if p.Index <= 2 {
					require.Equal(t, p.Mask, p.Share)
				}
			}
			if v.Threshold == 2 {
				secret, err := combine([]scalarShare{
					all[0].share, all[len(all)-1].share,
				})
				require.NoError(t, err)
				encoded := secret.Bytes()
				require.Equal(t, v.Secret, hex.EncodeToString(
					encoded[:],
				))
			}

			recovered, err := Recover(config.Network, blob, all...)
			require.NoError(t, err)
			require.Equal(t, v.Descriptor, recovered)

			// Go's own encoding of the same descriptor round-trips.
			payload, err := EncodeDescriptor(v.Descriptor)
			require.NoError(t, err)
			decoded, err := DecodeDescriptor(payload)
			require.NoError(t, err)
			require.Equal(t, v.Descriptor, decoded)
		})
	}
}

func FuzzOpen(f *testing.F) {
	participants, private := testParticipants(3)
	for _, threshold := range []byte{1, 2} {
		blob, err := Seal(
			testConfig(threshold), participants, testDescriptor(2, 3),
		)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(blob)
	}
	f.Add([]byte{})
	config := testConfig(1)
	f.Fuzz(func(t *testing.T, candidate []byte) {
		contribution, err := Open(
			config.Network, config.Epoch*EpochBlocks, candidate,
			private[0],
		)
		if err != nil {
			return
		}
		_, err = Recover(config.Network, candidate, contribution)
		if err != nil && !errors.Is(err, ErrInvalidBackup) &&
			!errors.Is(err, ErrInsufficientShares) {

			t.Fatal(err)
		}
	})
}
