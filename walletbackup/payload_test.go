// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/address/v2/base58"
	"github.com/stretchr/testify/require"
)

// TestDictionary pins the preset dictionary to the bytes published in
// docs/bip-opreturn-backup-v4.md.
func TestDictionary(t *testing.T) {
	t.Parallel()
	require.Len(t, dictionary, 462)
	digest := sha256.Sum256(dictionary)
	require.Equal(
		t, "77f58b334526d83a20d8a10ec10b197d486f20f8945ae3e9b00a10dbd8"+
			"92487b", hex.EncodeToString(digest[:]),
	)
}

// deflate compresses arbitrary bytes the way a payload is compressed, so
// tests can build payloads the encoder itself would never produce.
func deflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer, err := flate.NewWriterDict(
		&compressed, flate.BestCompression, dictionary,
	)
	require.NoError(t, err)
	_, err = writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return compressed.Bytes()
}

func TestDescriptorRoundTrip(t *testing.T) {
	t.Parallel()
	xpub := testExtendedKey(versionXpub, 1)
	tpub := testExtendedKey(versionTpub, 2)
	require.Len(t, xpub, extendedKeyChars)
	require.True(t, strings.HasPrefix(xpub, "xpub"))
	require.True(t, strings.HasPrefix(tpub, "tpub"))

	descriptors := []string{
		testDescriptor(2, 3),
		testDescriptor(3, 5),
		"wpkh([d34db33f/84'/0'/0']" + xpub + "/<0;1>/*)",
		"tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9a" +
			"ce803ac0,sortedmulti_a(2,[00000001/48h/0h/0h/2h]" +
			xpub + "/<0;1>/*,[00000002/48h/0h/0h/2h]" + tpub +
			"/<0;1>/*))",
		"wsh(or_d(pk(" + xpub + "/0/*),and_v(v:pkh(" + tpub +
			"/0/*),older(52560))))",

		// No extended key at all, and base58 runs that are not keys.
		"pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f281" +
			"5b16f81798)",
		"addr(bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq)",
		"x",
	}
	for _, descriptor := range descriptors {
		payload, err := EncodeDescriptor(descriptor)
		require.NoError(t, err)
		decoded, err := DecodeDescriptor(payload)
		require.NoError(t, err)
		require.Equal(t, descriptor, decoded)
	}

	// Binary keys and the dictionary must beat plain DEFLATE of the text,
	// and a 2-of-3 must stay near its 246 incompressible bytes.
	descriptor := testDescriptor(2, 3)
	payload, err := EncodeDescriptor(descriptor)
	require.NoError(t, err)
	var plain bytes.Buffer
	writer, err := flate.NewWriter(&plain, flate.BestCompression)
	require.NoError(t, err)
	_, err = writer.Write([]byte(descriptor))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.Less(t, len(payload), plain.Len()-50)
	require.Less(t, len(payload), 290)
	t.Logf("2-of-3: %d characters, %d bytes plain DEFLATE, %d bytes "+
		"payload", len(descriptor), plain.Len(), len(payload))
}

func TestDescriptorRejects(t *testing.T) {
	t.Parallel()
	xpub := testExtendedKey(versionXpub, 1)
	wif := base58.CheckEncode(append(bytes.Repeat([]byte{7}, 32), 1), 0x80)
	for _, descriptor := range []string{
		"",
		"wpkh(" + xpub + ")#abcdefgh",
		"wpkh(" + xpub + ")\n",
		"wpkh(\x00" + xpub + ")",
		"wpkh(caf\xc3\xa9)",
		"wpkh(" + testExtendedKey(versionXprv, 1) + "/0/*)",
		"wpkh(" + testExtendedKey(versionTprv, 1) + "/0/*)",
		"wpkh(" + wif + ")",
		"pk(" + base58.CheckEncode(bytes.Repeat([]byte{7}, 32), 0xef) + ")",
		strings.Repeat("a", MaxDescriptorSize+1),
	} {
		_, err := EncodeDescriptor(descriptor)
		require.ErrorIs(t, err, ErrInvalidDescriptor, "%q", descriptor)
	}

	// Many keys are fine until the compressed form exceeds its bound.
	_, err := EncodeDescriptor(strings.Repeat(xpub+",", 30))
	require.NoError(t, err)
	var many strings.Builder
	for i := 0; i < 70; i++ {
		many.WriteString(testExtendedKey(versionXpub, byte(i)) + ",")
	}
	_, err = EncodeDescriptor(many.String())
	require.ErrorIs(t, err, ErrInvalidDescriptor)

	valid, err := EncodeDescriptor("wpkh(" + xpub + "/0/*)")
	require.NoError(t, err)
	key, _, err := base58.CheckDecode(testExtendedKey(versionXprv, 1))
	require.NoError(t, err)
	private := append([]byte{keyMarker, versionXprv[0]}, key...)
	for name, payload := range map[string][]byte{
		"empty":             nil,
		"not deflate":       bytes.Repeat([]byte{0xff}, 40),
		"truncated stream":  valid[:len(valid)-1],
		"trailing byte":     append(bytes.Clone(valid), 0),
		"oversized payload": make([]byte, MaxPayloadSize+1),
		"empty descriptor":  deflate(t, nil),
		"inflates too far": deflate(t, bytes.Repeat(
			[]byte{'a'}, MaxDescriptorSize+1,
		)),
		"control byte":       deflate(t, []byte("wpkh(\x01)")),
		"checksum":           deflate(t, []byte("wpkh(a)#abcdefgh")),
		"truncated key":      deflate(t, append([]byte("pk("), private[:40]...)),
		"private key binary": deflate(t, private),
		"private key text": deflate(t, []byte(
			"wpkh("+testExtendedKey(versionTprv, 1)+")",
		)),
		"unknown key version": deflate(t, append(
			[]byte{keyMarker}, bytes.Repeat([]byte{1}, extendedKeySize)...,
		)),
	} {
		_, err := DecodeDescriptor(payload)
		require.ErrorIs(t, err, ErrInvalidDescriptor, name)
	}

	// Exactly at the bound is accepted.
	_, err = DecodeDescriptor(deflate(t, bytes.Repeat(
		[]byte{'a'}, MaxDescriptorSize,
	)))
	require.NoError(t, err)
}

func FuzzDecodeDescriptor(f *testing.F) {
	for _, descriptor := range []string{
		testDescriptor(2, 3), "wpkh(" + testExtendedKey(versionXpub, 1) + ")",
	} {
		payload, err := EncodeDescriptor(descriptor)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(payload)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		descriptor, err := DecodeDescriptor(payload)
		if err != nil {
			return
		}

		// Anything that decodes is public-only and re-encodes to the
		// same string, unless it compresses beyond the payload bound.
		encoded, err := EncodeDescriptor(descriptor)
		if err != nil {
			require.Greater(t, len(descriptor), MaxPayloadSize/2)
			return
		}
		decoded, err := DecodeDescriptor(encoded)
		require.NoError(t, err)
		require.Equal(t, descriptor, decoded)
	})
}
