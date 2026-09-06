// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/address/v2/base58"
)

const (
	// MaxPayloadSize bounds the compressed descriptor. It is an
	// experimental application limit, not relay policy.
	MaxPayloadSize = 4096

	// MaxDescriptorSize bounds the descriptor after inflation, with its
	// extended keys still in binary form.
	MaxDescriptorSize = 8192

	// keyMarker introduces a binary extended key. A descriptor string
	// never contains this byte.
	keyMarker = 0x00

	// extendedKeySize is the length of a serialized BIP32 extended key
	// without its base58check checksum.
	extendedKeySize = 78

	// extendedKeyChars is the base58check length of every such key whose
	// version starts with 0x04.
	extendedKeyChars = 111

	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZ" +
		"abcdefghijkmnopqrstuvwxyz"
)

// ErrInvalidDescriptor indicates a descriptor that cannot be backed up, or a
// decrypted payload that does not decode to one.
var ErrInvalidDescriptor = errors.New("invalid descriptor")

var (
	versionXpub = [4]byte{0x04, 0x88, 0xb2, 0x1e}
	versionTpub = [4]byte{0x04, 0x35, 0x87, 0xcf}
	versionXprv = [4]byte{0x04, 0x88, 0xad, 0xe4}
	versionTprv = [4]byte{0x04, 0x35, 0x83, 0x94}
)

// dictionary is the preset DEFLATE dictionary of
// docs/bip-opreturn-backup-v4.md. More likely fragments sit nearer the end,
// where back-references are cheapest. Changing a single byte breaks every
// existing backup; TestDictionary pins its hash.
var dictionary = []byte("" +
	// Hash and miniscript fragments.
	"ripemd160(hash160(hash256(sha256(" +
	"andor(and_b(and_n(or_b(or_c(or_i(or_d(and_v(v:pk(" +
	"thresh(after(older(" +

	// Key and script functions.
	"pk_h(pk_k(pkh(sh(wpkh(musig(multi_a(sortedmulti_a(multi(" +

	// Standard origin paths, in both hardened notations.
	"/44h/49h/45h/87h/1h/0h]/84h/0h/0h]/86h/0h/0h]" +
	"/48h/1h/0h/2h]/48h/0h/0h/2h]" +
	"/44'/49'/45'/87'/1'/0']/84'/0'/0']/86'/0'/0']" +
	"/48'/1'/0'/2']/48'/0'/0'/2']" +
	"/0/*/1/*)" +

	// Taproot with the BIP 341 unspendable internal key.
	"tr(50929b74c1a04954b78b4b6035e97a5e" +
	"078a5a0f28ec96d547bfee9ace803ac0,{" +

	// Hardened child numbers 0, 1 and 2 inside a binary extended key.
	"\x80\x00\x00\x00\x80\x00\x00\x01\x80\x00\x00\x02" +

	// End of an origin, key marker, tpub or xpub version, depth 3 or 4.
	"]\x00\x04\x35\x87\xcf\x03]\x00\x04\x35\x87\xcf\x04" +
	"]\x00\x04\x88\xb2\x1e\x03]\x00\x04\x88\xb2\x1e\x04" +

	// The most common multisig skeleton.
	"/<0;1>/*)),[/<0;1>/*,[" +
	"wsh(sortedmulti(2,[")

func isBase58(c byte) bool {
	return bytes.IndexByte([]byte(base58Alphabet), c) >= 0
}

// EncodeDescriptor turns a BIP 380 descriptor string, without its #checksum
// suffix, into a backup payload: every base58 xpub or tpub becomes a marker
// byte plus its 78 raw bytes, and the result is compressed with raw DEFLATE
// and the preset dictionary.
//
// The descriptor is not parsed. Extended private keys and WIF keys are
// rejected by pattern; the caller remains responsible for passing a valid,
// public-only descriptor.
func EncodeDescriptor(descriptor string) ([]byte, error) {
	substituted, err := substituteKeys(descriptor)
	if err != nil {
		return nil, err
	}

	var compressed bytes.Buffer
	writer, err := flate.NewWriterDict(
		&compressed, flate.BestCompression, dictionary,
	)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(substituted); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if compressed.Len() > MaxPayloadSize {
		return nil, fmt.Errorf("%w: compressed size %d",
			ErrInvalidDescriptor, compressed.Len())
	}
	return compressed.Bytes(), nil
}

// substituteKeys validates the descriptor's character set, rejects private
// keys, and replaces each base58 xpub or tpub with a marker and its 78 raw
// bytes. The bound applies to the substituted form, which is what a reader
// inflates.
func substituteKeys(descriptor string) ([]byte, error) {
	// A substituted key is 79 bytes for 111 characters, so text longer
	// than twice the bound can never fit.
	if len(descriptor) == 0 || len(descriptor) > 2*MaxDescriptorSize {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidDescriptor,
			len(descriptor))
	}
	for i := 0; i < len(descriptor); i++ {
		c := descriptor[i]
		if c < 0x20 || c > 0x7e {
			return nil, fmt.Errorf("%w: byte 0x%02x at offset %d",
				ErrInvalidDescriptor, c, i)
		}
		if c == '#' {
			return nil, fmt.Errorf("%w: remove the #checksum "+
				"suffix", ErrInvalidDescriptor)
		}
	}

	// Keys are always delimited by characters outside the base58 alphabet,
	// so every key is exactly one maximal base58 run.
	substituted := make([]byte, 0, len(descriptor))
	for start := 0; start < len(descriptor); {
		end := start
		for end < len(descriptor) && isBase58(descriptor[end]) {
			end++
		}
		if end == start {
			substituted = append(substituted, descriptor[start])
			start++
			continue
		}
		run := descriptor[start:end]
		start = end

		payload, version, err := base58.CheckDecode(run)
		if err != nil {
			substituted = append(substituted, run...)
			continue
		}

		// WIF private keys: 32 bytes, optionally a compression flag.
		if (version == 0x80 || version == 0xef) &&
			(len(payload) == 32 || len(payload) == 33) {

			clear(payload)
			return nil, fmt.Errorf("%w: contains a private key",
				ErrInvalidDescriptor)
		}
		if len(payload) != extendedKeySize-1 {
			substituted = append(substituted, run...)
			continue
		}
		var keyVersion [4]byte
		keyVersion[0] = version
		copy(keyVersion[1:], payload)
		switch keyVersion {
		case versionXprv, versionTprv:
			clear(payload)
			return nil, fmt.Errorf("%w: contains a private key",
				ErrInvalidDescriptor)

		case versionXpub, versionTpub:
			substituted = append(substituted, keyMarker, version)
			substituted = append(substituted, payload...)

		default:
			substituted = append(substituted, run...)
		}
	}
	if len(substituted) > MaxDescriptorSize {
		return nil, fmt.Errorf("%w: encoded length %d",
			ErrInvalidDescriptor, len(substituted))
	}
	return substituted, nil
}

// DecodeDescriptor reverses EncodeDescriptor. Inflation stops at
// MaxDescriptorSize, trailing bytes after the DEFLATE stream are rejected, and
// only public extended key versions are restored.
//
// The result is a string that decrypted correctly, not an approved wallet:
// the caller must still parse and validate the descriptor.
func DecodeDescriptor(payload []byte) (string, error) {
	if len(payload) == 0 || len(payload) > MaxPayloadSize {
		return "", fmt.Errorf("%w: payload length %d",
			ErrInvalidDescriptor, len(payload))
	}

	// A bytes.Reader is an io.ByteReader, so the inflater consumes exactly
	// the stream and unread trailing bytes remain visible.
	source := bytes.NewReader(payload)
	reader := flate.NewReaderDict(source, dictionary)
	inflated, err := io.ReadAll(io.LimitReader(reader, MaxDescriptorSize+1))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidDescriptor, err)
	}
	if len(inflated) == 0 || len(inflated) > MaxDescriptorSize ||
		source.Len() != 0 {

		return "", fmt.Errorf("%w: bad inflated length or trailing "+
			"data", ErrInvalidDescriptor)
	}

	descriptor := make([]byte, 0, len(inflated)+len(inflated)/2)
	for i := 0; i < len(inflated); i++ {
		c := inflated[i]
		if c != keyMarker {
			if c < 0x20 || c > 0x7e || c == '#' {
				return "", fmt.Errorf("%w: byte 0x%02x",
					ErrInvalidDescriptor, c)
			}
			descriptor = append(descriptor, c)
			continue
		}
		if len(inflated)-i-1 < extendedKeySize {
			return "", fmt.Errorf("%w: truncated extended key",
				ErrInvalidDescriptor)
		}
		key := inflated[i+1 : i+1+extendedKeySize]
		var version [4]byte
		copy(version[:], key)
		if version != versionXpub && version != versionTpub {
			return "", fmt.Errorf("%w: extended key version %x",
				ErrInvalidDescriptor, version)
		}
		encoded := base58.CheckEncode(key[1:], key[0])
		if len(encoded) != extendedKeyChars {
			return "", fmt.Errorf("%w: extended key encoding",
				ErrInvalidDescriptor)
		}
		descriptor = append(descriptor, encoded...)
		i += extendedKeySize
	}

	// A key may also arrive as literal text. Running the encoder's scan
	// over the result rejects private keys in that form too.
	if _, err := substituteKeys(string(descriptor)); err != nil {
		return "", err
	}
	return string(descriptor), nil
}
