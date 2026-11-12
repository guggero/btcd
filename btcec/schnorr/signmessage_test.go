package schnorr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// bip340VarLenSecretKey is the secret key the variable length message test
// vectors of BIP-340 are signed with, using all zero auxiliary randomness.
const bip340VarLenSecretKey = "03400340034003400340034003400340034003400340" +
	"03400340034003400340"

// TestSchnorrSignMessageVectors tests that signing a message of arbitrary
// length with the nonce derivation of BIP-340 produces the signatures of the
// BIP-340 test vectors.
func TestSchnorrSignMessageVectors(t *testing.T) {
	t.Parallel()

	privKey, pubKey := btcec.PrivKeyFromBytes(
		decodeHex(bip340VarLenSecretKey),
	)

	for i, test := range bip340VarLenTestVectors {
		if !bytes.Equal(
			SerializePubKey(pubKey), decodeHex(test.publicKey),
		) {

			t.Fatalf("test #%v: secret key doesn't match the "+
				"public key of the vector", i)
		}

		msg := decodeHex(test.message)
		sig, err := SignMessage(privKey, msg, CustomNonce([32]byte{}))
		if err != nil {
			t.Fatalf("test #%v: sig generation failed: %v", i, err)
		}

		got := strings.ToUpper(hex.EncodeToString(sig.Serialize()))
		if got != test.signature {
			t.Fatalf("test #%v: got signature %v, want %v", i, got,
				test.signature)
		}
	}
}

// TestSchnorrSignMessage tests the properties of the deterministic signatures
// over messages of arbitrary length.
func TestSchnorrSignMessage(t *testing.T) {
	t.Parallel()

	privKey, pubKey := btcec.PrivKeyFromBytes(
		decodeHex(bip340VarLenSecretKey),
	)

	msgs := [][]byte{
		{}, {0x00}, {0x01}, bytes.Repeat([]byte{0x02}, 31),
		bytes.Repeat([]byte{0x02}, 33), bytes.Repeat([]byte{0x03}, 64),
		bytes.Repeat([]byte{0x04}, 1000),
	}

	seenNonces := make(map[string]int)
	for i, msg := range msgs {
		for _, opts := range [][]SignOption{nil, {FastSign()}} {
			sig, err := SignMessage(privKey, msg, opts...)
			if err != nil {
				t.Fatalf("test #%v: sig generation failed: %v",
					i, err)
			}

			if !sig.VerifyMessage(msg, pubKey) {
				t.Fatalf("test #%v: verification failed", i)
			}

			// The signature is deterministic.
			sig2, err := SignMessage(privKey, msg, opts...)
			if err != nil {
				t.Fatalf("test #%v: sig generation failed: %v",
					i, err)
			}
			if !sig.IsEqual(sig2) {
				t.Fatalf("test #%v: signature isn't "+
					"deterministic", i)
			}

			// Every message gets a nonce of its own.
			nonce := hex.EncodeToString(sig.Serialize()[:32])
			if other, ok := seenNonces[nonce]; ok && other != i {
				t.Fatalf("test #%v: nonce reused from test "+
					"#%v", i, other)
			}
			seenNonces[nonce] = i
		}

		// A message that isn't 32 bytes long can't be signed as a hash.
		if _, err := Sign(privKey, msg); err == nil {
			t.Fatalf("test #%v: Sign accepted a message of %d "+
				"bytes", i, len(msg))
		}
	}
}

// TestSchnorrSignMessageHash tests that a message of 32 bytes is signed the
// same way as a hash, and that the nonce used for a message of any other size
// is not the one used for the hash of that message.
func TestSchnorrSignMessageHash(t *testing.T) {
	t.Parallel()

	privKey, pubKey := btcec.PrivKeyFromBytes(
		decodeHex(bip340VarLenSecretKey),
	)

	msg := []byte("a message that is longer than thirty-two bytes")
	hash := sha256.Sum256(msg)

	for _, opts := range [][]SignOption{nil, {CustomNonce([32]byte{1})}} {
		hashSig, err := Sign(privKey, hash[:], opts...)
		if err != nil {
			t.Fatalf("sig generation failed: %v", err)
		}
		hashMsgSig, err := SignMessage(privKey, hash[:], opts...)
		if err != nil {
			t.Fatalf("sig generation failed: %v", err)
		}
		if !hashSig.IsEqual(hashMsgSig) {
			t.Fatalf("32-byte message signed differently than a " +
				"hash")
		}

		// Signing the message and its hash with the same nonce would
		// reveal the private key to whoever sees both signatures.
		msgSig, err := SignMessage(privKey, msg, opts...)
		if err != nil {
			t.Fatalf("sig generation failed: %v", err)
		}
		if !msgSig.VerifyMessage(msg, pubKey) {
			t.Fatalf("verification failed")
		}
		if bytes.Equal(
			msgSig.Serialize()[:32], hashSig.Serialize()[:32],
		) {

			t.Fatalf("message and its hash signed with the same " +
				"nonce")
		}
	}
}
