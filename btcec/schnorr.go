package btcec

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

var (
	// curve is a KoblitzCurve which implements secp256k1.
	curve = S256()

	TagBIP0340Challenge = []byte("BIP0340/challenge")
	TagBIP0340Aux       = []byte("BIP0340/aux")
	TagBIP0340Nonce     = []byte("BIP0340/nonce")
)

type SchnorrSig [64]byte

func (sig SchnorrSig) GetR() ([32]byte, *big.Int, error) {
	r := new(big.Int).SetBytes(sig[:32])
	if r.Cmp(curve.P) >= 0 {
		return [32]byte{}, nil, errors.New("r is larger than or equal " +
			"to field size")
	}

	return padInt(r), r, nil
}

func (sig SchnorrSig) GetS() ([32]byte, *big.Int, error) {
	s := new(big.Int).SetBytes(sig[32:64])
	if s.Cmp(curve.N) >= 0 {
		return [32]byte{}, nil, errors.New("s is larger than or equal " +
			"to curve order")
	}

	return padInt(s), s, nil
}

func privKeyWithEvenY(privKey *PrivateKey) *PrivateKey {
	if isOdd(privKey.PubKey().Y) {
		evenKey := new(big.Int).SetBytes(privKey.D.Bytes())
		evenKey.Sub(evenKey, curve.N)
		evenPrivKey, _ := PrivKeyFromBytes(curve, evenKey.Bytes())

		return evenPrivKey
	}

	return privKey
}

func TaggedHash(tag []byte, msg ...[]byte) [32]byte {
	tagHash := sha256.Sum256(tag)

	fullMsg := concat(msg...)
	return sha256.Sum256(concat(tagHash[:], tagHash[:], fullMsg))
}

func concat(slices ...[]byte) []byte {
	var totalLen int
	for _, slice := range slices {
		totalLen += len(slice)
	}

	result := make([]byte, 0, totalLen)
	for _, slice := range slices {
		result = append(result, slice...)
	}

	return result
}

func padInt(i *big.Int) [32]byte {
	result := [32]byte{}
	unpadded := i.Bytes()
	copy(result[32-len(unpadded):], unpadded)
	return result
}

func xor(key *big.Int, aux [32]byte) [32]byte {
	paddedKey := padInt(key)
	for i := 0; i < 32; i++ {
		paddedKey[i] ^= aux[i]
	}

	return paddedKey
}

func getE(Rx, Px []byte, message [32]byte) *big.Int {
	hash := TaggedHash(TagBIP0340Challenge, Rx, Px, message[:])

	e := new(big.Int).SetBytes(hash[:])
	e.Mod(e, curve.N)
	return e
}

func LiftX(Px []byte) (*PublicKey, error) {
	pubkey := PublicKey{}
	pubkey.Curve = curve

	pubkey.X = new(big.Int).SetBytes(Px)

	var err error
	pubkey.Y, err = decompressPoint(curve, pubkey.X, false)
	if err != nil {
		return nil, err
	}

	return &pubkey, nil
}

// SchnorrSign signs a 32 byte message with the private key, returning a 64 byte
// signature according to the BIP0340 schnorr signature scheme.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
func SchnorrSign(privateKey *PrivateKey, message [32]byte,
	aux [32]byte) (SchnorrSig, error) {

	// Let P = d'⋅G.
	P := privateKey.PubKey()
	Px := P.SerializeCompact()

	// Let d = d' if has_even_y(P), otherwise let d = n - d'.
	d := privKeyWithEvenY(privateKey)

	// Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
	t := xor(d.D, TaggedHash(TagBIP0340Aux, aux[:]))

	// Let rand = hashBIP0340/nonce(t || bytes(P) || m).
	rnd := TaggedHash(TagBIP0340Nonce, t[:], Px, message[:])

	// Let k' = int(rand) mod n.
	kPrime := new(big.Int).SetBytes(rnd[:])
	kPrime.Mod(kPrime, curve.N)

	// Fail if k' = 0.
	sig := SchnorrSig{}
	if kPrime.Sign() <= 0 {
		return sig, fmt.Errorf("k' was 0")
	}

	// Let R = k'⋅G.
	k, R := PrivKeyFromBytes(curve, kPrime.Bytes())
	Rx := R.SerializeCompact()

	// Let k = k' if has_even_y(R), otherwise let k = n - k'.
	k = privKeyWithEvenY(k)

	// Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	e := getE(Rx, Px, message)

	// Let sig = bytes(R) || bytes((k + ed) mod n).
	copy(sig[:32], Rx)
	e.Mul(e, d.D)
	e.Add(e, k.D)
	e.Mod(e, curve.N)
	paddedE := padInt(e)
	copy(sig[32:], paddedE[:])

	// If Verify(bytes(P), m, sig) (see below) returns failure, abort.
	ok, err := SchnorrVerify(Px, message, sig)
	if err != nil {
		return sig, err
	}
	if !ok {
		return sig, fmt.Errorf("verification failed")
	}

	// Return the signature sig.
	return sig, nil
}

// SchnorrVerify verifies a 64 byte BIP0340 schnorr signature of a 32 byte
// message against the compact public key. Returns an error if verification
// fails.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
func SchnorrVerify(compactKey []byte, message [32]byte,
	signature SchnorrSig) (bool, error) {

	// Let P = lift_x(int(pk)); fail if that fails.
	P, err := LiftX(compactKey)
	if err != nil {
		return false, err
	}

	// Let r = int(sig[0:32]); fail if r ≥ p.
	rPadded, rInt, err := signature.GetR()
	if err != nil {
		return false, err
	}

	// Let s = int(sig[32:64]); fail if s ≥ n.
	sPadded, _, err := signature.GetS()
	if err != nil {
		return false, err
	}

	// Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	e := getE(rPadded[:], compactKey, message)

	// Let R = s⋅G - e⋅P.
	sGx, sGy := curve.ScalarBaseMult(sPadded[:])
	ePx, ePy := curve.ScalarMult(P.X, P.Y, e.Bytes())

	negEPy := new(big.Int).Neg(ePy)
	negEPy = negEPy.Mod(negEPy, curve.P)
	Rx, Ry := curve.Add(sGx, sGy, ePx, negEPy)

	// Fail if is_infinite(R).
	// Fail if not has_even_y(R).
	// Fail if x(R) ≠ r.
	if (Rx.Sign() == 0 && Ry.Sign() == 0) || isOdd(Ry) || Rx.Cmp(rInt) != 0 {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}
