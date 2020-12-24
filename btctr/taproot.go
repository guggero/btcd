package btctr

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var (
	// curve is a KoblitzCurve which implements secp256k1.
	curve = btcec.S256()

	TagTapTweak   = []byte("TapTweak")
	TagTapSighash = []byte("TapSighash")
)

func TapRoot(scripts [][]byte) [32]byte {
	if len(scripts) == 0 {
		return [32]byte{}
	}

	// TODO(guggero): implement
	return [32]byte{}
}

// https://en.bitcoin.it/wiki/BIP_0341#cite_note-22
func TapConstruct(pubKey *btcec.PublicKey, scripts [][]byte) (*btcec.PublicKey,
	error) {

	h := TapRoot(scripts)
	P, err := btcec.LiftX(pubKey.SerializeCompact())
	if err != nil {
		return nil, err
	}
	tag := btcec.TaggedHash(TagTapTweak, P.SerializeCompact(), h[:])
	tweakX, tweakY := curve.ScalarBaseMult(tag[:])
	Qx, Qy := curve.Add(P.X, P.Y, tweakX, tweakY)

	return &btcec.PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

func TweakPrivKey(privKey *btcec.PrivateKey,
	scripts [][]byte) (*btcec.PrivateKey, error) {

	h := TapRoot(scripts)
	d := privKey.D
	if privKey.PubKey().Y.Bit(0) == 1 {
		d.Sub(new(big.Int).SetBytes(curve.N.Bytes()), d)
	}
	_, P := btcec.PrivKeyFromBytes(curve, d.Bytes())
	tag := btcec.TaggedHash(TagTapTweak, P.SerializeCompact(), h[:])
	tweakedKey := new(big.Int).SetBytes(tag[:])
	tweakedKey.Add(tweakedKey, privKey.D)
	tweakedKey.Mod(tweakedKey, curve.N)

	newPrivKey, _ := btcec.PrivKeyFromBytes(curve, tweakedKey.Bytes())
	return newPrivKey, nil
}
