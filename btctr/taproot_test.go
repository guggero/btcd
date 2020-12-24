package btctr

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

var (
	testPubKey1, _ = hex.DecodeString(
		"024027578c6ec26e8fe4a7989c3ffbd02bd9a96b7dee5bf1faca2737e300" +
			"6e9a63",
	)
	testPubKey2, _ = hex.DecodeString(
		"03d68ec529705f7fe7385eb94d2f304cffb71bc85d85050b4a3a99b03144" +
			"b6d449",
	)
	testAddr1 = "bc1pghknv8r7hye5h7f464vvvhdkas8sh9ek9kk3udc3p8qr7mhy6ajs" +
		"28rmdg"
	testAddr2 = "bc1p44py567gutw3fct747ca500pu7am2tfyrunsm8axfc72cpfdsncs" +
		"9rjvfe"
)

func TestTapConstruct(t *testing.T) {
	pubKey, err := btcec.ParsePubKey(testPubKey1, curve)
	if err != nil {
		t.Fatalf("error parsing pubkey: %v", err)
	}

	tapKey, err := TapConstruct(pubKey, nil)
	if err != nil {
		t.Fatalf("error constructing tap key: %v", err)
	}

	addr, err := btcutil.NewAddressTaproot(
		tapKey.SerializeCompact(), &chaincfg.MainNetParams,
	)
	if err != nil {
		t.Fatalf("error creating taproot address: %v", err)
	}

	if addr.String() != testAddr1 {
		t.Fatalf("address mismatch, wanted %s got %s", testAddr1, addr)
	}

	pubKey, err = btcec.ParsePubKey(testPubKey2, curve)
	if err != nil {
		t.Fatalf("error parsing pubkey: %v", err)
	}

	tapKey, err = TapConstruct(pubKey, nil)
	if err != nil {
		t.Fatalf("error constructing tap key: %v", err)
	}

	addr, err = btcutil.NewAddressTaproot(
		tapKey.SerializeCompact(), &chaincfg.MainNetParams,
	)
	if err != nil {
		t.Fatalf("error creating taproot address: %v", err)
	}

	if addr.String() != testAddr2 {
		t.Fatalf("address mismatch, wanted %s got %s", testAddr2, addr)
	}
}
