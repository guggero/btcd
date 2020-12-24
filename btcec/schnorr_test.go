package btcec

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"
)

type testCase struct {
	D       string `json:"d"`
	Pk      string `json:"pk"`
	M       string `json:"m"`
	Sig     string `json:"sig"`
	Result  bool   `json:"result"`
	Comment string `json:"comment"`
	Aux     string `json:"aux"`
}

func (t *testCase) DecodePrivateKey(tt *testing.T) *PrivateKey {
	raw, err := hex.DecodeString(t.D)
	if err != nil {
		tt.Fatalf("error decoding private key: %v", err)
	}

	key, _ := PrivKeyFromBytes(curve, raw)
	return key
}

func (t *testCase) DecodePublicKey(tt *testing.T) []byte {
	raw, err := hex.DecodeString(t.Pk)
	if err != nil {
		tt.Fatalf("error decoding public key: %v", err)
	}

	return raw
}

func (t *testCase) DecodeMessage(tt *testing.T) [32]byte {
	raw, err := hex.DecodeString(t.M)
	if err != nil {
		tt.Fatalf("error decoding message: %v", err)
	}

	msg := [32]byte{}
	copy(msg[:], raw)
	return msg
}

func (t *testCase) DecodeAux(tt *testing.T) [32]byte {
	raw, err := hex.DecodeString(t.Aux)
	if err != nil {
		tt.Fatalf("error decoding aux: %v", err)
	}

	aux := [32]byte{}
	copy(aux[:], raw)
	return aux
}

func (t *testCase) DecodeSignature(tt *testing.T) SchnorrSig {
	raw, err := hex.DecodeString(t.Sig)
	if err != nil {
		tt.Fatalf("error decoding signature: %v", err)
	}

	sig := SchnorrSig{}
	copy(sig[:], raw)
	return sig
}

func loadTestCases(t *testing.T) []*testCase {
	rawData, err := ioutil.ReadFile("testdata/schnorr_test_vectors.json")
	if err != nil {
		t.Fatalf("error reading test vectors: %v", err)
	}

	var testCases []*testCase
	err = json.Unmarshal(rawData, &testCases)
	if err != nil {
		t.Fatalf("error parsing test vectors: %v", err)
	}

	return testCases
}

func TestSchnorrSign(t *testing.T) {
	testCases := loadTestCases(t)

	for _, test := range testCases {
		if test.D == "" {
			continue
		}

		privateKey := test.DecodePrivateKey(t)
		message := test.DecodeMessage(t)
		aux := test.DecodeAux(t)

		result, err := SchnorrSign(privateKey, message, aux)
		if err != nil {
			t.Fatalf("Unexpected error from SchnorrSign(%x, %x, "+
				"%x): %v", privateKey.Serialize(), message, aux,
				err)
		}

		observed := hex.EncodeToString(result[:])
		expected := strings.ToLower(test.Sig)

		if observed != expected {
			t.Fatalf("SchnorrSign(%x, %x, %x) = %s, want %s",
				privateKey.Serialize(), message, aux, observed,
				expected)
		}
	}
}

func TestSchnorrVerify(t *testing.T) {
	testCases := loadTestCases(t)

	for _, test := range testCases {
		publicKey := test.DecodePublicKey(t)
		message := test.DecodeMessage(t)
		signature := test.DecodeSignature(t)

		observed, _ := SchnorrVerify(publicKey, message, signature)
		if observed != test.Result {
			t.Fatalf("SchnorrVerify(%x, %x, %x) = %v, want %v",
				publicKey, message, signature, observed,
				test.Result)
		}
	}
}
