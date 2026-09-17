package miniscript

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// TestMuSigKeyExpressions checks that an aggregate is one symbolic key through
// parsing, resolution and compilation, including its participant path commas.
func TestMuSigKeyExpressions(t *testing.T) {
	t.Parallel()
	key := "musig([12345678/1]A/2,B)/<0;1>/*"
	for _, expression := range []string{
		"pk(" + key + ")", "c:pk_k(" + key + ")",
		"multi_a(1," + key + ",C)", "sortedmulti_a(1,C," + key + ")",
	} {

		t.Run(expression, func(t *testing.T) {
			ast, err := Parse(expression, P2TR)
			require.NoError(t, err)
			require.Contains(t, ast.Keys(), key)

			// The resolver sees the whole expression and provides
			// the aggregate point. Miniscript does not run MuSig2.
			err = ast.ApplyVars(
				func(identifier string) ([]byte, error) {
					scalar := byte(1)
					if identifier == "C" {
						scalar = 2
					} else {
						require.Equal(
							t, key, identifier,
						)
					}
					_, pub := btcec.PrivKeyFromBytes([]byte{
						scalar,
					})
					return schnorr.SerializePubKey(pub), nil
				},
			)
			require.NoError(t, err)
			_, err = ast.Script()
			require.NoError(t, err)
		})
	}
}

// TestMuSigKeySyntax rejects nesting and non-key use without recursive descent.
func TestMuSigKeySyntax(t *testing.T) {
	t.Parallel()
	for _, expression := range []string{
		"musig(A,B)", "sha256(musig(A,B))", "after(musig(A,B))",
		"and_v(musig(A,B),pk(C))", "multi_a(musig(A,B),C)",
		"pk(musig())", "pk(musig(A,))", "pk(musig(,A))",
		"pk(musig(A,,B))", "pk(musig(A,B)", "pk(musig(A,B)C)",
		"pk(musig(musig(A,B),C))", "pk(musig(A(B),C))",
		"pk(" + strings.Repeat(
			"musig(", 10000,
		) + "A" + strings.Repeat(
			")", 10001,
		),
	} {

		_, err := ParseInsane(expression, P2TR)
		require.Error(t, err, expression)
	}
	for _, ctx := range []Context{P2WSH, Legacy} {
		_, err := Parse("pk(musig(A,B))", ctx)
		require.Error(t, err)
	}
}
