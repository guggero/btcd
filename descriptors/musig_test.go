package descriptors

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

// readMuSigVectors decodes pinned fixtures strictly so new vector fields cannot
// silently go unused after a future fixture refresh.
func readMuSigVectors(t *testing.T, path string, target any) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(target))
}

// TestBIP390Vectors executes all official positive and negative cases. rawtr
// remains unsupported as a descriptor; its vectors still test the complete
// aggregate key derivation, followed by the specified untweaked output script.
func TestBIP390Vectors(t *testing.T) {
	t.Parallel()
	var vectors struct {
		Valid []struct {
			Descriptor string
			Scripts    []string
		}
		Invalid []struct{ Descriptor, Reason string }
	}
	readMuSigVectors(t, "testdata/bip390.json", &vectors)
	require.Len(t, vectors.Valid, 6)
	require.Len(t, vectors.Invalid, 14)
	for i, vector := range vectors.Valid {
		t.Run(fmt.Sprintf("valid/%d", i), func(t *testing.T) {
			for index, expected := range vector.Scripts {
				var script []byte
				if strings.HasPrefix(
					vector.Descriptor, "rawtr(",
				) {

					// rawtr commits to the key without a
					// TapTweak. Do not skip these BIP328
					// derivation vectors.
					_, err := NewDescriptor(
						vector.Descriptor,
					)
					require.Error(t, err)
					expression := vector.Descriptor[len(
						"rawtr(",
					) : len(vector.Descriptor)-1]
					key, err := parseDescKey(
						expression, keyFormXOnly,
					)
					require.NoError(t, err)
					pub, err := key.derivePub(0, uint32(
						index,
					))
					require.NoError(t, err)
					script, err = txscript.PayToTaprootScript(pub)
					require.NoError(t, err)
				} else {
					// Exercise the public descriptor API
					// for both internal and tapscript
					// aggregate keys.
					d, err := NewDescriptor(
						vector.Descriptor,
					)
					require.NoError(t, err)
					script, err = outputScriptAt(
						d, 0, uint32(index),
					)
					require.NoError(t, err)
				}
				require.Equal(t, expected, hex.EncodeToString(
					script,
				))
			}
		})
	}
	for _, vector := range vectors.Invalid {
		t.Run("invalid/"+vector.Reason, func(t *testing.T) {
			_, err := NewDescriptor(vector.Descriptor)
			require.Error(t, err)
		})
	}
}

// TestBIP328Aggregation verifies all participant lists as well as synthetic
// xpubs, bridging the independently tested MuSig2 and hdkeychain packages.
func TestBIP328Aggregation(t *testing.T) {
	t.Parallel()
	var vectors []struct {
		AggregatePubkey string   `json:"aggregate_pubkey"`
		Keys            []string `json:"keys"`
		Xpub            string   `json:"xpub"`
	}
	readMuSigVectors(t, "testdata/bip328.json", &vectors)
	require.Len(t, vectors, 3)
	for _, vector := range vectors {
		t.Run(vector.AggregatePubkey, func(t *testing.T) {
			// BIP328 does not itself prescribe sorting. Its vectors
			// supply the aggregation order, unlike BIP390.
			keys := make([]*btcec.PublicKey, len(vector.Keys))
			for i, raw := range vector.Keys {
				data, err := hex.DecodeString(raw)
				require.NoError(t, err)
				keys[i], err = btcec.ParsePubKey(data)
				require.NoError(t, err)
			}
			aggregate, _, _, err := musig2.AggregateKeys(
				keys, false,
			)
			require.NoError(t, err)
			require.Equal(
				t, vector.AggregatePubkey,
				hex.EncodeToString(aggregate.FinalKey.SerializeCompressed()),
			)
			key, err := hdkeychain.NewMuSig2Key(
				aggregate.FinalKey, &chaincfg.MainNetParams,
			)
			require.NoError(t, err)
			require.Equal(t, vector.Xpub, key.String())
		})
	}
}

// TestMuSigDerivation checks participant and aggregate ranges independently.
// Reversing participants must leave scripts unchanged after derivation, while
// lookup identities and policy keys retain the original expression.
func TestMuSigDerivation(t *testing.T) {
	t.Parallel()
	a, err := hdkeychain.NewMaster(
		[]byte("first participant seed for musig"),
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	b, err := hdkeychain.NewMaster(
		[]byte("second participant seed for musig"),
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	pubA, err := a.Neuter()
	require.NoError(t, err)
	pubB, err := b.Neuter()
	require.NoError(t, err)
	for _, aggregatePath := range []bool{false, true} {
		t.Run(
			fmt.Sprintf("aggregate_path=%v", aggregatePath),
			func(t *testing.T) {
				left, right, suffix := pubA.String(), pubB.String(), ""
				if aggregatePath {
					suffix = "/<0;1>/*"
				} else {
					left += "/<0;1>/*"
					right += "/<2;3>/*"
				}
				expression := "musig(" + left + "," + right +
					")" + suffix
				d, err := NewDescriptor(
					"tr(" + expression + ")",
				)
				require.NoError(t, err)
				require.Equal(t, 2, d.MultipathLen())
				require.Equal(t, []string{expression}, d.Keys())
				policy, err := d.Lift()
				require.NoError(t, err)
				require.Equal(t, expression, *policy.Key)
				reversed, err := NewDescriptor(
					"tr(musig(" + right + "," + left + ")" + suffix + ")",
				)
				require.NoError(t, err)

				// Resolve both dimensions. The definite
				// descriptor must produce exactly the same
				// script at any unused index.
				for mp := range uint32(2) {
					for index := range uint32(4) {
						actual, err := outputScriptAt(
							d, mp, index,
						)
						require.NoError(t, err)
						other, err := outputScriptAt(
							reversed, mp, index,
						)
						require.NoError(t, err)
						require.Equal(t, actual, other)
						definite := d.keys[0].definiteString(
							mp, index,
						)
						require.NotContains(
							t, definite, "*",
						)
						require.NotContains(
							t, definite, "<",
						)
						resolved, err := NewDescriptor(
							"tr(" + definite + ")",
						)
						require.NoError(t, err)
						fixed, err := outputScriptAt(
							resolved, 0, 0,
						)
						require.NoError(t, err)
						require.Equal(t, actual, fixed)
						_, err = d.PlanAt(
							mp, index, Assets{
								LookupTapKeySpendSig: func(
									key string) (uint32,
									bool) {

									require.Equal(
										t,
										definite,
										key,
									)
									return 64, true
								},
							},
						)
						require.NoError(t, err)
					}
				}
				_, err = outputScriptAt(d, 2, 0)
				require.Error(t, err)
				_, err = outputScriptAt(
					d, 0, hdkeychain.HardenedKeyStart,
				)
				require.Error(t, err)
			},
		)
	}

	// Hardened participant derivation works with xprvs, including the
	// existing eager public-key cache used for concurrent descriptor reads.
	privateExpr := "musig(" + a.String() + "/1h," + b.String() + "/2h)/3"
	private, err := NewDescriptor("tr(" + privateExpr + ")")
	require.NoError(t, err)
	_, err = outputScriptAt(private, 0, 0)
	require.NoError(t, err)
}

// TestMuSigRejectedKeys supplements the official invalid vectors with syntax,
// participant serialization, origin and multipath-boundary cases.
func TestMuSigRejectedKeys(t *testing.T) {
	t.Parallel()
	master, err := hdkeychain.NewMaster(
		make([]byte, 32), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	pub, err := master.Neuter()
	require.NoError(t, err)
	xpub := pub.String()
	_, point := btcec.PrivKeyFromBytes([]byte{1})
	compressed := hex.EncodeToString(point.SerializeCompressed())
	for _, expression := range []string{
		"musig()", "musig(" + compressed + ",)", "musig(," + compressed + ")",
		"musig(musig(" + compressed + "))", "musig(" + compressed + ")garbage",
		"[12345678]musig(" + compressed + ")",
		"musig(" + compressed[2:] + ")",
		"musig(" + hex.EncodeToString(
			point.SerializeUncompressed(),
		) + ")",
		"musig(" + xpub + ")/", "musig(" + xpub + ")/*/0",
		"musig(" + xpub + ")/<0;1>/<2;3>",
		"musig(" + xpub + ")/<0;1h>", "musig(" + xpub + ")/*'",
		"musig(" + xpub + "/<0;1>)/2",
		"musig(" + xpub + "/<0;1>," + xpub + "/<0;1;2>)",
		"musig(" + compressed + "," + xpub + ")/0",
	} {

		_, err := NewDescriptor("tr(" + expression + ")")
		require.Error(t, err, expression)
	}

	// A malformed point is detected when deriving, just like ordinary raw
	// descriptor keys. A signature-availability callback cannot bypass it.
	d, err := NewDescriptor("tr(musig(02" + strings.Repeat("ff", 32) + "))")
	require.NoError(t, err)
	_, err = d.PlanAt(0, 0, Assets{
		LookupTapKeySpendSig: func(string) (uint32, bool) {
			return 64, true
		},
	})
	require.Error(t, err)
}
