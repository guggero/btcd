package descriptors

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// signMuSigSpend runs a fresh MuSig2 signing session for one message. Each
// signer uses a freshly generated nonce exactly once; fixed fixture nonces must
// never be reused across the transactions exercised by this integration test.
func signMuSigSpend(t *testing.T, signers []*btcec.PrivateKey,
	keys []*btcec.PublicKey, tweaks []musig2.KeyTweakDesc,
	message [32]byte) []byte {

	t.Helper()
	nonces := make([]*musig2.Nonces, len(signers))
	publicNonces := make([][musig2.PubNonceSize]byte, len(signers))
	for i, signer := range signers {
		var err error
		nonces[i], err = musig2.GenNonces(
			musig2.WithPublicKey(signer.PubKey()),
			musig2.WithNonceSecretKeyAux(signer),
			musig2.WithNonceMessageAux(message),
		)
		require.NoError(t, err)
		publicNonces[i] = nonces[i].PubNonce
	}
	aggregateNonce, err := musig2.AggregateNonces(publicNonces)
	require.NoError(t, err)

	// Both signing and combination must use the same sorted participant
	// list and ordered plain/x-only tweaks as the output construction.
	partials := make([]*musig2.PartialSignature, len(signers))
	for i, signer := range signers {
		partials[i], err = musig2.Sign(
			nonces[i].SecNonce, signer, aggregateNonce, keys,
			message, musig2.WithSortedKeys(),
			musig2.WithTweaks(tweaks...),
		)
		require.NoError(t, err)
		clear(nonces[i].SecNonce[:])
	}
	sig := musig2.CombineSigs(
		partials[0].R, partials,
		musig2.WithTweakedCombine(message, keys, tweaks, true),
	)
	aggregate, _, _, err := musig2.AggregateKeys(
		keys, true, musig2.WithKeyTweaks(tweaks...),
	)
	require.NoError(t, err)
	require.True(t, sig.Verify(message[:], aggregate.FinalKey))
	return sig.Serialize()
}

// TestMuSigSpends completes real key-path and script-path spends after multiple
// BIP328 derivations. The script engine checks the aggregate signature, final
// TapTweak, sighash, leaf script and control block rather than only key
// equality.
func TestMuSigSpends(t *testing.T) {
	t.Parallel()
	var signers []*btcec.PrivateKey
	var keys []*btcec.PublicKey
	var xpubs []string
	for i := range byte(2) {
		seed := make([]byte, 32)
		seed[0] = i + 1
		master, err := hdkeychain.NewMaster(
			seed, &chaincfg.MainNetParams,
		)
		require.NoError(t, err)
		private, err := master.ECPrivKey()
		require.NoError(t, err)
		public, err := master.Neuter()
		require.NoError(t, err)
		signers = append(signers, private)
		keys = append(keys, private.PubKey())
		xpubs = append(xpubs, public.String())
	}
	expression := fmt.Sprintf("musig(%s,%s)/0/*", xpubs[0], xpubs[1])
	aggregate, _, _, err := musig2.AggregateKeys(keys, true)
	require.NoError(t, err)
	root, err := hdkeychain.NewMuSig2Key(
		aggregate.FinalKey, &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	_, internal := btcec.PrivKeyFromBytes([]byte{42})
	internalHex := hex.EncodeToString(schnorr.SerializePubKey(internal))

	for index := range uint32(3) {
		for _, scriptPath := range []bool{false, true} {
			t.Run(
				fmt.Sprintf("index=%d/script=%v", index, scriptPath),
				func(t *testing.T) {
					// Retain each I_L in derivation order
					// and plain mode. The aggregate's Y
					// parity must survive every step.
					derived := root
					var tweaks []musig2.KeyTweakDesc
					for _, childIndex := range []uint32{
						0, index,
					} {

						var tweak [32]byte
						derived, tweak, err = derived.DeriveWithTweak(childIndex)
						require.NoError(t, err)
						tweaks = append(
							tweaks,
							musig2.KeyTweakDesc{
								Tweak: tweak,
							},
						)
					}
					pub, err := derived.ECPubKey()
					require.NoError(t, err)
					leafScript, err := txscript.NewScriptBuilder().
						AddData(schnorr.SerializePubKey(
							pub,
						)).
						AddOp(txscript.OP_CHECKSIG).Script()
					require.NoError(t, err)
					leaf := txscript.NewBaseTapLeaf(
						leafScript,
					)
					leafHash := leaf.TapHash()
					desc := "tr(" + expression + ")"
					if scriptPath {
						desc = "tr(" + internalHex +
							",pk(" + expression +
							"))"
					} else {
						// A key-only Taproot output
						// still has a final x-only
						// TapTweak after all BIP328
						// tweaks.
						tapTweak := chainhash.TaggedHash(
							chainhash.TagTapTweak,
							schnorr.SerializePubKey(
								pub,
							),
						)
						tweaks = append(
							tweaks,
							musig2.KeyTweakDesc{
								Tweak:   [32]byte(*tapTweak),
								IsXOnly: true,
							},
						)
					}
					d, err := NewDescriptor(desc)
					require.NoError(t, err)
					pkScript, err := outputScriptAt(
						d, 0, index,
					)
					require.NoError(t, err)
					definite := fmt.Sprintf("musig(%s,%s)"+
						"/0/%d", xpubs[0], xpubs[1], index)

					// Plan with one finished signature,
					// never with one independently
					// available signature per participant.
					assets := Assets{
						LookupTapKeySpendSig: func(
							key string) (uint32,
							bool) {

							return 64, !scriptPath && key == definite
						},
						LookupTapLeafScriptSig: func(
							key, hash string) (uint32,
							bool) {

							return 64, scriptPath && key == definite && hash == hex.EncodeToString(leafHash[:])
						},
					}
					plan, err := d.PlanAt(0, index, assets)
					require.NoError(t, err)
					_, err = plan.Satisfy(&Satisfier{})
					require.Error(t, err)
					const amount = int64(100000)
					fetcher := txscript.NewCannedPrevOutputFetcher(
						pkScript, amount,
					)
					tx := wire.NewMsgTx(2)
					tx.AddTxIn(wire.NewTxIn(
						&wire.OutPoint{}, nil, nil,
					))
					tx.AddTxOut(&wire.TxOut{
						Value:    amount - 500,
						PkScript: pkScript,
					})
					hashes := txscript.NewTxSigHashes(
						tx, fetcher,
					)
					var digest []byte
					if scriptPath {
						digest, err = txscript.CalcTapscriptSignaturehash(hashes, txscript.SigHashDefault, tx, 0, fetcher, leaf)
					} else {
						digest, err = txscript.CalcTaprootSignatureHash(hashes, txscript.SigHashDefault, tx, 0, fetcher)
					}
					require.NoError(t, err)
					sig := signMuSigSpend(
						t, signers, keys, tweaks,
						[32]byte(digest),
					)
					result, err := plan.Satisfy(&Satisfier{
						LookupTapKeySpendSig: func() ([]byte,
							bool) {

							return sig, !scriptPath
						},
						LookupTapLeafScriptSig: func(
							key, hash string) ([]byte,
							bool) {

							return sig, scriptPath && key == definite && hash == hex.EncodeToString(leafHash[:])
						},
					})
					require.NoError(t, err)

					// Consensus execution is the final
					// check that the planner, signer and
					// output construction agree.
					tx.TxIn[0].Witness = result.Witness
					tx.TxIn[0].SignatureScript = result.ScriptSig
					engine, err := txscript.NewEngine(
						pkScript, tx, 0,
						txscript.StandardVerifyFlags,
						nil, hashes, amount, fetcher,
					)
					require.NoError(t, err)
					require.NoError(t, engine.Execute())
				},
			)
		}
	}
}
