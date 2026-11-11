//go:build rpctest
// +build rpctest

package integration

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestRebindableSignature tests the three op codes of BIP 448 together, by
// using them for what the BIP calls a rebindable signature: The taproot
// internal key (OP_INTERNALKEY, BIP 349) signs the template hash of a
// transaction (OP_TEMPLATEHASH, BIP 446), and that signature is verified by
// OP_CHECKSIGFROMSTACK (BIP 348). Such a signature commits to the transaction
// that spends an output, but not to the output itself, so it can be used to
// spend any output with the same script.
func TestRebindableSignature(t *testing.T) {
	t.Parallel()

	// Integration tests require a full harness setup which is
	// resource-intensive.
	if testing.Short() {
		t.Skip("Skipping rebindable signature integration test in " +
			"short mode")
	}

	// We use regtest, where taproot and the deployments of all three op
	// codes are always active.
	harness, err := rpctest.New(&chaincfg.RegressionNetParams, nil, nil, "")
	require.NoError(t, err)
	defer harness.TearDown()

	require.NoError(t, harness.SetUp(true, 25))
	for _, forkKey := range []string{
		"templatehash", "checksigfromstack", "internalkey",
	} {
		assertSoftForkStatus(
			harness, t, forkKey, blockchain.ThresholdActive,
		)
	}

	// Create the taproot output with a single leaf that requires a
	// signature of the internal key over the template hash.
	internalPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	internalKey := internalPrivKey.PubKey()

	leafScript := []byte{
		txscript.OP_TEMPLATEHASH, txscript.OP_INTERNALKEY,
		txscript.OP_CHECKSIGFROMSTACK,
	}
	tree := txscript.AssembleTaprootScriptTree(
		txscript.NewBaseTapLeaf(leafScript),
	)
	rootHash := tree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, rootHash[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	ctrlBlock := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	// This is the transaction that is signed. The template hash doesn't
	// cover the outpoint that is spent, so we can sign the transaction
	// before the output it spends exists.
	const (
		fundingAmount = btcutil.Amount(100_000)
		spendAmount   = btcutil.Amount(90_000)
	)
	spendAddr, err := harness.NewAddress()
	require.NoError(t, err)
	spendScript, err := txscript.PayToAddrScript(spendAddr)
	require.NoError(t, err)

	spendTx := wire.NewMsgTx(wire.TxVersion)
	spendTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	spendTx.AddTxOut(wire.NewTxOut(int64(spendAmount), spendScript))

	templateHash, err := txscript.CalcTemplateHash(nil, spendTx, 0, nil)
	require.NoError(t, err)

	sig, err := schnorr.Sign(internalPrivKey, templateHash)
	require.NoError(t, err)
	witness := wire.TxWitness{sig.Serialize(), leafScript, ctrlBlockBytes}

	// fundOutput sends coins to the output and returns the signed
	// transaction, bound to the new output.
	fundOutput := func() *wire.MsgTx {
		fundingTxHash, err := harness.SendOutputs([]*wire.TxOut{
			wire.NewTxOut(int64(fundingAmount), pkScript),
		}, 10)
		require.NoError(t, err)

		fundingTx, err := harness.Client.GetRawTransaction(fundingTxHash)
		require.NoError(t, err)

		outputIndex := -1
		for idx, txOut := range fundingTx.MsgTx().TxOut {
			if bytes.Equal(txOut.PkScript, pkScript) {
				outputIndex = idx
			}
		}
		require.NotEqual(t, -1, outputIndex)

		_, err = harness.Client.Generate(1)
		require.NoError(t, err)

		tx := spendTx.Copy()
		tx.TxIn[0].PreviousOutPoint = wire.OutPoint{
			Hash:  *fundingTxHash,
			Index: uint32(outputIndex),
		}
		tx.TxIn[0].Witness = witness

		return tx
	}

	// requireMined asserts that the transaction is part of the block.
	requireMined := func(block *wire.MsgBlock, tx *wire.MsgTx) {
		txHash := tx.TxHash()
		for _, blockTx := range block.Transactions {
			if blockTx.TxHash() == txHash {
				return
			}
		}

		require.Failf(t, "tx not mined", "tx %v not in block", txHash)
	}

	// requireRejected asserts that the transaction is rejected by the
	// mempool and that a block that contains it is invalid, in both cases
	// because the signature doesn't verify. The latter proves that the op
	// codes are part of the consensus rules.
	requireRejected := func(name string, tx *wire.MsgTx) {
		const sigFailure = "signature not valid for message"

		_, err := harness.Client.SendRawTransaction(tx, true)
		require.ErrorContains(t, err, sigFailure, name)

		_, err = harness.GenerateAndSubmitBlock(
			[]*btcutil.Tx{btcutil.NewTx(tx)}, -1, time.Time{},
		)
		require.ErrorContains(t, err, sigFailure, name)
	}

	// The signature isn't valid for a transaction that doesn't match the
	// template that was signed.
	validTx := fundOutput()

	invalidTx := validTx.Copy()
	invalidTx.TxOut[0].Value--
	requireRejected("output value", invalidTx)

	invalidTx = validTx.Copy()
	invalidTx.LockTime = 1
	requireRejected("locktime", invalidTx)

	// Neither is the signature of any other key than the internal key.
	otherPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	otherSig, err := schnorr.Sign(otherPrivKey, templateHash)
	require.NoError(t, err)

	invalidTx = validTx.Copy()
	invalidTx.TxIn[0].Witness = wire.TxWitness{
		otherSig.Serialize(), leafScript, ctrlBlockBytes,
	}
	requireRejected("other key", invalidTx)

	// The transaction that was signed is accepted to the mempool and gets
	// included in the next block the node creates.
	validTxHash, err := harness.Client.SendRawTransaction(validTx, true)
	require.NoError(t, err)
	require.Equal(t, validTx.TxHash(), *validTxHash)

	blockHashes, err := harness.Client.Generate(1)
	require.NoError(t, err)
	require.Len(t, blockHashes, 1)

	block, err := harness.Client.GetBlock(blockHashes[0])
	require.NoError(t, err)
	requireMined(block, validTx)

	// The very same signature can be used again to spend another output
	// with the same script, this time in a block that wasn't assembled
	// from the mempool of the node.
	reboundTx := fundOutput()
	require.Equal(t, validTx.TxIn[0].Witness, reboundTx.TxIn[0].Witness)
	require.NotEqual(
		t, validTx.TxIn[0].PreviousOutPoint,
		reboundTx.TxIn[0].PreviousOutPoint,
	)

	submittedBlock, err := harness.GenerateAndSubmitBlock(
		[]*btcutil.Tx{btcutil.NewTx(reboundTx)}, -1, time.Time{},
	)
	require.NoError(t, err)

	bestHash, err := harness.Client.GetBestBlockHash()
	require.NoError(t, err)
	require.Equal(t, submittedBlock.Hash(), bestHash)
	requireMined(submittedBlock.MsgBlock(), reboundTx)
}
