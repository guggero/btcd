//go:build rpctest
// +build rpctest

package integration

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestTemplateHash tests that an output can be committed to the transaction
// that spends it by using OP_TEMPLATEHASH (BIP 446): The committed transaction
// is relayed and mined, while a transaction that deviates from the template is
// rejected by the mempool as well as by the consensus rules.
func TestTemplateHash(t *testing.T) {
	t.Parallel()

	// Integration tests require a full harness setup which is
	// resource-intensive.
	if testing.Short() {
		t.Skip("Skipping OP_TEMPLATEHASH integration test in short mode")
	}

	// We use regtest, where both taproot and BIP 446 are always active.
	harness, err := rpctest.New(&chaincfg.RegressionNetParams, nil, nil, "")
	require.NoError(t, err)
	defer harness.TearDown()

	require.NoError(t, harness.SetUp(true, 25))
	assertSoftForkStatus(
		harness, t, "templatehash", blockchain.ThresholdActive,
	)

	// This is the transaction we're going to commit an output to. The
	// template hash doesn't cover the outpoint that is spent, so we can
	// calculate it before that output exists.
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

	// Create the taproot output that can only be spent by that
	// transaction. Nobody knows the private key of the internal key, so
	// the script path is the only way to spend the output.
	leafScript, err := txscript.NewScriptBuilder().AddData(templateHash).
		AddOp(txscript.OP_TEMPLATEHASH).AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)

	internalKeyPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	internalKey := internalKeyPriv.PubKey()

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
	witness := wire.TxWitness{leafScript, ctrlBlockBytes}

	// fundOutput sends coins to the output and returns the transaction
	// that spends them according to the template.
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

	// A transaction that changes any of the committed fields must be
	// rejected by the mempool, and a block that contains it is invalid.
	// The latter proves that the op code is part of the consensus rules.
	// In both cases it must be the script that fails, as the template
	// hash on the stack no longer equals the one in the script.
	const scriptFailure = "false stack entry at end of script execution"

	validTx := fundOutput()
	mutations := map[string]func(tx *wire.MsgTx){
		"version": func(tx *wire.MsgTx) {
			tx.Version++
		},
		"locktime": func(tx *wire.MsgTx) {
			tx.LockTime = 1
		},
		"sequence": func(tx *wire.MsgTx) {
			tx.TxIn[0].Sequence--
		},
		"output value": func(tx *wire.MsgTx) {
			tx.TxOut[0].Value--
		},
		"output script": func(tx *wire.MsgTx) {
			tx.TxOut[0].PkScript = pkScript
		},
		"additional output": func(tx *wire.MsgTx) {
			tx.AddTxOut(wire.NewTxOut(1_000, spendScript))
		},
		"annex": func(tx *wire.MsgTx) {
			tx.TxIn[0].Witness = append(
				tx.TxIn[0].Witness,
				[]byte{txscript.TaprootAnnexTag},
			)
		},
	}
	for name, mutate := range mutations {
		invalidTx := validTx.Copy()
		mutate(invalidTx)

		_, err = harness.Client.SendRawTransaction(invalidTx, true)
		require.ErrorContains(t, err, scriptFailure, name)

		_, err = harness.GenerateAndSubmitBlock(
			[]*btcutil.Tx{btcutil.NewTx(invalidTx)}, -1, time.Time{},
		)
		require.ErrorContains(t, err, scriptFailure, name)
	}

	// The transaction we committed to is accepted to the mempool and gets
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

	// The same goes for a block that wasn't assembled from the mempool of
	// the node. Any number of outputs can be committed to the same
	// template, as the outpoint isn't part of it.
	validTx = fundOutput()
	submittedBlock, err := harness.GenerateAndSubmitBlock(
		[]*btcutil.Tx{btcutil.NewTx(validTx)}, -1, time.Time{},
	)
	require.NoError(t, err)

	bestHash, err := harness.Client.GetBestBlockHash()
	require.NoError(t, err)
	require.Equal(t, submittedBlock.Hash(), bestHash)
	requireMined(submittedBlock.MsgBlock(), validTx)
}
