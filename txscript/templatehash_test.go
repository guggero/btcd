// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

const (
	// templateHashTestTx is the transaction the basic BIP 446 test vectors
	// are built around, without any witness data. It has two inputs and a
	// single output.
	templateHashTestTx = "0200000002c997a5e56e104102fa209c6a852dd90660a2" +
		"0b2d9c352423edce25857fcd37041500000000ffffffff169e1e83e9308" +
		"53391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f40c000000" +
		"00ffffffff01327906000000000016001482074bdf6ce32b071dd120a17" +
		"cf99cbc01ad308000000000"

	// templateHashTestNoAnnex is the template hash of the first input of
	// the test transaction when that input has no annex, as committed to
	// in the BIP 446 test vectors.
	templateHashTestNoAnnex = "d1f1955b1327167cb7ae3dc39d52c277be39d7573" +
		"7b9cb80514ce6e825fd8eea"

	// templateHashTestAnnex is the annex used by the BIP 446 test vectors.
	templateHashTestAnnex = "5064617461"

	// templateHashTestWithAnnex is the template hash of the first input of
	// the test transaction when that input carries the test annex, as
	// committed to in the BIP 446 test vectors.
	templateHashTestWithAnnex = "40ee92735bd9b32fc51d9b6df6be4dafc834cf38" +
		"3506dcb45a61151aeee3460c"
)

// tapscriptTestPrevOuts returns a previous output fetcher for the inputs
// of the given transaction, where every input spends the same dummy output.
func tapscriptTestPrevOuts(tx *wire.MsgTx) *MultiPrevOutFetcher {
	prevOuts := NewMultiPrevOutFetcher(nil)
	for _, txIn := range tx.TxIn {
		prevOuts.AddPrevOut(txIn.PreviousOutPoint, &wire.TxOut{
			Value:    1_000,
			PkScript: []byte{OP_TRUE},
		})
	}

	return prevOuts
}

// tapscriptTestTx parses the transaction all the tapscript tests in this file
// are based on.
func tapscriptTestTx(t *testing.T) *wire.MsgTx {
	t.Helper()

	txBytes, err := hex.DecodeString(templateHashTestTx)
	require.NoError(t, err)

	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(txBytes)))

	return &tx
}

// TestCalcTemplateHash asserts that the template hash matches the values of
// the BIP 446 test vectors, with and without an annex, and independently of
// whether the pre-computed sighash midstate is supplied.
func TestCalcTemplateHash(t *testing.T) {
	t.Parallel()

	tx := tapscriptTestTx(t)
	sigHashes := NewTxSigHashes(tx, tapscriptTestPrevOuts(tx))

	annex, err := hex.DecodeString(templateHashTestAnnex)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		sigHashes *TxSigHashes
		annex     []byte
		expected  string
	}{{
		name:      "no annex",
		sigHashes: sigHashes,
		expected:  templateHashTestNoAnnex,
	}, {
		name:     "no annex, no sighash midstate",
		expected: templateHashTestNoAnnex,
	}, {
		name:      "annex",
		sigHashes: sigHashes,
		annex:     annex,
		expected:  templateHashTestWithAnnex,
	}, {
		name:     "annex, no sighash midstate",
		annex:    annex,
		expected: templateHashTestWithAnnex,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			templateHash, err := CalcTemplateHash(
				tc.sigHashes, tx, 0, tc.annex,
			)
			require.NoError(t, err)
			require.Equal(
				t, tc.expected, hex.EncodeToString(templateHash),
			)
		})
	}
}

// TestCalcTemplateHashInvalidIndex asserts that an input index that doesn't
// exist in the transaction is rejected.
func TestCalcTemplateHashInvalidIndex(t *testing.T) {
	t.Parallel()

	tx := tapscriptTestTx(t)

	for _, idx := range []int{-1, len(tx.TxIn), len(tx.TxIn) + 1} {
		_, err := CalcTemplateHash(nil, tx, idx, nil)
		require.Error(t, err, "index %d", idx)
	}
}

// TestCalcTemplateHashCommitments asserts that the template hash changes with
// every field BIP 446 commits to, and with none of the fields it leaves out.
func TestCalcTemplateHashCommitments(t *testing.T) {
	t.Parallel()

	annex, err := hex.DecodeString(templateHashTestAnnex)
	require.NoError(t, err)

	// calc returns the template hash for the first input, always using a
	// freshly computed sighash midstate for the mutated transaction.
	calc := func(tx *wire.MsgTx, idx int, annex []byte) []byte {
		sigHashes := NewTxSigHashes(tx, tapscriptTestPrevOuts(tx))
		templateHash, err := CalcTemplateHash(sigHashes, tx, idx, annex)
		require.NoError(t, err)

		return templateHash
	}

	baseTx := tapscriptTestTx(t)
	baseHash := calc(baseTx, 0, nil)

	testCases := []struct {
		name      string
		mutate    func(tx *wire.MsgTx)
		idx       int
		annex     []byte
		committed bool
	}{{
		name: "version",
		mutate: func(tx *wire.MsgTx) {
			tx.Version = 42
		},
		committed: true,
	}, {
		name: "locktime",
		mutate: func(tx *wire.MsgTx) {
			tx.LockTime = 42
		},
		committed: true,
	}, {
		name: "sequence of this input",
		mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].Sequence = 42
		},
		committed: true,
	}, {
		name: "sequence of another input",
		mutate: func(tx *wire.MsgTx) {
			tx.TxIn[1].Sequence = 42
		},
		committed: true,
	}, {
		name: "output value",
		mutate: func(tx *wire.MsgTx) {
			tx.TxOut[0].Value++
		},
		committed: true,
	}, {
		name: "output script",
		mutate: func(tx *wire.MsgTx) {
			tx.TxOut[0].PkScript[0] ^= 0x01
		},
		committed: true,
	}, {
		name: "additional output",
		mutate: func(tx *wire.MsgTx) {
			tx.AddTxOut(wire.NewTxOut(0, nil))
		},
		committed: true,
	}, {
		name: "additional input",
		mutate: func(tx *wire.MsgTx) {
			tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
		},
		committed: true,
	}, {
		name:      "input index",
		mutate:    func(tx *wire.MsgTx) {},
		idx:       1,
		committed: true,
	}, {
		name:      "annex presence",
		mutate:    func(tx *wire.MsgTx) {},
		annex:     []byte{TaprootAnnexTag},
		committed: true,
	}, {
		name: "previous outpoint of this input",
		mutate: func(tx *wire.MsgTx) {
			tx.TxIn[0].PreviousOutPoint.Index++
		},
	}, {
		name: "previous outpoint of another input",
		mutate: func(tx *wire.MsgTx) {
			tx.TxIn[1].PreviousOutPoint.Hash[0] ^= 0x01
		},
	}, {
		name: "signature script of another input",
		mutate: func(tx *wire.MsgTx) {
			tx.TxIn[1].SignatureScript = []byte{OP_TRUE}
		},
	}, {
		name: "witness of another input",
		mutate: func(tx *wire.MsgTx) {
			tx.TxIn[1].Witness = wire.TxWitness{
				{0x01}, {TaprootAnnexTag, 0x02},
			}
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := baseTx.Copy()
			tc.mutate(tx)

			templateHash := calc(tx, tc.idx, tc.annex)
			if tc.committed {
				require.NotEqual(t, baseHash, templateHash)
			} else {
				require.Equal(t, baseHash, templateHash)
			}
		})
	}

	// Two different annexes must result in two different template hashes,
	// and the length of the annex must be committed to as well.
	annexHash := calc(baseTx, 0, annex)
	require.NotEqual(t, annexHash, calc(baseTx, 0, annex[:len(annex)-1]))
	require.NotEqual(
		t, annexHash, calc(baseTx, 0, append([]byte{}, annex[:4]...)),
	)
}
