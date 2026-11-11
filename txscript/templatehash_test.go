// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
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

const (
	// tapscriptTestFlags is the set of consensus flags that is active on
	// a chain that enforces taproot.
	tapscriptTestFlags = ScriptBip16 | ScriptVerifyWitness |
		ScriptVerifyTaproot

	// templateHashTestFlagsActive is the set of consensus flags that is
	// active on a chain that enforces taproot and BIP 446.
	templateHashTestFlagsActive = tapscriptTestFlags |
		ScriptVerifyTemplateHash
)

// tapscriptTestInternalKey returns the key pair that is used as the internal
// key of the taproot outputs created by tapscriptTestLeaf.
func tapscriptTestInternalKey() (*btcec.PrivateKey, *btcec.PublicKey) {
	return btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x01}, 32))
}

// tapscriptTestLeaf returns the pkScript of a taproot output that commits
// to a single leaf with the given version and script, along with the witness
// elements that reveal that leaf.
func tapscriptTestLeaf(t *testing.T, leafVersion TapscriptLeafVersion,
	script []byte) ([]byte, wire.TxWitness) {

	t.Helper()

	_, internalKey := tapscriptTestInternalKey()

	tree := AssembleTaprootScriptTree(NewTapLeaf(leafVersion, script))
	rootHash := tree.RootNode.TapHash()
	outputKey := ComputeTaprootOutputKey(internalKey, rootHash[:])

	pkScript, err := PayToTaprootScript(outputKey)
	require.NoError(t, err)

	ctrlBlock := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	return pkScript, wire.TxWitness{script, ctrlBlockBytes}
}

// tapscriptTestExecute validates the given input of the transaction
// against the passed previous output script.
func tapscriptTestExecute(tx *wire.MsgTx, idx int, pkScript []byte,
	flags ScriptFlags, withSigHashes bool) error {

	prevOuts := tapscriptTestPrevOuts(tx)
	prevOuts.AddPrevOut(tx.TxIn[idx].PreviousOutPoint, &wire.TxOut{
		Value:    1_000,
		PkScript: pkScript,
	})

	var sigHashes *TxSigHashes
	if withSigHashes {
		sigHashes = NewTxSigHashes(tx, prevOuts)
	}

	vm, err := NewEngine(
		pkScript, tx, idx, flags, nil, sigHashes, 1_000, prevOuts,
	)
	if err != nil {
		return err
	}

	return vm.Execute()
}

// requireScriptErr asserts that the error is a script error with
// the expected error code, or nil if no error code is expected.
func requireScriptErr(t *testing.T, err error, expected *ErrorCode) {
	t.Helper()

	if expected == nil {
		require.NoError(t, err)
		return
	}

	require.Error(t, err)
	require.Truef(
		t, IsErrorCode(err, *expected), "expected error code %v, "+
			"got: %v", *expected, err,
	)
}

// errCode returns a pointer to the given error code, to distinguish an
// expected ErrInternal from the absence of an error in test tables.
func errCode(code ErrorCode) *ErrorCode {
	return &code
}

// TestOpTemplateHashOpSuccess asserts that OP_TEMPLATEHASH keeps behaving as
// an OP_SUCCESS until ScriptVerifyTemplateHash is set, that the two policy
// flags discouraging its use are applied in the order the op codes appear in
// the script, and that a remaining OP_SUCCESS still makes a script succeed
// once OP_TEMPLATEHASH is active.
func TestOpTemplateHashOpSuccess(t *testing.T) {
	t.Parallel()

	const (
		active        = ScriptVerifyTemplateHash
		discourage    = ScriptVerifyDiscourageTemplateHash
		discourageAll = ScriptVerifyDiscourageOpSuccess
	)

	var (
		errTemplate  = errCode(ErrDiscourageTemplateHash)
		errOpSuccess = errCode(ErrDiscourageOpSuccess)
	)

	testCases := []struct {
		name   string
		script []byte

		// expected maps the flags that are set in addition to the base
		// taproot flags to the expected result.
		expected map[ScriptFlags]*ErrorCode
	}{{
		// Executing the op code leaves the template hash as the only,
		// truthy, element on the stack.
		name:   "only op code",
		script: []byte{OP_TEMPLATEHASH},
		expected: map[ScriptFlags]*ErrorCode{
			0:                                   nil,
			discourageAll:                       errOpSuccess,
			discourage:                          errTemplate,
			discourage | discourageAll:          errTemplate,
			active:                              nil,
			active | discourageAll:              nil,
			active | discourage:                 errTemplate,
			active | discourage | discourageAll: errTemplate,
		},
	}, {
		// The script only fails if the op code is actually executed.
		name:   "dropped template hash",
		script: []byte{OP_TEMPLATEHASH, OP_DROP},
		expected: map[ScriptFlags]*ErrorCode{
			0:                          nil,
			discourageAll:              errOpSuccess,
			discourage:                 errTemplate,
			active:                     errCode(ErrCleanStack),
			active | discourageAll:     errCode(ErrCleanStack),
			active | discourage:        errTemplate,
			discourage | discourageAll: errTemplate,
		},
	}, {
		// An OP_SUCCESS before the op code decides the outcome.
		name:   "preceded by op success",
		script: []byte{OP_RESERVED, OP_TEMPLATEHASH},
		expected: map[ScriptFlags]*ErrorCode{
			0:                                   nil,
			discourageAll:                       errOpSuccess,
			discourage:                          nil,
			discourage | discourageAll:          errOpSuccess,
			active:                              nil,
			active | discourageAll:              errOpSuccess,
			active | discourage:                 nil,
			active | discourage | discourageAll: errOpSuccess,
		},
	}, {
		// An OP_SUCCESS after the op code still makes the script
		// succeed without executing anything.
		name:   "followed by op success",
		script: []byte{OP_TEMPLATEHASH, OP_DROP, OP_RESERVED},
		expected: map[ScriptFlags]*ErrorCode{
			0:                                   nil,
			discourageAll:                       errOpSuccess,
			discourage:                          errTemplate,
			discourage | discourageAll:          errTemplate,
			active:                              nil,
			active | discourageAll:              errOpSuccess,
			active | discourage:                 errTemplate,
			active | discourage | discourageAll: errTemplate,
		},
	}, {
		// The op code is discouraged even if it isn't executed.
		name: "unexecuted branch",
		script: []byte{
			OP_0, OP_IF, OP_TEMPLATEHASH, OP_ENDIF, OP_1,
		},
		expected: map[ScriptFlags]*ErrorCode{
			0:                      nil,
			discourageAll:          errOpSuccess,
			discourage:             errTemplate,
			active:                 nil,
			active | discourageAll: nil,
			active | discourage:    errTemplate,
		},
	}, {
		// As an OP_SUCCESS the op code hides a parse error behind it.
		// Once active, the script must parse in full.
		name:   "followed by truncated push",
		script: []byte{OP_TEMPLATEHASH, OP_DATA_2, 0x01},
		expected: map[ScriptFlags]*ErrorCode{
			0:                   nil,
			discourageAll:       errOpSuccess,
			active:              errCode(ErrMalformedPush),
			active | discourage: errTemplate,
		},
	}}

	for _, tc := range testCases {
		pkScript, witness := tapscriptTestLeaf(
			t, BaseLeafVersion, tc.script,
		)

		tx := tapscriptTestTx(t)
		tx.TxIn[0].Witness = witness

		for extraFlags, expectedErr := range tc.expected {
			flags := tapscriptTestFlags | extraFlags
			err := tapscriptTestExecute(
				tx, 0, pkScript, flags, true,
			)

			if expectedErr == nil {
				require.NoErrorf(
					t, err, "%s, flags %b", tc.name,
					extraFlags,
				)
				continue
			}

			require.Truef(
				t, IsErrorCode(err, *expectedErr), "%s, flags "+
					"%b: expected error code %v, got: %v",
				tc.name, extraFlags, *expectedErr, err,
			)
		}
	}
}

// TestOpTemplateHashUnknownLeafVersion asserts that the op code has no
// meaning in a tapscript leaf with a version we don't know the rules for.
func TestOpTemplateHashUnknownLeafVersion(t *testing.T) {
	t.Parallel()

	const leafVersion TapscriptLeafVersion = 0xc2

	script := []byte{OP_TEMPLATEHASH, OP_DROP}
	pkScript, witness := tapscriptTestLeaf(t, leafVersion, script)

	tx := tapscriptTestTx(t)
	tx.TxIn[0].Witness = witness

	// The script would fail if it was executed, and it would be rejected
	// as non-standard if it was a base leaf. Neither is the case as the
	// leaf must remain opaque.
	flags := templateHashTestFlagsActive |
		ScriptVerifyDiscourageTemplateHash |
		ScriptVerifyDiscourageOpSuccess
	err := tapscriptTestExecute(tx, 0, pkScript, flags, true)
	require.NoError(t, err)

	flags |= ScriptVerifyDiscourageUpgradeableTaprootVersion
	err = tapscriptTestExecute(tx, 0, pkScript, flags, true)
	requireScriptErr(
		t, err, errCode(ErrDiscourageUpgradeableTaprootVersion),
	)
}

// TestOpTemplateHashOutsideTapscript asserts that the op code remains an
// invalid op code that only fails a script if it's executed everywhere but in
// tapscript, no matter whether BIP 446 is active.
func TestOpTemplateHashOutsideTapscript(t *testing.T) {
	t.Parallel()

	script := []byte{OP_IF, OP_TEMPLATEHASH, OP_ENDIF, OP_1}
	scriptPush, err := NewScriptBuilder().AddData(script).Script()
	require.NoError(t, err)

	p2shScript, err := payToScriptHashScript(address.Hash160(script))
	require.NoError(t, err)

	witnessScriptHash := sha256.Sum256(script)
	p2wshScript, err := payToWitnessScriptHashScript(witnessScriptHash[:])
	require.NoError(t, err)

	testCases := []struct {
		name     string
		pkScript []byte

		// spend returns the signature script and witness that select
		// whether the branch with the op code is executed.
		spend func(execute bool) ([]byte, wire.TxWitness)
	}{{
		name:     "bare",
		pkScript: script,
		spend: func(execute bool) ([]byte, wire.TxWitness) {
			if execute {
				return []byte{OP_1}, nil
			}

			return []byte{OP_0}, nil
		},
	}, {
		name:     "p2sh",
		pkScript: p2shScript,
		spend: func(execute bool) ([]byte, wire.TxWitness) {
			if execute {
				return append([]byte{OP_1}, scriptPush...), nil
			}

			return append([]byte{OP_0}, scriptPush...), nil
		},
	}, {
		name:     "p2wsh",
		pkScript: p2wshScript,
		spend: func(execute bool) ([]byte, wire.TxWitness) {
			if execute {
				return nil, wire.TxWitness{{0x01}, script}
			}

			return nil, wire.TxWitness{{}, script}
		},
	}}

	flagSets := []ScriptFlags{
		tapscriptTestFlags,
		templateHashTestFlagsActive,
		templateHashTestFlagsActive |
			ScriptVerifyDiscourageTemplateHash |
			ScriptVerifyDiscourageOpSuccess,
	}

	for _, tc := range testCases {
		for _, flags := range flagSets {
			tx := tapscriptTestTx(t)

			sigScript, witness := tc.spend(false)
			tx.TxIn[0].SignatureScript = sigScript
			tx.TxIn[0].Witness = witness
			err := tapscriptTestExecute(
				tx, 0, tc.pkScript, flags, true,
			)
			require.NoErrorf(t, err, "%s, flags %b", tc.name, flags)

			sigScript, witness = tc.spend(true)
			tx.TxIn[0].SignatureScript = sigScript
			tx.TxIn[0].Witness = witness
			err = tapscriptTestExecute(
				tx, 0, tc.pkScript, flags, true,
			)
			require.Truef(
				t, IsErrorCode(err, ErrReservedOpcode), "%s, "+
					"flags %b: unexpected error: %v",
				tc.name, flags, err,
			)
		}
	}
}

// TestOpTemplateHashValue asserts that the op code pushes the template hash
// of the input being validated, taking the annex of that input into account,
// and that it does so with or without a pre-computed sighash midstate.
func TestOpTemplateHashValue(t *testing.T) {
	t.Parallel()

	annex, err := hex.DecodeString(templateHashTestAnnex)
	require.NoError(t, err)

	testCases := []struct {
		name string
		idx  int

		// committedAnnex is the annex the script commits to, while
		// annex is the one the input is actually spent with.
		committedAnnex []byte
		annex          []byte

		expectedErr *ErrorCode
	}{{
		name: "first input",
	}, {
		name: "second input",
		idx:  1,
	}, {
		name:           "annex",
		committedAnnex: annex,
		annex:          annex,
	}, {
		name:        "unexpected annex",
		annex:       annex,
		expectedErr: errCode(ErrEvalFalse),
	}, {
		name:           "missing annex",
		committedAnnex: annex,
		expectedErr:    errCode(ErrEvalFalse),
	}, {
		name:           "different annex",
		committedAnnex: annex,
		annex:          []byte{TaprootAnnexTag},
		expectedErr:    errCode(ErrEvalFalse),
	}}

	for _, tc := range testCases {
		tx := tapscriptTestTx(t)

		templateHash, err := CalcTemplateHash(
			nil, tx, tc.idx, tc.committedAnnex,
		)
		require.NoError(t, err)

		script, err := NewScriptBuilder().AddData(templateHash).
			AddOp(OP_TEMPLATEHASH).AddOp(OP_EQUAL).Script()
		require.NoError(t, err)

		pkScript, witness := tapscriptTestLeaf(
			t, BaseLeafVersion, script,
		)
		if tc.annex != nil {
			witness = append(witness, tc.annex)
		}
		tx.TxIn[tc.idx].Witness = witness

		for _, withSigHashes := range []bool{true, false} {
			err := tapscriptTestExecute(
				tx, tc.idx, pkScript,
				templateHashTestFlagsActive, withSigHashes,
			)
			requireScriptErr(t, err, tc.expectedErr)
		}

		// The committed hash is just data as long as the op code is an
		// OP_SUCCESS.
		err = tapscriptTestExecute(
			tx, tc.idx, pkScript, tapscriptTestFlags,
			true,
		)
		require.NoError(t, err, tc.name)
	}
}

// TestOpTemplateHashRepeated asserts that every execution of the op code
// within a script pushes the same value.
func TestOpTemplateHashRepeated(t *testing.T) {
	t.Parallel()

	script := []byte{
		OP_TEMPLATEHASH, OP_TEMPLATEHASH, OP_EQUALVERIFY,
		OP_TEMPLATEHASH, OP_SIZE, OP_DATA_1, 0x20, OP_EQUALVERIFY,
		OP_TEMPLATEHASH, OP_EQUAL,
	}
	pkScript, witness := tapscriptTestLeaf(t, BaseLeafVersion, script)

	tx := tapscriptTestTx(t)
	tx.TxIn[0].Witness = append(witness, []byte{TaprootAnnexTag, 0x01})

	for _, withSigHashes := range []bool{true, false} {
		err := tapscriptTestExecute(
			tx, 0, pkScript, templateHashTestFlagsActive,
			withSigHashes,
		)
		require.NoError(t, err)
	}
}

// TestOpTemplateHashStackLimit asserts that the element the op code pushes
// counts towards the maximum stack size.
func TestOpTemplateHashStackLimit(t *testing.T) {
	t.Parallel()

	script := []byte{OP_TEMPLATEHASH}
	pkScript, witness := tapscriptTestLeaf(t, BaseLeafVersion, script)

	// stackItems returns a witness that leaves the given number of
	// elements on the stack before the script is executed.
	stackItems := func(num int) wire.TxWitness {
		items := make(wire.TxWitness, 0, num+len(witness))
		for i := 0; i < num; i++ {
			items = append(items, []byte{0x01})
		}

		return append(items, witness...)
	}

	// With one element less than the limit on the stack the template hash
	// can still be pushed. The script then only fails because it leaves
	// more than one element behind.
	tx := tapscriptTestTx(t)
	tx.TxIn[0].Witness = stackItems(MaxStackSize - 1)
	err := tapscriptTestExecute(
		tx, 0, pkScript, templateHashTestFlagsActive, true,
	)
	requireScriptErr(t, err, errCode(ErrCleanStack))

	// With a full stack, pushing the template hash exceeds the limit.
	tx.TxIn[0].Witness = stackItems(MaxStackSize)
	err = tapscriptTestExecute(
		tx, 0, pkScript, templateHashTestFlagsActive, true,
	)
	requireScriptErr(t, err, errCode(ErrStackOverflow))
}

// TestOpTemplateHashOpcodeName asserts that the op code can be looked up by
// its new name as well as by the name it had as an unknown op code.
func TestOpTemplateHashOpcodeName(t *testing.T) {
	t.Parallel()

	require.EqualValues(t, 0xce, OP_TEMPLATEHASH)
	require.EqualValues(t, OP_UNKNOWN206, OP_TEMPLATEHASH)
	require.Equal(t, byte(OP_TEMPLATEHASH), OpcodeByName["OP_TEMPLATEHASH"])
	require.Equal(t, byte(OP_TEMPLATEHASH), OpcodeByName["OP_UNKNOWN206"])

	disasm, err := DisasmString([]byte{OP_TEMPLATEHASH, OP_EQUAL})
	require.NoError(t, err)
	require.Equal(t, "OP_TEMPLATEHASH OP_EQUAL", disasm)
}

// BenchmarkOpTemplateHash measures the validation of a script that executes
// the op code many times for an input with a large annex. The annex must only
// be hashed once for the cost per execution to stay constant.
func BenchmarkOpTemplateHash(b *testing.B) {
	const (
		numExecutions = 10_000
		annexSize     = 100_000
	)

	script := make([]byte, 0, 2*numExecutions+1)
	for i := 0; i < numExecutions; i++ {
		script = append(script, OP_TEMPLATEHASH, OP_DROP)
	}
	script = append(script, OP_TEMPLATEHASH)

	_, internalKey := tapscriptTestInternalKey()

	tree := AssembleTaprootScriptTree(NewBaseTapLeaf(script))
	rootHash := tree.RootNode.TapHash()
	outputKey := ComputeTaprootOutputKey(internalKey, rootHash[:])
	pkScript, err := PayToTaprootScript(outputKey)
	require.NoError(b, err)

	ctrlBlock := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(b, err)

	annex := make([]byte, annexSize)
	annex[0] = TaprootAnnexTag

	txBytes, err := hex.DecodeString(templateHashTestTx)
	require.NoError(b, err)

	var tx wire.MsgTx
	require.NoError(b, tx.Deserialize(bytes.NewReader(txBytes)))
	tx.TxIn[0].Witness = wire.TxWitness{script, ctrlBlockBytes, annex}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := tapscriptTestExecute(
			&tx, 0, pkScript, templateHashTestFlagsActive, true,
		)
		require.NoError(b, err)
	}
}
