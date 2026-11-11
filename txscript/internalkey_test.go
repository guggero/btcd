// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// upgradedSuccessOpcodeTest describes how an op code that was given a meaning
// by a soft fork is expected to behave in the tests that are shared by all of
// these op codes.
type upgradedSuccessOpcodeTest struct {
	name   string
	opcode byte

	// activeFlag and discourageFlag are the two script flags of the op
	// code, discourageErr is the error code expected while it is
	// discouraged.
	activeFlag     ScriptFlags
	discourageFlag ScriptFlags
	discourageErr  ErrorCode

	// executeErr is the error code that is expected if a script consisting
	// of nothing but the op code is executed with an empty stack, or nil
	// if such a script is valid.
	executeErr *ErrorCode
}

// upgradedSuccessOpcodeTests lists the op codes that were given a meaning by a
// soft fork.
var upgradedSuccessOpcodeTests = []upgradedSuccessOpcodeTest{{
	// The template hash is the only, truthy, element left on the stack.
	name:           "OP_TEMPLATEHASH",
	opcode:         OP_TEMPLATEHASH,
	activeFlag:     ScriptVerifyTemplateHash,
	discourageFlag: ScriptVerifyDiscourageTemplateHash,
	discourageErr:  ErrDiscourageTemplateHash,
}, {
	// The internal key is the only, truthy, element left on the stack.
	name:           "OP_INTERNALKEY",
	opcode:         OP_INTERNALKEY,
	activeFlag:     ScriptVerifyInternalKey,
	discourageFlag: ScriptVerifyDiscourageInternalKey,
	discourageErr:  ErrDiscourageInternalKey,
}}

// TestUpgradedSuccessOpcodesTable asserts that the tests cover all the op
// codes that were given a meaning by a soft fork, with the flags and error
// code the engine uses for them.
func TestUpgradedSuccessOpcodesTable(t *testing.T) {
	t.Parallel()

	require.Len(t, upgradedSuccessOpcodeTests, len(upgradedSuccessOpcodes))

	for _, tc := range upgradedSuccessOpcodeTests {
		// Each of the op codes must still be an OP_SUCCESS op code
		// for as long as its flag isn't set.
		require.Contains(t, successOpcodes, tc.opcode, tc.name)
		require.True(t, ScriptHasOpSuccess([]byte{tc.opcode}), tc.name)

		upgrade, ok := upgradedSuccessOpcodes[tc.opcode]
		require.True(t, ok, tc.name)
		require.Equal(t, tc.activeFlag, upgrade.activeFlag, tc.name)
		require.Equal(
			t, tc.discourageFlag, upgrade.discourageFlag, tc.name,
		)
		require.Equal(t, tc.discourageErr, upgrade.discourageErr, tc.name)

		// The name used in the engine is the name of the op code.
		require.Equal(t, tc.name, opcodeArray[tc.opcode].name)
		require.Equal(t, tc.opcode, OpcodeByName[tc.name])
	}
}

// TestUpgradedSuccessOpcodes asserts for each op code that was given a meaning
// by a soft fork that it keeps behaving as an OP_SUCCESS until its flag is
// set, that the two policy flags discouraging its use are applied in the order
// the op codes appear in the script, that a remaining OP_SUCCESS still makes a
// script succeed once the op code is active, and that none of that depends on
// the flags of any other op code.
func TestUpgradedSuccessOpcodes(t *testing.T) {
	t.Parallel()

	const discourageAll = ScriptVerifyDiscourageOpSuccess

	errOpSuccess := errCode(ErrDiscourageOpSuccess)

	for _, tc := range upgradedSuccessOpcodeTests {
		var (
			op         = tc.opcode
			active     = tc.activeFlag
			discourage = tc.discourageFlag
			errUpgrade = errCode(tc.discourageErr)
		)

		// The flags of all the other op codes must not make a
		// difference, so we run every test without and with them.
		var otherFlags ScriptFlags
		for _, other := range upgradedSuccessOpcodeTests {
			if other.opcode == op {
				continue
			}

			otherFlags |= other.activeFlag | other.discourageFlag
		}

		testCases := []struct {
			name   string
			script []byte

			// expected maps the flags that are set in addition to
			// the base taproot flags to the expected result.
			expected map[ScriptFlags]*ErrorCode
		}{{
			name:   "only op code",
			script: []byte{op},
			expected: map[ScriptFlags]*ErrorCode{
				0:                                   nil,
				discourageAll:                       errOpSuccess,
				discourage:                          errUpgrade,
				discourage | discourageAll:          errUpgrade,
				active:                              tc.executeErr,
				active | discourageAll:              tc.executeErr,
				active | discourage:                 errUpgrade,
				active | discourage | discourageAll: errUpgrade,
			},
		}, {
			// An OP_SUCCESS before the op code decides the outcome.
			name:   "preceded by op success",
			script: []byte{OP_RESERVED, op},
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
			// An OP_SUCCESS after the op code still makes the
			// script succeed without executing anything.
			name:   "followed by op success",
			script: []byte{op, OP_RESERVED},
			expected: map[ScriptFlags]*ErrorCode{
				0:                                   nil,
				discourageAll:                       errOpSuccess,
				discourage:                          errUpgrade,
				discourage | discourageAll:          errUpgrade,
				active:                              nil,
				active | discourageAll:              errOpSuccess,
				active | discourage:                 errUpgrade,
				active | discourage | discourageAll: errUpgrade,
			},
		}, {
			// The op code is discouraged even if it isn't executed.
			name:   "unexecuted branch",
			script: []byte{OP_0, OP_IF, op, OP_ENDIF, OP_1},
			expected: map[ScriptFlags]*ErrorCode{
				0:                      nil,
				discourageAll:          errOpSuccess,
				discourage:             errUpgrade,
				active:                 nil,
				active | discourageAll: nil,
				active | discourage:    errUpgrade,
			},
		}, {
			// As an OP_SUCCESS the op code hides a parse error
			// behind it. Once active, the script must parse in
			// full.
			name:   "followed by truncated push",
			script: []byte{op, OP_DATA_2, 0x01},
			expected: map[ScriptFlags]*ErrorCode{
				0:                   nil,
				discourageAll:       errOpSuccess,
				active:              errCode(ErrMalformedPush),
				active | discourage: errUpgrade,
			},
		}}

		for _, testCase := range testCases {
			pkScript, witness := tapscriptTestLeaf(
				t, BaseLeafVersion, testCase.script,
			)

			tx := tapscriptTestTx(t)
			tx.TxIn[0].Witness = witness

			for extraFlags, expectedErr := range testCase.expected {
				for _, other := range []ScriptFlags{0, otherFlags} {
					flags := tapscriptTestFlags | extraFlags |
						other
					err := tapscriptTestExecute(
						tx, 0, pkScript, flags, true,
					)

					if expectedErr == nil {
						require.NoErrorf(
							t, err, "%s: %s, flags %b",
							tc.name, testCase.name,
							flags,
						)

						continue
					}

					require.Truef(
						t, IsErrorCode(err, *expectedErr),
						"%s: %s, flags %b: expected "+
							"error code %v, got: %v",
						tc.name, testCase.name, flags,
						*expectedErr, err,
					)
				}
			}
		}
	}
}

// TestUpgradedSuccessOpcodesUnknownLeafVersion asserts that none of the op
// codes has a meaning in a tapscript leaf with a version we don't know the
// rules for.
func TestUpgradedSuccessOpcodesUnknownLeafVersion(t *testing.T) {
	t.Parallel()

	const leafVersion TapscriptLeafVersion = 0xc2

	for _, tc := range upgradedSuccessOpcodeTests {
		// The script would fail if it was executed, and it would be
		// rejected as non-standard if it was a base leaf. Neither is
		// the case as the leaf must remain opaque.
		script := []byte{tc.opcode, OP_RETURN}
		pkScript, witness := tapscriptTestLeaf(t, leafVersion, script)

		tx := tapscriptTestTx(t)
		tx.TxIn[0].Witness = witness

		flags := tapscriptTestFlags | tc.activeFlag | tc.discourageFlag |
			ScriptVerifyDiscourageOpSuccess
		err := tapscriptTestExecute(tx, 0, pkScript, flags, true)
		require.NoError(t, err, tc.name)

		flags |= ScriptVerifyDiscourageUpgradeableTaprootVersion
		err = tapscriptTestExecute(tx, 0, pkScript, flags, true)
		requireScriptErr(
			t, err, errCode(ErrDiscourageUpgradeableTaprootVersion),
		)
	}
}

// TestUpgradedSuccessOpcodesOutsideTapscript asserts that each of the op codes
// remains an invalid op code that only fails a script if it's executed
// everywhere but in tapscript, no matter whether its soft fork is active.
func TestUpgradedSuccessOpcodesOutsideTapscript(t *testing.T) {
	t.Parallel()

	for _, tc := range upgradedSuccessOpcodeTests {
		script := []byte{OP_IF, tc.opcode, OP_ENDIF, OP_1}
		scriptPush, err := NewScriptBuilder().AddData(script).Script()
		require.NoError(t, err)

		p2shScript, err := payToScriptHashScript(
			address.Hash160(script),
		)
		require.NoError(t, err)

		witnessScriptHash := sha256.Sum256(script)
		p2wshScript, err := payToWitnessScriptHashScript(
			witnessScriptHash[:],
		)
		require.NoError(t, err)

		testCases := []struct {
			name     string
			pkScript []byte

			// spend returns the signature script and witness that
			// select whether the branch with the op code is
			// executed.
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
					return append(
						[]byte{OP_1}, scriptPush...,
					), nil
				}

				return append([]byte{OP_0}, scriptPush...), nil
			},
		}, {
			name:     "p2wsh",
			pkScript: p2wshScript,
			spend: func(execute bool) ([]byte, wire.TxWitness) {
				if execute {
					return nil, wire.TxWitness{
						{0x01}, script,
					}
				}

				return nil, wire.TxWitness{{}, script}
			},
		}}

		flagSets := []ScriptFlags{
			tapscriptTestFlags,
			tapscriptTestFlags | tc.activeFlag,
			tapscriptTestFlags | tc.activeFlag | tc.discourageFlag |
				ScriptVerifyDiscourageOpSuccess,
		}

		for _, testCase := range testCases {
			for _, flags := range flagSets {
				tx := tapscriptTestTx(t)

				sigScript, witness := testCase.spend(false)
				tx.TxIn[0].SignatureScript = sigScript
				tx.TxIn[0].Witness = witness
				err := tapscriptTestExecute(
					tx, 0, testCase.pkScript, flags, true,
				)
				require.NoErrorf(
					t, err, "%s: %s, flags %b", tc.name,
					testCase.name, flags,
				)

				sigScript, witness = testCase.spend(true)
				tx.TxIn[0].SignatureScript = sigScript
				tx.TxIn[0].Witness = witness
				err = tapscriptTestExecute(
					tx, 0, testCase.pkScript, flags, true,
				)
				require.Truef(
					t, IsErrorCode(err, ErrReservedOpcode),
					"%s: %s, flags %b: unexpected error: %v",
					tc.name, testCase.name, flags, err,
				)
			}
		}
	}
}

// internalKeyTestFlags is the set of consensus flags that is active on a chain
// that enforces taproot and BIP 349.
const internalKeyTestFlags = tapscriptTestFlags | ScriptVerifyInternalKey

// TestOpInternalKeyValue asserts that the op code pushes the x-only internal
// key of the taproot output that is spent.
func TestOpInternalKeyValue(t *testing.T) {
	t.Parallel()

	_, internalKey := tapscriptTestInternalKey()
	internalKeyBytes := schnorr.SerializePubKey(internalKey)
	require.Len(t, internalKeyBytes, 32)

	// The output key is a different key, which must not be confused with
	// the internal key.
	otherKey := make([]byte, len(internalKeyBytes))
	copy(otherKey, internalKeyBytes)
	otherKey[0] ^= 0x01

	testCases := []struct {
		name        string
		script      []byte
		expectedErr *ErrorCode
	}{{
		name: "internal key",
		script: append(
			[]byte{OP_INTERNALKEY, OP_DATA_32},
			append(internalKeyBytes, OP_EQUAL)...,
		),
	}, {
		name: "other key",
		script: append(
			[]byte{OP_INTERNALKEY, OP_DATA_32},
			append(otherKey, OP_EQUAL)...,
		),
		expectedErr: errCode(ErrEvalFalse),
	}, {
		name: "size",
		script: []byte{
			OP_INTERNALKEY, OP_SIZE, OP_DATA_1, 0x20,
			OP_EQUALVERIFY, OP_DROP, OP_1,
		},
	}, {
		name: "repeated",
		script: []byte{
			OP_INTERNALKEY, OP_INTERNALKEY, OP_EQUALVERIFY,
			OP_INTERNALKEY, OP_INTERNALKEY, OP_EQUAL,
		},
	}}

	for _, tc := range testCases {
		pkScript, witness := tapscriptTestLeaf(
			t, BaseLeafVersion, tc.script,
		)

		// The output key in the pkScript is not the internal key.
		require.NotEqual(t, internalKeyBytes, pkScript[2:], tc.name)

		// The annex is not part of what the op code looks at.
		for _, annex := range [][]byte{nil, {TaprootAnnexTag, 0x01}} {
			tx := tapscriptTestTx(t)
			tx.TxIn[0].Witness = witness
			if annex != nil {
				tx.TxIn[0].Witness = append(
					wire.TxWitness{}, witness...,
				)
				tx.TxIn[0].Witness = append(
					tx.TxIn[0].Witness, annex,
				)
			}

			err := tapscriptTestExecute(
				tx, 0, pkScript, internalKeyTestFlags, true,
			)
			requireScriptErr(t, err, tc.expectedErr)
		}
	}
}

// TestOpInternalKeyMerkleProof asserts that the op code pushes the internal
// key if the script is revealed with a merkle proof, in which case more data
// follows the internal key in the control block.
func TestOpInternalKeyMerkleProof(t *testing.T) {
	t.Parallel()

	_, internalKey := tapscriptTestInternalKey()
	internalKeyBytes := schnorr.SerializePubKey(internalKey)

	script := append(
		[]byte{OP_INTERNALKEY, OP_DATA_32},
		append(internalKeyBytes, OP_EQUAL)...,
	)
	tree := AssembleTaprootScriptTree(
		NewBaseTapLeaf([]byte{OP_1}), NewBaseTapLeaf(script),
		NewBaseTapLeaf([]byte{OP_2}),
	)
	rootHash := tree.RootNode.TapHash()
	outputKey := ComputeTaprootOutputKey(internalKey, rootHash[:])
	pkScript, err := PayToTaprootScript(outputKey)
	require.NoError(t, err)

	leafIdx, ok := tree.LeafProofIndex[NewBaseTapLeaf(script).TapHash()]
	require.True(t, ok)

	ctrlBlock := tree.LeafMerkleProofs[leafIdx].ToControlBlock(internalKey)
	require.NotEmpty(t, ctrlBlock.InclusionProof)
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	tx := tapscriptTestTx(t)
	tx.TxIn[0].Witness = wire.TxWitness{script, ctrlBlockBytes}

	err = tapscriptTestExecute(tx, 0, pkScript, internalKeyTestFlags, true)
	require.NoError(t, err)
}

// TestOpInternalKeyStackLimit asserts that the element the op code pushes
// counts towards the maximum stack size.
func TestOpInternalKeyStackLimit(t *testing.T) {
	t.Parallel()

	script := []byte{OP_INTERNALKEY}
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

	// With one element less than the limit on the stack the internal key
	// can still be pushed. The script then only fails because it leaves
	// more than one element behind.
	tx := tapscriptTestTx(t)
	tx.TxIn[0].Witness = stackItems(MaxStackSize - 1)
	err := tapscriptTestExecute(tx, 0, pkScript, internalKeyTestFlags, true)
	requireScriptErr(t, err, errCode(ErrCleanStack))

	// With a full stack, pushing the internal key exceeds the limit.
	tx.TxIn[0].Witness = stackItems(MaxStackSize)
	err = tapscriptTestExecute(tx, 0, pkScript, internalKeyTestFlags, true)
	requireScriptErr(t, err, errCode(ErrStackOverflow))
}

// TestOpInternalKeyOpcodeName asserts that the op code can be looked up by
// its new name as well as by the name it had as an unknown op code.
func TestOpInternalKeyOpcodeName(t *testing.T) {
	t.Parallel()

	require.EqualValues(t, 0xcb, OP_INTERNALKEY)
	require.EqualValues(t, OP_UNKNOWN203, OP_INTERNALKEY)
	require.Equal(t, byte(OP_INTERNALKEY), OpcodeByName["OP_INTERNALKEY"])
	require.Equal(t, byte(OP_INTERNALKEY), OpcodeByName["OP_UNKNOWN203"])

	disasm, err := DisasmString([]byte{OP_INTERNALKEY, OP_EQUAL})
	require.NoError(t, err)
	require.Equal(t, "OP_INTERNALKEY OP_EQUAL", disasm)
}
