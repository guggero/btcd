package txscript

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// tapscriptDebugEngine returns an engine for the first input of the test
// transaction, spending the given leaf script with the given witness stack.
func tapscriptDebugEngine(t *testing.T, script []byte, stack wire.TxWitness,
	flags ScriptFlags) *Engine {

	t.Helper()

	pkScript, witness := tapscriptTestLeaf(t, BaseLeafVersion, script)

	tx := tapscriptTestTx(t)
	tx.TxIn[0].Witness = append(stack, witness...)

	prevOuts := tapscriptTestPrevOuts(tx)
	prevOuts.AddPrevOut(tx.TxIn[0].PreviousOutPoint, &wire.TxOut{
		Value:    1_000,
		PkScript: pkScript,
	})

	vm, err := NewEngine(
		pkScript, tx, 0, flags, nil, NewTxSigHashes(tx, prevOuts),
		1_000, prevOuts,
	)
	require.NoError(t, err)

	return vm
}

// TestTapscriptSigOpsBudget tests that the remaining signature operation
// budget of a tapscript spend is reported as it is used up.
func TestTapscriptSigOpsBudget(t *testing.T) {
	t.Parallel()

	const flags = tapscriptTestFlags | ScriptVerifyCheckSigFromStack

	privKey, pubKey := tapscriptTestInternalKey()
	msg := make([]byte, 32)
	sig, err := schnorr.Sign(privKey, msg)
	require.NoError(t, err)

	// Two signature checks: the first one with a signature, which is
	// charged, and the second one with an empty signature, which is free.
	script, err := NewScriptBuilder().
		AddData(msg).
		AddData(schnorr.SerializePubKey(pubKey)).
		AddOp(OP_CHECKSIGFROMSTACK).
		AddOp(OP_VERIFY).
		AddData(msg).
		AddData(schnorr.SerializePubKey(pubKey)).
		AddOp(OP_CHECKSIGFROMSTACK).
		AddOp(OP_NOT).
		Script()
	require.NoError(t, err)

	vm := tapscriptDebugEngine(
		t, script, wire.TxWitness{{}, sig.Serialize()}, flags,
	)

	// There is no budget before the engine got to the witness program.
	_, ok := vm.TapscriptSigOpsBudget()
	require.False(t, ok)

	// Step through the script and record every change of the budget.
	var budgets []int32
	for done := false; !done; {
		done, err = vm.Step()
		require.NoError(t, err)

		budget, ok := vm.TapscriptSigOpsBudget()
		if !ok {
			continue
		}
		if len(budgets) == 0 || budgets[len(budgets)-1] != budget {
			budgets = append(budgets, budget)
		}
	}
	require.NoError(t, vm.CheckErrorCondition(true))

	// The budget starts at 50 plus the size of the witness, and only the
	// check of the non-empty signature costs 50.
	witnessSize := int32(vm.tx.TxIn[0].Witness.SerializeSize())
	require.Equal(
		t, []int32{sigOpsDelta + witnessSize, witnessSize}, budgets,
	)
	require.False(t, vm.TapscriptOpSuccess())
}

// TestTapscriptSigOpsBudgetNonTaproot tests that no budget is reported for an
// input that isn't a taproot spend.
func TestTapscriptSigOpsBudgetNonTaproot(t *testing.T) {
	t.Parallel()

	tx := tapscriptTestTx(t)
	pkScript := []byte{OP_TRUE}

	vm, err := NewEngine(
		pkScript, tx, 0, tapscriptTestFlags, nil, nil, 1_000,
		tapscriptTestPrevOuts(tx),
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute())

	_, ok := vm.TapscriptSigOpsBudget()
	require.False(t, ok)
	require.False(t, vm.TapscriptOpSuccess())
}

// TestTapscriptOpSuccess tests that a tapscript that succeeds because of an
// OP_SUCCESS op code is reported as such, and that this follows the flags of
// the op codes that were given a meaning by a soft fork.
func TestTapscriptOpSuccess(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		script    []byte
		flags     ScriptFlags
		opSuccess bool
	}{{
		name:   "no OP_SUCCESS",
		script: []byte{OP_TRUE},
		flags:  tapscriptTestFlags,
	}, {
		name:      "plain OP_SUCCESS",
		script:    []byte{OP_RETURN, OP_UNKNOWN187},
		flags:     tapscriptTestFlags,
		opSuccess: true,
	}, {
		name:      "inactive OP_INTERNALKEY",
		script:    []byte{OP_RETURN, OP_INTERNALKEY},
		flags:     tapscriptTestFlags,
		opSuccess: true,
	}, {
		name:   "active OP_INTERNALKEY",
		script: []byte{OP_INTERNALKEY},
		flags:  tapscriptTestFlags | ScriptVerifyInternalKey,
	}, {
		name:      "active OP_INTERNALKEY next to an inactive one",
		script:    []byte{OP_RETURN, OP_INTERNALKEY, OP_TEMPLATEHASH},
		flags:     tapscriptTestFlags | ScriptVerifyInternalKey,
		opSuccess: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vm := tapscriptDebugEngine(t, tc.script, nil, tc.flags)
			require.False(t, vm.TapscriptOpSuccess())

			require.NoError(t, vm.Execute())
			require.Equal(t, tc.opSuccess, vm.TapscriptOpSuccess())
		})
	}
}
