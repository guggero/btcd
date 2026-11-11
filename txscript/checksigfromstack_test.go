// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// checkSigFromStackTestFlags is the set of consensus flags that is active on a
// chain that enforces taproot and BIP 348.
const checkSigFromStackTestFlags = tapscriptTestFlags |
	ScriptVerifyCheckSigFromStack

// checkSigFromStackTestScript returns a script that pushes the given elements
// onto the stack, followed by the given op codes.
func checkSigFromStackTestScript(t *testing.T, pushes [][]byte,
	opcodes ...byte) []byte {

	t.Helper()

	builder := NewScriptBuilder()
	for _, push := range pushes {
		builder.AddData(push)
	}
	for _, opcode := range opcodes {
		builder.AddOp(opcode)
	}

	script, err := builder.Script()
	require.NoError(t, err)

	return script
}

// checkSigFromStackTestExecute spends a taproot output through a leaf with
// the given script, with the given elements as the initial stack.
func checkSigFromStackTestExecute(t *testing.T, script []byte,
	stack [][]byte, flags ScriptFlags) error {

	t.Helper()

	pkScript, witness := tapscriptTestLeaf(t, BaseLeafVersion, script)

	tx := tapscriptTestTx(t)
	tx.TxIn[0].Witness = append(
		append(wire.TxWitness{}, stack...), witness...,
	)

	return tapscriptTestExecute(tx, 0, pkScript, flags, true)
}

// TestOpCheckSigFromStack asserts that the op code verifies a BIP 340
// signature over a message from the stack according to the rules of BIP 348.
func TestOpCheckSigFromStack(t *testing.T) {
	t.Parallel()

	const (
		csfs             = OP_CHECKSIGFROMSTACK
		discouragePubKey = ScriptVerifyDiscourageUpgradeablePubkeyType
	)

	// A key, a 32-byte message and a valid BIP 340 signature over it.
	privKey, pubKey := btcec.PrivKeyFromBytes(
		bytes.Repeat([]byte{0x02}, 32),
	)
	pubKeyBytes := schnorr.SerializePubKey(pubKey)

	msg := bytes.Repeat([]byte{0x03}, 32)
	sig, err := schnorr.Sign(privKey, msg)
	require.NoError(t, err)
	sigBytes := sig.Serialize()
	require.Len(t, sigBytes, 64)

	// A second key the signature is not valid for.
	_, otherPubKey := btcec.PrivKeyFromBytes(
		bytes.Repeat([]byte{0x04}, 32),
	)
	otherPubKeyBytes := schnorr.SerializePubKey(otherPubKey)

	// mutate returns a copy of the passed bytes that is changed by the
	// given function.
	mutate := func(b []byte, change func([]byte) []byte) []byte {
		return change(append([]byte{}, b...))
	}
	flipBit := func(b []byte) []byte {
		b[10] ^= 0x01
		return b
	}
	dropByte := func(b []byte) []byte {
		return b[:len(b)-1]
	}
	appendZero := func(b []byte) []byte {
		return append(b, 0x00)
	}
	appendOne := func(b []byte) []byte {
		return append(b, 0x01)
	}

	// A 32-byte public key that isn't the x coordinate of a point on the
	// curve, and one that exceeds the field size. Both are taken from the
	// BIP 340 test vectors.
	notOnCurvePubKey, err := hex.DecodeString("eefdea4cdb677750a420fee80" +
		"7eacf21eb9898ae79b9768766e4faa04a2d4a34")
	require.NoError(t, err)
	tooBigPubKey, err := hex.DecodeString("fffffffffffffffffffffffffffff" +
		"ffffffffffffffffffffffffffefffffc30")
	require.NoError(t, err)
	require.Len(t, notOnCurvePubKey, schnorr.PubKeyBytesLen)
	require.Len(t, tooBigPubKey, schnorr.PubKeyBytesLen)

	// Public keys of a type we don't know.
	unknownPubKeys := [][]byte{
		{0x01},
		bytes.Repeat([]byte{0x02}, 31),
		bytes.Repeat([]byte{0x02}, 33),
		bytes.Repeat([]byte{0x02}, 64),
	}

	testCases := []struct {
		name string

		// sig, msg and pubKey are pushed onto the stack by the script,
		// followed by the op code under test and extraOps.
		sig      []byte
		msg      []byte
		pubKey   []byte
		extraOps []byte

		extraFlags  ScriptFlags
		expectedErr *ErrorCode
	}{{
		name:   "valid signature",
		sig:    sigBytes,
		msg:    msg,
		pubKey: pubKeyBytes,
	}, {
		// A valid signature results in exactly the byte 0x01.
		name:     "valid signature pushes one",
		sig:      sigBytes,
		msg:      msg,
		pubKey:   pubKeyBytes,
		extraOps: []byte{OP_1, OP_EQUAL},
	}, {
		name:        "modified signature",
		sig:         mutate(sigBytes, flipBit),
		msg:         msg,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		name:        "modified message",
		sig:         sigBytes,
		msg:         mutate(msg, flipBit),
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		name:        "truncated message",
		sig:         sigBytes,
		msg:         mutate(msg, dropByte),
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		name:        "extended message",
		sig:         sigBytes,
		msg:         mutate(msg, appendZero),
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		name:        "empty message",
		sig:         sigBytes,
		msg:         nil,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		name:        "other public key",
		sig:         sigBytes,
		msg:         msg,
		pubKey:      otherPubKeyBytes,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		// The signature can't be parsed, as neither of its two values
		// is within the allowed range.
		name:        "signature out of range",
		sig:         bytes.Repeat([]byte{0xff}, 64),
		msg:         msg,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		name:        "public key not on curve",
		sig:         sigBytes,
		msg:         msg,
		pubKey:      notOnCurvePubKey,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		name:        "public key exceeds field size",
		sig:         sigBytes,
		msg:         msg,
		pubKey:      tooBigPubKey,
		expectedErr: errCode(ErrTaprootSigInvalid),
	}, {
		// A public key is only looked at if there is a signature to
		// verify.
		name:     "empty signature, public key not on curve",
		msg:      msg,
		pubKey:   notOnCurvePubKey,
		extraOps: []byte{OP_NOT},
	}, {
		name:        "signature too short",
		sig:         mutate(sigBytes, dropByte),
		msg:         msg,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrInvalidTaprootSigLen),
	}, {
		// Unlike for the other signature checking op codes there is no
		// sighash type that could be appended to the signature.
		name:        "signature with sighash type",
		sig:         mutate(sigBytes, appendOne),
		msg:         msg,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrInvalidTaprootSigLen),
	}, {
		name:        "signature with zero byte",
		sig:         mutate(sigBytes, appendZero),
		msg:         msg,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrInvalidTaprootSigLen),
	}, {
		name:        "single byte signature",
		sig:         []byte{0x01},
		msg:         msg,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrInvalidTaprootSigLen),
	}, {
		// An empty signature isn't an error, the result is false.
		name:     "empty signature",
		msg:      msg,
		pubKey:   pubKeyBytes,
		extraOps: []byte{OP_NOT},
	}, {
		// That result is the empty vector.
		name:     "empty signature pushes empty vector",
		msg:      msg,
		pubKey:   pubKeyBytes,
		extraOps: []byte{OP_0, OP_EQUAL},
	}, {
		name:        "empty signature is false",
		msg:         msg,
		pubKey:      pubKeyBytes,
		expectedErr: errCode(ErrEvalFalse),
	}, {
		name:        "empty public key",
		sig:         sigBytes,
		msg:         msg,
		expectedErr: errCode(ErrTaprootPubkeyIsEmpty),
	}, {
		name:        "empty signature, empty public key",
		msg:         msg,
		extraOps:    []byte{OP_NOT},
		expectedErr: errCode(ErrTaprootPubkeyIsEmpty),
	}}

	// For a public key of an unknown type, any signature that isn't empty
	// is valid, unless such keys are discouraged.
	for _, unknownPubKey := range unknownPubKeys {
		testCases = append(testCases, []struct {
			name        string
			sig         []byte
			msg         []byte
			pubKey      []byte
			extraOps    []byte
			extraFlags  ScriptFlags
			expectedErr *ErrorCode
		}{{
			name:     "unknown public key type",
			sig:      []byte{0x01},
			msg:      msg,
			pubKey:   unknownPubKey,
			extraOps: []byte{OP_1, OP_EQUAL},
		}, {
			name:     "unknown public key type, valid signature",
			sig:      sigBytes,
			msg:      msg,
			pubKey:   unknownPubKey,
			extraOps: []byte{OP_1, OP_EQUAL},
		}, {
			name:     "unknown public key type, empty signature",
			msg:      msg,
			pubKey:   unknownPubKey,
			extraOps: []byte{OP_0, OP_EQUAL},
		}, {
			name:        "discouraged public key type",
			sig:         []byte{0x01},
			msg:         msg,
			pubKey:      unknownPubKey,
			extraFlags:  discouragePubKey,
			expectedErr: errCode(ErrDiscourageUpgradeablePubKeyType),
		}, {
			name: "discouraged public key type, empty " +
				"signature",
			msg:         msg,
			pubKey:      unknownPubKey,
			extraOps:    []byte{OP_NOT},
			extraFlags:  discouragePubKey,
			expectedErr: errCode(ErrDiscourageUpgradeablePubKeyType),
		}}...)
	}

	for _, tc := range testCases {
		opcodes := append([]byte{csfs}, tc.extraOps...)
		pushes := [][]byte{tc.sig, tc.msg, tc.pubKey}
		flags := checkSigFromStackTestFlags | tc.extraFlags

		// The result must be the same no matter whether the three
		// elements are pushed by the script or come from the witness.
		script := checkSigFromStackTestScript(t, pushes, opcodes...)
		err := checkSigFromStackTestExecute(t, script, nil, flags)
		if tc.expectedErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Truef(
				t, IsErrorCode(err, *tc.expectedErr), "%s: "+
					"expected error code %v, got: %v",
				tc.name, *tc.expectedErr, err,
			)
		}

		script = checkSigFromStackTestScript(t, nil, opcodes...)
		err = checkSigFromStackTestExecute(t, script, pushes, flags)
		if tc.expectedErr == nil {
			require.NoError(t, err, tc.name)
		} else {
			require.Truef(
				t, IsErrorCode(err, *tc.expectedErr), "%s: "+
					"expected error code %v, got: %v",
				tc.name, *tc.expectedErr, err,
			)
		}

		// As long as the op code isn't active, it remains an
		// OP_SUCCESS and none of this is looked at.
		err = checkSigFromStackTestExecute(
			t, script, pushes, tapscriptTestFlags,
		)
		require.NoError(t, err, tc.name)
	}
}

// TestOpCheckSigFromStackMessageSize asserts that the op code verifies
// signatures over messages of any size without hashing them, by using the BIP
// 340 test vectors for messages of variable length.
func TestOpCheckSigFromStackMessageSize(t *testing.T) {
	t.Parallel()

	const pubKeyHex = "778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086" +
		"497324d6fd117"

	testCases := []struct {
		msg string
		sig string
	}{{
		msg: "",
		sig: "71535db165ecd9fbbc046e5ffaea61186bb6ad436732fccc25291a55" +
			"895464cf6069ce26bf03466228f19a3a62db8a649f2d560fac6528" +
			"27d1af0574e427ab63",
	}, {
		msg: "11",
		sig: "08a20a0afef64124649232e0693c583ab1b9934ae63b4c3511f3ae11" +
			"34c6a303ea3173bfea6683bd101fa5aa5dbc1996fe7cacfc5a577d" +
			"33ec14564cec2bacbf",
	}, {
		msg: "0102030405060708090a0b0c0d0e0f1011",
		sig: "5130f39a4059b43bc7cac09a19ece52b5d8699d1a71e3c52da9afdb6" +
			"b50ac370c4a482b77bf960f8681540e25b6771ece1e5a37fd80e5a" +
			"51897c5566a97ea5a5",
	}, {
		msg: "99999999999999999999999999999999999999999999999999999999" +
			"99999999999999999999999999999999999999999999999999999" +
			"99999999999999999999999999999999999999999999999999999" +
			"99999999999999999999999999999999999999",
		sig: "403b12b0d8555a344175ea7ec746566303321e5dbfa8be6f09163516" +
			"3eca79a8585ed3e3170807e7c03b720fc54c7b23897fcba0e9d0b4" +
			"a06894cfd249f22367",
	}}

	pubKey, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)

	for _, tc := range testCases {
		msg, err := hex.DecodeString(tc.msg)
		require.NoError(t, err)
		sig, err := hex.DecodeString(tc.sig)
		require.NoError(t, err)

		// The signature and the message come from the witness, where
		// a push doesn't need to be minimal.
		script := checkSigFromStackTestScript(
			t, [][]byte{pubKey}, OP_CHECKSIGFROMSTACK,
		)
		err = checkSigFromStackTestExecute(
			t, script, [][]byte{sig, msg},
			checkSigFromStackTestFlags,
		)
		require.NoErrorf(t, err, "message size %d", len(msg))

		// The signature isn't valid for a message that is one byte
		// longer.
		longerMsg := append(append([]byte{}, msg...), 0x00)
		err = checkSigFromStackTestExecute(
			t, script, [][]byte{sig, longerMsg},
			checkSigFromStackTestFlags,
		)
		require.Truef(
			t, IsErrorCode(err, ErrTaprootSigInvalid), "message "+
				"size %d: unexpected error: %v", len(msg), err,
		)
	}

	// A message can be as large as a stack element can be.
	privKey, sigPubKey := btcec.PrivKeyFromBytes(
		bytes.Repeat([]byte{0x02}, 32),
	)
	script := checkSigFromStackTestScript(
		t, [][]byte{schnorr.SerializePubKey(sigPubKey)},
		OP_CHECKSIGFROMSTACK, OP_NOT,
	)
	maxMsg := bytes.Repeat([]byte{0x05}, MaxScriptElementSize)
	err = checkSigFromStackTestExecute(
		t, script, [][]byte{{}, maxMsg}, checkSigFromStackTestFlags,
	)
	require.NoError(t, err)

	tooBigMsg := append(maxMsg, 0x05)
	err = checkSigFromStackTestExecute(
		t, script, [][]byte{{}, tooBigMsg}, checkSigFromStackTestFlags,
	)
	requireScriptErr(t, err, errCode(ErrElementTooBig))

	// A 32-byte message is verified the same way a sighash is, so a
	// signature created for a hash is valid.
	msg := bytes.Repeat([]byte{0x06}, 32)
	sig, err := schnorr.Sign(privKey, msg)
	require.NoError(t, err)

	script = checkSigFromStackTestScript(
		t, [][]byte{schnorr.SerializePubKey(sigPubKey)},
		OP_CHECKSIGFROMSTACK,
	)
	err = checkSigFromStackTestExecute(
		t, script, [][]byte{sig.Serialize(), msg},
		checkSigFromStackTestFlags,
	)
	require.NoError(t, err)
}

// TestOpCheckSigFromStackStack asserts that the op code fails the script if
// there are fewer than three elements on the stack, and that it consumes
// exactly three of them.
func TestOpCheckSigFromStackStack(t *testing.T) {
	t.Parallel()

	script := []byte{OP_CHECKSIGFROMSTACK, OP_NOT}
	pubKey := bytes.Repeat([]byte{0x02}, 33)
	msg := []byte{0x01, 0x02}

	for numElements := 0; numElements < 3; numElements++ {
		stack := [][]byte{{}, msg, pubKey}[3-numElements:]
		err := checkSigFromStackTestExecute(
			t, script, stack, checkSigFromStackTestFlags,
		)
		require.Truef(
			t, IsErrorCode(err, ErrInvalidStackOperation), "%d "+
				"elements: unexpected error: %v", numElements,
			err,
		)
	}

	err := checkSigFromStackTestExecute(
		t, script, [][]byte{{}, msg, pubKey},
		checkSigFromStackTestFlags,
	)
	require.NoError(t, err)

	// A fourth element is left untouched, which violates the clean stack
	// rule.
	err = checkSigFromStackTestExecute(
		t, script, [][]byte{{0x01}, {}, msg, pubKey},
		checkSigFromStackTestFlags,
	)
	requireScriptErr(t, err, errCode(ErrCleanStack))
}

// TestOpCheckSigFromStackSigOps asserts that each execution of the op code
// with a signature that isn't empty counts towards the sig ops budget of the
// input, the same way it does for the other signature checking op codes.
func TestOpCheckSigFromStackSigOps(t *testing.T) {
	t.Parallel()

	privKey, pubKey := btcec.PrivKeyFromBytes(
		bytes.Repeat([]byte{0x02}, 32),
	)
	pubKeyBytes := schnorr.SerializePubKey(pubKey)

	msg := bytes.Repeat([]byte{0x03}, 32)
	sig, err := schnorr.Sign(privKey, msg)
	require.NoError(t, err)

	// repeatedScript returns a script that executes the op code the given
	// number of times with the same three elements.
	repeatedScript := func(sig, pubKey []byte, num int) []byte {
		builder := NewScriptBuilder().AddData(sig).AddData(msg).
			AddData(pubKey)
		for i := 0; i < num; i++ {
			builder.AddOp(OP_3DUP).AddOp(OP_CHECKSIGFROMSTACK).
				AddOp(OP_DROP)
		}
		builder.AddOp(OP_2DROP).AddOp(OP_DROP).AddOp(OP_1)

		script, err := builder.Script()
		require.NoError(t, err)

		return script
	}

	// execute validates the script and returns the result along with the
	// sig ops budget of the input, which is the size of the witness plus
	// the budget every input starts with.
	execute := func(script []byte) (int, error) {
		pkScript, witness := tapscriptTestLeaf(t, BaseLeafVersion, script)

		tx := tapscriptTestTx(t)
		tx.TxIn[0].Witness = witness

		err := tapscriptTestExecute(
			tx, 0, pkScript, checkSigFromStackTestFlags, true,
		)

		return witness.SerializeSize() + sigOpsDelta, err
	}

	// Each valid signature uses up the same amount of the budget, while
	// each execution only adds three bytes to it. So at some point the
	// budget is exceeded.
	var numFailed int
	for num := 1; num <= 20; num++ {
		script := repeatedScript(sig.Serialize(), pubKeyBytes, num)
		budget, err := execute(script)

		if num*sigOpsDelta <= budget {
			require.NoErrorf(t, err, "%d executions", num)
			continue
		}

		numFailed++
		require.Truef(
			t, IsErrorCode(err, ErrTaprootMaxSigOps), "%d "+
				"executions: unexpected error: %v", num, err,
		)
	}
	require.NotZero(t, numFailed)
	require.NotEqual(t, 20, numFailed)

	// The same goes for a signature that is valid because the type of the
	// public key is unknown.
	unknownPubKey := bytes.Repeat([]byte{0x02}, 33)
	_, err = execute(repeatedScript([]byte{0x01}, unknownPubKey, 3))
	require.NoError(t, err)
	_, err = execute(repeatedScript([]byte{0x01}, unknownPubKey, 100))
	requireScriptErr(t, err, errCode(ErrTaprootMaxSigOps))

	// An empty signature doesn't count towards the budget, no matter how
	// often the op code is executed.
	_, err = execute(repeatedScript(nil, pubKeyBytes, 300))
	require.NoError(t, err)
	_, err = execute(repeatedScript(nil, unknownPubKey, 300))
	require.NoError(t, err)
}

// TestRebindableSignature asserts that the three op codes of BIP 448 can be
// combined into a signature check that commits to the transaction spending an
// output, but not to the output itself: the internal key signs the template
// hash.
func TestRebindableSignature(t *testing.T) {
	t.Parallel()

	const flags = tapscriptTestFlags | ScriptVerifyTemplateHash |
		ScriptVerifyInternalKey | ScriptVerifyCheckSigFromStack

	script := []byte{
		OP_TEMPLATEHASH, OP_INTERNALKEY, OP_CHECKSIGFROMSTACK,
	}
	pkScript, witness := tapscriptTestLeaf(t, BaseLeafVersion, script)

	// Sign the template hash of the transaction with the internal key.
	internalPrivKey, _ := tapscriptTestInternalKey()
	tx := tapscriptTestTx(t)
	templateHash, err := CalcTemplateHash(nil, tx, 0, nil)
	require.NoError(t, err)

	sig, err := schnorr.Sign(internalPrivKey, templateHash)
	require.NoError(t, err)

	tx.TxIn[0].Witness = append(wire.TxWitness{sig.Serialize()}, witness...)
	err = tapscriptTestExecute(tx, 0, pkScript, flags, true)
	require.NoError(t, err)

	// The signature remains valid if the transaction spends a different
	// output with the same script.
	reboundTx := tx.Copy()
	reboundTx.TxIn[0].PreviousOutPoint.Index++
	err = tapscriptTestExecute(reboundTx, 0, pkScript, flags, true)
	require.NoError(t, err)

	// It's not valid for a transaction that doesn't match the template.
	otherTx := tx.Copy()
	otherTx.TxOut[0].Value--
	err = tapscriptTestExecute(otherTx, 0, pkScript, flags, true)
	requireScriptErr(t, err, errCode(ErrTaprootSigInvalid))

	// Each of the op codes has its own flag. As long as one of them isn't
	// set, the script contains an OP_SUCCESS and nothing is verified.
	for _, missing := range []ScriptFlags{
		ScriptVerifyTemplateHash, ScriptVerifyInternalKey,
		ScriptVerifyCheckSigFromStack,
	} {
		err = tapscriptTestExecute(
			otherTx, 0, pkScript, flags&^missing, true,
		)
		require.NoError(t, err)
	}
}

// TestOpCheckSigFromStackOpcodeName asserts that the op code can be looked up
// by its new name as well as by the name it had as an unknown op code.
func TestOpCheckSigFromStackOpcodeName(t *testing.T) {
	t.Parallel()

	require.EqualValues(t, 0xcc, OP_CHECKSIGFROMSTACK)
	require.EqualValues(t, OP_UNKNOWN204, OP_CHECKSIGFROMSTACK)
	require.Equal(
		t, byte(OP_CHECKSIGFROMSTACK),
		OpcodeByName["OP_CHECKSIGFROMSTACK"],
	)
	require.Equal(
		t, byte(OP_CHECKSIGFROMSTACK), OpcodeByName["OP_UNKNOWN204"],
	)

	disasm, err := DisasmString([]byte{OP_CHECKSIGFROMSTACK, OP_VERIFY})
	require.NoError(t, err)
	require.Equal(t, "OP_CHECKSIGFROMSTACK OP_VERIFY", disasm)
}
