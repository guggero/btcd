package bip322

import (
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// validateToSignTx checks that the to_sign transaction structure conforms to
// the BIP-322 verification process basic validation requirements:
//   - to_sign has at least one input
//   - to_sign's first input spends the output of to_spend (at index 0)
//   - to_sign has exactly one output with value 0 and an OP_RETURN scriptPubKey
//
// The toSpendTxHash argument is the txid of the to_spend transaction
// reconstructed from the message and challenge script.
func validateToSignTx(tx *wire.MsgTx, toSpendTxHash chainhash.Hash) error {
	if len(tx.TxIn) == 0 {
		return fmt.Errorf("%w: to_sign must have at least one input",
			ErrInvalidToSign)
	}

	// The first input must spend the to_spend transaction's only output
	// (at index 0).
	firstPrev := tx.TxIn[0].PreviousOutPoint
	if firstPrev.Hash != toSpendTxHash {
		return fmt.Errorf("%w: to_sign first input prev hash %s does "+
			"not match to_spend txid %s", ErrInvalidToSign,
			firstPrev.Hash, toSpendTxHash)
	}
	if firstPrev.Index != 0 {
		return fmt.Errorf("%w: to_sign first input prev index must be "+
			"0, got %d", ErrInvalidToSign, firstPrev.Index)
	}

	// to_sign must have exactly one output: value 0, scriptPubKey
	// OP_RETURN.
	if len(tx.TxOut) != 1 {
		return fmt.Errorf("%w: to_sign must have exactly one output, "+
			"got %d", ErrInvalidToSign, len(tx.TxOut))
	}
	out := tx.TxOut[0]
	if out.Value != 0 {
		return fmt.Errorf("%w: to_sign output value must be 0, got %d",
			ErrInvalidToSign, out.Value)
	}
	if len(out.PkScript) != 1 || out.PkScript[0] != txscript.OP_RETURN {
		return fmt.Errorf("%w: to_sign output scriptPubKey must be a "+
			"single OP_RETURN byte, got %x", ErrInvalidToSign,
			out.PkScript)
	}

	return nil
}

// validateUpgradeableRules implements the BIP-322 "upgradeable rules" check:
// the to_sign tx version must be 0 or 2. Other versions cause an inconclusive
// result.
//
// The remaining upgradeable rules (no upgrade-reserved NOPs, no Segwit versions
// > 1) are enforced by the script engine via StandardVerifyFlags
// (ScriptDiscourageUpgradableNops,
// ScriptVerifyDiscourageUpgradeableWitnessProgram,
// ScriptVerifyDiscourageUpgradeableTaprootVersion).
func validateUpgradeableRules(version int32) error {
	if version != 0 && version != 2 {
		return fmt.Errorf("%w: to_sign tx version must be 0 or 2, "+
			"got %d", ErrInconclusive, version)
	}
	return nil
}

// validateSigHashFlags inspects the witness stack and signature script of an
// input and ensures that any signature-like elements use the sighash flag
// required by BIP-322:
//   - SIGHASH_DEFAULT (the 64-byte Schnorr form) for P2TR inputs.
//   - SIGHASH_ALL (0x01) for all ECDSA signatures.
//
// The detection is heuristic: a 64-byte witness item in taproot context is
// treated as a SIGHASH_DEFAULT Schnorr signature; a 65-byte one (that doesn't
// look like an uncompressed pubkey, control block, or annex) is treated as a
// Schnorr signature with an explicit (non-default) sighash byte and rejected.
// For non-taproot inputs, items that have a plausible DER signature shape are
// inspected; their trailing sighash byte must be SIGHASH_ALL.
func validateSigHashFlags(utxoPkScript []byte, witness wire.TxWitness,
	sigScript []byte) error {

	if txscript.IsPayToTaproot(utxoPkScript) {
		return validateTaprootSigHashFlags(witness)
	}

	return validateECDSASigHashFlags(witness, sigScript)
}

// validateTaprootSigHashFlags walks a P2TR input's witness stack and rejects
// any Schnorr signatures that don't use SIGHASH_DEFAULT (i.e., aren't in the
// 64-byte form).
//
// The witness is structured as either a key-path spend (1 sig, optionally
// followed by an annex) or a script-path spend (stack items, script, control
// block, optionally annex). We strip annex/script/control_block heuristically
// so the inspection only runs on items that could plausibly be signatures.
func validateTaprootSigHashFlags(witness wire.TxWitness) error {
	if len(witness) == 0 {
		return nil
	}

	items := witness

	// Per BIP-341, if there are 2+ items and the last item starts with
	// 0x50, it is the annex and is removed before script-path/key-path
	// detection.
	if len(items) >= 2 {
		last := items[len(items)-1]
		if len(last) > 0 && last[0] == 0x50 {
			items = items[:len(items)-1]
		}
	}

	switch {
	// Key-path spend: a single item, the signature.
	case len(items) == 1:
		return checkTaprootSig(items[0])

	// Script-path spend: last item is the control block, second-to-last
	// is the tapscript. Inspect every earlier stack item for sigs.
	case len(items) >= 2:
		stack := items[:len(items)-2]
		for _, item := range stack {
			if err := checkTaprootSig(item); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkTaprootSig validates a single Schnorr signature candidate. A 64-byte
// element is SIGHASH_DEFAULT by definition (per BIP-341) and is accepted. A
// 65-byte element carries an explicit sighash byte at index 64, which BIP-322
// allows to be SIGHASH_ALL only. Elements of any other length are not
// signatures and are skipped.
func checkTaprootSig(item []byte) error {
	switch len(item) {
	case 64:
		// SIGHASH_DEFAULT (implicit). OK.
		return nil

	case 65:
		sighash := item[len(item)-1]

		// Explicit SIGHASH_ALL. OK.
		if sighash == byte(txscript.SigHashAll) {
			return nil
		}

		// Schnorr signature with explicit sighash byte.
		return fmt.Errorf("%w: P2TR signature must use "+
			"SIGHASH_DEFAULT (64-byte form), or SIGHASH_ALL "+
			"(65-byte form), got 65-byte signature with incorrect "+
			"sighash byte 0x%02x", ErrInvalidSigHashFlag, item[64])
	}

	return nil
}

// validateECDSASigHashFlags walks an input's witness stack and signature
// script pushes and rejects any DER-encoded ECDSA signatures whose trailing
// sighash byte is not SIGHASH_ALL.
func validateECDSASigHashFlags(witness wire.TxWitness,
	sigScript []byte) error {

	for _, item := range witness {
		if err := checkECDSASig(item); err != nil {
			return err
		}
	}

	// PushedData walks all the OP_PUSH-style data pushes inside the
	// scriptSig. If the script is malformed we silently skip the sighash
	// inspection here; the script engine will reject the signature itself.
	pushes, err := txscript.PushedData(sigScript)
	if err != nil {
		return nil
	}
	for _, push := range pushes {
		if err := checkECDSASig(push); err != nil {
			return err
		}
	}

	return nil
}

// checkECDSASig inspects a witness/sigScript element. If it has a plausible
// DER ECDSA signature shape, the trailing sighash byte is checked to be
// SIGHASH_ALL.
func checkECDSASig(item []byte) error {
	if !looksLikeDERSig(item) {
		return nil
	}

	sighash := item[len(item)-1]
	if sighash != byte(txscript.SigHashAll) {
		return fmt.Errorf("%w: ECDSA signature must use SIGHASH_ALL "+
			"(0x01), got 0x%02x", ErrInvalidSigHashFlag, sighash)
	}

	return nil
}

// looksLikeDERSig returns true if the input has the structural shape of a
// DER-encoded ECDSA signature followed by a single sighash byte. The check
// is intentionally lightweight: it bounds the length, requires the leading
// ASN.1 SEQUENCE byte, and validates the embedded total-length byte against
// the actual size. False positives are unlikely because non-signature
// elements (compressed/uncompressed pubkeys, witness scripts, control blocks,
// hashes, etc.) do not satisfy all three conditions at once.
func looksLikeDERSig(item []byte) bool {
	// A DER signature body is 8..72 bytes (min when R and S are 1 byte,
	// max when both are 33 bytes). With the trailing sighash byte, the
	// full element is 9..73 bytes.
	if len(item) < 9 || len(item) > 73 {
		return false
	}

	// ASN.1 SEQUENCE identifier.
	if item[0] != 0x30 {
		return false
	}

	// The DER length byte covers everything after itself (R type marker
	// onwards) but NOT the trailing sighash byte. So body length =
	// total - 0x30 - length-byte - sighash-byte = len(item) - 3.
	if int(item[1]) != len(item)-3 {
		return false
	}

	return true
}
