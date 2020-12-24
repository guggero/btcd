package txscript

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btctr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	Epoch = byte(0)
)

// TxSigHashes houses the partial set of sighashes introduced within BIP0143.
// This partial set of sighashes may be re-used within each input across a
// transaction when validating all inputs. As a result, validation complexity
// for SigHashAll can be reduced by a polynomial factor.
type TxSigHashesTaproot struct {
	HashPrevOuts      chainhash.Hash
	HashPrevAmounts   chainhash.Hash
	HashPrevPkScripts chainhash.Hash
	HashSequences     chainhash.Hash
	HashOutputs       chainhash.Hash
}

func NewTxSigHashesTaproot(tx *wire.MsgTx,
	utxos []*wire.TxOut) *TxSigHashesTaproot {

	return &TxSigHashesTaproot{
		HashPrevOuts:      calcSingleHashPrevOuts(tx),
		HashPrevAmounts:   calcSingleHashAmounts(utxos),
		HashPrevPkScripts: calcSingleHashPkScripts(utxos),
		HashSequences:     calcSingleHashSequences(tx),
		HashOutputs:       calcSingleHashOutputs(tx),
	}
}

// calcSingleHashPrevOuts calculates a single hash of all the previous outputs
// (txid:index) referenced within the passed transaction. This calculated hash
// can be re-used when validating all inputs spending segwit outputs, with a
// signature hash type of SigHashAll. This allows validation to re-use previous
// hashing computation, reducing the complexity of validating SigHashAll inputs
// from  O(N^2) to O(N).
func calcSingleHashPrevOuts(tx *wire.MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		// First write out the 32-byte transaction ID one of whose
		// outputs are being referenced by this input.
		b.Write(in.PreviousOutPoint.Hash[:])

		// Next, we'll encode the index of the referenced output as a
		// little endian integer.
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.PreviousOutPoint.Index)
		b.Write(buf[:])
	}

	return chainhash.HashH(b.Bytes())
}

// calcSingleHashSequences computes an aggregated hash of each of the sequence
// numbers within the inputs of the passed transaction. This single hash can be
// re-used when validating all inputs spending segwit outputs, which include
// signatures using the SigHashAll sighash type. This allows validation to
// re-use previous hashing computation, reducing the complexity of validating
// SigHashAll inputs from O(N^2) to O(N).
func calcSingleHashSequences(tx *wire.MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.Sequence)
		b.Write(buf[:])
	}

	return chainhash.HashH(b.Bytes())
}

// calcSingleHashOutputs computes a hash digest of all outputs created by the
// transaction encoded using the wire format. This single hash can be re-used
// when validating all inputs spending witness programs, which include
// signatures using the SigHashAll sighash type. This allows computation to be
// cached, reducing the total hashing complexity from O(N^2) to O(N).
func calcSingleHashOutputs(tx *wire.MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, out := range tx.TxOut {
		_ = wire.WriteTxOut(&b, 0, 0, out)
	}

	return chainhash.HashH(b.Bytes())
}

// calcHashAmounts computes a hash digest of all UTXO amounts spent by the
// transaction encoded using the wire format. This single hash can be re-used
// when validating all inputs spending witness programs, which include
// signatures using the SigHashAll sighash type. This allows computation to be
// cached, reducing the total hashing complexity from O(N^2) to O(N).
func calcSingleHashAmounts(utxos []*wire.TxOut) chainhash.Hash {
	var b bytes.Buffer
	for _, utxo := range utxos {
		var bAmount [8]byte
		binary.LittleEndian.PutUint64(bAmount[:], uint64(utxo.Value))
		b.Write(bAmount[:])
	}

	return chainhash.HashH(b.Bytes())
}

// calcSingleHashPkScripts computes a hash digest of all UTXO scriptPubKeys spent by
// the transaction encoded using the wire format. This single hash can be re-
// used when validating all inputs spending witness programs, which include
// signatures using the SigHashAll sighash type. This allows computation to be
// cached, reducing the total hashing complexity from O(N^2) to O(N).
func calcSingleHashPkScripts(utxos []*wire.TxOut) chainhash.Hash {
	var b bytes.Buffer
	for _, utxo := range utxos {
		wire.WriteVarBytes(&b, 0, utxo.PkScript)
	}

	return chainhash.HashH(b.Bytes())
}

// https://en.bitcoin.it/wiki/BIP_0341#Signature_validation_rules
func CalcTaprootSignatureHash(subScript []parsedOpcode,
	sigHashes *TxSigHashesTaproot, hashType SigHashType, tx *wire.MsgTx,
	idx int, spendType byte) (chainhash.Hash, error) {

	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx > len(tx.TxIn)-1 {
		return chainhash.Hash{}, fmt.Errorf("idx %d but %d txins", idx,
			len(tx.TxIn))
	}
	outputType := hashType & SigHashSingle
	if hashType == SigHashTaprootDefault {
		outputType = SigHashAll
	}
	inputType := hashType & SigHashAnyOneCanPay

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature message for this transaction. All following comments
	// are referring to the BIP341 specification.
	var sigMsg bytes.Buffer

	// epoch and hash_type (1).
	sigMsg.Write([]byte{Epoch, byte(hashType)})

	// nVersion (4): the nVersion of the transaction.
	var bVersion [4]byte
	binary.LittleEndian.PutUint32(bVersion[:], uint32(tx.Version))
	sigMsg.Write(bVersion[:])

	// nLockTime (4): the nLockTime of the transaction.
	var bLockTime [4]byte
	binary.LittleEndian.PutUint32(bLockTime[:], tx.LockTime)
	sigMsg.Write(bLockTime[:])

	// If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
	if inputType != SigHashAnyOneCanPay {
		// sha_prevouts (32): the SHA256 of the serialization of all
		// input outpoints.
		sigMsg.Write(sigHashes.HashPrevOuts[:])

		// sha_amounts (32): the SHA256 of the serialization of all
		// spent output amounts.
		sigMsg.Write(sigHashes.HashPrevAmounts[:])

		// sha_scriptpubkeys (32): the SHA256 of the serialization of
		// all spent output scriptPubKeys.
		sigMsg.Write(sigHashes.HashPrevPkScripts[:])

		// sha_sequences (32): the SHA256 of the serialization of all
		// input nSequence.
		sigMsg.Write(sigHashes.HashSequences[:])
	}

	// If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
	if outputType == SigHashAll {
		sigMsg.Write(sigHashes.HashOutputs[:])
	}

	// spend_type (1): equal to (ext_flag * 2) + annex_present, where
	// annex_present is 0 if no annex is present, or 1 otherwise (the
	// original witness stack has two or more witness elements, and the
	// first byte of the last element is 0x50)
	sigMsg.WriteByte(spendType)

	// If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
	if inputType == SigHashAnyOneCanPay {
		// TODO(guggero): implement
	} else {
		// input_index (4): index of this input in the transaction input
		// vector. Index of the first input is 0.
		var bIndex [4]byte
		binary.LittleEndian.PutUint32(bIndex[:], uint32(idx))
		sigMsg.Write(bIndex[:])
	}

	// If an annex is present (the lowest bit of spend_type is set):
	if spendType&1 == 1 {
		// TODO(guggero): implement
	}

	// If hash_type & 3 equals SIGHASH_SINGLE:
	if outputType == SigHashSingle {
		// TODO(guggero): implement
	}

	fmt.Printf("SigMsg: %x\n", sigMsg.Bytes())

	return btcec.TaggedHash(btctr.TagTapSighash, sigMsg.Bytes()), nil
}
