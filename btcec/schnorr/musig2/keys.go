// Copyright 2013-2022 The btcsuite developers

package musig2

import (
	"bytes"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var (
	// KeyAggTagList is the tagged hash tag used to compute the hash of the
	// list of sorted public keys.
	KeyAggTagList = []byte("KeyAgg list")

	// KeyAggTagCoeff is the tagged hash tag used to compute the key
	// aggregation coefficient for each key.
	KeyAggTagCoeff = []byte("KeyAgg coefficient")
)

// sortableKeys defines a type of slice of public keys that implements the sort
// interface for BIP 340 keys.
type sortableKeys []*btcec.PublicKey

// Less reports whether the element with index i must sort before the element
// with index j.
func (s sortableKeys) Less(i, j int) bool {
	// TODO(roasbeef): more efficient way to compare...
	keyIBytes := schnorr.SerializePubKey(s[i])
	keyJBytes := schnorr.SerializePubKey(s[j])

	return bytes.Compare(keyIBytes, keyJBytes) == -1
}

// Swap swaps the elements with indexes i and j.
func (s sortableKeys) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Len is the number of elements in the collection.
func (s sortableKeys) Len() int {
	return len(s)
}

// sortKeys takes a set of schnorr public keys and returns a new slice that is
// a copy of the keys sorted in lexicographical order bytes on the x-only
// pubkey serialization.
func sortKeys(keys []*btcec.PublicKey) []*btcec.PublicKey {
	keySet := sortableKeys(keys)
	if sort.IsSorted(keySet) {
		return keys
	}

	sort.Sort(keySet)
	return keySet
}

// keyHashFingerprint computes the tagged hash of the series of (sorted) public
// keys passed as input. This is used to compute the aggregation coefficient
// for each key. The final computation is:
//   * H(tag=KeyAgg list, pk1 || pk2..)
func keyHashFingerprint(keys []*btcec.PublicKey, sort bool) []byte {
	if sort {
		keys = sortKeys(keys)
	}

	// We'll create a single buffer and slice into that so the bytes buffer
	// doesn't continually need to grow the underlying buffer.
	keyAggBuf := make([]byte, 32*len(keys))
	keyBytes := bytes.NewBuffer(keyAggBuf[0:0])
	for _, key := range keys {
		keyBytes.Write(schnorr.SerializePubKey(key))
	}

	h := chainhash.TaggedHash(KeyAggTagList, keyBytes.Bytes())
	return h[:]
}

// keyBytesEqual returns true if two keys are the same from the PoV of BIP
// 340's 32-byte x-only public keys.
func keyBytesEqual(a, b *btcec.PublicKey) bool {
	return bytes.Equal(
		schnorr.SerializePubKey(a),
		schnorr.SerializePubKey(b),
	)
}

// aggregationCoefficient computes the key aggregation coefficient for the
// specified target key. The coefficient is computed as:
//  * H(tag=KeyAgg coefficient, keyHashFingerprint(pks) || pk)
func aggregationCoefficient(keySet []*btcec.PublicKey,
	targetKey *btcec.PublicKey, keysHash []byte,
	secondKeyIdx int) *btcec.ModNScalar {

	var mu btcec.ModNScalar

	// If this is the second key, then this coefficient is just one.
	if secondKeyIdx != -1 && keyBytesEqual(keySet[secondKeyIdx], targetKey) {
		return mu.SetInt(1)
	}

	// Otherwise, we'll compute the full finger print hash for this given
	// key and then use that to compute the coefficient tagged hash:
	//  * H(tag=KeyAgg coefficient, keyHashFingerprint(pks, pk) || pk)
	var coefficientBytes [64]byte
	copy(coefficientBytes[:], keysHash[:])
	copy(coefficientBytes[32:], schnorr.SerializePubKey(targetKey))

	muHash := chainhash.TaggedHash(KeyAggTagCoeff, coefficientBytes[:])

	mu.SetByteSlice(muHash[:])

	return &mu
}

// secondUniqueKeyIndex returns the index of the second unique key. If all keys
// are the same, then a value of -1 is returned.
func secondUniqueKeyIndex(keySet []*btcec.PublicKey) int {
	// Find the first key that isn't the same as the very first key (second
	// unique key).
	for i := range keySet {
		if !keyBytesEqual(keySet[i], keySet[0]) {
			return i
		}
	}

	// A value of negative one is used to indicate that all the keys in the
	// sign set are actually equal, which in practice actually makes musig2
	// useless, but we need a value to distinguish this case.
	return -1
}

// KeyAggOption is a functional option argument that allows callers to specify
// more or less information that has been pre-computed to the main routine.
type KeyAggOption func(*keyAggOption)

// keyAggOption houses the set of functional options that modify key
// aggregation.
type keyAggOption struct {
	// keyHash is the output of keyHashFingerprint for a given set of keys.
	keyHash []byte

	// uniqueKeyIndex is the pre-computed index of the second unique key.
	uniqueKeyIndex *int
}

// WithKeysHash allows key aggregation to be optimize, by allowing the caller
// to specify the hash of all the keys.
func WithKeysHash(keyHash []byte) KeyAggOption {
	return func(o *keyAggOption) {
		o.keyHash = keyHash
	}
}

// WithUniqueKeyIndex allows the caller to specify the index of the second
// unique key.
func WithUniqueKeyIndex(idx int) KeyAggOption {
	return func(o *keyAggOption) {
		i := idx
		o.uniqueKeyIndex = &i
	}
}

// defaultKeyAggOptions returns the set of default arguments for key
// aggregation.
func defaultKeyAggOptions() *keyAggOption {
	return &keyAggOption{}
}

// AggregateKeys takes a list of possibly unsorted keys and returns a single
// aggregated key as specified by the musig2 key aggregation algorithm. A nil
// value can be passed for keyHash, which causes this function to re-derive it.
func AggregateKeys(keys []*btcec.PublicKey, sort bool,
	keyOpts ...KeyAggOption) *btcec.PublicKey {

	// First, parse the set of optional signing options.
	opts := defaultKeyAggOptions()
	for _, option := range keyOpts {
		option(opts)
	}

	// Sort the set of public key so we know we're working with them in
	// sorted order for all the routines below.
	if sort {
		keys = sortKeys(keys)
	}

	// The caller may provide the hash of all the keys as an optimization
	// during signing, as it already needs to be computed.
	if opts.keyHash == nil {
		opts.keyHash = keyHashFingerprint(keys, sort)
	}

	// A caller may also specify the unique key index themselves so we
	// don't need to re-compute it.
	if opts.uniqueKeyIndex == nil {
		idx := secondUniqueKeyIndex(keys)
		opts.uniqueKeyIndex = &idx
	}

	// For each key, we'll compute the intermediate blinded key: a_i*P_i,
	// where a_i is the aggregation coefficient for that key, and P_i is
	// the key itself, then accumulate that (addition) into the main final
	// key: P = P_1 + P_2 ... P_N.
	var finalKeyJ btcec.JacobianPoint
	for _, key := range keys {
		// Port the key over to Jacobian coordinates as we need it in
		// this format for the routines below.
		var keyJ btcec.JacobianPoint
		key.AsJacobian(&keyJ)

		// Compute the aggregation coefficient for the key, then
		// multiply it by the key itself: P_i' = a_i*P_i.
		var tweakedKeyJ btcec.JacobianPoint
		a := aggregationCoefficient(
			keys, key, opts.keyHash, *opts.uniqueKeyIndex,
		)
		btcec.ScalarMultNonConst(a, &keyJ, &tweakedKeyJ)

		// Finally accumulate this into the final key in an incremental
		// fashion.
		btcec.AddNonConst(&finalKeyJ, &tweakedKeyJ, &finalKeyJ)
	}

	finalKeyJ.ToAffine()
	return btcec.NewPublicKey(&finalKeyJ.X, &finalKeyJ.Y)
}
