package descriptors

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/address/v2/base58"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// DerivedInfo is independently owned public metadata for one descriptor
// instance. It makes no claim about available signatures or satisfiability.
type DerivedInfo struct {
	ScriptPubKey       []byte
	RedeemScript       []byte
	WitnessScript      []byte
	Keys               []DerivedKey
	TaprootInternalKey []byte
	TaprootMerkleRoot  []byte
	TaprootLeaves      []DerivedTapLeaf
	MuSig2Groups       []DerivedMuSig2Group
}

// DerivedKey describes a signing key or MuSig2 participant. Position is the
// zero-based descriptor key occurrence; Participant is -1 for a signing key and
// otherwise the participant's expression index. PubKey uses the script's key
// encoding (participants remain compressed). LeafHashes use forward byte order.
// A nil Origin means full ancestry is unavailable. ExtendedKey, when nonempty,
// is a public 78-byte BIP32 serialization with a structurally usable full
// origin. XPubOmission is a stable reason for omitting an otherwise present
// extended key.
type DerivedKey struct {
	Position       int
	Participant    int
	PubKey         []byte
	Origin         *KeyOrigin
	LeafHashes     [][]byte
	ExtendedKey    []byte
	ExtendedOrigin *KeyOrigin
	XPubOmission   string
}

// DerivedTapLeaf describes one tree position in depth-first order. Repeated
// leaves are retained. ControlBlock proves this position in the output tree.
type DerivedTapLeaf struct {
	Depth        uint8
	Version      byte
	Script       []byte
	Hash         []byte
	ControlBlock []byte
	KeyPositions []int
}

// DerivedMuSig2Group records the untweaked compressed aggregate and ordered
// compressed participants, including duplicates. DerivedKey is the x-only key
// used by the descriptor after any BIP328 derivation. Path is relative to the
// implicit BIP328 root, whose fingerprint is carried by the signing key Origin.
type DerivedMuSig2Group struct {
	Position     int
	AggregateKey []byte
	Participants [][]byte
	DerivedKey   []byte
	Path         []uint32
}

// ScriptPubKeyAt derives the network-independent output script without building
// origins or tree proofs. Coordinate rules are the same as AddressAt, including
// for bare descriptors which do not have addresses.
func (d *Descriptor) ScriptPubKeyAt(mp, idx uint32) ([]byte, error) {
	if uint64(mp) >= uint64(d.multipath) {
		return nil, fmt.Errorf("multipath index out of bounds")
	}
	if d.root.kind == nodePk || d.root.kind == nodeMulti ||
		d.root.kind == nodeSortedMulti {

		return d.innerScript(d.root, mp, idx)
	}

	// Address encoding depends on a network, but its script bytes do not.
	// Reuse the existing constructor rather than maintain a second
	// compiler.
	addr, err := d.address(d.root, &chaincfg.MainNetParams, mp, idx)
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(addr)
}

// DerivedInfoAt exports independently owned public signing metadata. Private
// descriptors are rejected without echoing source text. Origins are retained
// only when structurally usable as full BIP32 origins; missing ancestry does
// not prevent script export. No PSBT fields, signatures or nonce state are
// created.
func (d *Descriptor) DerivedInfoAt(mp, idx uint32) (*DerivedInfo, error) {
	if d.HasPrivateKeys() {
		return nil, fmt.Errorf("public descriptor required")
	}
	script, err := d.ScriptPubKeyAt(mp, idx)
	if err != nil {
		return nil, err
	}
	info := &DerivedInfo{ScriptPubKey: script}

	// Unwrap each commitment separately: a nested P2WSH output needs both
	// the witness program as redeem script and its inner witness script.
	n := d.root
	if n.kind == nodeSh {
		info.RedeemScript, err = d.redeemScript(n.sub, mp, idx)
		if err != nil {
			return nil, err
		}
		n = n.sub
	}
	if n.kind == nodeWsh {
		info.WitnessScript, err = d.innerScript(n.sub, mp, idx)
		if err != nil {
			return nil, err
		}
	}
	if n.kind == nodeTr {
		if err := d.exportTaproot(info, mp, idx); err != nil {
			return nil, err
		}
	}

	// Each occurrence has its own origin claim, even when two occurrences
	// derive the same public key. Consumers must detect conflicting claims.
	for position, key := range d.keys {
		if err := d.exportKey(
			info, key, position, mp, idx,
		); err != nil {

			return nil, err
		}
	}
	return info, nil
}

// exportTaproot uses the same DFS proofs as planning, without selecting a leaf.
func (d *Descriptor) exportTaproot(info *DerivedInfo, mp, idx uint32) error {
	internal, err := d.root.keys[0].derivePub(mp, idx)
	if err != nil {
		return err
	}
	info.TaprootInternalKey = schnorr.SerializePubKey(internal)
	if d.root.tapTree == nil {
		return nil
	}

	// The parity bit belongs to the tweaked output, not the internal point.
	leaves, root, err := d.collectLeafPlans(d.root.tapTree, mp, idx)
	if err != nil {
		return err
	}
	info.TaprootMerkleRoot = bytes.Clone(root[:])
	output := txscript.ComputeTaprootOutputKey(internal, root[:])
	parity := output.SerializeCompressed()[0] & 1
	for _, leaf := range leaves {
		hash := txscript.NewBaseTapLeaf(leaf.script).TapHash()
		control := []byte{byte(txscript.BaseLeafVersion) | parity}
		control = append(control, info.TaprootInternalKey...)
		control = append(control, leaf.proof...)
		entry := DerivedTapLeaf{
			Depth:        uint8(len(leaf.proof) / 32),
			Version:      byte(txscript.BaseLeafVersion),
			Script:       leaf.script,
			Hash:         bytes.Clone(hash[:]),
			ControlBlock: control,
		}

		// Retain syntactic key membership rather than searching script
		// bytes: key hashes and constants cannot reliably identify
		// source keys.
		for _, key := range leaf.leaf.keys {
			for position, candidate := range d.keys {
				if key == candidate {
					entry.KeyPositions = append(
						entry.KeyPositions, position,
					)
				}
			}
		}
		info.TaprootLeaves = append(info.TaprootLeaves, entry)
	}
	return nil
}

// exportKey adds an ordinary signing key. Aggregate relationships are handled
// separately so participant wallet origins never become aggregate origins.
func (d *Descriptor) exportKey(info *DerivedInfo, key *descKey, position int,
	mp, idx uint32) error {

	if len(key.participants) != 0 {
		return fmt.Errorf("MuSig2 metadata is not yet supported")
	}
	entry, err := key.derivedKey(position, -1, mp, idx)
	if err != nil {
		return err
	}
	entry.LeafHashes = info.keyLeafHashes(position)
	info.Keys = append(info.Keys, entry)
	return nil
}

// keyLeafHashes returns owned, deduplicated leaf membership for an occurrence.
func (info *DerivedInfo) keyLeafHashes(position int) [][]byte {
	var hashes [][]byte
	for _, leaf := range info.TaprootLeaves {
		for _, keyPosition := range leaf.KeyPositions {
			if keyPosition != position {
				continue
			}
			duplicate := false
			for _, hash := range hashes {
				duplicate = duplicate ||
					bytes.Equal(hash, leaf.Hash)
			}
			if !duplicate {
				hashes = append(hashes, bytes.Clone(leaf.Hash))
			}
		}
	}
	return hashes
}

// derivedKey exports one concrete key and only structurally usable ancestry.
// An intermediate extended key without a full origin cannot invent a master.
func (k *descKey) derivedKey(position, participant int,
	mp, idx uint32) (DerivedKey, error) {

	pub, err := k.derive(mp, idx)
	if err != nil {
		return DerivedKey{}, err
	}
	entry := DerivedKey{
		Position:    position,
		Participant: participant,
		PubKey:      pub,
	}
	origin := cloneOrigin(k.origin)
	if k.xpub != nil {
		// Strict validation is local to export. It neither changes the
		// descriptor parser nor registers additional version bytes
		// globally.
		_, err := hdkeychain.NewKeyFromStringStrict(k.xpub.String())
		if err != nil {
			entry.XPubOmission = "invalid_extended_key"
		}

		// Export eligibility and known ancestry are separate. An
		// unfamiliar public version must not discard a complete
		// supplied signing origin.
		depth := int(k.xpub.Depth())
		originDepth := 0
		if origin != nil {
			originDepth = len(origin.Path)
		}
		switch {
		case depth == 0 && (k.xpub.ParentFingerprint() != 0 || k.xpub.ChildIndex() != 0):
			origin = nil

		case depth == 0 && origin == nil:
			rootPub, err := k.xpub.ECPubKey()
			if err != nil {
				return DerivedKey{}, err
			}
			origin = &KeyOrigin{}
			copy(
				origin.Fingerprint[:],
				address.Hash160(rootPub.SerializeCompressed())[:4],
			)

		case origin == nil || originDepth != depth:
			entry.XPubOmission = "incomplete_origin"
			origin = nil

		case originDepth > 0 && origin.Path[originDepth-1] != k.xpub.ChildIndex():
			entry.XPubOmission = "inconsistent_origin"
			origin = nil
		}
		if origin != nil && entry.XPubOmission == "" {
			encoded := base58.Decode(k.xpub.String())
			entry.ExtendedKey = bytes.Clone(encoded[:78])
			entry.ExtendedOrigin = cloneOrigin(origin)
		}
	}

	// Only the suffix is appended; the origin is historical derivation.
	if origin != nil {
		path, err := k.resolvePath(mp, idx)
		if err != nil {
			return DerivedKey{}, err
		}
		origin.Path = append(origin.Path, path...)
		entry.Origin = origin
	}
	return entry, nil
}
