package descriptors

import (
	"bytes"

	"github.com/btcsuite/btcd/address/v2"
)

// exportMuSig2 exports participant wallet origins separately from the implicit
// BIP328 aggregate root. The PSBT consumer can then describe both the group and
// any post-aggregation derivation without inventing a wallet master for it.
func (d *Descriptor) exportMuSig2(info *DerivedInfo, key *descKey, position int,
	mp, idx uint32) error {

	aggregate, participants, err := key.aggregateKeys(mp, idx)
	if err != nil {
		return err
	}
	pub, err := key.derive(mp, idx)
	if err != nil {
		return err
	}
	path, err := key.resolvePath(mp, idx)
	if err != nil {
		return err
	}
	group := DerivedMuSig2Group{
		Position:     position,
		AggregateKey: aggregate.SerializeCompressed(),
		DerivedKey:   bytes.Clone(pub),
		Path:         path,
	}
	for _, participant := range participants {
		group.Participants = append(
			group.Participants, participant.SerializeCompressed(),
		)
	}
	info.MuSig2Groups = append(info.MuSig2Groups, group)

	// The synthetic root is implicit in BIP373. Its fingerprint requires
	// the full aggregate point, including parity, rather than x-only bytes.
	origin := &KeyOrigin{Path: path}
	copy(origin.Fingerprint[:], address.Hash160(group.AggregateKey)[:4])
	info.Keys = append(info.Keys, DerivedKey{
		Position:    position,
		Participant: -1,
		PubKey:      pub,
		Origin:      origin,
		LeafHashes:  info.keyLeafHashes(position),
	})

	// Participants keep their source positions for omission diagnostics.
	// Only the aggregation group, not their expression order, is sorted.
	for i, participant := range key.participants {
		entry, err := participant.derivedKey(position, i, mp, idx)
		if err != nil {
			return err
		}
		entry.LeafHashes = info.keyLeafHashes(position)
		info.Keys = append(info.Keys, entry)
	}
	return nil
}
