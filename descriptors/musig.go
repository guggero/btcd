package descriptors

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

// parseMuSigKey validates BIP390's non-nested aggregate key expression. The
// aggregate is only valid in tapscript or as a Taproot internal key.
// Participant keys retain their compressed parity for BIP327 aggregation.
func parseMuSigKey(s string, form keyForm) (*descKey, error) {
	if form != keyFormXOnly {
		return nil, fmt.Errorf("musig() requires a taproot key " +
			"position")
	}
	end := strings.IndexByte(s, ')')
	if end < 0 || strings.ContainsAny(s[len("musig("):end], "()") {
		return nil, fmt.Errorf("unterminated or nested musig()")
	}
	k := &descKey{raw: s, form: form}

	// Participants may repeat, but all multipaths select the same branch.
	// Reject nested syntax before parsing any participant, so malicious
	// nesting cannot cause recursive descent through parseDescKey.
	arity := 1
	for participant := range strings.SplitSeq(s[len("musig("):end], ",") {
		key, err := parseDescKey(participant, keyFormCompressed)
		if err != nil {
			return nil, fmt.Errorf("musig() participant: %w", err)
		}
		if n := key.multipathLen(); n > 1 {
			if arity > 1 && arity != n {
				return nil, fmt.Errorf("musig() participant " +
					"multipaths differ in length")
			}
			arity = n
		}
		k.participants = append(k.participants, key)
	}
	if end == len(s)-1 {
		return k, nil
	}

	// An aggregate path is a synthetic xpub derivation. BIP390 requires
	// fixed extended-key participants and forbids hardened aggregate steps.
	if s[end+1] != '/' {
		return nil, fmt.Errorf("invalid musig() suffix")
	}
	for _, key := range k.participants {
		if key.xpub == nil || key.isWildcard() ||
			key.multipathLen() > 1 {

			return nil, fmt.Errorf("musig() derivation requires " +
				"fixed extended-key participants")
		}
	}
	var err error
	k.steps, err = parseKeyPath(s[end+2:])
	if err != nil {
		return nil, err
	}
	for _, step := range k.steps {
		if step.index.hardened {
			return nil, fmt.Errorf("hardened musig() derivation " +
				"is not possible")
		}
		for _, index := range step.multipath {
			if index.hardened {
				return nil, fmt.Errorf("hardened musig() " +
					"multipath is not possible")
			}
		}
	}
	return k, nil
}

// aggregatePub derives each participant before applying BIP390's sorted BIP327
// aggregation. The returned point retains its parity for subsequent BIP328
// derivation; conversion to x-only happens only at the script boundary.
func (k *descKey) aggregatePub(
	multipathIndex, derivationIndex uint32) (*btcec.PublicKey, error) {

	keys := make([]*btcec.PublicKey, len(k.participants))
	for i, participant := range k.participants {
		pub, err := participant.derivePub(
			multipathIndex, derivationIndex,
		)
		if err != nil {
			return nil, fmt.Errorf("derive musig() participant "+
				"%d: %w", i, err)
		}
		keys[i] = pub
	}

	// AggregateKeys sorts a fresh slice, never the descriptor's immutable
	// participant list. Duplicates are retained as BIP390 requires.
	aggregate, _, _, err := musig2.AggregateKeys(keys, true)
	if err != nil {
		return nil, fmt.Errorf("aggregate musig() keys: %w", err)
	}
	return aggregate.FinalKey, nil
}
