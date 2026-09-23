package descriptors

import (
	"encoding/hex"
	"slices"
	"strings"
)

// KeyOrigin identifies a master key and a path from it. Path elements include
// the BIP32 hardened bit. Fingerprint is in serialized byte order. An origin is
// a caller-supplied claim, not proof of ancestry or wallet ownership.
type KeyOrigin struct {
	Fingerprint [4]byte
	Path        []uint32
}

// parseValidatedOrigin retains an origin after checkKeyOrigin has validated its
// fingerprint and fixed path components. It does not derive any keys.
func parseValidatedOrigin(origin string) *KeyOrigin {
	parts := strings.Split(origin, "/")
	fingerprint, _ := hex.DecodeString(parts[0])
	result := &KeyOrigin{}
	copy(result.Fingerprint[:], fingerprint)

	// Parsing has already excluded wildcards and multipath components here.
	for _, part := range parts[1:] {
		step, _ := parsePathStep(part)
		result.Path = append(result.Path, step.index.childIndex())
	}
	return result
}

// cloneOrigin returns independently owned origin data, preserving absence.
func cloneOrigin(origin *KeyOrigin) *KeyOrigin {
	if origin == nil {
		return nil
	}
	return &KeyOrigin{
		Fingerprint: origin.Fingerprint,
		Path:        slices.Clone(origin.Path),
	}
}

// hasPrivateKeys checks the semantic source type, including aggregate members.
func (k *descKey) hasPrivateKeys() bool {
	if k.private {
		return true
	}
	for _, participant := range k.participants {
		if participant.hasPrivateKeys() {
			return true
		}
	}
	return false
}

// HasPrivateKeys reports whether any key expression originated from an extended
// private key or WIF, including MuSig2 participants. Parsing private
// descriptors remains supported; consumers can use this to enforce a
// public-only policy.
func (d *Descriptor) HasPrivateKeys() bool {
	for _, key := range d.keys {
		if key.hasPrivateKeys() {
			return true
		}
	}
	return false
}

// IsRanged reports whether deriving an instance requires a wildcard index.
// Multipath selection alone does not make a descriptor ranged.
func (d *Descriptor) IsRanged() bool {
	for _, key := range d.keys {
		if key.isWildcard() {
			return true
		}
	}
	return false
}
