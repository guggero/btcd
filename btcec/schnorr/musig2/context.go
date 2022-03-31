// Copyright (c) 2013-2022 The btcsuite developers

package musig2

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var (
	// ErrSignerNotInKeySet is returned when a the private key for a signer
	// isn't included in the set of signing public keys.
	ErrSignerNotInKeySet = fmt.Errorf("signing key is not found in key" +
		" set")

	// ErrAlredyHaveAllNonces is called when RegisterPubNonce is called too
	// many times for a given signing session.
	ErrAlredyHaveAllNonces = fmt.Errorf("already have all nonces")

	// ErrAlredyHaveAllSigs is called when CombineSig is called too many
	// times for a given signing session.
	ErrAlredyHaveAllSigs = fmt.Errorf("already have all sigs")

	// ErrSigningContextReuse is returned if a user attempts to sign using
	// the same signing context more than once.
	ErrSigningContextReuse = fmt.Errorf("nonce already used")

	// ErrFinalSigInvalid is returned when the combined signature turns out
	// to be invalid.
	ErrFinalSigInvalid = fmt.Errorf("final signature is invalid")

	// ErrCombinedNonceUnavailable is returned when a caller attempts to
	// sign a partial signature, without first having collected all the
	// required combined nonces.
	ErrCombinedNonceUnavailable = fmt.Errorf("missing combined nonce")
)

// Context is a managed signing context for musig2. It takes care of things
// like securely generating secret nonces, aggregating keys and nonces, etc.
type Context struct {
	// signingKey is the key we'll use for signing.
	signingKey *btcec.PrivateKey

	// pubKey is our even-y coordinate public  key.
	pubKey *btcec.PublicKey

	// keySet is the set of all signers.
	keySet []*btcec.PublicKey

	// combinedKey is the aggregated public key.
	combinedKey *btcec.PublicKey

	// uniqueKeyIndex is the index of the second unique key in the keySet.
	// This is used to speed up signing and verification computations.
	uniqueKeyIndex int

	// keysHash is the hash of all the keys as defined in musig2.
	keysHash []byte

	// tweaks is a set of optional tweak values that affect the final
	// combined public key.
	tweaks []KeyTweakDesc

	// shouldSort keeps track of if the public keys should be sorted before
	// any operations.
	shouldSort bool
}

// ContextOption is a functional option argument that allows callers to modify
// the musig2 signing is done within a context.
type ContextOption func(*contextOptions)

// contextOptions houses the set of functional options that can be used to
// musig2 signing protocol.
type contextOptions struct {
	tweaks []KeyTweakDesc
}

// defaultContextOptions returns the default context options.
func defaultContextOptions() *contextOptions {
	return &contextOptions{}
}

// WithTweakedContext specifies that within the context, the aggregated public
// key should be tweaked with the specified tweaks.
func WithTweakedContext(tweaks []KeyTweakDesc) ContextOption {
	return func(o *contextOptions) {
		o.tweaks = tweaks
	}
}

// NewContext creates a new signing context with the passed singing key and set
// of public keys for each of the other signers.
//
// NOTE: This struct should be used over the raw Sign API whenever possible.
func NewContext(signingKey *btcec.PrivateKey,
	signers []*btcec.PublicKey, shouldSort bool,
	ctxOpts ...ContextOption) (*Context, error) {

	// First, parse the set of optional context options.
	opts := defaultContextOptions()
	for _, option := range ctxOpts {
		option(opts)
	}

	// As a sanity check, make sure the signing key is actually amongst the sit
	// of signers.
	//
	// TODO(roasbeef): instead have pass all the _other_ signers?
	pubKey, err := schnorr.ParsePubKey(
		schnorr.SerializePubKey(signingKey.PubKey()),
	)
	if err != nil {
		return nil, err
	}

	var keyFound bool
	for _, key := range signers {
		if key.IsEqual(pubKey) {
			keyFound = true
			break
		}
	}
	if !keyFound {
		return nil, ErrSignerNotInKeySet
	}

	// Now that we know that we're actually a signer, we'll generate the
	// key hash finger print and second unique key index so we can speed up
	// signing later.
	keysHash := keyHashFingerprint(signers, shouldSort)
	uniqueKeyIndex := secondUniqueKeyIndex(signers, shouldSort)

	// Next, we'll use this information to compute the aggregated public
	// key that'll be used for signing in practice.
	combinedKey, _, _, err := AggregateKeys(
		signers, shouldSort, WithKeysHash(keysHash),
		WithUniqueKeyIndex(uniqueKeyIndex),
		WithKeyTweaks(opts.tweaks...),
	)
	if err != nil {
		return nil, err
	}

	return &Context{
		signingKey:     signingKey,
		pubKey:         pubKey,
		keySet:         signers,
		combinedKey:    combinedKey,
		uniqueKeyIndex: uniqueKeyIndex,
		keysHash:       keysHash,
		tweaks:         opts.tweaks,
		shouldSort:     shouldSort,
	}, nil
}

// CombinedKey returns the combined public key that will be used to generate
// multi-signatures  against.
func (c *Context) CombinedKey() btcec.PublicKey {
	return *c.combinedKey
}

// PubKey returns the public key of the signer of this session.
func (c *Context) PubKey() btcec.PublicKey {
	return *c.pubKey
}

// SigningKeys returns the set of keys used for signing.
func (c *Context) SigningKeys() []*btcec.PublicKey {
	keys := make([]*btcec.PublicKey, len(c.keySet))
	copy(keys, c.keySet)

	return keys
}

// Session represents a musig2 signing session. A new instance should be
// created each time a multi-signature is needed. The session struct handles
// nonces management, incremental partial sig vitrifaction, as well as final
// signature combination. Errors are returned when unsafe behavior such as
// nonce re-use is attempted.
//
// NOTE: This struct should be used over the raw Sign API whenever possible.
type Session struct {
	ctx *Context

	localNonces *Nonces

	pubNonces [][PubNonceSize]byte

	combinedNonce *[PubNonceSize]byte

	msg [32]byte

	ourSig *PartialSignature
	sigs   []*PartialSignature

	finalSig *schnorr.Signature
}

// TODO(roasbeef): optional arg to allow parsing in pre-generated nonces

// NewSession creates a new musig2 signing session.
func (c *Context) NewSession() (*Session, error) {
	localNonces, err := GenNonces()
	if err != nil {
		return nil, err
	}

	s := &Session{
		ctx:         c,
		localNonces: localNonces,
		pubNonces:   make([][PubNonceSize]byte, 0, len(c.keySet)),
		sigs:        make([]*PartialSignature, 0, len(c.keySet)),
	}

	s.pubNonces = append(s.pubNonces, localNonces.PubNonce)

	return s, nil
}

// PublicNonce returns the public nonce for a signer. This should be sent to
// other parties before signing begins, so they can compute the aggregated
// public nonce.
func (s *Session) PublicNonce() [PubNonceSize]byte {
	return s.localNonces.PubNonce
}

// NumRegisteredNonces returns the total number of nonces that have been
// regsitered so far.
func (s *Session) NumRegisteredNonces() int {
	return len(s.pubNonces)
}

// RegisterPubNonce should be called for each public nonce from the set of
// signers. This method returns true once all the public nonces have been
// accounted for.
func (s *Session) RegisterPubNonce(nonce [PubNonceSize]byte) (bool, error) {
	// If we already have all the nonces, then this method was called too many
	// times.
	haveAllNonces := len(s.pubNonces) == len(s.ctx.keySet)
	if haveAllNonces {
		return false, nil
	}

	// Add this nonce and check again if we already have tall the nonces we
	// need.
	s.pubNonces = append(s.pubNonces, nonce)
	haveAllNonces = len(s.pubNonces) == len(s.ctx.keySet)

	// If we have all the nonces, then we can go ahead and combine them
	// now.
	if haveAllNonces {
		combinedNonce, err := AggregateNonces(s.pubNonces)
		if err != nil {
			return false, err
		}

		s.combinedNonce = &combinedNonce
	}

	return haveAllNonces, nil
}

// Sign generates a partial signature for the target message, using the target
// context. If this method is called more than once per context, then an error
// is returned, as that means a nonce was re-used.
func (s *Session) Sign(msg [32]byte,
	signOpts ...SignOption) (*PartialSignature, error) {

	s.msg = msg

	switch {
	// If no local nonce is present, then this means we already signed, so
	// we'll return an error to prevent nonce re-use.
	case s.localNonces == nil:
		return nil, ErrSigningContextReuse

	// We also need to make sure we have the combined nonce, otherwise this
	// funciton was called too early.
	case s.combinedNonce == nil:
		return nil, ErrCombinedNonceUnavailable
	}

	if len(s.ctx.tweaks) != 0 {
		signOpts = append(signOpts, WithTweaks(s.ctx.tweaks...))
	}

	partialSig, err := Sign(
		s.localNonces.SecNonce, s.ctx.signingKey, *s.combinedNonce,
		s.ctx.keySet, msg, signOpts...,
	)

	// Now that we've generated our signature, we'll make sure to blank out
	// our signing nonce.
	s.localNonces = nil

	if err != nil {
		return nil, err
	}

	s.ourSig = partialSig
	s.sigs = append(s.sigs, partialSig)

	return partialSig, nil
}

// CombineSigs buffers a partial signature received from a signing party. The
// method returns true once all the signatures are available, and can be
// combined into the final signature.
func (s *Session) CombineSig(sig *PartialSignature) (bool, error) {
	// First check if we already have all the signatures we need. We
	// already accumulated our own signature when we generated the sig.
	haveAllSigs := len(s.sigs) == len(s.ctx.keySet)
	if haveAllSigs {
		return false, ErrAlredyHaveAllSigs
	}

	// TODO(roasbeef): incremental check for invalid sig, or just detect at
	// the very end?

	// Accumulate this sig, and check again if we have all the sigs we
	// need.
	s.sigs = append(s.sigs, sig)
	haveAllSigs = len(s.sigs) == len(s.ctx.keySet)

	// If we have all the signatures, then we can combine them all into the
	// final signature.
	if haveAllSigs {
		var combineOpts []CombineOption
		if len(s.ctx.tweaks) != 0 {
			combineOpts = append(
				combineOpts, WithTweakedCombine(
					s.msg, s.ctx.keySet, s.ctx.tweaks,
					s.ctx.shouldSort,
				),
			)
		}

		finalSig := CombineSigs(s.ourSig.R, s.sigs, combineOpts...)

		// We'll also verify the signature at this point to ensure it's
		// valid.
		//
		// TODO(roasbef): allow skipping?
		if !finalSig.Verify(s.msg[:], s.ctx.combinedKey) {
			return false, ErrFinalSigInvalid
		}

		s.finalSig = finalSig
	}

	return haveAllSigs, nil
}

// FinalSig returns the final combined multi-signature, if present.
func (s *Session) FinalSig() *schnorr.Signature {
	return s.finalSig
}
