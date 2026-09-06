// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletbackup

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MaxParticipants bounds the beacon area and the work per candidate.
	MaxParticipants = 5

	// EpochBlocks is the length of a discovery epoch.
	EpochBlocks = 2016

	// BeaconAreaSize is the length of the fixed beacon area at the start
	// of every envelope. A discovery index covers these aligned four-byte
	// chunks.
	BeaconAreaSize = 4 * MaxParticipants

	formatOffset   = BeaconAreaSize
	pointOffset    = formatOffset + 1
	headerSize     = pointOffset + 32
	wrapSize       = 16
	correctionSize = 32
	summaryFixed   = 20
	formatVersion  = 0x40
	tagSize        = chacha20poly1305.Overhead
)

var (
	// ErrInvalidBackup indicates malformed input or failed authentication.
	ErrInvalidBackup = errors.New("invalid backup")

	// ErrNotRecipient indicates that the key did not open the backup.
	ErrNotRecipient = errors.New("key did not open backup")

	// ErrInsufficientShares indicates that more distinct participants are
	// needed.
	ErrInsufficientShares = errors.New("insufficient recovery shares")

	// Every AEAD key is derived from fresh randomness and used for exactly
	// one message, so the nonce is constant.
	zeroNonce = make([]byte, chacha20poly1305.NonceSize)
)

// Participant contains only public configuration. Fingerprint is an optional
// BIP32 master fingerprint for display, never an authenticated device identity.
type Participant struct {
	PublicKey   [33]byte
	Fingerprint [4]byte
}

// Config identifies a publication. Threshold is 1 for single-device recovery
// or 2 for two-device recovery. Network is the genesis hash in wire byte
// order. Epoch is the construction tip height divided by EpochBlocks.
//
// WalletID and Revision go into the summary and are used only with Threshold
// 2, where WalletID must be a nonzero, randomly assigned ID retained across
// revisions. Separate accounts or policies using the same devices should have
// separate IDs.
type Config struct {
	Network   [32]byte
	WalletID  [16]byte
	Revision  uint32
	Epoch     uint32
	Threshold byte
}

// Summary is what one participant alone learns from a two-device backup. Its
// contents are claims by the publisher, not proof that the device approved
// this wallet configuration. A single-device backup has no summary: WalletID,
// Revision and Fingerprints are then zero.
type Summary struct {
	WalletID     [16]byte
	Revision     uint32
	Threshold    byte
	Participants byte
	Fingerprints [MaxParticipants][4]byte
}

// Contribution holds what one participant decrypted from one exact
// publication. Treat it as secret. This prototype supports local combination;
// it does not define a wire protocol for exchanging shares between people.
type Contribution struct {
	summary  Summary
	share    scalarShare
	seed     [wrapSize]byte
	epoch    uint32
	backupID [32]byte
}

// Summary returns a copy of the decrypted wallet summary.
func (c *Contribution) Summary() Summary {
	return c.summary
}

// Index returns the participant's one-based position in canonical key order.
func (c *Contribution) Index() byte {
	return c.share.index
}

// Epoch returns the publication epoch whose beacon matched.
func (c *Contribution) Epoch() uint32 {
	return c.epoch
}

// Seal encodes a descriptor and encrypts it to the participants' backup
// public keys. With Threshold 1 any participant recovers the descriptor. With
// Threshold 2 any participant opens the summary and any two recover the
// descriptor.
//
// Seal obtains fresh randomness from crypto/rand on every call. To
// retransmit, retain and reuse the returned bytes rather than recreating the
// publication.
func Seal(config Config, participants []Participant, descriptor string) ([]byte,
	error) {

	payload, err := EncodeDescriptor(descriptor)
	if err != nil {
		return nil, err
	}
	return seal(rand.Reader, config, participants, payload)
}

// entriesSize returns the length of the entry table: a wrap per participant
// and, for two-device recovery, a correction for participants 3..n.
func entriesSize(n, threshold int) int {
	size := n * wrapSize
	if threshold == 2 {
		size += (n - 2) * correctionSize
	}
	return size
}

// summaryCTSize returns the length of the encrypted summary, which exists
// only for two-device recovery.
func summaryCTSize(n, threshold int) int {
	if threshold != 2 {
		return 0
	}
	return summaryFixed + 4*n + tagSize
}

// seal's explicit random reader and pre-encoded payload are internal so
// reproducible tests cannot accidentally turn into a public
// deterministic-encryption API.
func seal(random io.Reader, config Config, participants []Participant,
	payload []byte) ([]byte, error) {

	n := len(participants)
	threshold := int(config.Threshold)
	if n < 1 || n > MaxParticipants || threshold < 1 || threshold > 2 ||
		threshold > n || len(payload) > MaxPayloadSize {

		return nil, fmt.Errorf("invalid backup configuration")
	}
	if threshold == 2 && config.WalletID == ([16]byte{}) {
		return nil, fmt.Errorf("two-device backup needs a wallet ID")
	}

	// Sorting a copy preserves the caller's association of keys and hints.
	participants = append([]Participant(nil), participants...)
	sort.Slice(participants, func(i, j int) bool {
		return bytes.Compare(
			participants[i].PublicKey[:],
			participants[j].PublicKey[:],
		) < 0
	})
	publicKeys := make([]*btcec.PublicKey, n)
	for i, participant := range participants {
		public, err := btcec.ParsePubKey(participant.PublicKey[:])
		if err != nil {
			return nil, fmt.Errorf("participant %d: %w", i+1, err)
		}
		if i > 0 &&
			participant.PublicKey == participants[i-1].PublicKey {

			return nil, fmt.Errorf("duplicate backup public key")
		}
		publicKeys[i] = public
	}

	for {
		blob, err := sealOnce(
			random, config, participants, publicKeys, payload,
		)
		if errors.Is(err, errConstantLine) {
			continue
		}
		return blob, err
	}
}

// errConstantLine reports the negligible case of two equal derived shares,
// which restarts publication with new randomness.
var errConstantLine = errors.New("derived shares are equal")

func sealOnce(random io.Reader, config Config, participants []Participant,
	publicKeys []*btcec.PublicKey, payload []byte) ([]byte, error) {

	n := len(participants)
	threshold := int(config.Threshold)

	// The publisher temporarily knows all secrets. They are the ephemeral
	// scalar and one key seed; everything else is derived.
	e, err := randomScalar(random)
	if err != nil {
		return nil, err
	}
	defer e.Zero()

	// The point is published x-only, so normalize to even Y as in BIP340.
	// The ECDH x-coordinate is the same for either sign.
	if btcec.PrivKeyFromScalar(&e).PubKey().SerializeCompressed()[0] ==
		secpOddPrefix {

		e.Negate()
	}
	ephemeral := btcec.PrivKeyFromScalar(&e)
	defer ephemeral.Zero()

	var seed [wrapSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, err
	}
	defer clear(seed[:])

	header := make([]byte, headerSize)
	for i, participant := range participants {
		beacon := Beacon(
			config.Network, participant.PublicKey, config.Epoch,
		)
		copy(header[4*i:], beacon[:])
	}
	filler := header[4*n : BeaconAreaSize]
	if _, err := io.ReadFull(random, filler); err != nil {
		return nil, err
	}
	header[formatOffset] = formatVersion | byte(threshold-1)<<3 | byte(n)
	copy(header[pointOffset:], schnorr.SerializePubKey(ephemeral.PubKey()))

	context := taggedHash(
		"context", config.Network[:], epochBytes(config.Epoch), header,
	)
	entries := make([]byte, entriesSize(n, threshold))
	masks := make([]btcec.ModNScalar, n)
	defer func() {
		for i := range masks {
			masks[i].Zero()
		}
	}()
	for i, participant := range participants {
		shared := btcec.GenerateSharedSecret(ephemeral, publicKeys[i])
		wrap, mask := recipientKeys(
			shared, context, participant.PublicKey[:], byte(i+1),
		)
		clear(shared)
		masks[i] = mask
		mask.Zero()
		for j := range wrap {
			entries[i*wrapSize+j] = seed[j] ^ wrap[j]
		}
		clear(wrap[:])
	}
	aad := append(context[:32:32], entries...)

	if threshold == 1 {
		contentKey := taggedHash("content-key", context[:], seed[:])
		defer clear(contentKey[:])
		contentAEAD, _ := chacha20poly1305.New(contentKey[:])
		blob := append(header, entries...)
		return contentAEAD.Seal(blob, zeroNonce, payload, aad), nil
	}

	// The line is defined by the first two derived values. Only the other
	// participants need a stored correction d_i = P(i) - h_i.
	if masks[0].Equals(&masks[1]) {
		return nil, errConstantLine
	}
	for i := 2; i < n; i++ {
		correction := lineShare(&masks[0], &masks[1], byte(i+1))
		correction.Add(new(btcec.ModNScalar).NegateVal(&masks[i]))
		encoded := correction.Bytes()
		offset := n*wrapSize + (i-2)*correctionSize
		copy(entries[offset:], encoded[:])
		correction.Zero()
	}
	aad = append(context[:32:32], entries...)

	summary := make([]byte, summaryFixed+4*n)
	copy(summary, config.WalletID[:])
	binary.BigEndian.PutUint32(summary[16:], config.Revision)
	for i, participant := range participants {
		copy(summary[summaryFixed+4*i:], participant.Fingerprint[:])
	}
	summaryKey := taggedHash("summary-key", context[:], seed[:])
	defer clear(summaryKey[:])
	summaryAEAD, _ := chacha20poly1305.New(summaryKey[:])
	summaryCT := summaryAEAD.Seal(nil, zeroNonce, summary, aad)

	// s = P(0) = 2*h_1 - h_2.
	secret := lineShare(&masks[0], &masks[1], 0)
	defer secret.Zero()
	secretBytes := secret.Bytes()
	defer clear(secretBytes[:])
	contentKey := taggedHash("content-key", context[:], secretBytes[:])
	defer clear(contentKey[:])
	contentAEAD, _ := chacha20poly1305.New(contentKey[:])

	blob := append(header, entries...)
	blob = append(blob, summaryCT...)
	return contentAEAD.Seal(
		blob, zeroNonce, payload, append(aad, summaryCT...),
	), nil
}

// secpOddPrefix is the first byte of a compressed point with odd Y.
const secpOddPrefix = 0x03

type envelope struct {
	blob      []byte
	n         int
	threshold int
	header    []byte
	entries   []byte
	summaryCT []byte
	contentCT []byte
	public    *btcec.PublicKey
}

// parse checks everything that needs no key and no epoch: lengths, the format
// byte, the ephemeral X coordinate, and canonical corrections.
func parse(blob []byte) (*envelope, error) {
	if len(blob) < headerSize {
		return nil, ErrInvalidBackup
	}
	format := blob[formatOffset]
	n := int(format & 0x07)
	threshold := int(format>>3&1) + 1
	if format&0xf0 != formatVersion || n < 1 || n > MaxParticipants ||
		threshold > n {

		return nil, ErrInvalidBackup
	}
	summaryStart := headerSize + entriesSize(n, threshold)
	contentStart := summaryStart + summaryCTSize(n, threshold)
	payloadSize := len(blob) - contentStart - tagSize
	if payloadSize < 0 || payloadSize > MaxPayloadSize {
		return nil, ErrInvalidBackup
	}
	public, err := schnorr.ParsePubKey(blob[pointOffset:headerSize])
	if err != nil {
		return nil, ErrInvalidBackup
	}
	entries := blob[headerSize:summaryStart]
	for offset := n * wrapSize; offset < len(entries); {
		var correction btcec.ModNScalar
		if correction.SetByteSlice(
			entries[offset : offset+correctionSize],
		) {

			return nil, ErrInvalidBackup
		}
		offset += correctionSize
	}
	return &envelope{
		blob:      blob,
		n:         n,
		threshold: threshold,
		header:    blob[:headerSize],
		entries:   entries,
		summaryCT: blob[summaryStart:contentStart],
		contentCT: blob[contentStart:],
		public:    public,
	}, nil
}

func (e *envelope) context(network [32]byte, epoch uint32) [32]byte {
	return taggedHash("context", network[:], epochBytes(epoch), e.header)
}

func (e *envelope) backupID(network [32]byte, epoch uint32) [32]byte {
	return taggedHash("publication", network[:], epochBytes(epoch), e.blob)
}

func (e *envelope) summaryAAD(context [32]byte) []byte {
	return append(context[:32:32], e.entries...)
}

// openContent decrypts the payload with a content key derived from secret,
// which is the key seed for single-device recovery and the interpolated
// scalar for two-device recovery.
func (e *envelope) openContent(context [32]byte, secret []byte) ([]byte,
	error) {

	key := taggedHash("content-key", context[:], secret)
	defer clear(key[:])
	aead, _ := chacha20poly1305.New(key[:])
	aad := append(e.summaryAAD(context), e.summaryCT...)
	return aead.Open(nil, zeroNonce, e.contentCT, aad)
}

// Open lets one participant decrypt its part of a backup. Height is the
// publication's confirmed block height, not the current tip. The epoch is not
// transmitted: the block's epoch and the preceding one are tried, matching
// the two beacons used in discovery.
//
// For a two-device backup the result carries the summary and one share. For
// a single-device backup it already authorizes Recover on its own.
func Open(network [32]byte, height uint32, blob []byte,
	private *btcec.PrivateKey) (*Contribution, error) {

	if private == nil || private.Key.IsZero() {
		return nil, ErrNotRecipient
	}
	envelope, err := parse(blob)
	if err != nil {
		return nil, err
	}
	var public [33]byte
	copy(public[:], private.PubKey().SerializeCompressed())
	shared := btcec.GenerateSharedSecret(private, envelope.public)
	defer clear(shared)

	epochs := []uint32{height / EpochBlocks}
	if epochs[0] > 0 {
		epochs = append(epochs, epochs[0]-1)
	}
	for _, epoch := range epochs {
		beacon := Beacon(network, public, epoch)
		for i := 0; i < envelope.n; i++ {
			if !bytes.Equal(envelope.header[4*i:4*i+4], beacon[:]) {
				continue
			}
			contribution, err := envelope.open(
				network, epoch, public, shared, byte(i+1),
			)
			if errors.Is(err, ErrNotRecipient) {
				continue
			}
			return contribution, err
		}
	}
	return nil, ErrNotRecipient
}

// open tries one epoch and one index whose beacon slot matched.
func (e *envelope) open(network [32]byte, epoch uint32, public [33]byte,
	shared []byte, index byte) (*Contribution, error) {

	context := e.context(network, epoch)
	wrap, mask := recipientKeys(shared, context, public[:], index)
	defer mask.Zero()
	contribution := &Contribution{
		summary: Summary{
			Threshold:    byte(e.threshold),
			Participants: byte(e.n),
		},
		share:    scalarShare{index: index},
		epoch:    epoch,
		backupID: e.backupID(network, epoch),
	}
	entry := e.entries[int(index-1)*wrapSize:]
	for j := range wrap {
		contribution.seed[j] = wrap[j] ^ entry[j]
	}
	clear(wrap[:])

	// The payload AEAD is the only authentication of a single-device
	// backup, so membership is established by decrypting it.
	if e.threshold == 1 {
		plaintext, err := e.openContent(context, contribution.seed[:])
		if err != nil {
			return nil, ErrNotRecipient
		}
		clear(plaintext)
		return contribution, nil
	}

	key := taggedHash("summary-key", context[:], contribution.seed[:])
	clear(contribution.seed[:])
	aead, _ := chacha20poly1305.New(key[:])
	clear(key[:])
	summary, err := aead.Open(
		nil, zeroNonce, e.summaryCT, e.summaryAAD(context),
	)
	if err != nil {
		return nil, ErrNotRecipient
	}
	copy(contribution.summary.WalletID[:], summary)
	contribution.summary.Revision = binary.BigEndian.Uint32(summary[16:])
	for i := 0; i < e.n; i++ {
		copy(
			contribution.summary.Fingerprints[i][:],
			summary[summaryFixed+4*i:],
		)
	}
	if contribution.summary.WalletID == ([16]byte{}) {
		return nil, ErrInvalidBackup
	}

	// P(i) is h_i itself for the two participants that define the line,
	// and d_i + h_i for everyone else.
	contribution.share.value = mask
	if index > 2 {
		offset := e.n*wrapSize + int(index-3)*correctionSize
		var correction btcec.ModNScalar
		correction.SetByteSlice(
			e.entries[offset : offset+correctionSize],
		)
		contribution.share.value.Add(&correction)
	}
	return contribution, nil
}

// Recover combines contributions from this exact publication, decrypts the
// payload, and decodes the descriptor. A single-device backup needs one
// contribution, a two-device backup two from distinct participants.
// Combining a device with itself, or contributions from different
// publications, is rejected.
//
// AEAD success is not publisher authentication: the caller must validate the
// descriptor and must not treat it as an approved wallet.
func Recover(network [32]byte, blob []byte,
	contributions ...*Contribution) (string, error) {

	payload, err := recoverPayload(network, blob, contributions...)
	if err != nil {
		return "", err
	}
	descriptor, err := DecodeDescriptor(payload)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidBackup, err)
	}
	return descriptor, nil
}

func recoverPayload(network [32]byte, blob []byte,
	contributions ...*Contribution) ([]byte, error) {

	envelope, err := parse(blob)
	if err != nil {
		return nil, err
	}
	if len(contributions) == 0 {
		return nil, ErrInsufficientShares
	}
	if len(contributions) > envelope.n || contributions[0] == nil {
		return nil, ErrInvalidBackup
	}
	epoch := contributions[0].epoch
	backupID := envelope.backupID(network, epoch)
	shares := make([]scalarShare, len(contributions))
	defer func() {
		for i := range shares {
			shares[i].value.Zero()
		}
	}()
	var seen [MaxParticipants + 1]bool
	for i, contribution := range contributions {
		if contribution == nil || contribution.backupID != backupID ||
			contribution.summary != contributions[0].summary ||
			contribution.share.index == 0 ||
			int(contribution.share.index) > envelope.n ||
			seen[contribution.share.index] {

			return nil, ErrInvalidBackup
		}
		seen[contribution.share.index] = true
		shares[i] = contribution.share
	}
	context := envelope.context(network, epoch)

	if envelope.threshold == 1 {
		plaintext, err := envelope.openContent(
			context, contributions[0].seed[:],
		)
		if err != nil {
			return nil, ErrInvalidBackup
		}
		return plaintext, nil
	}

	if len(shares) < envelope.threshold {
		return nil, ErrInsufficientShares
	}
	secret, err := combine(shares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBackup, err)
	}
	defer secret.Zero()
	encoded := secret.Bytes()
	defer clear(encoded[:])
	plaintext, err := envelope.openContent(context, encoded[:])
	if err != nil {
		return nil, ErrInvalidBackup
	}
	return plaintext, nil
}
