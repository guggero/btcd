# On-chain encrypted descriptor backups: v3 experiment

Status: design review and executable proposal, 2026-09-06. No BIP number or
derivation purpose is assigned by this document. The v1 and v2 drafts in the
adjacent `bips` checkout are unchanged. The implementation was
[`walletbackup`](../walletbackup/README.md) as of commit `6f6fefdf`. That
package has since moved to [v4](bip-opreturn-backup-v4.md), which narrows this
format; the byte layout below describes v3 only.

## Verdict on v2

The recovery experience makes sense. Dedicated seed-derived backup keys,
public-key encryption, a single-participant summary, and a threshold-encrypted
descriptor are a useful combination. The specific v2 construction should not
be deployed. Its main problems are substantive, not just missing test vectors.

| Finding | Consequence | v3 decision |
| --- | --- | --- |
| Ephemeral private key is a public hash of configuration and plaintext | Public-key holders can validate plaintext guesses and recover encryption keys | Fresh independent randomness |
| Wallet ID depends only on the backup key set | Different accounts/policies using the same devices collide by construction | Independent wallet instance ID |
| Sorted beacons, length constraints, and repeated beacons | The complete output is not indistinguishable from random | Explicit experimental format; no disguise claim |
| Encryption accepts any publisher with the public keys | Fake wallet configurations can pass every AEAD check | Preserve candidates; separate approval from encryption |
| Minimum spending key count is treated as an access policy | General miniscript policies become broader recovery policies | Explicit recovery policy and documented trade-off |
| Filter header chain is described without its trust assumptions | An index provider can conceal backups | Explicit completeness assumptions |

### 1. The deterministic ephemeral key breaks the public-key security model

V2 computes, with public hashing and reduction modulo the group order:

```
e  = H(backup_public_keys || schema || payload)
E  = eG
K1 = H(e)
K2 = scalar(H(e))
```

An adversary who knows the backup public keys and has a candidate schema and
payload computes `e_guess G` and compares its x-coordinate with decoded `E`.
On a match, the adversary knows `e`, both encryption keys, every ECDH shared
secret, and the polynomial coefficients. No participant private key is needed.
Argon2 is irrelevant to this test: the content key is obtained directly from
`e`. ElligatorSwift also does not help; its point decoding is public.

This is a dictionary/known-plaintext failure, not a general method of
recovering an arbitrary unknown descriptor. A descriptor containing unknown
high-entropy xpubs may be infeasible to guess. But the security promise must
survive knowledge of all recipient public keys and predictable plaintext.
Policies, revisions, fingerprints and descriptors often already exist in the
coordinator data whose compromise the proposal discusses. A captured schema
from one participant further reduces uncertainty. An encrypted payload is not
a substitute for encryption randomness.

This is also not the SIV security property. A SIV construction uses a secret
cryptographic key; an unkeyed hash of guessable inputs does not supply that
key. See [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297).
`TestV2PlaintextGuessRecoversEphemeral` demonstrates the exact v2 key derivations
and resulting content-key recovery with two guesses and zero private keys.

The publisher necessarily knows the plaintext and the encryption secrets
while constructing any such backup. The achievable goal is that its retained
public configuration cannot later decrypt independently created backups,
assuming temporary secrets have been discarded. “The publisher never holds
anything that decrypts” is incorrect for both v2 and the repaired design.

### 2. A device set is not a wallet identity

With a backup key per seed, accounts 0 and 1 on the same three devices have
identical `B_1,B_2,B_3`. V2 consequently assigns both the same wallet ID and
tells recovery to select the highest version. Different thresholds, networks,
script types, and unrelated wallet policies can collide in the same way.
Conversely, replacing a device changes the ID despite a continuing wallet.

Use a random 32-byte wallet instance ID inside the encrypted summary. Retain it
across metadata revisions. Create a new ID for a distinct wallet/account or a
materially different spending policy; represent explicit succession in a future
payload format. Group by network and ID as a presentation aid, never as an
authorization decision. A publisher can lie about an ID, so grouping cannot
justify deleting or suppressing a competing backup.

### 3. The random-looking-output claim is false

For sixteen participants, all sixteen v2 beacons are sorted and there is no
filler. Sixteen distinct independent random words have that order with
probability `1/16!`, approximately `4.78e-14`. For smaller sets, a sorted prefix
also leaks information if the intended placement is the first `n` slots.

Moreover, with the recommended 64-byte payload padding, the v2 envelope length
is `240 + 64*n + 64*k`, hence always `48 mod 64`. This is another filter on
candidate outputs. Identical beacons across publications within an epoch
create equality relations inconsistent with independent random envelopes.
Leaked backup public keys identify publications in every epoch anyway.
Timing, funding, payload size, and co-occurrence can also support cross-epoch
inferences. Lack of a magic prefix is not a proof of anonymity or deniability.

ElligatorSwift can hide the encoding structure of the ephemeral point. It
does not hide these other structures. The point encoding is already available
in [`btcec/ellswift`](../btcec/ellswift/ellswift.go), but this experiment uses
compressed points and makes no format-hiding claim. A future hiding profile
needs a specified leakage model and a review of the entire transcript, not
just its individual fields. [BIP 324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
is the reference for the encoding, not a security proof for this envelope.

### 4. Encryption does not establish an approved wallet

Anyone with the recipient public keys can encrypt a convincing forged policy.
An AEAD tag proves integrity relative to its key, not who created that key.
V2 recognizes this attack, but “the forged wallet has no history” is not a
reliable defense. The attacker can fund a forged wallet, copy real history
through an unchanged descriptor with false metadata, or target a genuine
wallet which has not yet received funds. Real backups also naturally have
multiple revisions; their mere multiplicity is not itself evidence of attack.

Signatures are possible without a shared symmetric secret. For example, a
future profile could require device signatures over a domain-separated
manifest committing to network, wallet instance, policy, recipient keys,
threshold and revision. Signing should use a separate hardened approval key,
with a defined binding to the seed's backup key. Recovery must anchor approval
to keys it already trusts, including the recovered seed, rather than accepting
an attacker-provided signer list as a trust root. Threshold signatures do not
solve this trust bootstrap automatically.

This adds a setup/update ceremony and deserves its own specification. V3's
experiment explicitly retains unauthenticated public publishing. It MUST NOT
silently select a wallet for receiving funds based solely on decryption or the
largest revision number. A rescan and independent policy confirmation are
required; a rescan is useful evidence, not cryptographic approval.

### 5. Threshold recovery is a policy choice

For uniform `k-of-n` multisig with distinct participating seeds, choose either
`r=k` for quorum confidentiality or `r=1` for single-device recovery. The same
construction supports both; neither is cryptographically mandatory. The
single-operator case may reasonably prefer `r=1` for usability. A multi-person
wallet may prefer that one compromised seed reveal only a summary.

For `(A AND B) OR (C AND D)`, a 2-of-4 Shamir scheme also authorizes `{A,C}`,
which cannot spend. It satisfies a spending-implies-recovery requirement but
does not reproduce the spending policy. More generally, let `D(S)` be the set
of distinct backup identities available to a spending set `S`. A uniform
threshold must obey `r <= min_S |D(S)|` to give that guarantee. If this minimum
is zero, no positive threshold over the chosen key set works: reject the
guarantee or add a recovery method. Counting omitted signers informally is
not sufficient. Account keys derived from one seed count as one identity.

A future single-key timelock path forces `r=1` *today* under that rule. An
offline static ciphertext does not enforce a future decryption time just
because the spending script has a timelock. Hash preimages, DKG key shares,
and other recovery artifacts may also be needed to spend. Descriptor recovery
does not regenerate those secrets.

### 6. Smaller corrections that still matter

* Uniform Shamir coefficients give information-theoretic secrecy for the raw
  shares. The whole envelope has computational security: ECDH, HKDF, and AEAD
  are computational assumptions. V2's deterministic coefficients in
  particular do not justify an unconditional secrecy claim.
* “At least one strong seed” is not sufficient protection for a threshold
  wallet: in 2-of-3 with two enumerable seeds and one strong seed, the two weak
  ones suffice. Fewer than `r` compromised or guessable backup keys are needed
  for descriptor confidentiality; schema privacy has a one-key floor.
* Argon2 on an ECDH output is not needed to stretch a password. It cannot
  force seed enumeration through Argon2 when an attacker already has a backup
  public key, account xpub, or another cheap seed verifier. Beacon-based
  enumeration without such side information can have a different cost. This
  experiment removes stretching and assumes adequate seed entropy. It does
  not claim to harden weak seeds.
* V2 binds the entry table only at content decryption. An outsider can damage
  corrections or rearrange wraps while a summary still opens. Bind the table
  in the summary AEAD and bind recipient indexes in the KDF. A participant
  knowing the summary key can still rewrite a summary: this is not sender
  authentication or verifiable secret sharing.
* Validate points, reject duplicate backup public keys, reject noncanonical
  scalar encodings, and reject repeated share indexes. Zero is valid for a
  share or polynomial coefficient. Duplicate fingerprints are permitted; a
  four-byte fingerprint is a hint, not a key identity. Distinct public keys do
  not prove independent entropy sources or honest manufacturers.
* V2 mixes arbitrary monotonic version counters with block-height checks and
  epoch derivation. Separate a publication epoch from a wallet revision.
  Equality, reorgs, competing publishers and replay require explicit behavior.
* A backup advertised by a schema need not be decryptable by every intended
  quorum if the publisher is malicious or faulty. Payload AEAD detects failure
  at recovery time; it does not certify correct dealing at setup.

## Experimental v3 specification

The following byte layout and derivations are implemented, with independent
vectors. They deliberately trade format hiding for clear parsing and bounded
work. This is a reviewable candidate, not a proposed final BIP assignment.

### Keys and parameters

Each seed has a dedicated backup key pair `(b,B)`, separated by hardened BIP32
derivation from spending keys. The eventual specification must assign the
purpose and roles. The example's `m/100000'/0'` is explicitly test-only.
`B` is a valid 33-byte compressed secp256k1 point. Sort distinct `B` values
lexicographically; their one-based positions are Shamir indexes `1..n`.

Use `1 <= r <= n <= 16`. Network `network` is the chain's 32-byte genesis hash
in wire byte order, supplied externally. No human-displayed hex reversal is
performed inside the cryptographic functions. Assign a random, nonzero
32-byte `wallet_id` once per wallet instance. Maintain a `uint64` revision
separately from `epoch = floor(construction_tip_height/2016)`.

### Hashes, randomness, and notation

`T(label, parts...)` is BIP340 tagged SHA256, with tag equal to the UTF-8 bytes
of `btcd/walletbackup/v3-experiment/` followed by `label`. `||` denotes byte
concatenation. Integers use fixed-width big-endian encoding. Scalar arithmetic
uses secp256k1's group order `N`. Compressed points preserve their full parity;
the ECDH output is exactly the 32-byte big-endian `x(eB) = x(bE)`.

For each call to `Seal`, independently sample:

1. Nonzero scalar `e` uniformly in `[1,N-1]`.
2. 32-byte schema key `K1`.
3. Content secret `s` uniformly in `[0,N-1]`.
4. Coefficients `a_1..a_(r-1)` uniformly in `[0,N-1]`.
5. A 12-byte AEAD nonce, random slot filler, and a slot permutation.

Use rejection sampling for scalars; do not exclude zero from the coefficient
distribution. These independent samples avoid requiring a new security
argument about pseudorandomness of mutually related coefficients and keys.
The nonce is used once under each of two independent keys. Retry publication
using retained envelope bytes. Rebuilding samples new secrets even if the
configuration, revision, and payload are identical. Secure publisher randomness
is required; the public API does not accept test entropy.

### Discovery slots and public header

```
beacon_i = T("beacon", network || B_i || uint32(epoch))[0:4]
```

Fill sixteen slots with the real beacons and uniformly random four-byte
fillers, then uniformly shuffle all sixteen slots using Fisher-Yates.
Duplicates from accidental beacon/filler collisions are harmless; discovery
does not establish membership. Public beacon keys allow tracking, and the
same key on the same network in one epoch produces the same beacon.

The 115-byte header is:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 64 | Sixteen shuffled beacon/filler slots |
| 64 | 1 | Experimental format byte `0x03` |
| 65 | 1 | Participant count `n` |
| 66 | 4 | Publication epoch |
| 70 | 33 | Compressed ephemeral point `E=eG` |
| 103 | 12 | AEAD nonce |

Define `context = T("context", network || header)`.
Public `n` makes the entry boundary unambiguous before any decryption.

### Per-participant masking and Shamir sharing

```
P(x)       = s + sum(a_j * x^j) mod N
Z_i        = x(e*B_i) = x(b_i*E)
material_i = HKDF-SHA256(
    IKM  = Z_i,
    salt = context,
    info = UTF8("btcd/walletbackup/v3-experiment/recipient/") || B_i || byte(i),
    L    = 64
)
wrap_i     = K1 XOR material_i[0:32]
h_i        = int(material_i[32:64]) mod N
d_i        = (P(i) - h_i) mod N
entry_i    = wrap_i || scalar32(d_i)
entries    = entry_1 || ... || entry_n
```

HKDF extracts the ECDH material and binds the transcript and recipient. The
two halves serve separate purposes. Reducing a pseudorandom mask modulo `N`
has negligible bias below `2^-127`; random Shamir coefficients themselves use
rejection sampling. Decoders reject serialized corrections `>=N` rather than
silently reducing them.

This resembles the DHKEM/context-binding approach described in
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), but is **not HPKE**:
RFC 9180's specified KEM suites do not include secp256k1, and this is a custom
multi-recipient envelope and key schedule. It requires its own security review.

### Encrypted summary and content

The summary is exactly 112 plaintext bytes:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 32 | Nonzero wallet instance ID |
| 32 | 8 | Revision |
| 40 | 1 | Threshold `r` |
| 41 | 7 | Reserved, all zero |
| 48 | 64 | Sixteen master fingerprints in canonical key order |

Each fingerprint may be zero to omit that hint. Unused slots must be zero.
No uniqueness or identity check uses fingerprints. An actual all-zero
fingerprint is consequently indistinguishable from an omitted hint here.

```
schema_aad = context || entries
schema_ct  = ChaCha20Poly1305(K1).Seal(nonce, summary, schema_aad)
K2         = T("content-key", context || scalar32(s))
content_ct = ChaCha20Poly1305(K2).Seal(
    nonce, payload, schema_aad || schema_ct
)
envelope   = header || entries || schema_ct || content_ct
```

`schema_ct` is 128 bytes; the content tag adds 16 bytes. Total envelope size is
`259 + 64*n + len(payload)` bytes: 323 for 1-of-1, 451 for 2-of-3, and 579 for
3-of-5, before payload. These figures exclude the script push, output value,
transaction framing, and inputs. Neither serialization nor AEAD automatically
pads the payload in this experiment.

The plaintext is opaque to the crypto package. A final descriptor application
must specify framing, padding, descriptor checksum/canonicalization, a birth
height, network checks, policy validation and exclusion of private material.
Compatibility with BIP 138's evolving payload encoding is not claimed by this
implementation; the referenced PR could not be retrieved during this review.
The example carries a descriptor expression, not that external container.

### Recovery

1. Derive the seed's backup public key, and query the custom chunk filter with
   its beacons for the block's epoch and previous epoch. At epoch zero, omit
   the previous-epoch candidate. Download matching blocks and find matching
   slots; do not send seed keys to the index server.
2. Parse bounded lengths, version, count, point and canonical corrections.
   Require `published_epoch <= block_epoch <= published_epoch+1`. Use the
   original confirmation height, not today's tip. A transaction confirmed
   too late must be replaced with a freshly constructed publication to remain
   discoverable by this rule. Reorgs crossing this boundary matter too.
3. Compute the single ECDH result `Z=x(bE)` once. Try each of at most sixteen
   recipient/index KDFs to unwrap a candidate schema key. Check the schema
   AEAD, threshold, wallet ID, reserved bytes, and hint padding. All count and
   entry bytes are bound at this stage.
4. Display the summary as a recovery candidate. For the successful index,
   obtain `P(i)=d_i+h_i mod N`. Bind this contribution to
   `T("publication", network || entire_envelope)`; never combine contributions
   from separate envelopes, even with identical wallet IDs and revisions.
5. With at least `r` distinct indexes, compute
   `s=sum(P(i)*product_{j!=i}(j/(j-i))) mod N`, derive `K2`, and check content
   AEAD. Duplicate devices cannot be counted twice. Payload damage may allow
   a summary to open but must fail here.
6. Validate the recovered policy and the device's own account keys. Preserve
   all conflicting candidates. Revisions help presentation, but are not a
   chain position, signature, completeness proof, or guarantee of freshness.

`Open` and `Recover` implement steps 2–5. The API currently uses software
private keys and opaque local `Contribution` values. Hardware transport,
interactive approval, remote share transport, and the block/index client are
not implemented. The runnable BIP32 example demonstrates the data flow without
implying that private keys should leave real hardware devices.

## Why the interpolation works

For 2-of-3, suppose `s=42` and `a=7`. Then `P(x)=42+7x`, giving shares
`(1,49)`, `(2,56)`, `(3,63)`. Devices 1 and 3 recover:

```
lambda_1 = 3/(3-1) = 3/2
lambda_3 = 1/(1-3) = -1/2
P(0)     = 49*(3/2) + 63*(-1/2) = 42 mod N
```

Division means multiplication by the modular inverse, not floating-point
division. One share, say `(1,49)`, is compatible with every secret `s`: choose
`a=49-s mod N`. Uniform random coefficients make each possibility equally
likely before computational leakage from the rest of the envelope. The ECDH
mask prevents a chain observer from obtaining that share in the first place.

For `r=1`, `P` is constant and each participant recovers `s`. Nothing else in
the construction changes. This is the simplest way to keep the single-key
versus quorum design choice open without maintaining two encryption schemes.

## Discovery and availability are separate security questions

The custom filter needs a new element set: complete aligned four-byte chunks
of the first 64 bytes of concatenated OP_RETURN pushes. A final index protocol
must nail down script parsing, malformed pushes, non-push opcodes, deduplication,
block hash byte order, filter type/version, and reorg behavior. The test builds
the known chunk set with btcd's GCS implementation; it does not implement that
index protocol. [BIP 158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
basic filters explicitly exclude OP_RETURN scripts.

A filter-header chain is not a Bitcoin proof-of-work commitment to correct
filters. A malicious isolated provider can serve a mutually consistent chain
of incomplete filters. Recovery completeness needs independently checked
filters, an appropriate trusted checkpoint/provider model, or the honest-peer
and disagreement-resolution assumptions in
[BIP 157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki).
A block inclusion proof proves presence, not absence of other backups.

For `P=19,M=784931`, the accidental GCS false-positive rate per candidate is
approximately `1/M`, not `2^-19`. At one million blocks and two candidates per
block, this is about 2.55 extra matches. Four-byte chunk collisions add about
0.5 at `2^30` independent chunks, but workload and correlations matter. An
adversary copying beacons is not bound by either accidental-collision estimate.
Index size and initial filter download are additional costs; per-candidate
false-positive counts alone do not establish cheap mobile recovery.

The checked-out btcd policy has `MaxDataCarrierSize=80` in
[`txscript/standard.go`](../txscript/standard.go), so these backups do not fit
its ordinary `NullDataScript`/standard relay path. Confirmed data remains
recoverable from archival blocks, but publication requires an explicit relay
and miner deployment plan. Pruned nodes may not retain historical payloads.
This work does not change policy or broadcast transactions.

## Related code and next review questions

The local branches were inspected without switching the working tree:

* `frost` at `00a422ed`: the trusted dealer and Lagrange coefficients in
  `btcec/schnorr/frost/{dealer,keys}.go` supply the arithmetic pattern. This
  experiment uses scalar shares, including zero, rather than FROST signing
  keys. No FROST nonce generation or signing code is needed for basic recovery.
* `silent-payments-receive` at `6ae2e812`: `silentpayments/dleq.go` supplies a
  useful future direction. A proof that `B=bG` and `Z=bE` can authenticate a
  participant's ECDH contribution, with the publication digest as context.
  [BIP 374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
  is relevant. Such a proof does not prove that the publisher distributed
  shares of the advertised polynomial. Exchanging raw `Z` also releases that
  recipient's schema-unwrapping material; choose the share transport carefully.
* `miniscript` at `8f3b9c4a`: descriptor parsing, `Keys`, `Lift`, and spending
  plans are relevant to validating recovered payloads and explaining policy
  differences. This experiment does not transplant that branch into master.
* `bip-322` and `bip-musig2-psbt`: signing/PSBT work is relevant to a future
  approval ceremony, not necessary for the confidentiality primitive.
* Master already includes `btcec.GenerateSharedSecret`, ElligatorSwift,
  BIP32, GCS and ChaCha20-Poly1305 dependencies. No dependencies were added.
* In the adjacent lnd checkout, `keychain.SingleKeyECDH` returns
  `SHA256(ser_comp(bE))`, whereas this construction needs `x(bE)`. It is not a
  drop-in interface. Its private-key abstraction is useful, but a hardware
  API must specify the exact shared-secret encoding and validated input.

Before standardization, resolve whether device approval signatures are
required, how to verify correct dealing before funding, whether format hiding
is worth its size/complexity, how to represent nonuniform recovery policies,
and who serves complete historical filters. A DLEQ/VSS design and a hardware
approval protocol are follow-up cryptographic work, not properties implicitly
supplied by the current prototype.
