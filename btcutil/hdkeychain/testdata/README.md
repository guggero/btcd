# BIP vectors

Source: bitcoin/bips commit `55083d36ddebcd2a039135a2f4ee74917a5803d3`.

- `bip328.json` is the complete, unchanged `bip-0328/vectors.json` (CC0).
  The constructor tests use the supplied aggregate points; they do not depend
  on MuSig2. Descriptor integration tests verify participant aggregation too.
- `bip32.json` transcribes every case in the five vector groups of
  `bip-0032.mediawiki`: 17 derivation cases and 16 invalid extended keys.
  Paths replace the document's subscript H with an apostrophe.

The existing `NewKeyFromString` accepts arbitrary version bytes and nonzero
root metadata. `TestBIP32JSONVectors` explicitly checks these eight legacy
deviations instead of skipping those invalid vectors or changing compatibility
as a side effect of adding BIP328. The other eight invalid keys must be rejected.
