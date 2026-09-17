# MuSig2 vectors

Source: bitcoin/bips commit `55083d36ddebcd2a039135a2f4ee74917a5803d3`.

- `bip328.json` copies the complete `bip-0328/vectors.json` unchanged (CC0).
  Tests check participant aggregation and synthetic xpub serialization.
- `bip390.json` transcribes every vector from `bip-0390.mediawiki` (CC0):
  six valid descriptors, their twelve output scripts, and fourteen invalid
  descriptors. Scripts correspond to derivation indices starting at zero.
  The two `rawtr()` cases exercise key derivation and untweaked script creation
  directly; `rawtr()` itself remains unsupported by the descriptor parser.

All cases execute in `TestBIP328Aggregation` and `TestBIP390Vectors`.
