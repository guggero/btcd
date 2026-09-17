# BIP vectors

Source: bitcoin/bips commit `55083d36ddebcd2a039135a2f4ee74917a5803d3`.

- `bip328.json` is the complete, unchanged `bip-0328/vectors.json` (CC0).
  The constructor tests use the supplied aggregate points; they do not depend
  on MuSig2. Descriptor integration tests verify participant aggregation too.
- `bip32.json` transcribes every case in the five vector groups of
  `bip-0032.mediawiki`: 17 derivation cases and 16 invalid extended keys.
  Paths replace the document's subscript H with an apostrophe.

`slip132.json` transcribes all three Bitcoin test vectors from
[SLIP-0132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md),
retrieved 2026-09-22. The supplied account keys correspond to the listed paths;
each address is for the account's `/0/0` child. `TestSLIP132Vectors` checks both
parsers, neutering, child derivation and the published addresses. Mnemonic-to-seed
conversion is outside hdkeychain and is not part of this test.

`TestBIP32JSONVectors` round-trips every valid key through both parsing APIs.
`NewKeyFromString` retains its eight legacy metadata/version exceptions,
which are asserted explicitly rather than skipped. Bitcoin's SLIP-0132 pairs
can be enabled with `chaincfg.RegisterSLIP132KeyIDs` before concurrent use.

`NewKeyFromStringStrict` rejects all 16 invalid keys. Custom version
bytes must be registered with `chaincfg.RegisterHDKeyID` before parsing.
