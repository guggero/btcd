# BIP327 vectors

All eight JSON files are copied unchanged from bitcoin/bips commit
`55083d36ddebcd2a039135a2f4ee74917a5803d3`, `bip-0327/vectors` (CC0).
They replace the older, locally modified fixtures formerly under `data/`.

The existing vector harnesses execute key sorting, key aggregation, nonce
generation, nonce aggregation, signing/verification, tweaking, and signature
aggregation, including their negative cases.

Two arbitrary-length-message signing cases are explicitly skipped: the public
`Sign` API accepts a `[32]byte` digest. Nonce-generation tests do cover absent,
empty and variable-length messages through the internal options. The optional
deterministic-signing algorithm has no implementation here; its complete
`det_sign_vectors.json` is retained for future support, not claimed as tested.
Neither limitation affects BIP328 derivation or BIP390 output construction.
