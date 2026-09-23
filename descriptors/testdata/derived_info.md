# Derived descriptor metadata vectors

`derived_info.json` contains a subset of the independently differential-tested
`spending_vectors.json` corpus. Fields retain that file's encoding: scripts,
public keys and stack elements are hexadecimal; coordinates are zero-based.
The witness and scriptSig are reference completions, not signatures to create.
Their final script/control-block elements supply independent expected metadata.
The three `tr-tree-leaf-*` cases describe the same unbalanced tree and collectively
specify every script and proof, in descriptor depth-first order.

The harness checks output commitments, wrapping scripts, leaf membership, proof
verification and ownership isolation. Additional origin and MuSig2 tests exercise
the existing BIP32/328/390 key/vector corpora without changing this spending schema.
