#!/usr/bin/env python3
"""Independent, TEST-ONLY v4 vectors; requires Python cryptography.

Run from any directory; JSON is written beside this script. This uses
cryptography's secp256k1 ECDH, HKDF and ChaCha20Poly1305 implementations,
Python integer arithmetic, zlib's DEFLATE, and no Go code. All secrets are
public.
"""

import hashlib
import json
import re
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SUITE = b"btcd/walletbackup/v4-experiment/"
ZERO12 = bytes(12)
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NUMS = b"50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

# The preset DEFLATE dictionary, written out independently of the Go source.
DICTIONARY = (
    b"ripemd160(hash160(hash256(sha256("
    b"andor(and_b(and_n(or_b(or_c(or_i(or_d(and_v(v:pk("
    b"thresh(after(older("
    b"pk_h(pk_k(pkh(sh(wpkh(musig(multi_a(sortedmulti_a(multi("
    b"/44h/49h/45h/87h/1h/0h]/84h/0h/0h]/86h/0h/0h]"
    b"/48h/1h/0h/2h]/48h/0h/0h/2h]"
    b"/44'/49'/45'/87'/1'/0']/84'/0'/0']/86'/0'/0']"
    b"/48'/1'/0'/2']/48'/0'/0'/2']"
    b"/0/*/1/*)"
    b"tr(" + NUMS + b",{"
    b"\x80\x00\x00\x00\x80\x00\x00\x01\x80\x00\x00\x02"
    b"]\x00\x04\x35\x87\xcf\x03]\x00\x04\x35\x87\xcf\x04"
    b"]\x00\x04\x88\xb2\x1e\x03]\x00\x04\x88\xb2\x1e\x04"
    b"/<0;1>/*)),[/<0;1>/*,["
    b"wsh(sortedmulti(2,["
)
assert hashlib.sha256(DICTIONARY).hexdigest() == (
    "77f58b334526d83a20d8a10ec10b197d486f20f8945ae3e9b00a10dbd892487b"
)


def u32(value):
    return value.to_bytes(4, "big")


def scalar(value):
    return value.to_bytes(32, "big")


def tagged(label, *parts):
    tag = hashlib.sha256(SUITE + label).digest()
    return hashlib.sha256(tag + tag + b"".join(parts)).digest()


def private(value):
    return ec.derive_private_key(value, ec.SECP256K1())


def public(value):
    return private(value).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def base58check(data):
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    value, text = int.from_bytes(data, "big"), ""
    while value:
        value, digit = divmod(value, 58)
        text = ALPHABET[digit] + text
    return text


def base58check_decode(text):
    value = 0
    for char in text:
        value = value * 58 + ALPHABET.index(char)
    return value.to_bytes(82, "big")[:78]


def encode_descriptor(descriptor):
    substituted = re.sub(
        rb"[xt]pub[1-9A-HJ-NP-Za-km-z]{107}",
        lambda m: b"\x00" + base58check_decode(m.group().decode()),
        descriptor.encode(),
    )
    compressor = zlib.compressobj(
        9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY, DICTIONARY
    )
    return compressor.compress(substituted) + compressor.flush()


def test_key(priv, path):
    """A structurally valid tpub with deterministic, public contents."""
    label = u32(priv)
    return base58check(
        bytes.fromhex("043587cf") + bytes([len(path)])
        + hashlib.sha256(b"parent" + label).digest()[:4]
        + u32(path[-1] | 1 << 31)
        + hashlib.sha256(b"chain code" + label).digest()
        + public(100 + priv)
    )


def descriptor_for(threshold, privs):
    def key(priv, path):
        origin = "/".join("%dh" % p for p in path)
        return "[%s/%s]%s/<0;1>/*" % (
            u32(priv).hex(), origin, test_key(priv, path)
        )
    if len(privs) == 1:
        return "wpkh(%s)" % key(privs[0], [84, 1, 0])
    return "wsh(sortedmulti(%d,%s))" % (
        threshold, ",".join(key(p, [48, 1, 0, 2]) for p in privs)
    )


class Entropy:
    def __init__(self):
        self.data = b"".join(
            hashlib.sha256(b"walletbackup-vector-v4" + u32(i)).digest()
            for i in range(16)
        )
        self.offset = 0

    def read(self, size):
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        assert len(result) == size
        return result

    def scalar(self):
        while True:
            value = int.from_bytes(self.read(32), "big")
            if 0 < value < N:
                return value


def generate(threshold, count):
    rng = Entropy()
    network = bytes(range(32))
    wallet_id = hashlib.sha256(b"independent vector wallet").digest()[:16]
    epoch, revision = 450, 7
    participants = sorted((public(i), i) for i in range(1, count + 1))

    e = rng.scalar()
    if public(e)[0] == 3:
        e = N - e
    seed = rng.read(16)
    filler = rng.read(4 * (5 - count))

    beacons = [
        tagged(b"beacon", network, pub, u32(epoch))[:4]
        for pub, _ in participants
    ]
    header = (
        b"".join(beacons) + filler
        + bytes([0x40 | (threshold - 1) << 3 | count]) + public(e)[1:]
    )
    assert len(header) == 53
    context = tagged(b"context", network, u32(epoch), header)

    wraps, masks, details = [], [], []
    for i, (pub, priv) in enumerate(participants, start=1):
        shared = private(e).exchange(ec.ECDH(), private(priv).public_key())
        material = HKDF(
            algorithm=hashes.SHA256(), length=48, salt=context,
            info=SUITE + b"recipient/" + pub + bytes([i])
        ).derive(shared)
        mask = int.from_bytes(material[16:], "big") % N
        wraps.append(xor(seed, material[:16]))
        masks.append(mask)
        details.append({
            "private_key": scalar(priv).hex(), "public_key": pub.hex(),
            "index": i, "shared_x": shared.hex(),
            "wrap_pad": material[:16].hex(), "mask": scalar(mask).hex(),
        })

    descriptor = descriptor_for(threshold, [priv for _, priv in participants])
    payload = encode_descriptor(descriptor)
    entries = b"".join(wraps)
    result = {
        "name": f"{threshold}-of-{count}", "threshold": threshold,
        "network": network.hex(), "wallet_id": wallet_id.hex(),
        "epoch": epoch, "revision": revision,
        "entropy": rng.data[:rng.offset].hex(), "ephemeral": scalar(e).hex(),
        "seed": seed.hex(), "participants": details,
        "beacons": [b.hex() for b in beacons], "header": header.hex(),
        "context": context.hex(), "descriptor": descriptor,
        "payload": payload.hex(),
    }

    if threshold == 1:
        content_key = tagged(b"content-key", context, seed)
        content_ct = ChaCha20Poly1305(content_key).encrypt(
            ZERO12, payload, context + entries
        )
        blob = header + entries + content_ct
    else:
        slope = (masks[1] - masks[0]) % N
        assert slope != 0
        shares = [(masks[0] + (i - 1) * slope) % N for i in range(1, count + 1)]
        assert shares[0] == masks[0] and shares[1] == masks[1]
        secret = (2 * masks[0] - masks[1]) % N
        for i in range(2, count):
            correction = (shares[i] - masks[i]) % N
            entries += scalar(correction)
            details[i]["correction"] = scalar(correction).hex()
        for detail, share in zip(details, shares):
            detail["share"] = scalar(share).hex()
        hints = b"".join(u32(priv) for _, priv in participants)
        summary = wallet_id + u32(revision) + hints
        summary_key = tagged(b"summary-key", context, seed)
        summary_ct = ChaCha20Poly1305(summary_key).encrypt(
            ZERO12, summary, context + entries
        )
        content_key = tagged(b"content-key", context, scalar(secret))
        content_ct = ChaCha20Poly1305(content_key).encrypt(
            ZERO12, payload, context + entries + summary_ct
        )
        blob = header + entries + summary_ct + content_ct
        result.update({
            "slope": scalar(slope).hex(), "secret": scalar(secret).hex(),
            "summary": summary.hex(), "summary_key": summary_key.hex(),
            "summary_ct": summary_ct.hex(),
        })

    result.update({
        "entries": entries.hex(), "content_key": content_key.hex(),
        "content_ct": content_ct.hex(), "blob": blob.hex(),
    })
    return result


if __name__ == "__main__":
    vectors = [
        generate(1, 1), generate(1, 3), generate(2, 2), generate(2, 3),
        generate(2, 5),
    ]
    Path(__file__).with_name("vectors.json").write_text(
        json.dumps(vectors, indent=2) + "\n"
    )
