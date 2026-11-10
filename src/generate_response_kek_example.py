#!/usr/bin/env python3
"""
Generates the worked example of the SCEP response key-encryption key (KEK)
derivation defined in the "Encrypting responses" section of draft-pqc-scep.

Output: responseKekExample.md (next to this script), intended for direct
inclusion in the draft with:

    ~~~
    {::include ./src/responseKekExample.md}
    ~~~

All inputs are fixed, so the output is deterministic and only changes
when the derivation itself changes.
"""

import hashlib
import os
import textwrap

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5652

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "responseKekExample.md")
WRAP_WIDTH = 67

# Static label from the "Encrypting responses" section.
STATIC_INFO = b"SCEP-KEM-Response"

# Algorithms taken from the request's KEMRecipientInfo.
# These match RFC 9936 for ML-KEM-768: HKDF-SHA256 and AES-256 key wrap.
KDF_NAME = "id-alg-hkdf-with-sha256"
WRAP_NAME = "id-aes256-wrap"
ID_AES256_WRAP = univ.ObjectIdentifier("2.16.840.1.101.3.4.1.45")
KEK_LEN = 32  # key size of id-aes256-wrap

# Example transaction values. The CEKs are derived from fixed labels so that
# they look random but are reproducible.
TRANSACTION_ID = "2F3C5D7E9A1B4C6D8E0F1A2B3C4D5E6F"
REQUEST_CEK = hashlib.sha256(b"draft-pqc-scep example: request CEK").digest()    # AES-256-CBC
RESPONSE_CEK = hashlib.sha256(b"draft-pqc-scep example: response CEK").digest()  # AES-256-CBC


def wrap(label, value):
    """Formats 'label: value' wrapped to fit an RFC artwork block."""
    return "\n".join(textwrap.wrap(f"{label}: {value}", width=WRAP_WIDTH))


def derive_response_kek(request_cek, transaction_id):
    """Derives the response KEK from the request CEK. Returns (info, kek)."""
    info = STATIC_INFO + transaction_id.encode("ascii")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEK_LEN, salt=None, info=info)
    return info, hkdf.derive(request_cek)


def build_kekri(transaction_id, encrypted_key):
    """Builds the RecipientInfo (kekri choice) carried in the response EnvelopedData."""
    ri = rfc5652.RecipientInfo()
    kekri = ri["kekri"]
    kekri["version"] = 4
    kekri["kekid"]["keyIdentifier"] = transaction_id.encode("ascii")
    kekri["keyEncryptionAlgorithm"]["algorithm"] = ID_AES256_WRAP
    kekri["encryptedKey"] = encrypted_key
    return der_encode(ri)


def main():
    info, kek = derive_response_kek(REQUEST_CEK, TRANSACTION_ID)
    encrypted_key = aes_key_wrap(kek, RESPONSE_CEK)
    kekri_der = build_kekri(TRANSACTION_ID, encrypted_key)

    # Self-check: the client side recovers the response CEK.
    _, client_kek = derive_response_kek(REQUEST_CEK, TRANSACTION_ID)
    assert aes_key_unwrap(client_kek, encrypted_key) == RESPONSE_CEK

    lines = [
        "Example of deriving the response KEK and wrapping the response CEK.",
        "",
        "# Inputs:",
        "",
        wrap("transactionID", TRANSACTION_ID),
        "",
        wrap("KDF (from request KEMRecipientInfo)", KDF_NAME),
        "",
        wrap("wrap (from request KEMRecipientInfo)", WRAP_NAME),
        "",
        wrap("Request CEK", REQUEST_CEK.hex()),
        "",
        wrap("Response CEK", RESPONSE_CEK.hex()),
        "",
        "# Key derivation:",
        "# info = \"SCEP-KEM-Response\" || transactionID",
        "# KEK = HKDF-SHA256(IKM = Request CEK, salt = <absent>,",
        f"#                  info = info, L = {KEK_LEN})",
        "",
        wrap("info", info.hex()),
        "",
        wrap("KEK", kek.hex()),
        "",
        "# Outputs:",
        "# encryptedKey = AES-256-KeyWrap(KEK, Response CEK)",
        "",
        wrap("encryptedKey", encrypted_key.hex()),
        "",
        "# RecipientInfo (kekri), DER:",
        "",
        wrap("kekri", kekri_der.hex()),
        "",
    ]

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(lines))
    print(f"Wrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
