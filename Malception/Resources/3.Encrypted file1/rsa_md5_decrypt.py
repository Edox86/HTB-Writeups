#!/usr/bin/env python3
# rsa_md5_decrypt.py  •  pip install pycryptodome

from base64 import b64decode, b64encode
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher   import PKCS1_v1_5

# ──────────────────────────────────────────────────────────────────────
XML_PATH = "priv.xml"          # your decrypted <RSAKeyValue> file
CIPHERTEXT_HEX = (
    "9F 96 25 71 C8 0D 66 8C 67 80 31 1E 03 71 7B 80 "
    "6A 9E 56 C3 B2 BF A2 15 63 9C 68 C0 53 46 56 D9 "
    "88 96 DD 7F 25 27 A3 3A 1D 9D 1A 7E 9B E7 2A 3D "
    "69 3A 54 CC 97 59 6F 47 61 30 83 8C 0F 9C 92 E0 "
    "14 9F 63 4D 07 DD 11 91 ED 06 91 FE D8 2B CE 82 "
    "CC 91 46 0F 2E 03 CE E7 4F 3F FE 3F 8A 62 91 4B "
    "08 77 BF 62 03 CB D0 40 0E 0A 84 C6 B0 E4 AB F1 "
    "39 03 9A 4A FD 2F BA 57 E2 78 F7 49 BA B5 1E E7 "
)
# ──────────────────────────────────────────────────────────────────────

def tag(xml: str, name: str) -> bytes:
    """Base64-decode <name> … </name>."""
    part = xml.split(f"<{name}>")[1].split(f"</{name}>")[0]
    return b64decode(part)

def build_key(xml_text: str) -> RSA.RsaKey:
    n = int.from_bytes(tag(xml_text, "Modulus"),  "big")
    e = int.from_bytes(tag(xml_text, "Exponent"), "big")
    d = int.from_bytes(tag(xml_text, "D"),        "big")
    p = int.from_bytes(tag(xml_text, "P"),        "big")
    q = int.from_bytes(tag(xml_text, "Q"),        "big")

    # pycryptodome will recompute dp, dq, iq and verify them
    if p < q:                          # RSA.construct expects p > q
        p, q = q, p
    return RSA.construct((n, e, d, p, q))

def main() -> None:
    xml = Path(XML_PATH).read_text(encoding="utf-8")
    priv  = build_key(xml)
    cipher = PKCS1_v1_5.new(priv)

    ct = bytes.fromhex(CIPHERTEXT_HEX.replace(" ", ""))
    md5 = cipher.decrypt(ct, sentinel=b"\x00")   # sentinel dummy

    if len(md5) != 16:
        raise ValueError("Decryption failed – check ciphertext or key.")

    print("[+] MD5 (hex)    :", md5.hex())
    print("[+] MD5 (Base64) :", b64encode(md5).decode())

if __name__ == "__main__":
    main()
