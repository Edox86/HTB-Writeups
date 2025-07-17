#!/usr/bin/env python3
# rsa_md5_decrypt.py  •  pip install pycryptodome

from base64 import b64decode, b64encode
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher   import PKCS1_v1_5

# ──────────────────────────────────────────────────────────────────────
XML_PATH = "priv.xml"          # your decrypted <RSAKeyValue> file
CIPHERTEXT_HEX = (
    "47 A5 8E 3E 07 30 5D 49 88 F6 8A 9E 1D 4B 03 1B 13 19 C0 A2 B1 D0 83 D2 DC EE 58 DC 78 FC 2E 81 25 51 A5 BD 3C 2C 22 74 3D FF 0D F9 D2 83 B3 FD 00 D9 B9 BD 6F 93 5C BD 0E 2D 8C 48 7B 37 83 00 BC BE AF 10 90 45 13 04 4E 1E 1B C1 5F 06 1B BB 6D 51 AC BF 78 9E 62 3A 80 FF A4 49 3D AF 44 20 AC FC 6B 31 53 3B DF EF CA 19 73 F1 D4 80 9C 32 59 31 96 A4 7E 32 6E 31 D3 4A 22 3C 5C 23 0C 09"
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
