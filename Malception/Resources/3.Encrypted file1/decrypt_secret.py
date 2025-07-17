#!/usr/bin/env python3
# decrypt_secret.py  •  pip install pycryptodome
#
# Uses the very same parameters the .NET code (Graphy.Encrypt<RijndaelManaged>)
# employed:  PBKDF2-SHA1, Salt = [21,204,127,…], Iterations = 2, KeySize = 256,
# AES-CBC, PKCS7 padding.

from pathlib import Path
from base64   import b64encode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher       import AES
from Crypto.Util.Padding import unpad

# ----------------------------------------------------------------------
# ❶  inputs – edit if your paths / MD5-b64 differ
# ----------------------------------------------------------------------
ENC_PATH   = Path("secret.jpg.enc")     # ciphertext from the malware
OUT_PATH   = Path("secret.jpg")         # decrypted output
MD5_B64    = "obH+aYcMsXxTUtE1OOE5Kg==" # [+] MD5 (Base64) you recovered

# Graphy hard-coded constants
SALT       = bytes([21, 204, 127, 153, 3, 237, 10, 26,
                    19, 103, 23, 31, 55, 49, 32, 57])
ITERATIONS = 2
KEY_SIZE   = 32          # 256 bits
IV_SIZE    = 16          # AES block

# ----------------------------------------------------------------------
def derive_key_iv(password_str: str) -> tuple[bytes, bytes]:
    """
    Replicates .NET Rfc2898DeriveBytes successive .GetBytes() calls.
    First 32 bytes → key, next 16 bytes → IV.
    """
    pwd_bytes = password_str.encode("utf-8")                # ASCII chars
    blob48    = PBKDF2(pwd_bytes, SALT,
                       dkLen=KEY_SIZE + IV_SIZE,
                       count=ITERATIONS)                    # SHA-1 under the hood
    return blob48[:KEY_SIZE], blob48[KEY_SIZE:]

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(ciphertext), AES.block_size)

def main() -> None:
    key, iv = derive_key_iv(MD5_B64)
    ct      = ENC_PATH.read_bytes()
    plain   = decrypt(ct, key, iv)

    OUT_PATH.write_bytes(plain)
    print(f"[+] Decryption OK  →  {OUT_PATH}  ({len(plain)} bytes)")
    print("    Key :", key.hex())
    print("    IV  :", iv.hex())

if __name__ == "__main__":
    main()
