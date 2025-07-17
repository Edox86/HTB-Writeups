#!/usr/bin/env python3
# xor_decrypt.py

DATA_HEX = (
    "9F7C2FE52D5C64C080341AD3351777EF982910C5335C78C7"
    "AF1A30DC3F4A65DABA2F16D4024A73D0AE23079E3449719DB928"
)

KEY = bytes.fromhex("dc4673b05e3916b3")        # 8-byte repeating XOR key

cipher = bytes.fromhex(DATA_HEX)
plain  = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(cipher))

print("Decrypted bytes (hex):", plain.hex())
print("Decrypted bytes (ascii, best-effort):", plain.decode(errors="replace"))
