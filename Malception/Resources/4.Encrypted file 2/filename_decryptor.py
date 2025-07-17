#!/usr/bin/env python3
# xor_decrypt.py

DATA_HEX = (
    "9F7C2FE52D5C64C080341AD3351777EF982910C5335C78C7AF1A3ADD2E5664C7BD2807EC115F70DABF2F12DC704972D5F2231DD3"
)

KEY = bytes.fromhex("dc4673b05e3916b3")        # 8-byte repeating XOR key

cipher = bytes.fromhex(DATA_HEX)
plain  = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(cipher))

print("Decrypted bytes (hex):", plain.hex())
print("Decrypted bytes (ascii, best-effort):", plain.decode(errors="replace"))
