# HTB Reversing Challenge: Ransom

🔗 [https://app.hackthebox.com/challenges/Ransom](https://app.hackthebox.com/challenges/Ransom)

* * *

## 🧠 Skills Practiced

 *   Reversing x64 assembly with IDA Free
 *   Building a decryption tool from scratch
 *   Static key analysis in malware-like encryption
 *   Manual inspection with hex editors

* * *

## 🧩 Challenge Info

 *   **Challenge Name:** Ransom
 *   **Description:** We received an email from Microsoft Support recommending that we apply a critical patch to our Windows servers. A system administrator downloaded the attachment from the email and ran it, and now all our company data is encrypted. Can you help us decrypt our files?
 *   **Filename:** `Ransom.zip`
 *   **SHA-256 (zip):** `19d093367d621f5ad4e851d17b16ea1fbf191e6a8b299b3a460252af81cc5fbd`
 *   **Extracted Files:** `windows_update.exe`, `login.xlsx.enc`
 *   **Difficulty:** Easy
 *   **File Type:** Portable Executable 64-bit (C++ Console App)
 *   **Tools Used:** IDA Freeware, HxD, Python3
    
* * *
	
## 🛠 Tools Used

 *   **IDA Free (x64)**
 *   **CFF Explorer**
 *   **HxD**     
 *   **Python 3**

* * *

## 🕵️ Initial Analysis (CFF Explorer + Manual Execution)

Using **CFF Explorer**, the binary is identified as a 64-bit Windows Console Application:
 *   **Architecture:** AMD64
 *   **Compiler:** Microsoft Visual C++ 8.0
 *   **Packed:** No
 *   **SHA-1:** `82FDF141983CC76ACC7BA41DADF5E641E0DDED44`

⚠️ Running the binary directly without arguments simply closes immediately.  
📌 However, running it **with a parameter** reveals a usage message:

```
USAGE: windows_update.exe <filename>
```
I passed a dummy `.txt` file to it containing the string `hello`, and it got encrypted in-place. Running it again does not decrypt the file—this is a **one-way encryption** process.


### 📄 Encrypted File Content

The provided file `login.xlsx.enc` contains repeating fragments like:
```
SUPERSEC..., SECURESUP...
```
Confirming our suspicion that the plaintext might leak key segments and that the encryption is simple.

* * *

## 🔍 Digging Deeper with IDA Free

Opening `windows_update.exe` in **IDA Free (x64)** revealed:
 *   Entry point calls `main()`
 *   `main()` checks for argument count and prints the usage message if no filename is passed.
 *   With a valid file, it proceeds to call `list()` → `encryptFile()` → `encrypt()`.

### 🔐 Key Function: `encrypt()`

```
.text:0000000000401D13                 public encrypt
.text:0000000000401D13 encrypt         proc near               ; CODE XREF: encryptFile+32↑p
.text:0000000000401D13
.text:0000000000401D13 key_0           = qword ptr -0Fh
.text:0000000000401D13 key_8           = word ptr -7
.text:0000000000401D13 key_10          = byte ptr -5
.text:0000000000401D13 index           = dword ptr -4
.text:0000000000401D13 data_to_encrypt = qword ptr  10h
.text:0000000000401D13 length_of_data  = qword ptr  18h
.text:0000000000401D13
.text:0000000000401D13                 push    rbp
.text:0000000000401D14                 mov     rbp, rsp
.text:0000000000401D17                 sub     rsp, 10h
.text:0000000000401D1B                 mov     [rbp+data_to_encrypt], rcx
.text:0000000000401D1F                 mov     [rbp+length_of_data], rdx
.text:0000000000401D23                 mov     rax, 'CESREPUS'
.text:0000000000401D2D                 mov     [rbp+key_0], rax
.text:0000000000401D31                 mov     [rbp+key_8], 'RU'
.text:0000000000401D37                 mov     [rbp+key_10], 45h ; 'E'
.text:0000000000401D3B                 mov     [rbp+index], 0
.text:0000000000401D42                 jmp     short loc_401D9F
.text:0000000000401D44 ; ---------------------------------------------------------------------------
.text:0000000000401D44
.text:0000000000401D44 loc_401D44:                             ; CODE XREF: encrypt+95↓j
.text:0000000000401D44                 mov     eax, [rbp+index]
.text:0000000000401D47                 movsxd  rdx, eax
.text:0000000000401D4A                 mov     rax, [rbp+data_to_encrypt]
.text:0000000000401D4E                 add     rax, rdx
.text:0000000000401D51                 movzx   r8d, byte ptr [rax]
.text:0000000000401D55                 mov     eax, [rbp+index]
.text:0000000000401D58                 movsxd  rcx, eax
.text:0000000000401D5B                 mov     rdx, 2E8BA2E8BA2E8BA3h
.text:0000000000401D65                 mov     rax, rcx
.text:0000000000401D68                 mul     rdx
.text:0000000000401D6B                 shr     rdx, 1
.text:0000000000401D6E                 mov     rax, rdx
.text:0000000000401D71                 shl     rax, 2
.text:0000000000401D75                 add     rax, rdx
.text:0000000000401D78                 add     rax, rax
.text:0000000000401D7B                 add     rax, rdx
.text:0000000000401D7E                 sub     rcx, rax
.text:0000000000401D81                 mov     rdx, rcx
.text:0000000000401D84                 movzx   edx, byte ptr [rbp+rdx+key_0]
.text:0000000000401D89                 mov     eax, [rbp+index]
.text:0000000000401D8C                 movsxd  rcx, eax
.text:0000000000401D8F                 mov     rax, [rbp+data_to_encrypt]
.text:0000000000401D93                 add     rax, rcx
.text:0000000000401D96                 add     edx, r8d
.text:0000000000401D99                 mov     [rax], dl
.text:0000000000401D9B                 add     [rbp+index], 1
.text:0000000000401D9F
.text:0000000000401D9F loc_401D9F:                             ; CODE XREF: encrypt+2F↑j
.text:0000000000401D9F                 mov     eax, [rbp+index]
.text:0000000000401DA2                 cdqe
.text:0000000000401DA4                 cmp     [rbp+length_of_data], rax
.text:0000000000401DA8                 ja      short loc_401D44
.text:0000000000401DAA                 nop
.text:0000000000401DAB                 nop
.text:0000000000401DAC                 add     rsp, 10h
.text:0000000000401DB0                 pop     rbp
.text:0000000000401DB1                 retn
.text:0000000000401DB1 encrypt         endp
.text:0000000000401DB1
```

This function takes:
 *   `RCX` → pointer to data (plaintext)
 *   `RDX` → length of data

The constant key used for encryption is:

```
"SUPERSECURE" (11 bytes)
```

A loop applies the encryption:

```
cipher[i] = (plain[i] + key[i % 11]) % 256;
```

The modulo is done using a magic constant (`0x2E8BA2E8BA2E8BA3`) instead of the `DIV` instruction — a classic compiler optimization trick.


## 🔓 Writing the Decryptor in Python

Since this is a basic Vigenère-style cipher using modular addition, we can reverse it using modular subtraction.


### ✅ Decryption Formula:

```
plain[i] = (cipher[i] - key[i % 11]) % 256
```

###🐍 Python Script: decryptor.py

```
#!/usr/bin/env python3
"""
decrypt_supersecure.py – reverse the additive cipher used by the ‘encrypt’ routine
Usage:
    python decrypt_supersecure.py <input_encrypted_file> <output_plain_file>
"""
import sys
from pathlib import Path

KEY = b"SUPERSECURE"          # 11-byte key used by the routine
KEY_LEN = len(KEY)

def decrypt(data: bytes) -> bytes:
    """Invert the encrypt() function:  C[i] = (P[i] + K[i%11]) mod 256
       So  P[i] = (C[i] - K[i%11]) mod 256"""
    # Convert to mutable bytearray for speed
    plain = bytearray(data)
    for i, byte in enumerate(plain):
        plain[i] = (byte - KEY[i % KEY_LEN]) & 0xFF
    return bytes(plain)

def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    in_path  = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    enc_data = in_path.read_bytes()
    dec_data = decrypt(enc_data)
    out_path.write_bytes(dec_data)
    print(f"✔ Decrypted {in_path} → {out_path}")

if __name__ == "__main__":
    main()
```

Once run, it successfully decrypted `login.xlsx.enc` into a working Excel file.

* * *

## 🏁 Conclusion

This challenge demonstrated a simple, custom-built encryption scheme using an additive Vigenère cipher. Reversing the `encrypt()` routine revealed the static key `"SUPERSECURE"`, and the symmetric nature of the operation made decryption trivial.

     

