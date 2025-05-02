# 🧬 Hack The Box - Reversing Challenge Write-Up: [Baby Crypt] – [02/05/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Baby%2520Crypt
- **Challenge Description:** Give me the key and take what's yours.
- **Difficulty:** Easy
- **📦 Provided Files**:
  - File: `Baby Crypt.zip`  
  - Password: `hackthebox`
  - SHA256: `0342f52119bdfecd0f3d1401d4e07e8f616f618128bc5cb496260b65646ad4cf` 
- **📦 Extracted Files**:
  - File: `baby_crypt`
  - SHA256: `1f25b811caa4ab7161c134524a8285f60d38524c428b566f3c0c00275e6265c9`

---

## ⚙️ Environment Setup
- **Operating System:** Kali Linux
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `readelf`, `ldd`, `objdump`
  - Dynamic: `ltrace`, `strace`, `python3`

---

## 🔍 Static Analysis

### Initial Observations
- **File:** ELF 64-bit PIE executable, x86-64, dynamically linked, not stripped
- **Strings:** Identified key messages like:
  - `Give me the key and I'll give you the flag:`
  - `%.26s` → suggests a `printf()` of 26 chars
- **Notable Imports:** `malloc`, `fgets`, `printf`, `stdin`, etc.
- **Entry Point:** 0x10c0 (confirmed via objdump)

---

## 💻 Dynamic Analysis

### Execution Behavior
```bash
$ ./baby_crypt 
Give me the key and I'll give you the flag: hola
W
 Yd'+m

$ ./baby_crypt
Give me the key and I'll give you the flag: HTB
w0wDM;L;@LWQ`L`GTG
```

### ltrace
```bash
printf("Give me the key and I'll give yo"...) = 44
malloc(4) = 0x5570...
fgets("hol", 4, stdin) = ...
printf("%.26s\n", encoded_buffer) = ...
```

### strace
- Confirms deterministic behavior
- Output always the same for same input
- Uses `getrandom()`, `fgets()`, and prints a fixed result

---

## 2️⃣ Runtime Clues

### malloc / fgets
- Buffer of 4 bytes: allows for only 3 input chars + newline
- Suggests keyspace is 3 bytes long

### Output format
- Up to 26 characters printed from transformation of user input
- Pattern is deterministic but obfuscated

---

## 🚀 Brute Force Shortcut

### Because input is only 3 characters:
95 printable chars ^ 3 = ~857,375 possible keys → brute‑forceable!

### Python Script
```python
#!/usr/bin/env python3
import itertools, subprocess, string
for k in itertools.product(string.printable[:-6], repeat=3):
    key = ''.join(k)
    p = subprocess.run(['./baby_crypt'], input=key.encode()+b'\n', stdout=subprocess.PIPE)
    if b'HTB{' in p.stdout:
        print('FOUND', key, p.stdout)
        break
```

✅ **Flag found without reverse engineering.**  
Thinking outside the box pays off!

---

## 🧠 Key Takeaway

Even in reversing challenges, creative thinking and recognizing constrained input can lead to practical exploits.  
Reverse engineering is one tool—**brute-force with understanding** is another.

