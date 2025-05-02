# 🧬 Hack The Box - Reversing Challenge Write-Up: [You cant c me] – [02/05/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/You%2520Cant%2520C%2520Me
- **Challenge Description:** Can you see me?
- **Difficulty:** Easy (Very Easy in my opinion)
- **📦 Provided Files**:
  - File: `you Cant C Me.zip`
  - Password: `hackthebox`
  - SHA256: `182fae9fb14d57154129fb506c0026c773ec70059fb2f5f7e82064adfc162b9d`
- **📦 Extracted Files**:
  - File: `auth`
  - SHA256: `ad951d24694616eb871781e0bae3081a1eacda23245677ee00df4d7ee5f204e8`

---

## ⚙️ Environment Setup
- **Operating System:** Kali Linux
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `readelf`, `ldd`, `objdump`
  - Dynamic: `ltrace`

---

## 🔍 Static Analysis

### Initial Observations
- The file `auth` is an ELF 64-bit, dynamically linked, stripped binary for x86-64.
- `strings` reveals interesting outputs like:
  - `Welcome!`
  - `I said, you can't c me!`
  - `HTB{%s}`
  - `this_is_the_password`

These suggest a user prompt followed by validation logic likely using that string.

- `objdump`, `readelf`, and other ELF utilities confirm:
  - Entry point at `0x401070` in the `.text` section.
  - Imports like `fgets`, `strcmp`, `malloc`, `printf` from libc.
  - The binary is using `/lib64/ld-linux-x86-64.so.2` as the interpreter.

---

## 💻 Dynamic Analysis

### Execution Behavior
```sh
$ ./auth
Welcome!
hola
I said, you can't c me!

$ ./auth
Welcome!
password
I said, you can't c me!

$ ./auth
Welcome!
this_is_the_password
I said, you can't c me!
```

This implies the string `this_is_the_password` is not accepted as the correct input.

### `ltrace` Behavior
```sh
$ ltrace ./auth
printf("Welcome!\n") = 9
malloc(21) = 0x...
fgets("hola\n", 21, ...) = ...
strcmp("here_will_appear_the_password_that_I_cant_spoil", "hola\n") = ...
printf("I said, you can't c me!\n") = ...
```

From this trace we learn:
- The actual comparison string is ... can't spoil, sorry. Just use ltrace to solve the challenge.

Once entered:

```sh
$ ./auth
Welcome!
correct password found with ltrace
HTB{....}
```

---

## 🏁 Conclusion

Even though the binary is stripped, simple tools like `strings` and `ltrace` were enough to spot the correct password string. Once discovered, entering it gives us the flag.
