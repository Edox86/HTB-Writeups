# 🧬 Hack The Box - Reversing Challenge Write-Up: [Anti Flag] – [03/05/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag  
- **Link to the challenge:** https://app.hackthebox.com/challenges/Anti%2520Flag  
- **Challenge Description:** `Flag? What&#039;s a flag?`  
- **Difficulty:** Easy  

### 📦 Provided Files
- File: `Anti Flag.zip`  
- Password: `hackthebox`  
- SHA256: `ce6e9cc35087020e47588318c08c6cf03971db82b5830bd29bdf8daf6002069d`  

### 📂 Extracted Files
- File: `anti_flag`  
- SHA256: `5485512104be4c8bb3a25715b8eaf1392d91774839ca5c5d7a8f364f493a7c49`

---

## ⚙️ Environment Setup
- **Operating System:** Kali Linux  
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `readelf`, `ldd`, `objdump`
  - Dynamic: `ltrace`, `strace`, `IDA Free`, `Ghidra`

---

## 🔍 Static Analysis

### Initial Observations

- The binary is an ELF 64-bit PIE, dynamically linked, stripped:
  ```bash
  file anti_flag
  anti_flag: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
  ```

- Dynamic libraries:
  ```bash
  ldd anti_flag
  linux-vdso.so.1
  libc.so.6
  /lib64/ld-linux-x86-64.so.2
  ```

- Strings reveal key indicators:
  ```
  "puts", "strlen", "malloc", "ptrace", "__stack_chk_fail"
  "Well done!!", "No flag for you :("
  "2asdf-012=14" (hardcoded key)
  ```

- The `.rodata` section is very small (only 0x4a), likely holds small messages and encoded blob.
- `.text` is ~1.2 KiB – compact logic.
- Only one `.bss` variable (likely a flag or status).

---

## 💻 Dynamic Analysis

### Execution Behavior

- Running the binary normally or with parameters:
  ```
  ./anti_flag
  ./anti_flag hola
  ./anti_flag hola password
  => All print: No flag for you :(
  ```

### ltrace Results

- Reveals `ptrace()` is called and returns -1:
  ```
  ptrace(0, 0, 1, 0) = -1
  puts("Well done!!")
  ```

- So the program **rewards failure** of ptrace – indicating reverse anti-debug behavior.

### strace Results

- Confirms:
  ```
  ptrace(PTRACE_TRACEME) = -1 EPERM
  => prints: Well done!!
  ```

---

## 🧠 Reversing in Ghidra

- `main()` does the following:

```
undefined8
main(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
    undefined8 param_6)

{
  size_t sVar1;
  long lVar2;
  
  sVar1 = strlen(&DAT_00102011);
  malloc(sVar1 << 2);
  lVar2 = ptrace(PTRACE_TRACEME,0,1,0,param_5,param_6,param_2);
  if (lVar2 == -1) {
    puts("Well done!!");
  }
  else {
    puts("No flag for you :(");
  }
  return 0;
}
```

We can see that `main` is calling `strlen` on a hardcoded global variable, `"2asdf-012=14"`, and then allocating memory for a size equal to that length shifted left by 2 (i.e., multiplied by 4). Immediately after, it calls `ptrace`, which suggests it's checking for the presence of a debugger and will adapt its behaviour accordingly.

**A reversal of typical anti-debugging logic.**  
Normally, `ptrace(PTRACE_TRACEME, ...)` **succeeds** during a standard execution and **fails with `-1 (EPERM)`** if the process is already being debugged.  
In this case, however, the program **rewards** the failure condition, which means that in order to reach the “Well done!!” execution path, the program **must be run under a debugger**.

So, the key takeaway here is that the program is intentionally designed to be **traced**.

Since I prefer dynamic analysis using IDA, I’ll proceed with that approach.

---

## 🔬 IDA Analysis & Bypass

As soon as we open the binary in IDA, we’re presented with the entry point. From there, we jump to main, which IDA has already identified. In the first block of main, we observe the following sequence:

![Screenshot](./images/1.png)

However, we notice something interesting here: when `ptrace` is called and the result is stored in `RAX`, it returns `-1` at runtime. This causes execution to follow the “Well Done!!” branch. But crucially, there’s **no sign of the HTB flag** being printed in that branch. Therefore, the only viable path to the flag is to **force IDA to take the opposite branch**. So to bypass the ptrace call anyway!

To do this, I patched the value of `RAX` immediately after the call to `ptrace`, setting it to `0`. This reroutes execution into `loc_555555555509`. (Worth noting: this entire branch was **completely invisible** during Ghidra’s analysis! Read below to understand why).

Inside this block, another variable—initialized to `0` at the start of `main`—is compared to `0x539`. At runtime, this check fails as expected. To bypass this, I manipulated the Zero Flag at runtime to force the comparison to pass, thereby entering the branch that calls `_puts`. I set a breakpoint after the `_puts` call and, at that point, the **real HTB flag** is printed to the screen. Job Done!


BUT, let’s take a closer look at **why Ghidra didn’t reveal this execution path**:

- **`var_1C` is explicitly set to `0` at the start of `main` and never modified.**  
    So during analysis, Ghidra correctly deduces that:

```
	if (var_1C == 0x539) { ... }
```

- will always evaluate to false.
    
- As a result, Ghidra’s decompiler applies **constant propagation and dead-code elimination**, and prunes away the entire conditional block as unreachable.  
    In other words, Ghidra **hides the flag path** because, as the binary is written, it is indeed statically unreachable.
    

But here’s what that “hidden” path at `loc_555555555525` actually does (discovered with IDA):

```
if (ptrace() succeeded AND var_1C == 0x539) {
    sub_5555555553FF(enc_key, enc_msg, dst_buf);
    puts(dst_buf);  // <-- This prints the HTB flag
}
```

At that point, the register values are as follows:

| Register | Value                                          |
| -------- | ---------------------------------------------- |
| `RDI`    | Pointer to `"2asdf-012=14"`                    |
| `RSI`    | Pointer to a 25-byte encoded blob in `.rodata` |
| `RDX`    | Pointer to an allocated buffer (size = 4×25)   |

The function `sub_555...3FF` is responsible for **decrypting the 25-byte encoded blob** using the key `"2asdf-012=14"`, and placing the **decoded plaintext** into the buffer, which is then printed via `puts`.

---

## ✅ Challenges Encountered / Lessons Learned

- 🔁 Ghidra can hide logic due to optimization passes – always cross-verify.
- 🔍 Anti-debug logic reversed – program wants to be debugged?! But then, the right flag was in the opposite branch.
- 🛠 IDA dynamic patching & register editing helped reveal hidden path.

---

## 🏁 Conclusion

This challenge offered a clever twist on anti-debugging by rewarding `ptrace` **failure**, i.e., when **under a debugger**. The actual flag path was deliberately unreachable without patching due to a hardcoded variable check. Static analysis with Ghidra hid this path, but with IDA and dynamic runtime patching, the decryption routine and actual flag were revealed.

---

## 💡 Additional Notes / Reflections

- NA
