# 🧬 Hack The Box - Reversing Challenge Write-Up: Exatlon

## 🕵️‍♂️ Challenge Overview

**Name of the challenge:** Exatlon  
**Link to the challenge:** [https://app.hackthebox.com/challenges/Exatlon](https://app.hackthebox.com/challenges/Exatlon)  
**Difficulty:** Easy  

## 📄 Description  
Can you find the password?

## 📦 Provided Files

- **Zip File:** Exatlon.zip  
- **ZIP Password:** hackthebox  
- **SHA-256 of the Zip:** `dd981bac0147fd701b39e3405b9f46660b40cc2aa59a2e498f7a00f363ddd67b`  
- **After extraction, we get:** `exatlon_v1`

## 🧪 Initial Analysis

### 🔍 Basic File Info

- **File Type:** ELF 64-bit, statically linked, no section header  
- **Start Address:** `0x4916d0`  
- **After unpacking (see below), real entry point:** `0x404990`

### 🔒 UPX Packing

Using `strings` reveals `UPX!`, confirming the binary is packed.  
Unpacking with:

```bash
upx -d exatlon_v1
```

### 📄 Post-Unpacking Metadata

After unpacking, we confirm with `objdump`, `readelf`, and `ldd`:

- ELF64 binary  
- Not dynamically linked  
- Contains C++ symbols (e.g., `std::string`, `std::cin`, etc.)  
- No version information  
- No dynamic section  
- Entry point now at: `0x404990`

## 🧷 Runtime Behavior

Upon execution:

```bash
./exatlon_v1
```

The program prints a fancy banner and then prompts:

```
[+] Enter Exatlon Password  :
```

Any incorrect password results in a loop.

### 🧪 ltrace & strace

`ltrace` is mostly unhelpful due to delay and output cluttering from `sleep()` and banner animation.  
`strace` confirms the banner prints and input/output behavior but doesn't help understand internal logic.

## 🔎 Static Code Analysis with IDA Free

### 🎯 Entry Point: `main`

Opening in IDA shows the main function clearly. Strings pane reveals the prompt `[+] Enter Exatlon Password  :`.

#### 📌 Reference Analysis

Tracking this string brings us to the part of `main()` responsible for:

1. Asking for input using `std::cin`
2. Passing user input to function: `exatlon(std::string const&)`

At a certain point, I encountered the clear string `"[+] Looks Good ^_^ \n\n\n"`, which indicates that the preceding calls—just before the `jz short loc_404D83` instruction—are responsible for determining whether the password is correct. I placed a breakpoint immediately after the last call before `jz short loc_404D83` and ran the program dynamically.

At this stage, the program prompts for a password (I used "hola" for testing). Once entered, the breakpoint is triggered, allowing us to analyze the stack, local variables, and registers. During this analysis, I discovered two peculiar strings:

 ```
"1664 1776 1728 1552"
 ```

and:

   ```
   "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000"
   ```


However, I couldn’t find the string "hola" anywhere in the stack or local variables, which indicates that our input was transformed into something else. Based on the length and structure of the first discovered string, I suspect that `"1664 1776 1728 1552"` is a kind of hash of the input "hola".

To verify this, I set breakpoints on each of the previous calls after the password prompt and before the `jz short loc_404D83` instruction. I then re-ran the program and stepped into each function to determine which one was responsible for manipulating the input. Eventually, I identified the function that performs this transformation.
### 🧠 exatlon(std::string const&) Function Analysis

So this is the key function `_Z7exatlonRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE`.

Looking at this function, we can see that the function essentially does the following:

- **Initialize result**  
    It constructs a fresh `std::string` (the hidden return-slot) from a fixed literal at `unk_54B00C`.
    
- **For each character c in the input:**
    
    - Loads `c` (`movzx al, byte ptr [rax]`)
        
    - **Left-shifts** it by 4 bits (`shl eax, 4`), i.e. computes `c * 16`.
        
    - Calls `std::to_string(int)` to get the decimal ASCII code × 16 as text.
        
    - Appends a fixed suffix literal (at `unk_54B00D`) via a `std::string` concatenation --> this is a a space separator character (0x20).
        
    - Appends that whole little piece into the accumulating result.
        
- **Return** the final built-up string.

In summary, this is a function that convert our input into a sort of hash: “encode each character as its ASCII and multiply * 16, then add a space after each character”.

### 🔍 Example

Input `"hola"` becomes:

```
'h' = 104 → 1664
'o' = 111 → 1776
'l' = 108 → 1728
'a' = 97  → 1552
```

Thus `"hola"` becomes `"1664 1776 1728 1552"`

So, the author is "obfuscating" the input using this simple transformation, and later compares it against a pre-obfuscated, hardcoded string we observed earlier.

## 🛠️ Solution: Reverse the Transformation

To solve the challenge, we just need to reverse this process: instead of multiplying by 16, we divide each value by 16, character by character. Doing so will recover the original password (or flag)!

## 🏁 Conclusion

This challenge is a classic example of simple obfuscation used to hide a password check:

- UPX packing (to add noise)
- Static ELF with C++ symbols
- A basic string "encryption" using a character transform (`ord(c) * 16`)
- Manual analysis through IDA and runtime observation led us to a quick and satisfying solution.
