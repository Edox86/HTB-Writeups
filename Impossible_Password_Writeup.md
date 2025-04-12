
# 🔐 Hack The Box: Impossible Password – Writeup

**Challenge:** Impossible Password  
**Platform:** Hack The Box (HTB)  
**Category:** Reversing  
**Difficulty:** Easy  
**Date:** April 12, 2025  
**Author:** _Edox86_

----------

## 🧠 Overview

> **Challenge Description:**  
> _“Are you able to cheat me and get the flag?”_

The binary prompts for two inputs, compares them to internal values, and gives no hint unless the exact logic is broken. Our goal was to _cheat_ the application to retrieve the HTB flag. Let's dive in.

----------

## 🛠️ Environment Setup

-   **Operating System:** Kali Linux
    
-   **Target File:** `impossible_password.bin` (extracted from ZIP)
    
-   **Hash:** `815524fa57f7d8ad3593b1400c26ff7a8424e85b365ccdf815f83a790a444341`
    

### 🧰 Tools Used

Static Analysis

Dynamic Analysis

`file`, `sha256sum`, `strings`

`ltrace`, IDA Free

`ldd`, `objdump`

----------

## 🔍 Static Analysis

### Initial Observations
```
$ file impossible_password.bin
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ ldd impossible_password.bin
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
/lib64/ld-linux-x86-64.so.2
```

From `strings`, we can already spot something interesting:
```
SuperSeKretKey
%20s
[%s]
```
This clearly hints at a hidden password – maybe hardcoded? Let's keep going.

----------

## ⚙️ Execution & Dynamic Analysis

When executed, the binary:

1.  Prompts with `*` and takes the first input. If we use the "SuperSeKretKey" found previously, then:
2.  Prompts with `**` and takes a second input.
    

### Trying With `SuperSeKretKey`
```
$ ./impossible_password.bin
* SuperSeKretKey
[SuperSeKretKey]
** hola
```
Nothing happens at this point. The program ends.


Using ltrace to spy on libc calls:
```
$ ltrace ./impossible_password.bin
...
strcmp("SuperSeKretKey", "SuperSeKretKey") = 0
...
strcmp("hola", "K`~i6J|q!t.75^Y6|&Tc") = 29
```

ltrace confirms the first comparsion was made against "SuperSeKretKey", but as we can see the second comparsion involves a strange string. If we try that strings in another ltrace test, we quickly realize that the second strings which is compared against our second input is generated randomically at runtime. The second string is random every time, generated via multiple `rand()` calls seeded by `time(NULL)` (we can see this from ltrace output). This means... **it can never be guessed** reliably.

----------

## 🎯 Exploiting the Logic

Since the second comparison is always against a random string, the **only way** to pass it is to patch the logic at runtime.

### 💡 The Trick

We use **IDA Free** to:

1.  Set a breakpoint before the second `strcmp` call.
    
2.  Input the first password: `SuperSeKretKey`
    
3.  On second prompt, input any string.
    
4.  Once breakpoint hits, modify **EAX = 0** (the success return value of `strcmp`).
    
5.  Let execution continue.
    

🎉 **The flag prints to the console!**

----------

## 🔧 Alternative: Patch the Binary

Instead of runtime patching, you could modify the binary:

-   NOP out the conditional jump (`jnz`) after the second `strcmp`
    
-   Or force the second `strcmp` to return `0` by hardcoding its result
    

----------

## 🚧 Challenges Encountered

None. This was a **straightforward** challenge with no obfuscation or anti-debugging techniques.

----------

## ✅ Conclusion

The core lesson here is:

> When you can't beat the logic, **cheat it** – especially when the challenge _asks_ you to.

By dynamically modifying the return value of `strcmp`, we bypassed the impossible check and retrieved the flag.

----------

## 🧠 Final Thoughts

This was a solid warm-up reversing challenge that emphasized **runtime patching** and **basic dynamic analysis**. Perfect for beginners looking to learn practical reversing techniques.

Happy hacking! 🐚

----------
