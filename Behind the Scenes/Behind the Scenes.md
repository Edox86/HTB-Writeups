# 🧬 Hack The Box - Reversing Challenge Write-Up:[Behind the Scenes] – [12/05/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Behind%2520the%2520Scenes
- **Challenge Description:** After struggling to secure our secret strings for a long time, we finally figured out the solution to our problem: Make decompilation harder. It should now be impossible to figure out how our programs work!
- **Difficulty:** Very Easy
- **📦 Provided Files**:
	- File: `Behind the Scenes.zip`  
	- Password: `hackthebox`
	- SHA256: `60537fcf709d80e9dcd291008d0513f6e79c933f1ecc2dcf172e416e0c835d38` 
- **📦 Extracted Files**:
	-  File: `rev_behindthescenes/behindthescenes`
	- SHA256: `042e5fc7a5f75a75cf6d410c824759b6f3576a6dbd43ea6a400146a3d8b3ab6f`
---

## ⚙️ Environment Setup
- **Operating System:** `Kali Linux`
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `ldd`
  - Dynamic: `ltrace`, `IDA Free`

---

## 🔍 Static Analysis

#### Initial Observations
- File

```bash
behindthescenes: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e60ae4c886619b869178148afd12d0a5428bfe18, for GNU/Linux 3.2.0, not stripped
```

- ldd

```bash
ldd behindthescenes 
        linux-vdso.so.1 (0x00007fffb1bfb000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f087ef6a000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f087f180000)
```

- strings

```bash
strings behindthescenes          
/lib64/ld-linux-x86-64.so.2
libc.so.6
strncmp
puts
__stack_chk_fail
printf
strlen
sigemptyset
memset
sigaction
__cxa_finalize
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
./challenge <password>
> HTB{%s}
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8060
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
main.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
strncmp@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
sigaction@@GLIBC_2.2.5
_edata
strlen@@GLIBC_2.2.5
__stack_chk_fail@@GLIBC_2.4
printf@@GLIBC_2.2.5
memset@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
segill_sigaction
sigemptyset@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

no clear flag or password.


---

## 💻 Dynamic Analysis

- Execution Behavior

```bash
./behindthescenes 
./challenge <password>

./behindthescenes hola

./behindthescenes hola password
```

Display the usage information if no parameters are passed; otherwise, display nothing.

- ltrace
```bash
┌──(kali㉿kali)-[~/Downloads/rev_behindthescenes]
└─$ ltrace ./behindthescenes 
memset(0x7fff1c834510, '\0', 152)                                                                                    = 0x7fff1c834510
sigemptyset(<>)                                                                                                      = 0
sigaction(SIGILL, {0x5647b0df9229, <>, 0, nil}, nil)                                                                 = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
puts("./challenge <password>"./challenge <password>
)                                                                                       = 23
--- SIGILL (Illegal instruction) ---
+++ exited (status 1) +++
```

```bash
ltrace ./behindthescenes hola
memset(0x7ffe61108330, '\0', 152)                                                                                    = 0x7ffe61108330
sigemptyset(<>)                                                                                                      = 0
sigaction(SIGILL, {0x557e9ee26229, <>, 0, nil}, nil)                                                                 = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
strlen("hola")                                                                                                       = 4
--- SIGILL (Illegal instruction) ---
+++ exited (status 0) +++
```


From `ltrace`, I can see that the code calls `memset` and `strlen` with our input (which is something I can set a breakpoint on later), and then makes use of `sigemptyset` and `sigaction`. But what exactly are these functions?

These are functions related to process signaling.

**Signals** are a mechanism by which the operating system or a process can **asynchronously notify** another process that **a specific event has occurred**.

Think of them as **interrupts**—they "interrupt" a program to handle something that requires immediate attention.

Some common examples of signals include:

| Signal    | Description                                  |
| --------- | -------------------------------------------- |
| `SIGINT`  | Sent when you press `Ctrl+C`                 |
| `SIGTERM` | Sent to ask a process to terminate           |
| `SIGKILL` | Forcefully kills a process (can’t be caught) |
| `SIGSEGV` | Segmentation fault (invalid memory access)   |
| `SIGCHLD` | Sent to parent when a child process ends     |
| `SIGALRM` | Timer alarm goes off                         |
| `SIGILL`  | Illegal Instruction                          |
### 🔧 What Happens When a Signal Is Sent?

When a process receives a signal, **one of three things** can happen:

1. The **default action** is taken (e.g., termination, ignoring the signal).
    
2. The process **handles it** using a **signal handler** (a custom-defined function).
    
3. The signal is **blocked**, meaning it is temporarily ignored.
    

Now, specifically, the `_sigemptyset` function in C is used to initialize a signal set (a data structure) to be **empty**, meaning it contains **no signals**.

The `sigaction` function in Unix/Linux is used to **define how a process handles a particular signal**. Essentially, it sets a **custom handler** for a specific signal (like `SIGINT`, `SIGTERM`, etc.), allowing the code to control **how that signal is processed**.

So, what is our code doing with these signals?  
Let’s review everything in IDA.

---

## 🔬 IDA Analysis

### `main` Function

```

; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near

var_B0= qword ptr -0B0h
var_A4= dword ptr -0A4h
s= qword ptr -0A0h
var_18= dword ptr -18h
var_8= qword ptr -8

; __unwind { // 555555554000
endbr64
push    rbp
mov     rbp, rsp
sub     rsp, 0B0h
mov     [rbp+var_A4], edi
mov     [rbp+var_B0], rsi
mov     rax, fs:28h
mov     [rbp+var_8], rax
xor     eax, eax
lea     rax, [rbp+s]
mov     edx, 98h        ; n
mov     esi, 0          ; c
mov     rdi, rax        ; s
call    _memset
lea     rax, [rbp+s]
add     rax, 8
mov     rdi, rax        ; set
call    _sigemptyset
lea     rax, segill_sigaction
mov     [rbp+s], rax
mov     [rbp+var_18], 4
lea     rax, [rbp+s]
mov     edx, 0          ; oact
mov     rsi, rax        ; act
mov     edi, 4          ; sig
call    _sigaction
ud2
main endp
```

- **Zero a scratch buffer** (`memset(&s, 0, 0x98)`)
    
- **Prepare a `struct sigaction`** in that buffer, pointing its handler to the function `segill_sigaction`.
    
- **Install it for `SIGILL`** (`sigaction(4, &act, NULL)`) --> basically install a handler to catch illegal instruction
    
- **Execute a `ud2` instruction**, which is the x86 “invalid opcode” trap—this immediately raises a `SIGILL`, which your new handler catches.

iIt’s a clever way to hide the real entry point. However, we still have our call to `strlen`, which we can trace to see where the code leads. So, let’s look for references to `_strlen` — and we find only one, located at:

```
.text:000055555555531E                 call    _strlen
```

---

## 🔍 Password Logic Reverse Engineering

Here is a screenshot of the code that calls `strlen`:

![[Reversing/Behind the Scenes/1.png]]

After checking the length of our input (which must be 12 characters to proceed), it performs a series of `strncmp` calls — suggesting that it’s verifying a password.

In fact, IDA already reveals parts of these strings, so we have a partial password. Let’s try to reconstruct the full password, either manually or using `ltrace`.

```bash
ltrace ./behindthescenes 123456789012
memset(0x7ffeb7df5b10, '\0', 152)                        = 0x7ffeb7df5b10
sigemptyset(<>)                                          = 0
sigaction(SIGILL, {0x55ba23c85229, <>, 0, nil}, nil)     = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
strlen("123456789012")                                   = 12
--- SIGILL (Illegal instruction) ---
strncmp("123456789012", "Itz", 3)                        = -24
--- SIGILL (Illegal instruction) ---
+++ exited (status 0) +++

ltrace ./behindthescenes Itz456789012
memset(0x7fffb77ae820, '\0', 152)                        = 0x7fffb77ae820
sigemptyset(<>)                                          = 0
sigaction(SIGILL, {0x5569f1ddf229, <>, 0, nil}, nil)     = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
strlen("Itz456789012")                                   = 12
--- SIGILL (Illegal instruction) ---
strncmp("Itz456789012", "Itz", 3)                        = 0
--- SIGILL (Illegal instruction) ---
strncmp("456789012", "_0n", 3)                           = -43
--- SIGILL (Illegal instruction) ---
+++ exited (status 0) +++

ltrace ./behindthescenes Itz_0n789012
memset(0x7ffc630cc730, '\0', 152)                        = 0x7ffc630cc730
sigemptyset(<>)                                          = 0
sigaction(SIGILL, {0x55b8bc834229, <>, 0, nil}, nil)     = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
strlen("Itz_0n789012")                                   = 12
--- SIGILL (Illegal instruction) ---
strncmp("Itz_0n789012", "Itz", 3)                        = 0
--- SIGILL (Illegal instruction) ---
strncmp("_0n789012", "_0n", 3)                           = 0
--- SIGILL (Illegal instruction) ---
strncmp("789012", "Ly_", 3)                              = -21
--- SIGILL (Illegal instruction) ---
+++ exited (status 0) +++

ltrace ./behindthescenes Itz_0nLy_012
memset(0x7ffcb078de90, '\0', 152)                        = 0x7ffcb078de90
sigemptyset(<>)                                          = 0
sigaction(SIGILL, {0x55e300b6a229, <>, 0, nil}, nil)     = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
strlen("Itz_0nLy_012")                                   = 12
--- SIGILL (Illegal instruction) ---
strncmp("Itz_0nLy_012", "Itz", 3)                        = 0
--- SIGILL (Illegal instruction) ---
strncmp("_0nLy_012", "_0n", 3)                           = 0
--- SIGILL (Illegal instruction) ---
strncmp("Ly_012", "Ly_", 3)                              = 0
--- SIGILL (Illegal instruction) ---
strncmp("012", "UD2", 3)                                 = -37
--- SIGILL (Illegal instruction) ---
+++ exited (status 0) +++

ltrace ./behindthescenes Itz_0nLy_UD2
memset(0x7ffc6ec1fb10, '\0', 152)                        = 0x7ffc6ec1fb10
sigemptyset(<>)                                          = 0
sigaction(SIGILL, {0x55b9bfee7229, <>, 0, nil}, nil)     = 0
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
strlen("Itz_0nLy_UD2")                                   = 12
--- SIGILL (Illegal instruction) ---
strncmp("Itz_0nLy_UD2", "Itz", 3)                        = 0
--- SIGILL (Illegal instruction) ---
strncmp("_0nLy_UD2", "_0n", 3)                           = 0
--- SIGILL (Illegal instruction) ---
strncmp("Ly_UD2", "Ly_", 3)                              = 0
--- SIGILL (Illegal instruction) ---
strncmp("UD2", "UD2", 3)                                 = 0
--- SIGILL (Illegal instruction) ---
printf("> HTB{%s}\n", "Itz_0nLy_UD2"> HTB{Itz_0nLy_UD2}
)                    = 20
--- SIGILL (Illegal instruction) ---
+++ exited (status 0) +++
```


---
## ✅ Challenges Encountered / Lessons Learned

- Explored how Linux signals work (`SIGILL`, `sigaction`, `sigemptyset`)
- Learned that a custom signal handler can hide the main logic
- Used `ltrace` to efficiently brute-force chunked password checks

---
##  🏁 Conclusion

Although this challenge was marked as *Very Easy*, it cleverly used Linux signals to hide the real code path and required both static and dynamic approaches to understand the password-checking logic.

---
## 💡 Additional Notes / Reflections
None.

---

