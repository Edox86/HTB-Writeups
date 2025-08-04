# 🧬 Hack The Box - Reversing Challenge Write-Up:[Teleport] – [04/08/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Teleport
- **Challenge Description:** You've been sent to a strange planet, inhabited by a species with the natural ability to teleport. If you're able to capture one, you may be able to synthesise lightweight teleportation technology. However, they don't want to be caught, and disappear out of your grasp - can you get the drop on them?
- **Difficulty:** Medium
- **📦 Provided Files**:
	- File: `Teleport.zip`  
	- Password: `hackthebox`
	- SHA256: `329c9f93848fdb1d0b43c18d186e24e24298fc9d38736ffbef33ec0dab03253b` 
- **📦 Extracted Files**:
	-  File: `teleport`
	- SHA256: `220fd5bbbd0951c7cc9dc2314cf6268f9a27c7a80ed69e12e9193695032fa8f8`
---

## ⚙️ Environment Setup
- **Operating System:** `Kali Linux`
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `readelf`, `ldd`, `objdump`
  - Dynamic: `ltrace`, `strace`, `IDA Free`, `Ghidra`

---

## 🔍 Static Analysis

#### Initial Observations
- **File**: 

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ file teleport  
teleport: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1f87fe68fd7d1deaffefcf08ed2b30d660ee2d0b, stripped
```

It’s a 64-bit, position-independent, dynamically linked, stripped ELF executable for x86-64 Linux (kernel ≥ 3.2), using /lib64/ld-linux-x86-64.so.2 as its loader.
Binary is stripped means we can't read the symbols: functions are not named, so the decompiler will label them by guessing.

- **ldd**: 

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ ldd teleport  
        linux-vdso.so.1 (0x00007fff09d27000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0cece0a000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f0ced287000)
```

It depends solely on the kernel’s vDSO, glibc (libc.so.6), and the standard 64-bit dynamic loader /lib64/ld-linux-x86-64.so.2 at runtime—no other shared libraries are required.

- **strings**:

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ strings teleport                     
/lib64/ld-linux-x86-64.so.2
libc.so.6
strncpy
puts
longjmp
_setjmp
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
=!' 
=#* 
=K& 
=:& 
=o+ 
=[< 
=WB 
=n% 
=;% 
=*% 
=#1 
=o$ 
=^$ 
=+$ 
=OB 
=_# 
=N# 
=[7 
=O" 
=>" 
=;A 
=r! 
=?! 
=.! 
=C< 
=C6 
=s  
=b  
=/  
=;) 
='! 
=g! 
=K> 
=k; 
=w6 
={* 
=o# 
=c" 
=c5 
=/* 
=s= 
AWAVI
AUATL
[]A\A]A^A_
Missing password
Looks good to me!
Something's wrong...
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
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

It’s not a very long string output, but what we can read gives us a few clues:

1. There appears to be an encrypted or obfuscated three-letter string, each starting with the `=` character.
    
2. After that, we observe this pattern of ASCII:

```strings
AWAVI
AUATL
[]A\A]A^A_
```

3. And right after, there are hardcoded human-understandable strings that seem to be part of the program logic.

```strings
Missing password
Looks good to me!
Something's wrong...
```

4. At the top of strings output, there seems to be functions names like: strncpy, puts and longjmp/setjmp; about the latters is the first time I see them, so searching their behavior I found:

`longjmp` is a C-style non-local jump facility that, together with `setjmp`, lets you jump back to a previously saved execution point, bypassing normal call/return flow.
### Core idea

- `int setjmp(jmp_buf env);` saves the current execution context (stack pointer, instruction pointer, registers) into `env` and returns `0` immediately.
    
- Later, calling `void longjmp(env, val)` unwinds execution abruptly back to the point of the matching `setjmp`, and `setjmp` appears to return `val` (if `val` is 0 it behaves as if it returned from setjmp).
    

This is like a “goto” that jumps out of deep call chains without unwinding the usual stack frames.

**Functions prototypes**:

```C
int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val);
```

Where:

- `jmp_buf env` → `env` contains all the saved context (including the RIP register, which is likely what we’ll need to analyze at runtime to understand where it’s jumping next)
    
- `int val` → is the returned value, which can be read after the return to redirect the execution into different branches.

**Simplest example**:

```C
#include <csetjmp>
#include <cstdio>

std::jmp_buf env;

void deep_function() {
    // Something went wrong; jump back
    std::longjmp(env, 42);
}

int main() {
    int ret = std::setjmp(env);
    if (ret == 0) {
        // Initial invocation
        std::puts("First time through, calling deep_function");
        deep_function();
        std::puts("This line is never reached");
    } else {
        // Returned via longjmp, ret == 42
        std::printf("Recovered from longjmp with value %d\n", ret);
    }
    return 0;
}
```

So, I guess we’ll need to set a breakpoint right after `setjmp` to catch both the first execution and the subsequent ones.

- **objdump**: 

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ objdump -a -f teleport                                                

teleport:     file format elf64-x86-64
teleport
architecture: i386:x86-64, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x0000000000000a20
```

Just take note of the start address shown above.

- **readelf**: 

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ readelf -a teleport  
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0xa20
  Start of program headers:          64 (bytes into file)
  Start of section headers:          12944 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         27
  Section header string table index: 26

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000000238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000000254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.bu[...] NOTE             0000000000000274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000000298  00000298
       000000000000001c  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000000002b8  000002b8
       00000000000000f0  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           00000000000003a8  000003a8
       000000000000009a  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           0000000000000442  00000442
       0000000000000014  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000000458  00000458
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000000478  00000478
       00000000000004c8  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             0000000000000940  00000940
       0000000000000060  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         00000000000009a0  000009a0
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000000009c0  000009c0
       0000000000000050  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         0000000000000a10  00000a10
       0000000000000008  0000000000000008  AX       0     0     8
  [14] .text             PROGBITS         0000000000000a20  00000a20
       0000000000000de2  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         0000000000001804  00001804
       0000000000000009  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         0000000000001810  00001810
       000000000000003c  0000000000000000   A       0     0     4
  [17] .eh_frame_hdr     PROGBITS         000000000000184c  0000184c
       0000000000000194  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         00000000000019e0  000019e0
       0000000000000668  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000202da0  00002da0
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000202da8  00002da8
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .dynamic          DYNAMIC          0000000000202db0  00002db0
       00000000000001f0  0000000000000010  WA       6     0     8
  [22] .got              PROGBITS         0000000000202fa0  00002fa0
       0000000000000060  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000203000  00003000
       0000000000000178  0000000000000000  WA       0     0     32
  [24] .bss              NOBITS           0000000000203180  00003178
       00000000000023e0  0000000000000000  WA       0     0     32
  [25] .comment          PROGBITS         0000000000000000  00003178
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .shstrtab         STRTAB           0000000000000000  000031a1
       00000000000000ee  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

There are no section groups in this file.

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000001f8 0x00000000000001f8  R      0x8
  INTERP         0x0000000000000238 0x0000000000000238 0x0000000000000238
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000002048 0x0000000000002048  R E    0x200000
  LOAD           0x0000000000002da0 0x0000000000202da0 0x0000000000202da0
                 0x00000000000003d8 0x00000000000027c0  RW     0x200000
  DYNAMIC        0x0000000000002db0 0x0000000000202db0 0x0000000000202db0
                 0x00000000000001f0 0x00000000000001f0  RW     0x8
  NOTE           0x0000000000000254 0x0000000000000254 0x0000000000000254
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x000000000000184c 0x000000000000184c 0x000000000000184c
                 0x0000000000000194 0x0000000000000194  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000002da0 0x0000000000202da0 0x0000000000202da0
                 0x0000000000000260 0x0000000000000260  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .dynamic .got .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07     
   08     .init_array .fini_array .dynamic .got 

Dynamic section at offset 0x2db0 contains 27 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x9a0
 0x000000000000000d (FINI)               0x1804
 0x0000000000000019 (INIT_ARRAY)         0x202da0
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x202da8
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x298
 0x0000000000000005 (STRTAB)             0x3a8
 0x0000000000000006 (SYMTAB)             0x2b8
 0x000000000000000a (STRSZ)              154 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x202fa0
 0x0000000000000002 (PLTRELSZ)           96 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x940
 0x0000000000000007 (RELA)               0x478
 0x0000000000000008 (RELASZ)             1224 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
 0x000000006ffffffe (VERNEED)            0x458
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x442
 0x000000006ffffff9 (RELACOUNT)          46
 0x0000000000000000 (NULL)               0x0

Relocation section '.rela.dyn' at offset 0x478 contains 51 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000202da0  000000000008 R_X86_64_RELATIVE                    b20
000000202da8  000000000008 R_X86_64_RELATIVE                    ae0
000000203008  000000000008 R_X86_64_RELATIVE                    203008
000000203020  000000000008 R_X86_64_RELATIVE                    e16
000000203028  000000000008 R_X86_64_RELATIVE                    d8e
000000203030  000000000008 R_X86_64_RELATIVE                    1256
000000203038  000000000008 R_X86_64_RELATIVE                    15ca
000000203040  000000000008 R_X86_64_RELATIVE                    f26
000000203048  000000000008 R_X86_64_RELATIVE                    14ba
000000203050  000000000008 R_X86_64_RELATIVE                    bf6
000000203058  000000000008 R_X86_64_RELATIVE                    13aa
000000203060  000000000008 R_X86_64_RELATIVE                    1146
000000203068  000000000008 R_X86_64_RELATIVE                    d4a
000000203070  000000000008 R_X86_64_RELATIVE                    1542
000000203078  000000000008 R_X86_64_RELATIVE                    129a
000000203080  000000000008 R_X86_64_RELATIVE                    b2a
000000203088  000000000008 R_X86_64_RELATIVE                    160e
000000203090  000000000008 R_X86_64_RELATIVE                    ee2
000000203098  000000000008 R_X86_64_RELATIVE                    bb2
0000002030a0  000000000008 R_X86_64_RELATIVE                    fae
0000002030a8  000000000008 R_X86_64_RELATIVE                    107a
0000002030b0  000000000008 R_X86_64_RELATIVE                    13ee
0000002030b8  000000000008 R_X86_64_RELATIVE                    12de
0000002030c0  000000000008 R_X86_64_RELATIVE                    1432
0000002030c8  000000000008 R_X86_64_RELATIVE                    1212
0000002030d0  000000000008 R_X86_64_RELATIVE                    ff2
0000002030d8  000000000008 R_X86_64_RELATIVE                    1652
0000002030e0  000000000008 R_X86_64_RELATIVE                    b6e
0000002030e8  000000000008 R_X86_64_RELATIVE                    d06
0000002030f0  000000000008 R_X86_64_RELATIVE                    c3a
0000002030f8  000000000008 R_X86_64_RELATIVE                    1322
000000203100  000000000008 R_X86_64_RELATIVE                    14fe
000000203108  000000000008 R_X86_64_RELATIVE                    c7e
000000203110  000000000008 R_X86_64_RELATIVE                    1586
000000203118  000000000008 R_X86_64_RELATIVE                    11ce
000000203120  000000000008 R_X86_64_RELATIVE                    e9e
000000203128  000000000008 R_X86_64_RELATIVE                    1036
000000203130  000000000008 R_X86_64_RELATIVE                    1366
000000203138  000000000008 R_X86_64_RELATIVE                    cc2
000000203140  000000000008 R_X86_64_RELATIVE                    dd2
000000203148  000000000008 R_X86_64_RELATIVE                    1476
000000203150  000000000008 R_X86_64_RELATIVE                    118a
000000203158  000000000008 R_X86_64_RELATIVE                    1102
000000203160  000000000008 R_X86_64_RELATIVE                    e5a
000000203168  000000000008 R_X86_64_RELATIVE                    f6a
000000203170  000000000008 R_X86_64_RELATIVE                    10be
000000202fd8  000200000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTM[...] + 0
000000202fe0  000400000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000202fe8  000600000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000202ff0  000800000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_registerTMCl[...] + 0
000000202ff8  000900000006 R_X86_64_GLOB_DAT 0000000000000000 __cxa_finalize@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x940 contains 4 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000202fb8  000100000007 R_X86_64_JUMP_SLO 0000000000000000 strncpy@GLIBC_2.2.5 + 0
000000202fc0  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000202fc8  000500000007 R_X86_64_JUMP_SLO 0000000000000000 _setjmp@GLIBC_2.2.5 + 0
000000202fd0  000700000007 R_X86_64_JUMP_SLO 0000000000000000 longjmp@GLIBC_2.2.5 + 0
No processor specific unwind information to decode

Symbol table '.dynsym' contains 10 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     8: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
     9: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (2)

Version symbols section '.gnu.version' contains 10 entries:
 Addr: 0x0000000000000442  Offset: 0x00000442  Link: 5 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_2.2.5)   0 (*local*)       2 (GLIBC_2.2.5)
  004:   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   0 (*local*)       2 (GLIBC_2.2.5)
  008:   0 (*local*)       2 (GLIBC_2.2.5)

Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x0000000000000458  Offset: 0x00000458  Link: 6 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cnt: 1
  0x0010:   Name: GLIBC_2.2.5  Flags: none  Version: 2

Displaying notes found in: .note.ABI-tag
  Owner                Data size        Description
  GNU                  0x00000010       NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 3.2.0

Displaying notes found in: .note.gnu.build-id
  Owner                Data size        Description
  GNU                  0x00000014       NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 1f87fe68fd7d1deaffefcf08ed2b30d660ee2d0b
```

What can we observe from the above output as reverse engineers:

- **.text** (size `0xDE2` - 3554 bytes): This is all executable code, indicating it’s a short routine.
    
- **.init_array**: There’s an `init_array` that might be executed before `main`, and it’s worth checking what’s inside because it’s always a good place for anti-debugging or state initialization (to understand if a programmer-defined routine will alter the runtime code somehow): `INIT_ARRAY 0x202da0` size 8 — one constructor (pointer at `0x202da0`). Sometimes it's just the code to handle the TM clone tables (compiler-generated code), sometimes not - but worth checking.
    
- Only 4 functions are called: all real work is in internal code. `_setjmp`/`longjmp` hint at non-linear control-flow tricks (“teleporting” around the code).
    
- The **.bss** is strangely large (**0x23e0 ≈ 9 KB**) compared to the tiny code size. The program stores a chunk of runtime data and it might be worth checking.
    
- Another key point is not just which functions are present, but which are missing. There’s no `scanf`, `read`, etc. The binary **puts** but never asks the user for input. This typically implies:
    
    - It will _decode something internally_ and display it, **or**
        
    - It will fail immediately if a runtime check (e.g., CRC, time limit) is incorrect.
        
    - It uses program parameters or environment variables.
        

The rest of this information aligns with what we discovered earlier through hardcoded strings and previously executed commands.

We can try dumping the content of different sections using `objdump` and check if anything catches our attention (patterns, encrypted stuff, clues, etc.) or simply to better understand the structure of the ELF.

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ objdump -s -j .data teleport | head   

teleport:     file format elf64-x86-64

Contents of section .data:
 203000 00000000 00000000 08302000 00000000  .........0 .....
 203010 00000000 00000000 00000000 00000000  ................
 203020 160e0000 00000000 8e0d0000 00000000  ................
 203030 56120000 00000000 ca150000 00000000  V...............
 203040 260f0000 00000000 ba140000 00000000  &...............
 203050 f60b0000 00000000 aa130000 00000000  ................
                                                                                                                        
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ objdump -s -j .rodata teleport | head 

teleport:     file format elf64-x86-64

Contents of section .rodata:
 1810 01000200 4d697373 696e6720 70617373  ....Missing pass
 1820 776f7264 004c6f6f 6b732067 6f6f6420  word.Looks good 
 1830 746f206d 65210053 6f6d6574 68696e67  to me!.Something
 1840 27732077 726f6e67 2e2e2e00           's wrong....'                                                                                                                      
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ objdump -s -j .bss teleport | head 

teleport:     file format elf64-x86-64

Contents of section .bss:
 203180 00000000 00000000 00000000 00000000  ................
 203190 00000000 00000000 00000000 00000000  ................
 2031a0 00000000 00000000 00000000 00000000  ................
 2031b0 00000000 00000000 00000000 00000000  ................
 2031c0 00000000 00000000 00000000 00000000  ................
 2031d0 00000000 00000000 00000000 00000000  ................                                                                                                              
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ objdump -s -j .comment teleport | head 

teleport:     file format elf64-x86-64

Contents of section .comment:
 0000 4743433a 20285562 756e7475 20372e35  GCC: (Ubuntu 7.5
 0010 2e302d33 7562756e 7475317e 31382e30  .0-3ubuntu1~18.0
 0020 34292037 2e352e30 00                 4) 7.5.0.                                                                                                                         
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ objdump -s -j .dynamic teleport | head 

teleport:     file format elf64-x86-64

Contents of section .dynamic:
 202db0 01000000 00000000 01000000 00000000  ................
 202dc0 0c000000 00000000 a0090000 00000000  ................
 202dd0 0d000000 00000000 04180000 00000000  ................
 202de0 19000000 00000000 a02d2000 00000000  .........- .....
 202df0 1b000000 00000000 08000000 00000000  ................
 202e00 1a000000 00000000 a82d2000 00000000  .........- .....  ```

Nothing interesting, to be honest.

Alright, I think we have enough context now and can move on to the next step: looking at the execution behavior.

---

## 💻 Dynamic Analysis

- **Execution Behavior**: 

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ ./teleport                                   
Missing password
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ ./teleport hola
Something's wrong...'
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ ./teleport AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Something's wrong...'

                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ ./teleport hola 123                                       
Missing password
```

It seems the code is expecting the password as the first parameter (which explains why there’s no `fgets`, `scanf`, or similar functions, and only `puts`).  
It also looks like the program accepts only one valid parameter.

Let’s try tracing it with `ltrace` (though there could be some anti-debugging in place, considering the medium difficulty of the challenge and the presence of the `init_array` constructor).

- **ltrace**: 

```bash

──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ ltrace ./teleport hola                              
strncpy(0x555a8ce03280, "hola", 100)                                                                                 = 0x555a8ce03280
_setjmp(0x555a8ce04430, 0x7ffff092f2d3, 0x555a8cc00e16, 4)                                                           = 0
_setjmp(0x555a8ce04fe8, 0, 0x555a8cc00d8e, 4)                                                                        = 0
_setjmp(0x555a8ce033c8, 0, 0x555a8cc01256, 4)                                                                        = 0
_setjmp(0x555a8ce04b38, 0, 0x555a8cc015ca, 4)                                                                        = 0
_setjmp(0x555a8ce05240, 0, 0x555a8cc00f26, 4)                                                                        = 0
_setjmp(0x555a8ce041d8, 0, 0x555a8cc014ba, 4)                                                                        = 0
_setjmp(0x555a8ce04e58, 0, 0x555a8cc00bf6, 4)                                                                        = 0
_setjmp(0x555a8ce04f20, 0, 0x555a8cc013aa, 4)                                                                        = 0
_setjmp(0x555a8ce04c00, 0, 0x555a8cc01146, 4)                                                                        = 0
_setjmp(0x555a8ce03620, 0, 0x555a8cc00d4a, 4)                                                                        = 0
_setjmp(0x555a8ce037b0, 0, 0x555a8cc01542, 4)                                                                        = 0
_setjmp(0x555a8ce04688, 0, 0x555a8cc0129a, 4)                                                                        = 0
_setjmp(0x555a8ce03558, 0, 0x555a8cc00b2a, 4)                                                                        = 0
_setjmp(0x555a8ce04048, 0, 0x555a8cc0160e, 4)                                                                        = 0
_setjmp(0x555a8ce03a08, 0, 0x555a8cc00ee2, 4)                                                                        = 0
_setjmp(0x555a8ce04818, 0, 0x555a8cc00bb2, 4)                                                                        = 0
_setjmp(0x555a8ce04d90, 0, 0x555a8cc00fae, 4)                                                                        = 0
_setjmp(0x555a8ce04cc8, 0, 0x555a8cc0107a, 4)                                                                        = 0
_setjmp(0x555a8ce04a70, 0, 0x555a8cc013ee, 4)                                                                        = 0
_setjmp(0x555a8ce044f8, 0, 0x555a8cc012de, 4)                                                                        = 0
_setjmp(0x555a8ce03eb8, 0, 0x555a8cc01432, 4)                                                                        = 0
_setjmp(0x555a8ce049a8, 0, 0x555a8cc01212, 4)                                                                        = 0
_setjmp(0x555a8ce05308, 0, 0x555a8cc00ff2, 4)                                                                        = 0
_setjmp(0x555a8ce053d0, 0, 0x555a8cc01652, 4)                                                                        = 0
_setjmp(0x555a8ce036e8, 0, 0x555a8cc00b6e, 4)                                                                        = 0
_setjmp(0x555a8ce03490, 0, 0x555a8cc00d06, 4)                                                                        = 0
_setjmp(0x555a8ce03d28, 0, 0x555a8cc00c3a, 4)                                                                        = 0
_setjmp(0x555a8ce05178, 0, 0x555a8cc01322, 4)                                                                        = 0
_setjmp(0x555a8ce03878, 0, 0x555a8cc014fe, 4)                                                                        = 0
_setjmp(0x555a8ce03b98, 0, 0x555a8cc00c7e, 4)                                                                        = 0
_setjmp(0x555a8ce04368, 0, 0x555a8cc01586, 4)                                                                        = 0
_setjmp(0x555a8ce03300, 0, 0x555a8cc011ce, 4)                                                                        = 0
_setjmp(0x555a8ce042a0, 0, 0x555a8cc00e9e, 4)                                                                        = 0
_setjmp(0x555a8ce04110, 0, 0x555a8cc01036, 4)                                                                        = 0
_setjmp(0x555a8ce03f80, 0, 0x555a8cc01366, 4)                                                                        = 0
_setjmp(0x555a8ce03df0, 0, 0x555a8cc00cc2, 4)                                                                        = 0
_setjmp(0x555a8ce03c60, 0, 0x555a8cc00dd2, 4)                                                                        = 0
_setjmp(0x555a8ce03940, 0, 0x555a8cc01476, 4)                                                                        = 0
_setjmp(0x555a8ce03ad0, 0, 0x555a8cc0118a, 4)                                                                        = 0
_setjmp(0x555a8ce04750, 0, 0x555a8cc01102, 4)                                                                        = 0
_setjmp(0x555a8ce045c0, 0, 0x555a8cc00e5a, 4)                                                                        = 0
_setjmp(0x555a8ce050b0, 0, 0x555a8cc00f6a, 4)                                                                        = 0
_setjmp(0x555a8ce048e0, 0, 0x555a8cc010be, 4)                                                                        = 0
_setjmp(0x555a8ce031a0, 0, 0xd719dd4ace3256c8, 4)                                                                    = 0
longjmp(0x555a8ce03300, 1, 0x555a8ce03300, 4 <unfinished ...>
longjmp(0x555a8ce031a0, 101, 0x555a8cc011de, 0 <unfinished ...>
puts("Something's wrong..."Something's wrong...
)                                                                                         = 21
<... longjmp resumed> )                                                                                              = 21
+++ exited (status 0) +++

```

Interesting behavior and observations:

1. It’s unclear whether there’s an early anti-debugging trick in place (we may need to use `strace` to detect any `ptrace` or related mechanisms).
    
2. `argv[1]` is copied into a pre-sized 100-byte buffer.
    
3. Multiple `_setjmp` calls are made—likely to set up various "return points" and introduce code-flow obfuscation.
    
4. Two of those `_setjmp` slots are later used via `longjmp` calls.
    
5. Finally, `puts` is used to tell us the password is wrong—so the check and possibly decryption likely occurred earlier.
    

Deeper look into `_setjmp` behavior:

- Each `_setjmp` stores a snapshot (env containing RIP, stack, registers) into a fresh slot inside `.bss` (`0x555a8ce0XXXX`).
    
- The third argument shown by `ltrace` is the saved RIP (instruction pointer), which will be loaded when a `longjmp` targets that slot. All saved RIPs are located within the binary’s `.text`, essentially forming a jump table for rapid code redirection.
    
- A `longjmp` selects one of those buffers and provides a value (`1`, `101`, etc.), which is what the corresponding `setjmp` will appear to return.
    

This tells us:

1. The first `longjmp` targets `_setjmp` buffer at `0x555a8ce03300`, which saved RIP to `0x555a8cc011ce` — so execution will jump to `0x555a8cc011ce`.
    
2. The second `longjmp` targets `_setjmp` buffer at `0x555a8ce031a0`, which saved RIP to `0xd719dd4ace3256c8` — this address is outside `.text`, probably jumping to puts?
    

This gives us a clearer surgical path when diving into the disassembly.

Before moving into the IDA-disassembled code, let’s take a quick look at syscall tracing with `strace`.

- **strace**: 

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ strace ./teleport hola
execve("./teleport", ["./teleport", "hola"], 0x7ffe775bad98 /* 53 vars */) = 0
brk(NULL)                               = 0x55d33b13e000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f5f10d19000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=99250, ...}) = 0
mmap(NULL, 99250, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f5f10d00000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000\237\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2055640, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f5f10b0a000
mmap(0x7f5f10b32000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f5f10b32000
mmap(0x7f5f10c97000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f5f10c97000
mmap(0x7f5f10ced000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f5f10ced000
mmap(0x7f5f10cf3000, 52696, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f5f10cf3000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f5f10b07000
arch_prctl(ARCH_SET_FS, 0x7f5f10b07740) = 0
set_tid_address(0x7f5f10b07a10)         = 67002
set_robust_list(0x7f5f10b07a20, 24)     = 0
rseq(0x7f5f10b08060, 0x20, 0, 0x53053053) = 0
mprotect(0x7f5f10ced000, 16384, PROT_READ) = 0
mprotect(0x55d339402000, 4096, PROT_READ) = 0
mprotect(0x7f5f10d4e000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f5f10d00000, 99250)           = 0
fstat(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0), ...}) = 0
getrandom("\xc3\x9f\x59\x60\x2b\xf7\xaf\xbc", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55d33b13e000
brk(0x55d33b15f000)                     = 0x55d33b15f000
write(1, "Something's wrong...\n", 21Something's wrong...
)  = 21
exit_group(0)                           = ?
+++ exited with 0 +++
```

As always, we know the "real" code starts generating syscalls after the `brk(0x55d33b15f000)` line—everything before that comes from the Linux loader and is likely not the programmer’s intent.

So, the user-defined code generates these syscalls in sequence:

- `write(1, "Something's wrong...\n", 21Something's wrong...)  = 21`
    
- `exit_group`
    

Nothing unexpected or new here.

Now we can move on and inspect the disassembled code in IDA.

- **IDA**:  
    As usual, once IDA analyzes the code, it displays the `start` routine, which calls the **`libc_start_main_ptr`**, passing the actual `main` function as a parameter.

![Screenshot](Images/Pasted%20image%2020250804132748.png)

So, double-click on `main` to navigate to the real entry point of the code.

![Screenshot](Images/Pasted%20image%2020250804132833.png)

`main` looks small and contains the hardcoded strings like "Something's wrong..." along with the relevant logic observed during execution, so we’re definitely in the right place.

Before diving into `main`, we should also analyze the `.init_array` constructor to check for any programmer-defined tricks or hacks that run before the actual `main`.

To inspect the global constructor, open IDA and navigate to:  **View ▸ Open subviews ▸ Segments**

Then locate the segment with type **`INIT_ARRAY`** and double-click it.

![Screenshot](Images/Pasted%20image%2020250804133215.png)

We find that `sub_B20` is executed before `main`, so let’s take a look inside and see what it does.

![Screenshot](Images/Pasted%20image%2020250804133307.png)

The only meaningful part above is the `jmp sub_A90`—it acts as trampoline code to `sub_A90`, shown below. The instructions from `push` to `pop` are effectively doing nothing meaningful, so the real action is just in the jump instruction.

![Screenshot](Images/Pasted%20image%2020250804133405.png)

This isn’t a programmer’s trick—the code handles compiler-generated TM Clone tables for transactional memory support and is just a glibc constructor stub, not part of the program’s anti-debugging logic.

We can now safely move on to analyze the `main` function’s pseudo-C code generated by IDA (F5). I’ve renamed some variables for clarity.

```C
__int64 __fastcall main(int argc, char **argv, char **env)
{
  int val; // eax
  unsigned int i; // [rsp+18h] [rbp-8h]

  if ( argc == 2 )
  {
    strncpy(&dest, argv[1], 100u);
    for ( i = 0; i <= 42; ++i )
      funcs_1706[i]();
    val = _setjmp(jmp_env);
    if ( val == 100 )
    {
      puts("Looks good to me!");
    }
    else
    {
      if ( val != 101 )
        longjmp(&stru_203300[val], 1);
      puts("Something's wrong...");
    }
    return 0;
  }
  else
  {
    puts("Missing password");
    return 0xFFFFFFFFLL;
  }
}
```

The code reflects our earlier discoveries:

1. It checks whether `argc == 2`.
    
2. It copies `argv[1]` into a local buffer sized 100 bytes.
    

After that, we observe something new:

1. It enters a loop that executes `funcs_1706[i]();` 42 times.  
    → Upon inspecting `funcs_1706`, we find it’s a table containing function addresses.

![Screenshot](Images/Pasted%20image%2020250804134516.png)

So at each loop, one of those function is executed in sequence. Continuing with the inspection—for example, looking at what the first function `sub_D8E` does—we see:

![Screenshot](Images/Pasted%20image%2020250804134636.png)

There are pairs of `__setjmp` and `__longjmp`, and this pattern repeats across 42 different functions. This effectively "teleports" execution from one place to another 42 times, serving to obfuscate the control flow through layered jumps.

Just to be thorough, let’s also inspect the next function called, `sub_1256`.

![Screenshot](Images/Pasted%20image%2020250804134959.png)

Very similar functions indeed! One detail stands out: after the `setjmp` call—where execution would return if triggered by a `longjmp`—there's a `jz` instruction that checks whether the returned value is 0.

As a reminder, `setjmp` returns 0 the first time it's set, and non-zero when control returns from a `longjmp`. So the **red branch after `jz`** is taken only when control arrives via `longjmp`. This red branch is the one of interest for us (because we need to understand what happens when longjmp use this code, not when setjmp set this as return.).

Now, looking at the two red branches:

- In `sub_D8E`, it compares `byte_2032A5` with the letter `'n'`
    
- In `sub_1256`, it compares `byte_203281` with the letter `'T'`
    

Very interesting — this could be pieces of the flag being compared individually (?)

Also, if the comparison fails, the return value is set to `0x65` (101); otherwise, it’s set to a different value, and then `longjmp` is called to jump to the next logical point. Very interesting. Like "if character is good" move to the next function function, if not simply exit with value 101.

So this appears to be the mechanism used to compare our password **character by character**. In our earlier test with `"hola"`, only two `longjmp` calls were observed—likely because the first incorrect letter prevented further progress. I’ll bet that if the input letters are correct, we’ll see more `longjmp` calls.

Let’s go ahead and test this theory.

```bash
┌──(kali㉿kali)-[~/Downloads/rev_teleport]
└─$ ltrace ./teleport HTB{BLABLABLABLA}
strncpy(0x55b44f403280, "HTB{BLABLABLABLA}", 100)        = 0x55b44f403280
_setjmp(0x55b44f404430, 0x7ffe46b9b2b9, 0x55b44f200e16, 17) = 0
_setjmp(0x55b44f404fe8, 0, 0x55b44f200d8e, 17)           = 0
_setjmp(0x55b44f4033c8, 0, 0x55b44f201256, 17)           = 0
_setjmp(0x55b44f404b38, 0, 0x55b44f2015ca, 17)           = 0
_setjmp(0x55b44f405240, 0, 0x55b44f200f26, 17)           = 0
_setjmp(0x55b44f4041d8, 0, 0x55b44f2014ba, 17)           = 0
_setjmp(0x55b44f404e58, 0, 0x55b44f200bf6, 17)           = 0
_setjmp(0x55b44f404f20, 0, 0x55b44f2013aa, 17)           = 0
_setjmp(0x55b44f404c00, 0, 0x55b44f201146, 17)           = 0
_setjmp(0x55b44f403620, 0, 0x55b44f200d4a, 17)           = 0
_setjmp(0x55b44f4037b0, 0, 0x55b44f201542, 17)           = 0
_setjmp(0x55b44f404688, 0, 0x55b44f20129a, 17)           = 0
_setjmp(0x55b44f403558, 0, 0x55b44f200b2a, 17)           = 0
_setjmp(0x55b44f404048, 0, 0x55b44f20160e, 17)           = 0
_setjmp(0x55b44f403a08, 0, 0x55b44f200ee2, 17)           = 0
_setjmp(0x55b44f404818, 0, 0x55b44f200bb2, 17)           = 0
_setjmp(0x55b44f404d90, 0, 0x55b44f200fae, 17)           = 0
_setjmp(0x55b44f404cc8, 0, 0x55b44f20107a, 17)           = 0
_setjmp(0x55b44f404a70, 0, 0x55b44f2013ee, 17)           = 0
_setjmp(0x55b44f4044f8, 0, 0x55b44f2012de, 17)           = 0
_setjmp(0x55b44f403eb8, 0, 0x55b44f201432, 17)           = 0
_setjmp(0x55b44f4049a8, 0, 0x55b44f201212, 17)           = 0
_setjmp(0x55b44f405308, 0, 0x55b44f200ff2, 17)           = 0
_setjmp(0x55b44f4053d0, 0, 0x55b44f201652, 17)           = 0
_setjmp(0x55b44f4036e8, 0, 0x55b44f200b6e, 17)           = 0
_setjmp(0x55b44f403490, 0, 0x55b44f200d06, 17)           = 0
_setjmp(0x55b44f403d28, 0, 0x55b44f200c3a, 17)           = 0
_setjmp(0x55b44f405178, 0, 0x55b44f201322, 17)           = 0
_setjmp(0x55b44f403878, 0, 0x55b44f2014fe, 17)           = 0
_setjmp(0x55b44f403b98, 0, 0x55b44f200c7e, 17)           = 0
_setjmp(0x55b44f404368, 0, 0x55b44f201586, 17)           = 0
_setjmp(0x55b44f403300, 0, 0x55b44f2011ce, 17)           = 0
_setjmp(0x55b44f4042a0, 0, 0x55b44f200e9e, 17)           = 0
_setjmp(0x55b44f404110, 0, 0x55b44f201036, 17)           = 0
_setjmp(0x55b44f403f80, 0, 0x55b44f201366, 17)           = 0
_setjmp(0x55b44f403df0, 0, 0x55b44f200cc2, 17)           = 0
_setjmp(0x55b44f403c60, 0, 0x55b44f200dd2, 17)           = 0
_setjmp(0x55b44f403940, 0, 0x55b44f201476, 17)           = 0
_setjmp(0x55b44f403ad0, 0, 0x55b44f20118a, 17)           = 0
_setjmp(0x55b44f404750, 0, 0x55b44f201102, 17)           = 0
_setjmp(0x55b44f4045c0, 0, 0x55b44f200e5a, 17)           = 0
_setjmp(0x55b44f4050b0, 0, 0x55b44f200f6a, 17)           = 0
_setjmp(0x55b44f4048e0, 0, 0x55b44f2010be, 17)           = 0
_setjmp(0x55b44f4031a0, 0, 0x58d3006b79d29bf8, 17)       = 0
longjmp(0x55b44f403300, 1, 0x55b44f403300, 17 <unfinished ...>
longjmp(0x55b44f4031a0, 1, 0x55b44f2011de, 0 <unfinished ...>
longjmp(0x55b44f4033c8, 1, 0x55b44f403300, 0 <unfinished ...>
longjmp(0x55b44f4031a0, 2, 0x55b44f201266, 0 <unfinished ...>
longjmp(0x55b44f403490, 1, 0x55b44f403300, 0 <unfinished ...>
longjmp(0x55b44f4031a0, 3, 0x55b44f200d16, 0 <unfinished ...>
longjmp(0x55b44f403558, 1, 0x55b44f403300, 0 <unfinished ...>
longjmp(0x55b44f4031a0, 4, 0x55b44f200b3a, 0 <unfinished ...>
longjmp(0x55b44f403620, 1, 0x55b44f403300, 0 <unfinished ...>
longjmp(0x55b44f4031a0, 101, 0x55b44f200d5a, 0 <unfinished ...>
puts("Something's wrong..."Something's wrong...
)                             = 21
<... longjmp resumed> )                                  = 21
+++ exited (status 0) +++
```

Using the known prefix `HTB{` confirms the theory—more `longjmp` calls are triggered, indicating correct characters allow deeper progress.

At this point, let’s collect all the characters checked in each of the 42 functions into a table to reconstruct the key or flag.

The first two—`sub_D8E` and `sub_1256`—have already been analyzed. Now, let's apply the same approach to the remaining 40 functions:

- Enter each function
    
- Extract the character it's comparing against
    
- Note the return value (via `longjmp` parameter `val`)
    
- Record the memory address (e.g., `cs:byte_2032XX`) it compares against
    

This will allow us to reconstruct the flag accurately and validate.

```bash
1. byte_2032A5 --> n --> retuned value: 26h
2. byte_203281 --> T --> retuned value: 2h 
3. byte_20329F --> _ --> retuned value: 20h
4. byte_2032A8 --> m --> retuned value: 29h
5. byte_203293 --> 3 --> retuned value: 14h
6. byte_2032A3 -->  t --> retuned value: 24h
7. byte_2032A4 -->  1 --> retuned value: 25h
8. byte_2032A0 --> c --> retuned value: 21h
9. byte_203284 -->  j --> retuned value: 5h
10. byte_203286 -->  m --> retuned value: 7h
11. byte_203299 -->  3 --> retuned value: 1Ah
12. byte_203283 -->  { --> retuned value: 4h
13. byte_203291 -->  t --> retuned value: 12h
14. byte_203289 -->  n --> retuned value: 0Ah
15. byte_20329B --> t --> retuned value: 1Ch
16. byte_2032A2 --> n --> retuned value: 23h
17. byte_2032A1 --> 0 --> retuned value: 22h
18. byte_20329E  --> 3 --> retuned value: 1Fh
19. byte_203297 --> 4 --> retuned value: 18h
20. byte_20328F --> u --> retuned value: 10h
21. byte_20329D --> m --> retuned value: 1Eh
22. byte_2032A9 --> ! --> retuned value: 2Ah
23. byte_2032AA --> } --> retuned value: 64h
24. byte_203285 --> u --> retuned value: 6h
25. byte_203282 --> B --> retuned value: 3h
26. byte_20328D --> h --> retuned value: 0Eh
27. byte_2032A7 --> u --> retuned value: 28h
28. byte_203287 --> p --> retuned value: 8h
29. byte_20328B --> _ --> retuned value: 0Ch
30. byte_203295 --> s --> retuned value: 16h
31. cs:dest --> H --> retuned value: 1h
32. byte_203294 --> _ --> retuned value: 15h
33. byte_203292 --> h --> retuned value: 13h
34. byte_203290 --> _ --> retuned value: 11h
35. byte_20328E --> r --> retuned value: 0Fh
36. byte_20328C --> t --> retuned value: 0Dh
37. byte_203288 --> 1 --> retuned value: 9h
38. byte_20328A --> g --> retuned value: 0Bh
39. byte_20329A --> _ --> retuned value: 1Bh
40. byte_203298 --> c --> retuned value: 19h
41. byte_2032A6 --> u --> retuned value: 27h
42. byte_20329C --> 1 --> retuned value: 1Dh
```

Okay, the above clearly represents the flag characters, just out of order. But we can use the return values from each function to reassemble them correctly. As observed, `'H'` (from `HTB{`) returns `1`, `'T'` returns `2`, `'B'` returns `3`, and so on.

Have fun sorting it manually...  

Just kidding—I already did it for you:

```bash
dest --> H --> retuned value: 1h
byte_203281 --> T --> retuned value: 2h 
byte_203282 --> B --> retuned value: 3h
byte_203283 -->  { --> retuned value: 4h
byte_203284 -->  j --> retuned value: 5h
byte_203285 --> u --> retuned value: 6h
byte_203286 -->  m --> retuned value: 7h
byte_203287 --> p --> retuned value: 8h
byte_203288 --> 1 --> retuned value: 9h
byte_203289 -->  n --> retuned value: 0Ah
byte_20328A --> g --> retuned value: 0Bh
byte_20328B --> _ --> retuned value: 0Ch
byte_20328C --> t --> retuned value: 0Dh
byte_20328D --> h --> retuned value: 0Eh
byte_20328E --> r --> retuned value: 0Fh
byte_20328F --> u --> retuned value: 10h
byte_203290 --> _ --> retuned value: 11h
byte_203291 -->  t --> retuned value: 12h
byte_203292 --> h --> retuned value: 13h
byte_203293 --> 3 --> retuned value: 14h
byte_203294 --> _ --> retuned value: 15h
byte_203295 --> s --> retuned value: 16h

byte_203297 --> 4 --> retuned value: 18h
byte_203298 --> c --> retuned value: 19h
byte_203299 -->  3 --> retuned value: 1Ah
byte_20329A --> _ --> retuned value: 1Bh
byte_20329B --> t --> retuned value: 1Ch
byte_20329C --> 1 --> retuned value: 1Dh
byte_20329D --> m --> retuned value: 1Eh
byte_20329E  --> 3 --> retuned value: 1Fh
byte_20329F --> _ --> retuned value: 20h
byte_2032A0 --> c --> retuned value: 21h
byte_2032A1 --> 0 --> retuned value: 22h
byte_2032A2 --> n --> retuned value: 23h
byte_2032A3 -->  t --> retuned value: 24h
byte_2032A4 -->  1 --> retuned value: 25h
byte_2032A5 --> n --> retuned value: 26h
byte_2032A6 --> u --> retuned value: 27h
byte_2032A7 --> u --> retuned value: 28h
byte_2032A8 --> m --> retuned value: 29h
byte_2032A9 --> ! --> retuned value: 2Ah
byte_2032AA --> } --> retuned value: 64h (exit value)
```


Looks like the 17th character (`0x17`) was missing, but based on context, guessing it as `'p'` makes perfect sense:

**`HTB{jump1ng_thru_th3_sp4c3_t1m3_c0nt1nuum!}`**

And there it is—the complete flag!

Nicely done solving the challenge without even launching IDA's debugger. 🙂

---
## ✅ Challenges Encountered / Lessons Learned

This challenge stood out due to its creative use of `setjmp`/`longjmp` for control flow obfuscation. Instead of a straightforward comparison or decryption routine, the binary set up a network of jump buffers, each pointing to one of 42 functions that individually validated a character of the input.

The main challenges included:

- **Unusual control flow**: Following the logic through nested `setjmp`/`longjmp` patterns was unintuitive and required careful tracking of both saved jump locations and return values.
    
- **Non-linear execution**: The fact that valid characters triggered jumps forward in the function list while invalid ones ended the execution (with `longjmp` to an exit block) made dynamic tracing more difficult but also more interesting.
    
- **Ordering by return values**: Thinking outside the box by meticulously collecting both the comparison value and the hardcoded return address from `longjmp` allows for successful flag reordering without the need for live debugging.
    

Ultimately, the lesson was clear: **even basic libc primitives can be leveraged creatively for obfuscation and layered validation logic**, offering effective resistance against traditional analysis workflows.

---
##  🏁 Conclusion

The `Teleport` reversing challenge was an excellent exercise in low-level execution flow manipulation and reverse engineering discipline. By statically analyzing the binary structure and dynamically tracing execution paths using `ltrace` and `strace`, we discovered how the input was validated character by character through a chain of `setjmp`/`longjmp`-enabled comparison routines.

After extracting and reordering the expected characters based on the return values, we reconstructed the full flag:

```HTB
HTB{jump1ng_thru_th3_sp4c3_t1m3_c0nt1nuum!}
```

This challenge didn’t rely on encryption, packing, or anti-debugging tricks—it was purely a game of **clever control flow and patience**. It’s a perfect example of how simplicity in concept can still result in an elegant and rewarding challenge.

---
## 💡 Additional Notes / Reflections

- The `init_array` section initially appeared suspicious, as it often harbors anti-debugging tricks, but in this case, it only contained a standard TM Clone table registration routine—an excellent reminder not to jump to conclusions too quickly.
    
- The use of `setjmp` and `longjmp` was not only thematic (teleportation logic) but also effective in hiding the flag validation logic under layers of indirection. It’s uncommon to see these functions used so extensively, making this challenge particularly educational.
    
- Tools like `ltrace` and careful manual reordering proved more powerful than launching the debugger directly. In fact, the entire flag was recovered **without ever stepping through code in a live debugger**, highlighting the strength of methodical, static/dynamic hybrid analysis.
    

🎯 **Tip for future challenges**: When dealing with obfuscated logic or unusual control flow, always look for how state is preserved and transitioned—here, the `jmp_buf` was the key to everything.

---

