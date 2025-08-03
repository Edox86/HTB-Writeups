# 🧬 Hack The Box - Reversing Challenge Write-Up:[Rebuilding] – [03/08/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Rebuilding
- **Challenge Description:** You arrive on a barren planet, searching for the hideout of a scientist involved in the Longhir resistance movement. You touch down at the mouth of a vast cavern, your sensors picking up strange noises far below. All around you, ancient machinery whirrs and spins as strange sigils appear and change on the walls. You can tell that this machine has been running since long before you arrived, and will continue long after you're gone. Can you hope to understand its workings?
- **Difficulty:** Easy
- **📦 Provided Files**:
	- File: `Rebuilding.zip`  
	- Password: `hackthebox`
	- SHA256: `9bf28543ddd678b138e3962491e6691476e57cf56bdbbdba8a2d83806db4c461` 
- **📦 Extracted Files**:
	-  File: `Rebuilding`
	- SHA256: `e4d0b084451dfef1130f4a33a2f4a997059ee174cfc1b605118fc37d6e2703f4`
---

## ⚙️ Environment Setup
- **Operating System:** `Kali Linux`
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `readelf`, `ldd`,  `objdump`
  - Dynamic: `ltrace`, `IDA Free`

---

## 🔍 Static Analysis

#### Initial Observations
- File

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ file rebuilding         
rebuilding: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c7a145f3a4b213cf895a735e2b26adffc044c190, not stripped
```

It’s a 64-bit, position-independent, dynamically linked, non-stripped ELF executable for x86-64 Linux (kernel ≥ 3.2), using /lib64/ld-linux-x86-64.so.2 as its loader.
Binary not stripped is good because we can still read the symbols: functions are already named, so the decompiler will label them without guessing.

- ldd

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ ldd rebuilding 
        linux-vdso.so.1 (0x00007ffd70d9f000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5ca620a000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5ca672f000)
```

It depends solely on the kernel’s vDSO, glibc (libc.so.6), and the standard 64-bit dynamic loader /lib64/ld-linux-x86-64.so.2 at runtime—no other shared libraries are required.

- strings

```bash
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ strings rebuilding  
/lib64/ld-linux-x86-64.so.2
Zs^+&
libc.so.6
fflush
exit
puts
putchar
printf
strlen
stdout
usleep
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
AWAVI
AUATL
[]A\A]A^A_
Preparing secret keys
Missing required argument
Password length is incorrect
Calculating
The password is correct
The password is incorrect
;*3$"
humans
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
rebuilding.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
putchar@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
stdout@@GLIBC_2.2.5
encrypted
puts@@GLIBC_2.2.5
_edata
strlen@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
fflush@@GLIBC_2.2.5
__bss_start
main
exit@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
usleep@@GLIBC_2.2.5
.symtab
.strtab
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

I notice several function names that we can set as future breakpoints, including an interesting `usleep`, which is a wrapper around the `nanosleep` system call. I also see hard-coded strings that appear to be part of the program logic:

```strings
Preparing secret keys
Missing required argument
Password length is incorrect
Calculating
The password is correct
The password is incorrect
;*3$"
humans
```

Should we rely on `The password is correct` to locate the proper branch of the code? We will see, but not yet.

Another interesting part I noticed includes strings like:

```strings
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
completed.7698
rebuilding.c
```

These appear to be C file names and a system's uname, but the question is, why are they present?

To answer this, I did a quick bit of research and found that these “extra” strings aren’t Easter eggs left behind by the author—they’re typical by-products of how GCC and `ld` build an ELF executable when it hasn’t been stripped of its symbol table or “comment” section.

Let's proceed to the next step:

- objdump

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ objdump -a -f rebuilding 

rebuilding:     file format elf64-x86-64
rebuilding
architecture: i386:x86-64, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x0000000000000740
```

It's important that we take note of the start address shown above.

- readelf

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ readelf -a rebuilding 
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
  Entry point address:               0x740
  Start of program headers:          64 (bytes into file)
  Start of section headers:          6872 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         29
  Section header string table index: 28

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
       0000000000000024  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000000002c0  000002c0
       0000000000000150  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000000410  00000410
       00000000000000b2  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           00000000000004c2  000004c2
       000000000000001c  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          00000000000004e0  000004e0
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000000500  00000500
       00000000000000f0  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000000005f0  000005f0
       00000000000000a8  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         0000000000000698  00000698
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000000006b0  000006b0
       0000000000000080  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         0000000000000730  00000730
       0000000000000008  0000000000000008  AX       0     0     8
  [14] .text             PROGBITS         0000000000000740  00000740
       0000000000000352  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         0000000000000a94  00000a94
       0000000000000009  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         0000000000000aa0  00000aa0
       0000000000000091  0000000000000000   A       0     0     4
  [17] .eh_frame_hdr     PROGBITS         0000000000000b34  00000b34
       0000000000000044  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         0000000000000b78  00000b78
       0000000000000128  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000200d80  00000d80
       0000000000000010  0000000000000008  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000200d90  00000d90
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .dynamic          DYNAMIC          0000000000200d98  00000d98
       00000000000001f0  0000000000000010  WA       6     0     8
  [22] .got              PROGBITS         0000000000200f88  00000f88
       0000000000000078  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000201000  00001000
       0000000000000049  0000000000000000  WA       0     0     32
  [24] .bss              NOBITS           0000000000201050  00001049
       0000000000000010  0000000000000000  WA       0     0     8
  [25] .comment          PROGBITS         0000000000000000  00001049
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00001078
       00000000000006c0  0000000000000018          27    43     8
  [27] .strtab           STRTAB           0000000000000000  00001738
       00000000000002a1  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  000019d9
       00000000000000fe  0000000000000000           0     0     1
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
                 0x0000000000000ca0 0x0000000000000ca0  R E    0x200000
  LOAD           0x0000000000000d80 0x0000000000200d80 0x0000000000200d80
                 0x00000000000002c9 0x00000000000002e0  RW     0x200000
  DYNAMIC        0x0000000000000d98 0x0000000000200d98 0x0000000000200d98
                 0x00000000000001f0 0x00000000000001f0  RW     0x8
  NOTE           0x0000000000000254 0x0000000000000254 0x0000000000000254
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x0000000000000b34 0x0000000000000b34 0x0000000000000b34
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000000d80 0x0000000000200d80 0x0000000000200d80
                 0x0000000000000280 0x0000000000000280  R      0x1

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

Dynamic section at offset 0xd98 contains 27 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x698
 0x000000000000000d (FINI)               0xa94
 0x0000000000000019 (INIT_ARRAY)         0x200d80
 0x000000000000001b (INIT_ARRAYSZ)       16 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x200d90
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x298
 0x0000000000000005 (STRTAB)             0x410
 0x0000000000000006 (SYMTAB)             0x2c0
 0x000000000000000a (STRSZ)              178 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x200f88
 0x0000000000000002 (PLTRELSZ)           168 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x5f0
 0x0000000000000007 (RELA)               0x500
 0x0000000000000008 (RELASZ)             240 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
 0x000000006ffffffe (VERNEED)            0x4e0
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x4c2
 0x000000006ffffff9 (RELACOUNT)          4
 0x0000000000000000 (NULL)               0x0

Relocation section '.rela.dyn' at offset 0x500 contains 10 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000200d80  000000000008 R_X86_64_RELATIVE                    840
000000200d88  000000000008 R_X86_64_RELATIVE                    84a
000000200d90  000000000008 R_X86_64_RELATIVE                    800
000000201008  000000000008 R_X86_64_RELATIVE                    201008
000000200fd8  000200000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTM[...] + 0
000000200fe0  000600000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000200fe8  000700000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000200ff0  000a00000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_registerTMCl[...] + 0
000000200ff8  000b00000006 R_X86_64_GLOB_DAT 0000000000000000 __cxa_finalize@GLIBC_2.2.5 + 0
000000201050  000d00000005 R_X86_64_COPY     0000000000201050 stdout@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x5f0 contains 7 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000200fa0  000100000007 R_X86_64_JUMP_SLO 0000000000000000 putchar@GLIBC_2.2.5 + 0
000000200fa8  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000200fb0  000400000007 R_X86_64_JUMP_SLO 0000000000000000 strlen@GLIBC_2.2.5 + 0
000000200fb8  000500000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000200fc0  000800000007 R_X86_64_JUMP_SLO 0000000000000000 fflush@GLIBC_2.2.5 + 0
000000200fc8  000900000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
000000200fd0  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 usleep@GLIBC_2.2.5 + 0
No processor specific unwind information to decode

Symbol table '.dynsym' contains 14 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     7: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.2.5 (2)
    10: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    11: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    13: 0000000000201050     8 OBJECT  GLOBAL DEFAULT   24 [...]@GLIBC_2.2.5 (2)

Symbol table '.symtab' contains 72 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000238     0 SECTION LOCAL  DEFAULT    1 .interp
     2: 0000000000000254     0 SECTION LOCAL  DEFAULT    2 .note.ABI-tag
     3: 0000000000000274     0 SECTION LOCAL  DEFAULT    3 .note.gnu.build-id
     4: 0000000000000298     0 SECTION LOCAL  DEFAULT    4 .gnu.hash
     5: 00000000000002c0     0 SECTION LOCAL  DEFAULT    5 .dynsym
     6: 0000000000000410     0 SECTION LOCAL  DEFAULT    6 .dynstr
     7: 00000000000004c2     0 SECTION LOCAL  DEFAULT    7 .gnu.version
     8: 00000000000004e0     0 SECTION LOCAL  DEFAULT    8 .gnu.version_r
     9: 0000000000000500     0 SECTION LOCAL  DEFAULT    9 .rela.dyn
    10: 00000000000005f0     0 SECTION LOCAL  DEFAULT   10 .rela.plt
    11: 0000000000000698     0 SECTION LOCAL  DEFAULT   11 .init
    12: 00000000000006b0     0 SECTION LOCAL  DEFAULT   12 .plt
    13: 0000000000000730     0 SECTION LOCAL  DEFAULT   13 .plt.got
    14: 0000000000000740     0 SECTION LOCAL  DEFAULT   14 .text
    15: 0000000000000a94     0 SECTION LOCAL  DEFAULT   15 .fini
    16: 0000000000000aa0     0 SECTION LOCAL  DEFAULT   16 .rodata
    17: 0000000000000b34     0 SECTION LOCAL  DEFAULT   17 .eh_frame_hdr
    18: 0000000000000b78     0 SECTION LOCAL  DEFAULT   18 .eh_frame
    19: 0000000000200d80     0 SECTION LOCAL  DEFAULT   19 .init_array
    20: 0000000000200d90     0 SECTION LOCAL  DEFAULT   20 .fini_array
    21: 0000000000200d98     0 SECTION LOCAL  DEFAULT   21 .dynamic
    22: 0000000000200f88     0 SECTION LOCAL  DEFAULT   22 .got
    23: 0000000000201000     0 SECTION LOCAL  DEFAULT   23 .data
    24: 0000000000201050     0 SECTION LOCAL  DEFAULT   24 .bss
    25: 0000000000000000     0 SECTION LOCAL  DEFAULT   25 .comment
    26: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    27: 0000000000000770     0 FUNC    LOCAL  DEFAULT   14 deregister_tm_clones
    28: 00000000000007b0     0 FUNC    LOCAL  DEFAULT   14 register_tm_clones
    29: 0000000000000800     0 FUNC    LOCAL  DEFAULT   14 __do_global_dtors_aux
    30: 0000000000201058     1 OBJECT  LOCAL  DEFAULT   24 completed.7698
    31: 0000000000200d90     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtor[...]
    32: 0000000000000840     0 FUNC    LOCAL  DEFAULT   14 frame_dummy
    33: 0000000000200d80     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_in[...]
    34: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS rebuilding.c
    35: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    36: 0000000000000c9c     0 OBJECT  LOCAL  DEFAULT   18 __FRAME_END__
    37: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    38: 0000000000200d90     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_end
    39: 0000000000200d98     0 OBJECT  LOCAL  DEFAULT   21 _DYNAMIC
    40: 0000000000200d80     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_start
    41: 0000000000000b34     0 NOTYPE  LOCAL  DEFAULT   17 __GNU_EH_FRAME_HDR
    42: 0000000000200f88     0 OBJECT  LOCAL  DEFAULT   22 _GLOBAL_OFFSET_TABLE_
    43: 0000000000000a90     2 FUNC    GLOBAL DEFAULT   14 __libc_csu_fini
    44: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@@GLIBC_2.2.5
    45: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
    46: 0000000000201050     8 OBJECT  GLOBAL DEFAULT   24 stdout@@GLIBC_2.2.5
    47: 0000000000201000     0 NOTYPE  WEAK   DEFAULT   23 data_start
    48: 0000000000201020    34 OBJECT  GLOBAL DEFAULT   23 encrypted
    49: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
    50: 0000000000201049     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    51: 0000000000201042     7 OBJECT  GLOBAL DEFAULT   23 key
    52: 0000000000000a94     0 FUNC    GLOBAL DEFAULT   15 _fini
    53: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@@GLIBC_2.2.5
    54: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@@GLIBC_2.2.5
    55: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
    56: 0000000000201000     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
    57: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    58: 0000000000201008     0 OBJECT  GLOBAL HIDDEN    23 __dso_handle
    59: 0000000000000aa0     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
    60: 0000000000000a20   101 FUNC    GLOBAL DEFAULT   14 __libc_csu_init
    61: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fflush@@GLIBC_2.2.5
    62: 0000000000201060     0 NOTYPE  GLOBAL DEFAULT   24 _end
    63: 0000000000000740    43 FUNC    GLOBAL DEFAULT   14 _start
    64: 0000000000201049     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
    65: 0000000000000887   394 FUNC    GLOBAL DEFAULT   14 main
    66: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@@GLIBC_2.2.5
    67: 0000000000201050     0 OBJECT  GLOBAL HIDDEN    23 __TMC_END__
    68: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    69: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@@[...]
    70: 0000000000000698     0 FUNC    GLOBAL DEFAULT   11 _init
    71: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND usleep@@GLIBC_2.2.5

Histogram for `.gnu.hash' bucket list length (total of 2 buckets):
 Length  Number     % of total  Coverage
      0  1          ( 50.0%)
      1  1          ( 50.0%)    100.0%

Version symbols section '.gnu.version' contains 14 entries:
 Addr: 0x00000000000004c2  Offset: 0x000004c2  Link: 5 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_2.2.5)   0 (*local*)       2 (GLIBC_2.2.5)
  004:   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   0 (*local*)    
  008:   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   0 (*local*)       2 (GLIBC_2.2.5)
  00c:   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)

Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x00000000000004e0  Offset: 0x000004e0  Link: 6 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cnt: 1
  0x0010:   Name: GLIBC_2.2.5  Flags: none  Version: 2

Displaying notes found in: .note.ABI-tag
  Owner                Data size        Description
  GNU                  0x00000010       NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 3.2.0

Displaying notes found in: .note.gnu.build-id
  Owner                Data size        Description
  GNU                  0x00000014       NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: c7a145f3a4b213cf895a735e2b26adffc044c190
```

What can we observe from the above output as reverse engineers:

- **.text** (`0x740`–`0xa92`, size `0x352`): This is all executable code; only about `0x160` bytes belong to `main`, indicating it’s a short routine.
    
- **.data** contains two named globals: `encrypted` (34 B) and `key` (7 B). Their presence strongly suggests that decryption is involved.
    
- Another key point is not just which functions are present, but which are missing. There’s no `scanf`, `read`, etc. The binary **prints** but never asks the user for input. This typically implies:
    
    - It will _decode something internally_ and display it, **or**
        
    - It will fail immediately if a runtime check (e.g., CRC, time limit) is incorrect.
        
    - It uses program parameters or environment variables.
        

The rest of this information aligns with what we discovered earlier through hardcoded strings and previously executed commands.

Since `.data` appears to be significant, we can try dumping its content using `objdump`:

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ objdump -s -j .data rebuilding | head 
```

Contents of section .data:

```hex
 201000 00000000 00000000 08102000 00000000  .......... .....
 201010 00000000 00000000 00000000 00000000  ................
 201020 29382b1e 0642055d 07023110 51085a16  )8+..B.]..1.Q.Z.
 201030 31420f33 0a550000 151e1c06 1a431359  1B.3.U.......C.Y
 201040 14006875 6d616e73 00                 ..humans.  
```

This gives us both blobs, one of which contains the word *humans*.

For now, static analysis has provided sufficient information. Let's move on to observe the behavior of the executable code.

---

## 💻 Dynamic Analysis

- Execution Behavior

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ ./rebuilding          
Preparing secret keys
Missing required argument                                                                
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ ./rebuilding hola     
Preparing secret keys
Password length is incorrect
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ ./rebuilding hola hola
Preparing secret keys
Missing required argument

```

It seems the program requires at least one parameter to alter its behavior, and this parameter appears to function as a password. Only one parameter is accepted as valid. The error message indicates that the password length is incorrect, but we can quickly determine the correct length using a simple one-liner:

A Bash one-liner that repeatedly feeds the program a string of incrementing “A”s, and stops as soon as the error message **changes**—signaling that the length is correct and the binary has moved on to the next validation check.

```bash
#!/usr/bin/env bash
for n in {1..64}; do
  ./rebuilding "$(printf 'A%.0s' $(seq 1 $n))" 2>&1 |
    grep -q 'Password length is incorrect' || { echo "Likely length → $n"; break; }
done
```

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ ./bash_trick.sh   
Likely length → 32

┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ ./rebuilding aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 
Preparing secret keys
Calculating .    
The password is incorrect
```

This tells us that brute-forcing it is realistically not feasible. Also, the length of the blob found in `.data` seems to match what appears to be the encrypted password that our input parameter is being compared against.

It’s also worth noting that the dots in the `Calculating .` string are dynamically printed at varying positions to simulate a "loading" effect.

Let’s see if we can extract any clear data by tracing it with `ltrace`:

- `ltrace`

```bash
──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ ltrace ./rebuilding aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
puts("Preparing secret keys"Preparing secret keys
)                                                                                        = 22
strlen("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"...)                                                                        = 32
printf("\rCalculating")                                                                                              = 12
putchar(46, 0x616c75636c61430d, 0, 0)                                                                                = 46
putchar(32, 46, 0, 0)                                                                                                = 32
putchar(32, 32, 0, 0)                                                                                                = 32
putchar(32, 32, 0, 0)                                                                                                = 32
putchar(32, 32, 0, 0)                                                                                                = 32
putchar(32, 32, 0, 0)                                                                                                = 32
Calculating.     )                                                                                               = 0
usleep(200000)                                                                                                       = <void>
printf("\rCalculating")                                                                                              = 12
putchar(32, 0x616c75636c61430d, 1, 1)                                                                                = 32
putchar(46, 32, 1, 1)                                                                                                = 46
putchar(32, 46, 1, 1)                                                                                                = 32
putchar(32, 32, 1, 1)                                                                                                = 32
putchar(32, 32, 1, 1)                                                                                                = 32
putchar(32, 32, 1, 1)                                                                                                = 32
Calculating .    )                                                                                               = 0
usleep(200000)                                                                                                       = <void>
printf("\rCalculating")                                                                                              = 12
putchar(32, 0x616c75636c61430d, 2, 2)                                                                                = 32
putchar(32, 32, 2, 2)                                                                                                = 32
putchar(46, 32, 2, 2)                                                                                                = 46
putchar(32, 46, 2, 2)                                                                                                = 32
putchar(32, 32, 2, 2)                                                                                                = 32
putchar(32, 32, 2, 2)                                                                                                = 32
Calculating  .   )                                                                                               = 0
usleep(200000)                                                                                                       = <void>


...etc, until


usleep(200000)                                                                                                       = <void>
puts(""
)                                                                                                             = 1
puts("The password is incorrect"The password is incorrect
)                                                                                    = 26
+++ exited (status 255) +++
```

No leaks here—`ltrace` only reveals the functions used to create the dynamic dot-printing effect.

Just to complete the analysis, let’s also run `strace` (though it’s unlikely we’ll uncover anything new).

- strace

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ strace ./rebuilding aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
execve("./rebuilding", ["./rebuilding", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], 0x7fff2224a478 /* 54 vars */) = 0
brk(NULL)                               = 0x563abb713000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7effbd862000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=99250, ...}) = 0
mmap(NULL, 99250, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7effbd849000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000\237\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2055640, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7effbd653000
mmap(0x7effbd67b000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7effbd67b000
mmap(0x7effbd7e0000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7effbd7e0000
mmap(0x7effbd836000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7effbd836000
mmap(0x7effbd83c000, 52696, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7effbd83c000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7effbd650000
arch_prctl(ARCH_SET_FS, 0x7effbd650740) = 0
set_tid_address(0x7effbd650a10)         = 34719
set_robust_list(0x7effbd650a20, 24)     = 0
rseq(0x7effbd651060, 0x20, 0, 0x53053053) = 0
mprotect(0x7effbd836000, 16384, PROT_READ) = 0
mprotect(0x563aba600000, 4096, PROT_READ) = 0
mprotect(0x7effbd897000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7effbd849000, 99250)           = 0
fstat(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0), ...}) = 0


---


getrandom("\xaf\x4b\x30\x6c\x65\x08\x2d\xe7", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x563abb713000
brk(0x563abb734000)                     = 0x563abb734000
write(1, "Preparing secret keys\n", 22Preparing secret keys
) = 22
Calculating.     )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating .    )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating  .   )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating   .  )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating    . )     = 18. ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating     .)     = 18 .", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating.     )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating .    )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating  .   )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating   .  )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating    . )     = 18. ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating     .)     = 18 .", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating.     )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating .    )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating  .   )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating   .  )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating    . )     = 18. ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating     .)     = 18 .", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating.     )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating .    )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating  .   )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating   .  )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating    . )     = 18. ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating     .)     = 18 .", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating.     )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating .    )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating  .   )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating   .  )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating    . )     = 18. ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating     .)     = 18 .", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating.     )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
Calculating .    )     = 18  ", 18
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=200000000}, NULL) = 0
write(1, "\n", 1
)                       = 1
write(1, "The password is incorrect\n", 26The password is incorrect
) = 26
exit_group(-1)                          = ?
+++ exited with 255 +++
```

That’s actually quite interesting (excluding the syscalls from the loader, our analysis begins at `getrandom`):

```bash
getrandom("\xaf\x4b\x30\x6c\x65\x08\x2d\xe7", 8, GRND_NONBLOCK) = 8
```

_Interesting!_ This suggests that the program may generate the **actual** key from fresh randomness on each run. That would explain the “Preparing secret keys” message.

During the “Calculating” animation, we observe no additional syscalls, confirming that there's no keyboard or network I/O happening during that phase.

Furthermore, the absence of any useful syscalls before: `write(1, "\n", 1)` → `write(1, "The password is incorrect\n", 26)` tells us that the password verification has already failed within userland, before any system-level mechanism is triggered.

At this point, our best path forward is to disassemble the code and analyze it directly.

- **IDA**:  
    Upon launching IDA, we are immediately presented with the `main` function, where we find hardcoded strings—confirming that this is where the core logic resides.
    

Here is the pseudocode generated by IDA (F5):

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // eax
  int v5; // [rsp+14h] [rbp-Ch]
  int i; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  if ( argc != 2 )
  {
    puts("Missing required argument");
    exit(-1);
  }
  v5 = 0;
  if ( strlen(argv[1]) == 32 )
  {
    for ( i = 0; i <= 31; ++i )
    {
      printf("\rCalculating");
      for ( j = 0; j <= 5; ++j )
      {
        if ( j == i % 6 )
          v4 = 46;
        else
          v4 = 32;
        putchar(v4);
      }
      fflush(stdout);
      v5 += ((unsigned __int8)key[i % 6] ^ encrypted[i]) == argv[1][i];
      usleep(0x30D40u);
    }
    puts(&byte_AFE);
    if ( v5 == 32 )
    {
      puts("The password is correct");
      return 0;
    }
    else
    {
      puts("The password is incorrect");
      return -1;
    }
  }
  else
  {
    puts("Password length is incorrect");
    return -1;
  }
}
```

It’s easy to read and confirms our earlier findings. The crucial operations take place inside the `for` loops.

```C
v5 += ((unsigned __int8)key[i % 6] ^ encrypted[i]) == argv[1][i];
puts(&byte_AFE);
if ( v5 == 32 )
{
    puts("The password is correct");
    return 0;
}
```

This is the logic responsible for checking our password against the hardcoded encrypted blob. As we can see, the encrypted blob is decrypted (or encrypted) using an XOR operation with the `key` blob.

We have two approaches:

1. **Dynamic analysis** – set a breakpoint at the XOR decryption loop and read each resulting byte:

![[Pasted image 20250803190659.png]]

I set a breakpoint at the XOR instruction and ran IDA (with `argv[1]` set to something like `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`). By stepping through and reading the value stored in `esi` after each XOR, I extracted the following hex:

```hex
4854427B683164316E675F63306433735F316E5F63306E737472756374307235
```

Which converts to:

`HTB{h1d1ng_c0d3s_1n_c0nstruct0r5`

This method works but is quite slow, as it requires manual stepping for the entire key length. So let's proceed with the second approach:

2. Write a Python script to decrypt the encrypted blob.

```python
"""
rebuilding-decrypt.py
Reverse-engineering helper – recovers the plaintext checked in `main()`
from the two blobs sitting in the ELF’s .data section.
"""

# ──> Copy/paste from `objdump -s -j .data rebuilding`  (32 bytes)
enc_hex = """
29 38 2b 1e 06 42 05 5d 07 02 31 10 51 08 5a 16
31 42 0f 33 0a 55 00 00 15 1e 1c 06 1a 43 13 59
""".strip().replace("\n", " ")

encrypted = bytes.fromhex(enc_hex)

# ──> Value taken from the `key` symbol (length-6, *without* the NUL)
key = b"humans"

assert len(encrypted) == 32 and len(key) == 6, "size mismatch – double-check .data"

# XOR decrypt ────────────────────────────────────────────────────────────────
plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))

# Show result (UTF-8 decodable, but if you’d rather keep the flag out of the
# write-up, comment the next line and print `plaintext.hex()` instead).
print(plaintext.decode())      # → HTB{…}
```

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ python3 decryptor.py      
AMFh1m(jc_c9}7w_1gFg4ns}kqgt0{,
```

Interestingly, the decryption code above doesn't work. Upon investigation (and confirmation via AI analysis), it turns out:

**The program mutates the `.data` section _before_ `main()` is called.**

Referring back to the `readelf` output:

```bash
[19] .init_array       0x200d80  size 0x10   ← two constructor pointers
```

GCC/Clang place user-defined global constructor functions into this array. Everything in `.init_array` is executed **after** the loader maps `.data` but **before** `main()` runs.

To inspect the global constructor, open IDA and navigate to:

**View ▸ Open subviews ▸ Segments**

Then locate the segment with type **`INIT_ARRAY`** and double-click it.

![[Pasted image 20250803195122.png]]

We spot a new function, `sub_84A`. Let’s follow it to see what it does.
![[Pasted image 20250803195156.png]]

As we can see, this constructor indeed modifies the `key` at runtime—changing it from `humans` to `aliens`.

In fact, if we set a breakpoint at the first instruction of `main` and inspect the `key` value at runtime, we find it has been updated to `aliens`.

![[Pasted image 20250803194806.png]]

Let's update our Python script to use the correct key (`aliens`) and re-run the decryption.

```python
"""
rebuilding-decrypt.py
Reverse-engineering helper – recovers the plaintext checked in `main()`
from the two blobs sitting in the ELF’s .data section.
"""

# ──> Copy/paste from `objdump -s -j .data rebuilding`  (32 bytes)
enc_hex = """
29 38 2b 1e 06 42 05 5d 07 02 31 10 51 08 5a 16
31 42 0f 33 0a 55 00 00 15 1e 1c 06 1a 43 13 59
""".strip().replace("\n", " ")

encrypted = bytes.fromhex(enc_hex)

# ──> Value taken from the `key` symbol (length-6, *without* the NUL)
key = b"aliens"

assert len(encrypted) == 32 and len(key) == 6, "size mismatch – double-check .data"

# XOR decrypt ────────────────────────────────────────────────────────────────
plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))

# Show result (UTF-8 decodable, but if you’d rather keep the flag out of the
# write-up, comment the next line and print `plaintext.hex()` instead).
print(plaintext.decode())      # → HTB{…}
```

```bash
┌──(kali㉿kali)-[~/Downloads/rev_rebuilding]
└─$ python3 decryptor.py      
HTB{h1d1ng_c0d3s_1n_c0nstruct0r5
```


---
## ✅ Challenges Encountered / Lessons Learned

This challenge was deceptively simple at first glance but revealed several important reverse engineering concepts:

- **Global Constructors in ELF**: One of the most enlightening aspects was realizing that the `.init_array` section contains functions that run before `main()`. This is often overlooked by beginners and can completely change the behavior of static analysis if not accounted for.
    
- **Static vs. Runtime Data**: A key pitfall was assuming that the values in `.data` were static across execution. This led to an initial decryption script that failed until the mutation of the key from `humans` to `aliens` was discovered.
    
- **Importance of Runtime Verification**: Using `IDA` or `Ghidra` with runtime breakpoints and watching how values mutate just before `main()` gave crucial insight into the real decryption key.
    
- **Discipline in Methodology**: Although tools like `strings`, `objdump`, and `readelf` gave early clues, disciplined methodical progression—paired with runtime debugging—was what ultimately led to a successful flag recovery.

---
##  🏁 Conclusion

The challenge “Rebuilding” elegantly demonstrated the power of constructor-based obfuscation and the importance of examining the execution lifecycle of a binary beyond just `main()`. By combining:

- Static analysis (symbols, `.data`, `.init_array`)
    
- Dynamic runtime inspection (breakpoints, key mutation)
    
- Script-based automation (decryption via Python)
    

…we were able to fully reverse the XOR encryption and extract the flag:

`HTB{h1d1ng_c0d3s_1n_c0nstruct0r5}`

Despite being marked “Easy,” the subtle mutation of the decryption key pre-`main` provided a great lesson in ELF internals and control flow nuances.

---
## 💡 Additional Notes / Reflections

- **Use All the Tools**: `ltrace` and `strace` didn’t directly reveal the flag, but confirmed that no I/O or external dependencies were involved. This helped rule out red herrings early.
    
- **Don't Skip Segment Headers**: The initial look at `.init_array` via `readelf` was the breadcrumb that unlocked the challenge. Always inspect these sections—especially in CTF binaries with static XOR encryption.

---

