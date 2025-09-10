# 🧬 Hack The Box - Reversing Challenge Write-Up:[Indefinite] – [04/09/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Indefinite
- **Challenge Description:** You hold in one hand an encrypted datastream, and in the other the central core of a Golden Fang communications terminal. Countless spies have risked their lives to steal both the encrypted attack plans, and the technology used to conceal it, and bring them to you for expert analysis. To your horror, as you turn the screws on the core, its defense mechanisms spring to life, concealing and covering its workings. You have minutes to spare before the device destroys itself - can you crack the code?
- **Difficulty:** Medium
- **📦 Provided Files**:
	- File: Indefinite.zip  
	- Password: `hackthebox`
	- SHA256: `3bd0fc5fd1a0c4fe9abbfc0b22815cb135714a87f45778a4169c28a8edea6b73` 
- **📦 Extracted Files**:
tree rev_indefinite                          
rev_indefinite
├── flag.txt.enc
└── indefinite

---

## ⚙️ Environment Setup
- **Operating System:** `Kali Linux`
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `hexdump`, `base64`, `upx`, `readelf`, `ldd`, `objdump`
  - Dynamic: `ltrace`, `strace`, `IDA Free`

---

## 🔍 Static Analysis

#### Initial Observations
- **File**: 

```bash

└─$ file flag.txt.enc  
flag.txt.enc: data
     

└─$ file indefinite  
indefinite: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[shfilepath]=e1c467b8700dad4031ad3c0ab66153316df314db, not stripped
```

It’s a 64-bit, position-independent, dynamically linked, non-stripped ELF executable for x86-64 Linux (kernel ≥ 3.2), using /lib64/ld-linux-x86-64.so.2 as its loader.
Binary not stripped is good because we can still read the symbols: functions are already named, so the decompiler will label them without guessing.

- **ldd**: 

```bash

└─$ ldd indefinite 
        linux-vdso.so.1 (0x00007fdc1862b000)
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007fdc183e0000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fdc181ea000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fdc1862d000)
```

Binary uses the above libraries. It depends on the kernel’s vDSO, glibc (libc.so.6), and the standard 64-bit dynamic loader /lib64/ld-linux-x86-64.so.2 at runtime—no other shared libraries are required. Plus there is another library that I haven't came across often `libz.so` which is zlib (compression library). - It provides functions like:   
    - `compress()` / `uncompress()` – raw memory compression
    - `deflate()` / `inflate()` – stream-based compression/decompression
    - `gzopen()` / `gzread()` / `gzwrite()` – working with `.gz` files
Basically, it’s the go-to library for handling compressed data in C programs.

**zlib is important here because it’s likely hiding the real interesting data in a compressed form that only gets revealed when the program runs. 


- **strings**: 

```bash
└─$ strings indefinite 
/lib64/ld-linux-x86-64.so.2
aS1m
libz.so.1
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
inflateEnd
inflateInit_
inflate
libc.so.6
strcpy
exit
fopen
wait
perror
fork
__stack_chk_fail
process_vm_writev
calloc
strlen
fclose
mprotect
malloc
ptrace
fwrite
fread
__cxa_finalize
__libc_start_main
free
__xstat
GLIBC_2.15
GLIBC_2.4
GLIBC_2.2.5
A/5/
/<zM
E6HAw
w12@4
/<zM
210xt
v}Qvp
AWAVI
AUATL
[]A\A]A^A_
1.2.11
stat
Opening file
/dev/urandom
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
main.c
child.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
child
__stat
free@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
strcpy@@GLIBC_2.2.5
fread@@GLIBC_2.2.5
_edata
read_file_data
fclose@@GLIBC_2.2.5
strlen@@GLIBC_2.2.5
__stack_chk_fail@@GLIBC_2.4
do_encrypt_file
__libc_start_main@@GLIBC_2.2.5
calloc@@GLIBC_2.2.5
__data_start
do_encryption
__gmon_start__
__dso_handle
write_file_data
_IO_stdin_used
do_inflate
inflateEnd
__xstat@@GLIBC_2.2.5
advance
__libc_csu_init
malloc@@GLIBC_2.2.5
ptrace@@GLIBC_2.2.5
__bss_start
main
inflateInit_
mprotect@@GLIBC_2.2.5
fopen@@GLIBC_2.2.5
perror@@GLIBC_2.2.5
process_vm_writev@@GLIBC_2.15
exit@@GLIBC_2.2.5
fwrite@@GLIBC_2.2.5
__TMC_END__
get_filesize
_ITM_registerTMCloneTable
wait@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
fork@@GLIBC_2.2.5
tracer
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


└─$ strings flag.txt.enc 
-t~EX~2;=
```

1. I see many function names above, such as:

```functions
strcpy
exit
fopen
wait
perror
fork
__stack_chk_fail
process_vm_writev
calloc
strlen
fclose
mprotect
malloc
ptrace
fwrite
fread
free
```

Many of these can be combined to manage dynamic memory at runtime and even create new executable memory pages (e.g., `malloc`, `mprotect`). `ptrace` is also present, which can be used as an anti-debugging trick, along with a few other functions like `fork` and `process_vm_writev`.

2. Other interesting strings and their significance:
    
    - References to `/dev/urandom` → likely used for randomness or generating encryption keys.
        
    - Message: `"Opening file"` → likely corresponds to handling `flag.txt.enc`.
        
    - `inflateInit_`, `inflate`, and `inflateEnd` → the **ciphertext (`flag.txt.enc`) is probably decompressed with `zlib` before becoming readable**.

- **hexdump**: 

```bash                                                                          ┌──(cima㉿cima)-[~/Mine/Challenges/Indefinite/rev_indefinite]
└─$ hexdump flag.txt.enc 
0000000 23a8 d89b 9a6f 01e7 29c6 ea22 31ee a76d
0000010 115e f28e 96f0 7filepath9 0d99 043a 7f0c ce79
0000020 34d4 9c89 9299 d234 94a6 baff ecb1 a8da
0000030 91ed 1b88 c71c ecde 54c9 8e9a d589 d550
0000040 6c65 0db3 9a00 666c 4adb af7e 37a8 8018
0000050 60ff 420d 174b b92d 63bb bac0 c5ee e969
0000060 402a d561 6ec6 0f0e 742d 457e 7e58 3b32
0000070 c93d b2dc dbba 6494 184b e474 7bec 6b18
0000080 4805 f3aa fefe 4818 bbe7 d817 04c5 f2e8
0000090 aaa7 d31a 5fcf aaf8 839e 73de 9564 8489
00000a0 31eb 7f87 8765 d00b 1bc2 dab8 f9c4 eb03
00000b0 ef80 29db d402 eeb2 cf20 2408 1f65 26d0
00000c0 163d 5e8e d61b 6208 22f8 filepath71 1dbd f51a
00000d0 67ee 2c45 7c7f 5d22 a096 a254          
00000dc
```

- **objdump**: 

```bash
└─$ objdump -a -f indefinite 

indefinite:     formato del file elf64-x86-64
indefinite
architettura: i386:x86-64, flag 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
indirizzo di partenza 0x0000000000000b40
```

It's important that we take note of the start address shown above.

- **readelf**: 

```bash
└─$ readelf -a indefinite 
Intestazione ELF:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Classe:                            ELF64
  Dati:                              complemento a 2, little endian
  Version:                           1 (current)
  SO/ABI:                            UNIX - System V
  Versione ABI:                      0
  Tipo:                              DYN (Position-Independent Executable file)
  Macchina:                          Advanced Micro Devices X86-64
  Versione:                          0x1
  Indirizzo punto d'ingresso:        0xb40
  Inizio intestazioni di programma   64 (byte nel file)
  Inizio intestazioni di sezione:    11808 (byte nel file)
  Flag:                              0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         29
  Section header string table index: 28

Intestazioni di sezione:
  [N°] Nome              Tipo             Indirizzo         Offset
       Dimensione        DimEnt           Flag   Link  Info  Allin
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
       0000000000000288  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000000540  00000540
       0000000000000148  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           0000000000000688  00000688
       0000000000000036  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          00000000000006c0  000006c0
       0000000000000040  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000000700  00000700
       00000000000000c0  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000000007c0  000007c0
       00000000000001f8  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         00000000000009b8  000009b8
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000000009d0  000009d0
       0000000000000160  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         0000000000000b30  00000b30
       0000000000000008  0000000000000008  AX       0     0     8
  [14] .text             PROGBITS         0000000000000b40  00000b40
       0000000000000a20  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         0000000000001560  00001560
       0000000000000009  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         000000000000156c  0000156c
       000000000000002e  0000000000000000   A       0     0     4
  [17] .eh_frame_hdr     PROGBITS         000000000000159c  0000159c
       000000000000008c  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         0000000000001628  00001628
       0000000000000240  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000201d08  00001d08
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000201d10  00001d10
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .dynamic          DYNAMIC          0000000000201d18  00001d18
       0000000000000200  0000000000000010  WA       6     0     8
  [22] .got              PROGBITS         0000000000201f18  00001f18
       00000000000000e8  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000202000  00002000
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000202010  00002010
       0000000000000008  0000000000000000  WA       0     0     1
  [25] .comment          PROGBITS         0000000000000000  00002010
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00002040
       00000000000008e8  0000000000000018          27    45     8
  [27] .strtab           STRTAB           0000000000000000  00002928
       00000000000003f4  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00002d1c
       00000000000000fe  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

Non ci sono gruppi di sezioni in questo file.

Intestazioni di programma:
  Tipo           Offset             IndirVirt          IndirFis
                 DimFile            DimMem              Flag   Allin
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000001f8 0x00000000000001f8  R      0x8
  INTERP         0x0000000000000238 0x0000000000000238 0x0000000000000238
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000001868 0x0000000000001868  R E    0x200000
  LOAD           0x0000000000001d08 0x0000000000201d08 0x0000000000201d08
                 0x0000000000000308 0x0000000000000310  RW     0x200000
  DYNAMIC        0x0000000000001d18 0x0000000000201d18 0x0000000000201d18
                 0x0000000000000200 0x0000000000000200  RW     0x8
  NOTE           0x0000000000000254 0x0000000000000254 0x0000000000000254
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x000000000000159c 0x000000000000159c 0x000000000000159c
                 0x000000000000008c 0x000000000000008c  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000001d08 0x0000000000201d08 0x0000000000201d08
                 0x00000000000002f8 0x00000000000002f8  R      0x1

 Mappatura da sezione a segmento:
  Sezioni del segmento...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .dynamic .got .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07     
   08     .init_array .fini_array .dynamic .got 

Dynamic section at offset 0x1d18 contains 28 entries:
  Tag        Tipo                         Nome/Valore
 0x0000000000000001 (NEEDED)             Libreria condivisa: [libz.so.1]
 0x0000000000000001 (NEEDED)             Libreria condivisa: [libc.so.6]
 0x000000000000000c (INIT)               0x9b8
 0x000000000000000d (FINI)               0x1560
 0x0000000000000019 (INIT_ARRAY)         0x201d08
 0x000000000000001b (INIT_ARRAYSZ)       8 (byte)
 0x000000000000001a (FINI_ARRAY)         0x201d10
 0x000000000000001c (FINI_ARRAYSZ)       8 (byte)
 0x000000006ffffef5 (GNU_HASH)           0x298
 0x0000000000000005 (STRTAB)             0x540
 0x0000000000000006 (SYMTAB)             0x2b8
 0x000000000000000a (STRSZ)              328 (byte)
 0x000000000000000b (SYMENT)             24 (byte)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x201f18
 0x0000000000000002 (PLTRELSZ)           504 (byte)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x7c0
 0x0000000000000007 (RELA)               0x700
 0x0000000000000008 (RELASZ)             192 (byte)
 0x0000000000000009 (RELAENT)            24 (byte)
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flag: NOW PIE
 0x000000006ffffffe (VERNEED)            0x6c0
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x688
 0x000000006ffffff9 (RELACOUNT)          3
 0x0000000000000000 (NULL)               0x0

La sezione di rilocazione '.rela.dyn' at offset 0x700 contains 8 entries:
  Offset          Info           Tipo           Valore sim     Nome sim + Addendo
000000201d08  000000000008 R_X86_64_RELATIVE                    c40
000000201d10  000000000008 R_X86_64_RELATIVE                    c00
000000202008  000000000008 R_X86_64_RELATIVE                    202008
000000201fd8  000200000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTM[...] + 0
000000201fe0  000900000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000201fe8  000b00000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000201ff0  001700000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_registerTMCl[...] + 0
000000201ff8  001900000006 R_X86_64_GLOB_DAT 0000000000000000 __cxa_finalize@GLIBC_2.2.5 + 0

La sezione di rilocazione '.rela.plt' at offset 0x7c0 contains 21 entries:
  Offset          Info           Tipo           Valore sim     Nome sim + Addendo
000000201f30  000100000007 R_X86_64_JUMP_SLO 0000000000000000 free@GLIBC_2.2.5 + 0
000000201f38  000300000007 R_X86_64_JUMP_SLO 0000000000000000 strcpy@GLIBC_2.2.5 + 0
000000201f40  000400000007 R_X86_64_JUMP_SLO 0000000000000000 inflate + 0
000000201f48  000500000007 R_X86_64_JUMP_SLO 0000000000000000 fread@GLIBC_2.2.5 + 0
000000201f50  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fclose@GLIBC_2.2.5 + 0
000000201f58  000700000007 R_X86_64_JUMP_SLO 0000000000000000 strlen@GLIBC_2.2.5 + 0
000000201f60  000800000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000201f68  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 calloc@GLIBC_2.2.5 + 0
000000201f70  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 inflateEnd + 0
000000201f78  000d00000007 R_X86_64_JUMP_SLO 0000000000000000 __xstat@GLIBC_2.2.5 + 0
000000201f80  000e00000007 R_X86_64_JUMP_SLO 0000000000000000 malloc@GLIBC_2.2.5 + 0
000000201f88  000f00000007 R_X86_64_JUMP_SLO 0000000000000000 ptrace@GLIBC_2.2.5 + 0
000000201f90  001000000007 R_X86_64_JUMP_SLO 0000000000000000 inflateInit_ + 0
000000201f98  001100000007 R_X86_64_JUMP_SLO 0000000000000000 mprotect@GLIBC_2.2.5 + 0
000000201fa0  001200000007 R_X86_64_JUMP_SLO 0000000000000000 fopen@GLIBC_2.2.5 + 0
000000201fa8  001300000007 R_X86_64_JUMP_SLO 0000000000000000 perror@GLIBC_2.2.5 + 0
000000201fb0  001400000007 R_X86_64_JUMP_SLO 0000000000000000 process_vm_writev@GLIBC_2.15 + 0
000000201fb8  001500000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
000000201fc0  001600000007 R_X86_64_JUMP_SLO 0000000000000000 fwrite@GLIBC_2.2.5 + 0
000000201fc8  001800000007 R_X86_64_JUMP_SLO 0000000000000000 wait@GLIBC_2.2.5 + 0
000000201fd0  001a00000007 R_X86_64_JUMP_SLO 0000000000000000 fork@GLIBC_2.2.5 + 0
No processor specific unwind information to decode

Symbol table '.dynsym' contains 27 entries:
   Num:    Valore         Dim  Tipo    Assoc  Vis      Ind Nome
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.2.5 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND inflate
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fread@GLIBC_2.2.5 (2)
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (3)
     9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    10: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    11: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND inflateEnd
    13: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    14: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    15: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    16: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND inflateInit_
    17: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fopen@GLIBC_2.2.5 (2)
    19: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    20: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND p[...]@GLIBC_2.15 (4)
    21: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.2.5 (2)
    22: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    23: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    24: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND wait@GLIBC_2.2.5 (2)
    25: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (2)
    26: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fork@GLIBC_2.2.5 (2)

Symbol table '.symtab' contains 95 entries:
   Num:    Valore         Dim  Tipo    Assoc  Vis      Ind Nome
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000238     0 SECTION LOCAL  DEFAULT    1 .interp
     2: 0000000000000254     0 SECTION LOCAL  DEFAULT    2 .note.ABI-tag
     3: 0000000000000274     0 SECTION LOCAL  DEFAULT    3 .note.gnu.build-id
     4: 0000000000000298     0 SECTION LOCAL  DEFAULT    4 .gnu.hash
     5: 00000000000002b8     0 SECTION LOCAL  DEFAULT    5 .dynsym
     6: 0000000000000540     0 SECTION LOCAL  DEFAULT    6 .dynstr
     7: 0000000000000688     0 SECTION LOCAL  DEFAULT    7 .gnu.version
     8: 00000000000006c0     0 SECTION LOCAL  DEFAULT    8 .gnu.version_r
     9: 0000000000000700     0 SECTION LOCAL  DEFAULT    9 .rela.dyn
    10: 00000000000007c0     0 SECTION LOCAL  DEFAULT   10 .rela.plt
    11: 00000000000009b8     0 SECTION LOCAL  DEFAULT   11 .init
    12: 00000000000009d0     0 SECTION LOCAL  DEFAULT   12 .plt
    13: 0000000000000b30     0 SECTION LOCAL  DEFAULT   13 .plt.got
    14: 0000000000000b40     0 SECTION LOCAL  DEFAULT   14 .text
    15: 0000000000001560     0 SECTION LOCAL  DEFAULT   15 .fini
    16: 000000000000156c     0 SECTION LOCAL  DEFAULT   16 .rodata
    17: 000000000000159c     0 SECTION LOCAL  DEFAULT   17 .eh_frame_hdr
    18: 0000000000001628     0 SECTION LOCAL  DEFAULT   18 .eh_frame
    19: 0000000000201d08     0 SECTION LOCAL  DEFAULT   19 .init_array
    20: 0000000000201d10     0 SECTION LOCAL  DEFAULT   20 .fini_array
    21: 0000000000201d18     0 SECTION LOCAL  DEFAULT   21 .dynamic
    22: 0000000000201f18     0 SECTION LOCAL  DEFAULT   22 .got
    23: 0000000000202000     0 SECTION LOCAL  DEFAULT   23 .data
    24: 0000000000202010     0 SECTION LOCAL  DEFAULT   24 .bss
    25: 0000000000000000     0 SECTION LOCAL  DEFAULT   25 .comment
    26: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    27: 0000000000000b70     0 FUNC    LOCAL  DEFAULT   14 deregister_tm_clones
    28: 0000000000000bb0     0 FUNC    LOCAL  DEFAULT   14 register_tm_clones
    29: 0000000000000c00     0 FUNC    LOCAL  DEFAULT   14 __do_global_dtors_aux
    30: 0000000000202010     1 OBJECT  LOCAL  DEFAULT   24 completed.7698
    31: 0000000000201d10     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtor[...]
    32: 0000000000000c40     0 FUNC    LOCAL  DEFAULT   14 frame_dummy
    33: 0000000000201d08     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_in[...]
    34: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS main.c
    35: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS child.c
    36: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    37: 0000000000001864     0 OBJECT  LOCAL  DEFAULT   18 __FRAME_END__
    38: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    39: 0000000000001550    16 FUNC    LOCAL  DEFAULT   14 stat
    40: 0000000000201d10     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_end
    41: 0000000000201d18     0 OBJECT  LOCAL  DEFAULT   21 _DYNAMIC
    42: 0000000000201d08     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_start
    43: 000000000000159c     0 NOTYPE  LOCAL  DEFAULT   17 __GNU_EH_FRAME_HDR
    44: 0000000000201f18     0 OBJECT  LOCAL  DEFAULT   22 _GLOBAL_OFFSET_TABLE_
    45: 0000000000001540     2 FUNC    GLOBAL DEFAULT   14 __libc_csu_fini
    46: 0000000000001434   143 FUNC    GLOBAL DEFAULT   14 child
    47: 0000000000001550    16 FUNC    GLOBAL HIDDEN    14 __stat
    48: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@@GLIBC_2.2.5
    49: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
    50: 0000000000202000     0 NOTYPE  WEAK   DEFAULT   23 data_start
    51: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strcpy@@GLIBC_2.2.5
    52: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND inflate
    53: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fread@@GLIBC_2.2.5
    54: 0000000000202010     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    55: 000000000000123d   122 FUNC    GLOBAL DEFAULT   14 read_file_data
    56: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fclose@@GLIBC_2.2.5
    57: 0000000000001560     0 FUNC    GLOBAL DEFAULT   15 _fini
    58: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@@GLIBC_2.2.5
    59: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail[...]
    60: 00000000000010ad   267 FUNC    GLOBAL DEFAULT   14 do_encrypt_file
    61: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
    62: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND calloc@@GLIBC_2.2.5
    63: 0000000000202000     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
    64: 00000000000013c8   108 FUNC    GLOBAL DEFAULT   14 do_encryption
    65: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    66: 0000000000202008     0 OBJECT  GLOBAL HIDDEN    23 __dso_handle
    67: 00000000000012b7   121 FUNC    GLOBAL DEFAULT   14 write_file_data
    68: 000000000000156c     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
    69: 0000000000000d08   253 FUNC    GLOBAL DEFAULT   14 do_inflate
    70: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND inflateEnd
    71: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __xstat@@GLIBC_2.2.5
    72: 0000000000001330   152 FUNC    GLOBAL DEFAULT   14 advance
    73: 00000000000014d0   101 FUNC    GLOBAL DEFAULT   14 __libc_csu_init
    74: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@@GLIBC_2.2.5
    75: 0000000000202018     0 NOTYPE  GLOBAL DEFAULT   24 _end
    76: 0000000000000b40    43 FUNC    GLOBAL DEFAULT   14 _start
    77: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND ptrace@@GLIBC_2.2.5
    78: 0000000000202010     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
    79: 0000000000000c4a   190 FUNC    GLOBAL DEFAULT   14 main
    80: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND inflateInit_
    81: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND mprotect@@GLIBC_2.2.5
    82: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fopen@@GLIBC_2.2.5
    83: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND perror@@GLIBC_2.2.5
    84: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND process_vm_write[...]
    85: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND exit@@GLIBC_2.2.5
    86: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fwrite@@GLIBC_2.2.5
    87: 0000000000202010     0 OBJECT  GLOBAL HIDDEN    23 __TMC_END__
    88: 00000000000011b8   133 FUNC    GLOBAL DEFAULT   14 get_filesize
    89: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    90: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND wait@@GLIBC_2.2.5
    91: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@@[...]
    92: 00000000000009b8     0 FUNC    GLOBAL DEFAULT   11 _init
    93: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fork@@GLIBC_2.2.5
    94: 0000000000000e05   680 FUNC    GLOBAL DEFAULT   14 tracer

Version symbols section '.gnu.version' contains 27 entries:
 Addr: 0x0000000000000688  Offset: 0x00000688  Link: 5 (.dynsym)
  000:   0 (*locale*)       2 (GLIBC_2.2.5)   0 (*locale*)       2 (GLIBC_2.2.5)
  004:   0 (*locale*)       2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
  008:   3 (GLIBC_2.4)     2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   0 (*locale*)    
  00c:   0 (*locale*)       2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
  010:   0 (*locale*)       2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)
  014:   4 (GLIBC_2.15)    2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   0 (*locale*)    
  018:   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)   2 (GLIBC_2.2.5)

Version needs section '.gnu.version_r' contains 1 entry:
 Addr: 0x00000000000006c0  Offset: 0x000006c0  Link: 6 (.dynstr)
  000000: Version: 1  File: libc.so.6  Cont: 3
  0x0010:   Name: GLIBC_2.15  Flag: nessuna  versione: 4
  0x0020:   Name: GLIBC_2.4  Flag: nessuna  versione: 3
  0x0030:   Name: GLIBC_2.2.5  Flag: nessuna  versione: 2

Displaying notes found in: .note.ABI-tag
  Proprietario         Dimensione dati  Description
  GNU                  0x00000010       NT_GNU_ABI_TAG (tag della versione ABI)
    OS: Linux, ABI: 3.2.0

Displaying notes found in: .note.gnu.build-id
  Proprietario         Dimensione dati  Description
  GNU                  0x00000014       NT_GNU_BUILD_ID (stringa di bit unica dell'ID di creazione)
    ID di creazione: e1c467b8700dad4031ad3c0ab66153316df314db
```

New insights based on the above output:

- We have named functions, such as:
    
    - `do_inflate` (0x0000000000000d08)
        
    - `do_encrypt_file`, `do_encryption`
        
    - `child`, `tracer`
        
    - `ptrace`, `process_vm_writev`, `mprotect`, `fork`, `wait`
        

Net effect: it likely **forks**, sets up a **self-tracer** as an anti-debugging measure, then **decrypts and inflates** the contents of `flag.txt.enc`.

---
## zlib library

Before moving forward we need to understand a bit better the zlib library since it is used in this challenge and software. What AI says:


The **zlib library** in Linux is a widely-used C library for **compression and decompression** of data using the **DEFLATE algorithm** (same one used in `.zip`, `.gz`, PNG images, HTTP compression, etc.).

You can use zlib for:
- **Stream compression/decompression** (large data, chunks)
- **Memory buffer compression/decompression** (small blobs)
- **Checksum calculation** (`adler32`, `crc32`)

Since in our intel we are seeing functions like inflate, we need to understand more of how this are used.
- **`deflate`** → compresses a stream of data (input → smaller output).
- **`inflate`** → decompresses a stream of data (compressed input → original output).
    
They are used with a **`z_stream` structure**, which acts as a state machine holding input, output, and compression settings.
These functions work **incrementally** (in chunks), which is why they’re used for big files like `.gz`, `.png`, `.zip`.

### Typical Workflow for Inflation (decompression):

1. Initialize stream:
```C
inflateInit(&stream);
```

2. Provide compressed input (stream.next_in, stream.avail_in).
3. Provide output buffer (stream.next_out, stream.avail_out).
4. Call inflate(&stream, Z_NO_FLUSH) in a loop until finished.
5. Cleanup with inflateEnd(&stream).

---

## 💻 Dynamic Analysis

- **Execution Behavior**: 

```bash
└─$ ./indefinite                 

└─$ ./indefinite whatever    
stat: No such file or directory

└─$ ./indefinite flag.txt.enc 
malloc(): corrupted top size
```

The output indicates that the program expects a file as its first argument. When `flag.txt.enc` is provided, we get the error:

`malloc(): corrupted top size
`
This is a glibc runtime error, typically caused by corruption of heap metadata — likely due to a **heap overflow** or **use-after-free** condition.

This suggests the program may have some sort of memory mismanagement or is handling the file content incorrectly, possibly as part of its obfuscation or anti-debugging logic.

Next step: analyze the library calls and syscalls using `ltrace` and `strace` to gain deeper insight into what's happening at runtime.

- **ltrace**: 

```bash
└─$ ltrace ./indefinite         
exit(-1 <no return ...>
+++ exited (status 255) +++


└─$ ltrace ./indefinite whatever
mprotect(0x55f75ea01000, 4096, 0x7) = 0
fork() = 81273
wait(nil
^C <no return ...>
--- SIGINT (Interruzione) ---
+++ killed by SIGINT +++


└─$ ltrace ./indefinite flag.txt.enc
mprotect(0x555a48601000, 4096, 0x7) = 0
fork() = 81410
wait(nil^C <no return ...>
--- SIGINT (Interruzione) ---
+++ killed by SIGINT +++
```

- `./indefinite` with **no args** → immediate `exit(-1)`.
    
- With **any arg** → `mprotect → fork → wait`. Under `ltrace` it **hangs** because `ltrace` itself uses **ptrace**; the program detects tracing and switches to a “stall”/anti-debug path, so the parent just `wait()`s forever.

Nothing very useful from `ltrace` as it's being detected. `strace` will likely be detected as well, but let's run it to see if we can clarify the path the code is taking.

- **strace**: 

```bash
└─$ strace ./indefinite
execve("./indefinite", ["./indefinite"], 0x7fff7737cfb0 /* 60 vars */) = 0
brk(NULL)                               = 0x557328d2f000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f42481c7000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (File o directory non esistente)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=97382, ...}) = 0
mmap(NULL, 97382, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f42481af000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libz.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=125376, ...}) = 0
mmap(NULL, 127376, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f424818f000
mmap(0x7f4248192000, 81920, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x3000) = 0x7f4248192000
mmap(0x7f42481a6000, 28672, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x17000) = 0x7f42481a6000
mmap(0x7f42481ad000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1d000) = 0x7f42481ad000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p\236\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
mmap(NULL, 2055800, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f4247f99000
mmap(0x7f4247fc1000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f4247fc1000
mmap(0x7f4248126000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f4248126000
mmap(0x7f424817c000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f424817c000
mmap(0x7f4248182000, 52856, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f4248182000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f4247f96000
arch_prctl(ARCH_SET_FS, 0x7f4247f96740) = 0
set_tid_address(0x7f4247f96filepath0)         = 83502
set_robust_list(0x7f4247f96a20, 24)     = 0
rseq(0x7f4247f96680, 0x20, 0, 0x53053053) = 0
mprotect(0x7f424817c000, 16384, PROT_READ) = 0
mprotect(0x7f42481ad000, 4096, PROT_READ) = 0
mprotect(0x55730de01000, 4096, PROT_READ) = 0
mprotect(0x7f4248203000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f42481af000, 97382)           = 0
exit_group(-1)                          = ?
+++ exited with 255 +++




└─$ strace ./indefinite whatever
execve("./indefinite", ["./indefinite", "whatever"], 0x7fff9d3ffea8 /* 60 vars */) = 0
brk(NULL)                               = 0x55dbb5432000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f055e622000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (File o directory non esistente)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=97382, ...}) = 0
mmap(NULL, 97382, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f055e60a000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libz.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=125376, ...}) = 0
mmap(NULL, 127376, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f055e5ea000
mmap(0x7f055e5ed000, 81920, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x3000) = 0x7f055e5ed000
mmap(0x7f055e601000, 28672, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x17000) = 0x7f055e601000
mmap(0x7f055e608000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1d000) = 0x7f055e608000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p\236\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
mmap(NULL, 2055800, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f055e3f4000
mmap(0x7f055e41c000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f055e41c000
mmap(0x7f055e581000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f055e581000
mmap(0x7f055e5d7000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f055e5d7000
mmap(0x7f055e5dd000, 52856, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f055e5dd000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f055e3f1000
arch_prctl(ARCH_SET_FS, 0x7f055e3f1740) = 0
set_tid_address(0x7f055e3f1filepath0)         = 83699
set_robust_list(0x7f055e3f1a20, 24)     = 0
rseq(0x7f055e3f1680, 0x20, 0, 0x53053053) = 0
mprotect(0x7f055e5d7000, 16384, PROT_READ) = 0
mprotect(0x7f055e608000, 4096, PROT_READ) = 0
mprotect(0x55dbb3801000, 4096, PROT_READ) = 0
mprotect(0x7f055e65e000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f055e60a000, 97382)           = 0


here is where it stopped if no parameter were passed.


mprotect(0x55dbb3601000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0
rt_sigprocmask(SIG_BLOCK, ~[], [], 8)   = 0
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f055e3f1filepath0) = 83700
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
wait4(-1, NULL, 0, NULL)                = 83700
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83700, si_uid=1000, si_status=SIGTRAP, si_utime=0, si_stime=0} ---
ptrace(PTRACE_CONT, 83700, NULL, 0)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83700, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 83700
ptrace(PTRACE_GETREGS, 83700, {r15=0, r14=0x7f055e660000, r13=0x7ffc8c10d3e0, r12=0, rbp=0x7ffc8c10d280, rbx=0x7ffc8c10d3c8, r11=0x297, r10=0, r9=0, r8=0x1e0, rax=0x7ffc8c10e1e8, rcx=0x55dbb5432, rdx=0xb404529fd5f65da, rsi=0, rdi=0x7ffc8c10e1e8, orig_rax=0xffffffffffffffff, rip=0x55dbb36010ad, cs=0x33, eflags=0x10202, rsp=0x7ffc8c10d248, ss=0x2b, fs_base=0x7f055e3f1740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010ad, [0x10b00c50b0f]) = 0
getrandom("\xaf\x8e\x81\x5f\xc3\x7a\xcd\xca", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55dbb5432000
brk(0x55dbb5453000)                     = 0x55dbb5453000
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010b5, [0xd1ea7ce8f50b9c78]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010bd, [0x4785f6b3a3c0c6fc]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010c5, [0x1e1bd0ce8f03e967]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010cd, [0xba3c934filepath80fb5cd]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010d5, [0xfcfcc45fc742815d]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010dd, [0xbd882b00f9a3dfff]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010e5, [0x1dd1e07d74eec400]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010ed, [0x240d7e540f2802fa]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010f5, [0x7e3dc4185007f3fc]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36010fd, [0x183b438a907ffff0]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601105, [0x1e75a7faf3a3c080]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb360110d, [0xde8f05fbe3c279d]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601115, [0x2f419c70bc60a880]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb360111d, [0xcc030b0398f92f35]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601125, [0xfe400fd75ab02686]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb360112d, [0x26108c1eec07e687]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601135, [0xd2c436b4900e52d0]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb360113d, [0x53afba062031401f]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601145, [0xf6e8f0e00deccc00]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb360114d, [0x3ee5481ce53100fd]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601155, [0x4ab00e0f29604190]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb360115d, [0xd4b0263d29102990]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601165, [0x52c1eb880fd4a807]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb360116d, [0x61e4e130c0c8c4c]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601175, [0xb08563ab00]) = 0
process_vm_writev(83700, [{iov_base="UH\211\345H\203\3540H\211}\350H\211u\340H\211U\330H\203}\340\0ubH\213E\350H"..., iov_len=267}], 1, [{iov_base=0x55dbb36010ad, iov_len=267}], 1, 0) = 267
ptrace(PTRACE_CONT, 83700, NULL, 0)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83700, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 83700
ptrace(PTRACE_GETREGS, 83700, {r15=0, r14=0x7f055e660000, r13=0x7ffc8c10d3e0, r12=0, rbp=0x7ffc8c10d240, rbx=0x7ffc8c10d3c8, r11=0, r10=0, r9=0x1, r8=0x7f055e5dbac0, rax=0x7ffc8c10e1e8, rcx=0xfffffffffffffff6, rdx=0x8, rsi=0x7ffc8c10e1e8, rdi=0x7ffc8c10e1e8, orig_rax=0xffffffffffffffff, rip=0x55dbb36011b8, cs=0x33, eflags=0x10206, rsp=0x7ffc8c10d208, ss=0x2b, fs_base=0x7f055e3f1740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011b8, [0x8500790b0f]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011c0, [0xd1ea7ce8f50b9c78]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011c8, [0xe7478303030366f8]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011d0, [0x7478a7ffffff88de]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011d8, [0xc3faef9806aa8b3]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011e0, [0xee8a004d4ef4780f]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011e8, [0x5f0b0214ec300a00]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011f0, [0xddd1ec2filepathab1ecff]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb36011f8, [0xf3a3cd79d1e3d20a]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601200, [0x3d6860666770bf8]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601208, [0xe640c9b6bd1e6225]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601210, [0x940fdffffe3fed8b]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601218, [0xd75a900fece2fffe]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601220, [0x8c3c523fa5dd1e09]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601228, [0x560beb09416c04d]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601230, [0x42ac6d000c3c9f8a]) = 0
ptrace(PTRACE_PEEKTEXT, 83700, 0x55dbb3601238, [0x6f0b0f000000000a]) = 0
process_vm_writev(83700, [{iov_base="UH\211\345H\201\354\260\0\0\0H\211\275X\377\377\377dH\213\4%(\0\0\0H\211E\3701"..., iov_len=133}], 1, [{iov_base=0x55dbb36011b8, iov_len=133}], 1, 0) = 133
ptrace(PTRACE_CONT, 83700, NULL, 0)     = 0
stat: No such file or directory
wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 255}], 0, NULL) = 83700
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=83700, si_uid=1000, si_status=255, si_utime=0, si_stime=0} ---
ptrace(PTRACE_GETREGS, 83700, 0x7ffc8c10d1a0) = -1 ESRCH (Nessun processo corrisponde)
exit_group(0)                           = ?
+++ exited with 0 +++




└─$ strace ./indefinite flag.txt.enc
execve("./indefinite", ["./indefinite", "flag.txt.enc"], 0x7ffe18fb47b8 /* 60 vars */) = 0
brk(NULL)                               = 0x55d72f58b000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1769034000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (File o directory non esistente)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=97382, ...}) = 0
mmap(NULL, 97382, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f176901c000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libz.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0644, st_size=125376, ...}) = 0
mmap(NULL, 127376, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f1768ffc000
mmap(0x7f1768fff000, 81920, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x3000) = 0x7f1768fff000
mmap(0x7f1769013000, 28672, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x17000) = 0x7f1769013000
mmap(0x7f176901a000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1d000) = 0x7f176901a000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p\236\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
mmap(NULL, 2055800, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f1768e06000
mmap(0x7f1768e2e000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f1768e2e000
mmap(0x7f1768f93000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f1768f93000
mmap(0x7f1768fe9000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f1768fe9000
mmap(0x7f1768fef000, 52856, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f1768fef000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1768e03000
arch_prctl(ARCH_SET_FS, 0x7f1768e03740) = 0
set_tid_address(0x7f1768e03filepath0)         = 83866
set_robust_list(0x7f1768e03a20, 24)     = 0
rseq(0x7f1768e03680, 0x20, 0, 0x53053053) = 0
mprotect(0x7f1768fe9000, 16384, PROT_READ) = 0
mprotect(0x7f176901a000, 4096, PROT_READ) = 0
mprotect(0x55d708401000, 4096, PROT_READ) = 0
mprotect(0x7f1769070000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f176901c000, 97382)           = 0


here is where it stopped if no parameter were passed.


mprotect(0x55d708201000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0
rt_sigprocmask(SIG_BLOCK, ~[], [], 8)   = 0
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f1768e03filepath0) = 83867
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83867, si_uid=1000, si_status=SIGTRAP, si_utime=0, si_stime=0} ---
wait4(-1, NULL, 0, NULL)                = 83867
ptrace(PTRACE_CONT, 83867, NULL, 0)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83867, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 83867
ptrace(PTRACE_GETREGS, 83867, {r15=0, r14=0x7f1769072000, r13=0x7fffc1411020, r12=0, rbp=0x7fffc1410ec0, rbx=0x7fffc1411008, r11=0x297, r10=0, r9=0, r8=0x1e0, rax=0x7fffc14131e4, rcx=0x55d72f58b, rdx=0xe5b479ec92827ad7, rsi=0, rdi=0x7fffc14131e4, orig_rax=0xffffffffffffffff, rip=0x55d7082010ad, cs=0x33, eflags=0x10202, rsp=0x7fffc1410e88, ss=0x2b, fs_base=0x7f1768e03740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010ad, [0x10b00c50b0f]) = 0
getrandom("\x63\xb7\xbf\xe8\x04\x36\xa3\x3e", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55d72f58b000
brk(0x55d72f5ac000)                     = 0x55d72f5ac000
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010b5, [0xd1ea7ce8f50b9c78]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010bd, [0x4785f6b3a3c0c6fc]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010c5, [0x1e1bd0ce8f03e967]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010cd, [0xba3c934filepath80fb5cd]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010d5, [0xfcfcc45fc742815d]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010dd, [0xbd882b00f9a3dfff]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010e5, [0x1dd1e07d74eec400]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010ed, [0x240d7e540f2802fa]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010f5, [0x7e3dc4185007f3fc]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082010fd, [0x183b438a907ffff0]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201105, [0x1e75a7faf3a3c080]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820110d, [0xde8f05fbe3c279d]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201115, [0x2f419c70bc60a880]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820111d, [0xcc030b0398f92f35]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201125, [0xfe400fd75ab02686]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820112d, [0x26108c1eec07e687]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201135, [0xd2c436b4900e52d0]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820113d, [0x53afba062031401f]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201145, [0xf6e8f0e00deccc00]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820114d, [0x3ee5481ce53100fd]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201155, [0x4ab00e0f29604190]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820115d, [0xd4b0263d29102990]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201165, [0x52c1eb880fd4a807]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820116d, [0x61e4e130c0c8c4c]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201175, [0xb08563ab00]) = 0
process_vm_writev(83867, [{iov_base="UH\211\345H\203\3540H\211}\350H\211u\340H\211U\330H\203}\340\0ubH\213E\350H"..., iov_len=267}], 1, [{iov_base=0x55d7082010ad, iov_len=267}], 1, 0) = 267
ptrace(PTRACE_CONT, 83867, NULL, 0)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83867, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 83867
ptrace(PTRACE_GETREGS, 83867, {r15=0, r14=0x7f1769072000, r13=0x7fffc1411020, r12=0, rbp=0x7fffc1410e80, rbx=0x7fffc1411008, r11=0, r10=0, r9=0x1, r8=0x7f1768fedac0, rax=0x7fffc14131e4, rcx=0xfffffffffffffff2, rdx=0xc, rsi=0x7fffc14131e4, rdi=0x7fffc14131e4, orig_rax=0xffffffffffffffff, rip=0x55d7082011b8, cs=0x33, eflags=0x10202, rsp=0x7fffc1410e48, ss=0x2b, fs_base=0x7f1768e03740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011b8, [0x8500790b0f]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011c0, [0xd1ea7ce8f50b9c78]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011c8, [0xe7478303030366f8]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011d0, [0x7478a7ffffff88de]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011d8, [0xc3faef9806aa8b3]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011e0, [0xee8a004d4ef4780f]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011e8, [0x5f0b0214ec300a00]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011f0, [0xddd1ec2filepathab1ecff]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082011f8, [0xf3a3cd79d1e3d20a]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201200, [0x3d6860666770bf8]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201208, [0xe640c9b6bd1e6225]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201210, [0x940fdffffe3fed8b]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201218, [0xd75a900fece2fffe]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201220, [0x8c3c523fa5dd1e09]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201228, [0x560beb09416c04d]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201230, [0x42ac6d000c3c9f8a]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201238, [0x6f0b0f000000000a]) = 0
process_vm_writev(83867, [{iov_base="UH\211\345H\201\354\260\0\0\0H\211\275X\377\377\377dH\213\4%(\0\0\0H\211E\3701"..., iov_len=133}], 1, [{iov_base=0x55d7082011b8, iov_len=133}], 1, 0) = 133
ptrace(PTRACE_CONT, 83867, NULL, 0)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83867, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 83867
ptrace(PTRACE_GETREGS, 83867, {r15=0, r14=0x7f1769072000, r13=0x7fffc1411020, r12=0, rbp=0x7fffc1410e80, rbx=0x7fffc1411008, r11=0xd, r10=0, r9=0x1, r8=0x7f1768fedac0, rax=0x7fffc14131e4, rcx=0xe0, rdx=0x55d72f58b4a8, rsi=0xe0, rdi=0x7fffc14131e4, orig_rax=0xffffffffffffffff, rip=0x55d70820123d, cs=0x33, eflags=0x10206, rsp=0x7fffc1410e48, ss=0x2b, fs_base=0x7f1768e03740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820123d, [0x7a006f0b0f]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201245, [0xd1ea7ce8f50b9c78]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820124d, [0x4785f6b3a3c0c6fc]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201255, [0x1e1bd0ce8f03e967]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820125d, [0x98154d7a3c2faedd]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201265, [0xf988bf8f3a3c1819]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820126d, [0x8f0feba747bffff1]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201275, [0xbd1e62a50c1fdae6]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820127d, [0xe140filepath1799401cb6]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201285, [0x41483645e081fffd]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820128d, [0x6efea06e8f0fe877]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201295, [0x323177179d1e1bd7]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820129d, [0x3501c9077fe73440]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012a5, [0x382804f640c5d903]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012ad, [0xf642f519001879]) = 0
process_vm_writev(83867, [{iov_base="UH\211\345H\203\3540H\211}\350H\211u\340H\211U\330H\213E\350H\2155 \3\0\0H"..., iov_len=122}], 1, [{iov_base=0x55d70820123d, iov_len=122}], 1, 0) = 122
ptrace(PTRACE_CONT, 83867, NULL, 0)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83867, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 83867
ptrace(PTRACE_GETREGS, 83867, {r15=0, r14=0x7f1769072000, r13=0x7fffc1411020, r12=0, rbp=0x7fffc1410e80, rbx=0x7fffc1411008, r11=0x297, r10=0, r9=0, r8=0x1e0, rax=0xe0, rcx=0x55d72f58b4a8, rdx=0xe5b479ec92827ad7, rsi=0x55d72f58b4a8, rdi=0xe0, orig_rax=0xffffffffffffffff, rip=0x55d7082013c8, cs=0x33, eflags=0x10206, rsp=0x7fffc1410e48, ss=0x2b, fs_base=0x7f1768e03740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082013c8, [0x6c00610b0f]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082013d0, [0xd1ea7ce8f50b9c78]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082013d8, [0x4785f6b3a3c346fc]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082013e0, [0x1e1bd0ce8f03e967]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082013e8, [0x536bc100307f5dc7]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082013f0, [0x5fc79d1e1bd76e8f]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082013f8, [0xc813a3dffffffdd8]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201400, [0xc1e1fb14007d0eee]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201408, [0x17dba3c19ba3c178]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201410, [0x8318794ef2050bc8]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201418, [0xe0febb34793214]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201420, [0x27076517d76b02b]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201428, [0x34ee120018793832]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201430, [0xe5894855000000cf]) = 0
process_vm_writev(83867, [{iov_base="UH\211\345H\203\354(H\211}\350H\211u\340H\211U\330H\307E\370\0\0\0\0\3535H\213"..., iov_len=108}], 1, [{iov_base=0x55d7082013c8, iov_len=108}], 1, 0) = 108
ptrace(PTRACE_CONT, 83867, NULL, 0)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83867, si_uid=1000, si_status=SIGILL, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGILL}], 0, NULL) = 83867
ptrace(PTRACE_GETREGS, 83867, {r15=0, r14=0x7f1769072000, r13=0x7fffc1411020, r12=0, rbp=0x7fffc1410e80, rbx=0x7fffc1411008, r11=0x297, r10=0, r9=0, r8=0x1e0, rax=0x55d72f58b480, rcx=0xe8, rdx=0x55d72f58b4a0, rsi=0xe8, rdi=0x55d72f58b480, orig_rax=0xffffffffffffffff, rip=0x55d7082012b7, cs=0x33, eflags=0x10202, rsp=0x7fffc1410e48, ss=0x2b, fs_base=0x7f1768e03740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012b7, [0x7900700b0f]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012bf, [0xd1ea7ce8f50b9c78]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012c7, [0x4785f6b3a3c0c6fc]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012cf, [0x1e1bd0ce8f03e967]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012d7, [0x32b74d7a3c2faedd]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012df, [0xe8f17f1e74783031]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012e7, [0x3c3fae9d1efffffb]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012ef, [0xf4798a94307f6b9a]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012f7, [0xa06dc5e6501f6da]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d7082012ff, [0x14823e2f040fffef]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201307, [0xefea06e8f0fe8774]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820130f, [0x23177179d1e1bd76]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201317, [0x33501cb053f34403]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d70820131f, [0x2013ffffdbf3fd90]) = 0
ptrace(PTRACE_PEEKTEXT, 83867, 0x55d708201327, [0x94656ac0061e4e0]) = 0
process_vm_writev(83867, [{iov_base="UH\211\345H\203\3540H\211}\350H\211u\340H\211U\330H\213E\350H\2155\265\2\0\0H"..., iov_len=121}], 1, [{iov_base=0x55d7082012b7, iov_len=121}], 1, 0) = 121
ptrace(PTRACE_CONT, 83867, NULL, 0malloc(): corrupted top size
)     = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=83867, si_uid=1000, si_status=SIGABRT, si_utime=0, si_stime=0} ---
wait4(-1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGABRT}], 0, NULL) = 83867
ptrace(PTRACE_GETREGS, 83867, {r15=0x7fffc1410b10, r14=0x7fffc1410b10, r13=0x6, r12=0x7fffc1410b10, rbp=0x1000, rbx=0x1479b, r11=0x246, r10=0x22, r9=0, r8=0x7f1769071400, rax=0, rcx=0x7f1768e9a95c, rdx=0x6, rsi=0x1479b, rdi=0x1479b, orig_rax=0xea, rip=0x7f1768e9a95c, cs=0x33, eflags=0x246, rsp=0x7fffc14109b0, ss=0x2b, fs_base=0x7f1768e03740, gs_base=0, ds=0, es=0, fs=0, gs=0}) = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

Indeed, we can observe the types of syscalls being made, and when a parameter is correctly passed, the program attempts the following:

```bash
mprotect(..., PROT_READ|PROT_WRITE|PROT_EXEC)   # make .text page RWX
clone / fork
SIGILL stops in child (software breakpoint)
ptrace(PTRACE_GETREGS/CONT)                      # parent drives child
process_vm_writev(child, local_buf → 0x...10ad)  # writes code into child
```

The parent process is **literally injecting machine code** into the child.

Also, we notice that `getrandom(..., 8)` occurs right before the code injection. This suggests that the injected code may be **different on each run** — likely randomized but semantically equivalent.

We now have a solid overview of what's potentially happening. Let’s take a look at the disassembly.

- **IDA**: 

This is what IDA shows at the entry point (note: `return_id` was later renamed to `return_pid`):

![Screenshot](Images/Pasted%20image%2020250909143617.png)

What’s interesting is that there are two unlinked blocks in the top right corner (we’ll see why later). The above code can also be viewed as pseudocode by pressing F5.

```C
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int returned_pid; // [rsp+1Ch] [rbp-4h]

  if ( argc != 2 )
    exit(-1);
  mprotect((void *)((unsigned __int64)child & 0xFFFFFFFFFFFFF000LL), 0x1000u, 7);
  returned_pid = fork();
  if ( !returned_pid )
  {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    __debugbreak();
  }
  wait(0);
  ptrace(PTRACE_CONT, returned_pid, 0, 0);
  tracer(returned_pid);
}
```

But keep in mind that the pseudocode above omits the parts visible in the top-right corner of the disassembly.

Anyway, what’s clear is that the code does the following:

1. Checks if `argc != 2`.
    
2. Changes memory protection to RWX for a specific section within the `child` function — essentially making it modifiable at runtime.
    
3. Calls `fork()`. After this call, **both the parent and child processes** continue execution from the instruction immediately following `fork()`. Note:
    
    - In the **parent process**, `fork()` returns the **PID** of the child (a positive integer).
        
    - In the **child process**, `fork()` returns **0**.
        
4. The code then checks `returned_pid` to determine whether it should behave as the child or the parent.
### Parent behavior (returned_pid != 0)

The first parent-only call executed is `wait(0);`. The `wait()` function allows a **parent process** to wait until one of its child processes terminates. In this case, `NULL` is passed as the argument, meaning the parent doesn’t care about the child’s exit status — it simply **pauses execution** until any child process exits.

Once the child returns, the parent proceeds with:

1. `ptrace(PTRACE_CONT, returned_pid, 0, 0);`  
    This call **resumes the child from a ptrace stop without delivering any signal**. The child (as we’ll see later) uses `int3` to intentionally trigger a software breakpoint and pause itself. This parent-side `ptrace` call is used to **resume the child**, acting as a synchronization mechanism.
    
2. `tracer(returned_pid);`  
    We still need to examine what the `tracer` function actually does.
### Child behavior (returned_pid = 0)

It follows the left branch shown earlier, which leads to:

1. A `ptrace(PTRACE_TRACEME, 0, 0, 0);` call — this is how a process **makes itself traceable** by its parent (essentially saying “I’m the tracee, parent will be the tracer”).
    
2. It then executes an `int3` instruction — a **software breakpoint** that triggers a `SIGTRAP`, effectively pausing the child and signaling the parent. This is what causes the `wait()` in the parent to return.
    

But this behavior is suspicious... When viewed in a non-graphical form, we observe:

![Screenshot](Images/Pasted%20image%2020250909144437.png)
Right after the `int3` trap, there's actual code that could be executed **if the `int3` is skipped or resumed** — this is the code we previously saw in the top-right corner of the disassembly. This code:

- Calls `child(argv[1])`
    
- Then jumps past the parent-side logic (shown in gray), directly to the function's exit (`return 0`)
    

So, if that path is taken — and **it will be**, thanks to the parent calling `ptrace(PTRACE_CONT, returned_pid, 0, 0)` which effectively **resumes** the child from its `SIGTRAP` state — the `child` function will be executed.

Next, we need to analyze the behavior of the `child` function.

---

At this point, we need to investigate what the `child` and `tracer` functions actually do, and why part (or all) of the `child` function has been made RWX.

If I had to guess in advance, since `tracer` is called with the `child_id`, it's likely the **parent** that injects or modifies the child process’s memory. So rather than self-modification, we’re likely seeing **remote modification** — the parent altering the child’s memory space.

Also, since the parent is the one that resumes the child’s execution after the `int3`, I’d expect more synchronization logic — calls that pause and resume the child — to ensure that the child doesn’t proceed before its memory has been patched.

But for now, these are just hypotheses.

Since the key idea is that the parent and child **wait for each other**, I’ll analyze `tracer` and `child` together, jumping between them as needed. Let's start with `tracer` — showing it in assembly is inefficient due to its size, so I’ll present it in pseudocode.

```C
void __fastcall __noreturn tracer(unsigned int returned_pid)
{
  unsigned __int16 v1; // [rsp+1Ch] [rbp-134h]
  unsigned __int16 v2; // [rsp+1Eh] [rbp-132h]
  __WAIT_STATUS stat_loc; // [rsp+20h] [rbp-130h] BYREF
  __int64 v4; // [rsp+28h] [rbp-128h]
  __int64 v5; // [rsp+30h] [rbp-120h]
  void *ptr; // [rsp+38h] [rbp-118h]
  void *v7; // [rsp+40h] [rbp-110h]
  __int64 v8; // [rsp+48h] [rbp-108h]
  struct iovec lvec; // [rsp+50h] [rbp-100h] BYREF
  iovec rvec; // [rsp+60h] [rbp-F0h] BYREF
  _QWORD v11[28]; // [rsp+70h] [rbp-E0h] BYREF

  v11[27] = __readfsqword(0x28u);
  memset(v11, 0, 0xD8u);
  while ( 1 )
  {
    wait((__WAIT_STATUS)&stat_loc);
    ptrace(PTRACE_GETREGS, returned_pid, 0, v11);
    if ( LOBYTE(stat_loc.__uptr) != 127 || BYTE1(stat_loc.__uptr) != 4 )
      break;
    v4 = v11[16];
    v5 = ptrace(PTRACE_PEEKTEXT, returned_pid, v11[16], 0);
    if ( (unsigned __int16)v5 != 2831 )
      exit(-1);
    v5 >>= 16;
    v1 = v5;
    v5 >>= 16;
    v2 = v5;
    v4 += 8;
    ptr = calloc((unsigned __int16)v5, 1u);
    v7 = calloc(v1, 1u);
    HIDWORD(stat_loc.__iptr) = 0;
    while ( SHIDWORD(stat_loc.__iptr) < v1 )
    {
      v8 = ptrace(PTRACE_PEEKTEXT, returned_pid, v4 + SHIDWORD(stat_loc.__iptr), 0);
      *(_QWORD *)((char *)v7 + SHIDWORD(stat_loc.__iptr)) = v8;
      HIDWORD(stat_loc.__iptr) += 8;
    }
    do_inflate(v7, v1, ptr, v2);
    lvec.iov_base = ptr;
    lvec.iov_len = v2;
    rvec.iov_base = (void *)v11[16];
    rvec.iov_len = v2;
    if ( process_vm_writev(returned_pid, &lvec, 1u, &rvec, 1u, 0) == -1 )
      exit(-2);
    free(ptr);
    free(v7);
    ptrace(PTRACE_CONT, returned_pid, 0, 0);
  }
  exit(0);
}
```

Your hypotheses are confirmed — there’s indeed more `ptrace`/`wait` synchronization going on between the two processes. Let’s break it down step by step:

1. **`v11[27] = __readfsqword(0x28u);`**  
    This is unusual for Linux.
    
    - On **Windows x64**, `fs:[0x28]` relates to the TEB and stack canaries.
        
    - On **Linux x64**, the **GS segment** is typically used for thread-local storage, not FS.  
        So this instruction might be a leftover from cross-platform development, obfuscation, or just garbage (depending on how `fs` is set up at runtime). It’s safe to **ignore for now**, especially if it’s not used meaningfully later.
        
2. **The retrieved address is zeroed out**  
    It clears 216 bytes starting at `v11`. This is likely stack space or a local buffer being prepared for later use.
    
3. **Enters an infinite loop**
    
4. **Calls `wait((__WAIT_STATUS)&stat_loc);`**  
    This pauses until the **child process** does something (e.g., hits a breakpoint, exits, etc.). The exit/status info will be written into `stat_loc`.
    

So, at this point, the **parent is paused** and **waiting on the child** to hit a condition. Now it's time to **jump to the child** function to analyze what it does during this phase.

![Screenshot](Images/Pasted%20image%2020250909172849.png)

The overall structure of the `child` function, along with the fact that it’s marked as **RWX**, strongly suggests that this is not the **final version** of the code that will be executed — it’s likely to be **patched at runtime** by the parent.

That said, let’s focus for now on the **currently reachable part** of the code and examine its pseudocode to understand what happens before any modification takes place.

```C
void __fastcall __noreturn child(__int64 argv_1_filepath)
{
  __int64 ptr; // [rsp+18h] [rbp-18h] BYREF
  FILE *stream; // [rsp+20h] [rbp-10h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  ptr = 0;
  stream = fopen("/dev/urandom", "r");
  fread(&ptr, 8u, 1u, stream);
  fclose(stream);
  do_encrypt_file(argv_1_filepath, 0, ptr);
}
```

Step-by-step, here’s what the `child` function currently does:

1. **Reads from `fs:[0x28]`** again — still weird under Linux, as `fs` isn’t typically used for TLS (thread-local storage) on this platform. Probably irrelevant or an artifact of cross-platform obfuscation.
    
2. Initializes a local variable `ptr` to 0.
    
3. Opens `/dev/urandom` and reads **8 bytes** into `ptr` — so `ptr` now holds a random 64-bit value.
    
4. Closes the stream.
    
5. Calls what appears to be the encryption routine, passing:
    
    - The input file path (likely the argument `argv[1]`)
        
    - A `0` (possibly a mode/flag)
        
    - The freshly read 64-bit random value (we can name it `random_int`)
        

So it seems like the `child` generates a random key or seed, then calls the **encryption routine** — `do_encrypt_file`.

Let’s move on and analyze **`do_encrypt_file`** next.

![Screenshot](Images/Pasted%20image%2020250909174211.png)

And let's also view this in text form so we can see the upcoming opcodes.

![Screenshot](Images/Pasted%20image%2020250909181700.png)

It calls `ud2`: **`ud2`** is the x86/x86-64 _undefined instruction_ that triggers an **invalid opcode** exception (#UD). On Linux, this results in a **SIGILL** signal.

This is essentially another technique to hand off control from the child to the parent: in a **traced** child, executing `ud2` will cause the parent’s `wait()` to return with a **stopped-by-SIGILL** status. If the parent then delivers the signal, it will later be notified again upon the **child’s termination** (as we’ll see below).

So now let's be back in the parent tracer and see what happens next:  
5. the parent tracer calls `ptrace(PTRACE_GETREGS, returned_pid, 0, v11);` after wait: it means the parent gets the registers at the moment when `ud2` was executed (gets the remote context) and stores them in `v11` (so let's rename `v11` as `regs`). So now basically the parent can see and potentially manipulate the remote context.  
6. after that the parent checks `if ( LOBYTE(stat_loc.__uptr) != 127 || BYTE1(stat_loc.__uptr) != 4 )` — if true it exits (checks if the remote child has exited? if so, exit). Basically, in a nutshell:

- `LOBYTE(...) == 127 (0x7F)` → child is **stopped** (ptrace stop encoding).
    
- `BYTE1(...) == 4` → stop **signal is 4**, i.e. **SIGILL**.  
    So the loop **continues only** for SIGILL stops (what `ud2` causes). Any other stop breaks out.
    

7. if the process is not finished (ud2 hit and not any other stop), the parent saves the current remote RIP register with `v4 = v11[16];` (we can rename `v4` as `remote_rip_address`)
    
8. then it reads the 4-byte value at which the remote RIP is pointing with the call: `v5 = ptrace(PTRACE_PEEKTEXT, returned_pid, v11[16], 0);`
    

- If the child is stopped on `ud2`, the low 2 bytes of `v5` will be `0x0B 0x0F` (little-endian → `0x0B0F`), which is the opcode for `ud2`. We can rename `v5` as `remote_rip_instruction`.
    

Please note that at this stage what is read from the remote child process is:

```r
0F 0B  C5 00  0B 01  00 00
^ ^    ^  ^   ^  ^   ^  ^
| |    |  |   |  |   |  |
UD2    f1 f1  f2 f2  f3 f3
```

9. Now the parent checks the value of `remote_rip_instruction`, and if it’s not equal to `0xB0F` (i.e., different from the `ud2` instruction), it exits. This seems like a second check to ensure that the actual reason for the stop was indeed `ud2` — double-checking beyond what was done earlier with `stat_loc`.

```C
    if ( (unsigned __int16)remote_rip_instruction != 0xB0F )
      exit(-1);
```

10. at this point, the parent does `remote_rip_instruction >>= 16;`, which effectively shifts the value `0x0B0F` right by 16 bits — discarding the **UD2** marker (the first two bytes). After this shift, the **low 16 bits** now contain the **next 16-bit field** starting at `RIP+2` (in this case, `0x00C5`).

11. Then the parent does `v1 = remote_rip_instruction;` — assigning the shifted value (i.e., the next instruction) to `v1` (we can rename `v1` as `next_instruction`).
    
12. Again, it performs `remote_rip_instruction >>= 16;` — shifting to the next-next instruction (`0x010B`), and
    
13. Saves this into `v2` via `v2 = remote_rip_instruction;` — we can rename `v2` as `next_next_instruction`.
    
14. At this point, the instruction `remote_rip_address += 8;` skips 8 bytes — meaning the **actual payload starts at offset `+16` from the original RIP** (2 bytes for `ud2` + 2 for `next_instruction` + 2 for `next_next_instruction` + 8 skipped).
    

Please note that if we observe the hex dump in this section:

![Screenshot](Images/Pasted%20image%2020250910110008.png)
We see that at `0x10B5`, the bytes begin with **`78 9C ...`**, which is the classic **zlib** header — so the 197-byte blob is very likely **zlib-compressed** code or data that decompresses to around 267 bytes. A similar `78 9C` signature appears again at `0x01245` after another `ud2`, confirming that this pattern repeats.

So, essentially, steps **10–13** involve the parent reading a small header following the `ud2` instruction — likely metadata for the zlib-compressed blob (e.g., compressed size, uncompressed size, etc.).  
Then in **step 14**, it sets the pointer to the start of the **actual compressed payload**.

---

What happens next:

15. The parent allocates dynamic memory using two consecutive `calloc` calls:
    
16. `ptr = calloc((unsigned __int16)remote_rip_instruction, 1u);` → this allocates space for the **decompressed** payload
    
17. `v7 = calloc(next_instruction, 1u);` → this allocates a buffer for the **compressed** data blob
    

---

16. What follows is a loop, which appears to:

```C
offset = 0;
while (offset < next_instruction) {               // while (offset < 0x00C5)
    u64 word = PTRACE_PEEKTEXT(pid, remote_rip_address + offset, 0);
    *(u64*)((u8*)v7 + offset) = word;            // write 8 bytes into v7
    offset += 8;
}
```

It’s a copy loop: this copies **197 bytes** from the child process starting at `0x10B5` into `v7`, using 8-byte chunks. So we can rename `v7` as `remote_compressed_payload`.

---

17. A call is made to the function `do_inflate()`.
    

But before continuing, it's better to rename the previously used variables for clarity, as they represent header values, not actual instructions:

- `next_instruction` → **`in_len`** (u16) = compressed length = 197
    
- `next_next_instruction` → (low 16 bits) → **`out_len`** = 267
    
- `ptr` → **`out_buf`** (size = `out_len` = 267)
    
- `v7` → **`in_buf`** (size = `in_len` = 197)
    

---

The function `do_inflate()` is responsible for decompressing the zlib data. It builds a `z_stream` structure on the stack and uses the zlib API.

A cleaner pseudocode representation would be:
```C
unsigned __int64 do_inflate(void *in_buf, int in_len, void *out_buf, int out_len)
{
    z_stream strm;                  // they alias it as QWORD v8[15] (112 bytes)
    memset(&strm, 0, sizeof strm);

    inflateInit_(&strm, "1.2.11", sizeof strm);

    strm.next_in   = in_buf;        // v8[0]
    strm.avail_in  = in_len;        // LODWORD(v8[1])
    strm.next_out  = out_buf;       // v8[3]
    strm.avail_out = out_len;       // LODWORD(v8[4])

    do {
        int rc = inflate(&strm, 0);
        if (rc == Z_STREAM_END) break;           // rc == 1
        if (rc == Z_MEM_ERROR || rc == Z_DATA_ERROR || rc == Z_NEED_DICT) {
            inflateEnd(&strm);
            exit(-5);                             // fatal
        }
    } while (!strm.avail_out);                    // effectively irrelevant here

    // returns canary xor, just SSP epilogue noise; caller ignores it
}
```

So it **inflates the zlib stream in `in_buf` (197 bytes)** into **`out_buf` (2816 bytes)**.  
The version string `"1.2.11"` and stream size `112` match a typical zlib build on x86-64.

18. After `do_inflate` returns, the parent now holds the **decompressed payload** in its memory. What follows in the `tracer` function can be represented in pseudocode as:

```C
lvec.iov_base = out_buf;                // local iovec → your tracer’s buffer
lvec.iov_len  = out_len;                // 2816 bytes

rvec.iov_base = (void *)regs[16];       // remote iovec → child’s RIP (start of stub)
rvec.iov_len  = out_len;

if (process_vm_writev(returned_pid, &lvec, 1, &rvec, 1, 0) == -1)
    exit(-2);

free(out_buf);
free(in_buf);

ptrace(PTRACE_CONT, returned_pid, 0, 0);
```

Basically:

- It sets local pointers to the output buffer and its length (the decompressed blob).
    
- It uses `process_vm_writev` to write that decompressed blob into the **remote child process’s memory**, precisely into the previously marked **RWX region**.
    
- It then frees the parent’s local copy of the decompressed blob.
    
- Finally, it resumes the child with `ptrace(PTRACE_CONT, returned_pid, 0, 0);` — this makes the child start executing the **newly written code**.
    

---

This overwrites:

- The original `ud2` marker,
    
- The 6-byte length header,
    
- And the compressed blob section that followed,
    

with the actual **decrypted machine code** — the real body of `do_encrypt_file`.

Importantly, they **don’t change RIP** — that's intentional. When `PTRACE_CONT` is called, the child resumes **at the same address**, but now it points to valid instructions instead of `ud2`. This is a classic runtime patching trick.

---

At this point, it’s confirmed that the decompressed blob contains **executable instructions**. To verify this, let's now try to **decompile the decompressed bytes**.


```bash
objdump -D -b binary -m i386:x86-64 10B5             

10B5:     formato del file binary


Disassemblamento della sezione .data:

0000000000000000 <.data>:
   0:   55                      push   %rbp
   1:   48 89 e5                mov    %rsp,%rbp
   4:   48 83 ec 30             sub    $0x30,%rsp
   8:   48 89 7d e8             mov    %rdi,-0x18(%rbp)
   c:   48 89 75 e0             mov    %rsi,-0x20(%rbp)
  10:   48 89 55 d8             mov    %rdx,-0x28(%rbp)
  14:   48 83 7d e0 00          cmpq   $0x0,-0x20(%rbp)
  19:   75 62                   jne    0x7d
  1b:   48 8b 45 e8             mov    -0x18(%rbp),%rax
  1f:   48 89 c7                mov    %rax,%rdi
  22:   e8 5c f9 ff ff          call   0xfffffffffffff983
  27:   48 83 c0 05             add    $0x5,%rax
  2b:   48 89 c7                mov    %rax,%rdi
  2e:   e8 a0 f9 ff ff          call   0xfffffffffffff9d3
  33:   48 89 45 e0             mov    %rax,-0x20(%rbp)
  37:   48 8b 55 e8             mov    -0x18(%rbp),%rdx
  3b:   48 8b 45 e0             mov    -0x20(%rbp),%rax
  3f:   48 89 d6                mov    %rdx,%rsi
  42:   48 89 c7                mov    %rax,%rdi
  45:   e8 f9 f8 ff ff          call   0xfffffffffffff943
  4a:   48 8b 45 e0             mov    -0x20(%rbp),%rax
  4e:   48 c7 c1 ff ff ff ff    mov    $0xffffffffffffffff,%rcx
  55:   48 89 c2                mov    %rax,%rdx
  58:   b8 00 00 00 00          mov    $0x0,%eax
  5d:   48 89 d7                mov    %rdx,%rdi
  60:   f2 ae                   repnz scas %es:(%rdi),%al
  62:   48 89 c8                mov    %rcx,%rax
  65:   48 f7 d0                not    %rax
  68:   48 8d 50 ff             lea    -0x1(%rax),%rdx
  6c:   48 8b 45 e0             mov    -0x20(%rbp),%rax
  70:   48 01 d0                add    %rdx,%rax
  73:   c7 00 2e 65 6e 63       movl   $0x636e652e,(%rax)
  79:   c6 40 04 00             movb   $0x0,0x4(%rax)
  7d:   48 8b 45 e8             mov    -0x18(%rbp),%rax
  81:   48 89 c7                mov    %rax,%rdi
  84:   e8 82 00 00 00          call   0x10b
  89:   48 89 45 f0             mov    %rax,-0x10(%rbp)
  8d:   48 8b 45 f0             mov    -0x10(%rbp),%rax
  91:   83 e0 07                and    $0x7,%eax
  94:   48 01 45 f0             add    %rax,-0x10(%rbp)
  98:   48 8b 45 f0             mov    -0x10(%rbp),%rax
  9c:   48 83 c0 08             add    $0x8,%rax
  a0:   48 89 c7                mov    %rax,%rdi
  a3:   e8 2b f9 ff ff          call   0xfffffffffffff9d3
  a8:   48 89 45 f8             mov    %rax,-0x8(%rbp)
  ac:   48 8b 45 f8             mov    -0x8(%rbp),%rax
  b0:   48 8b 55 d8             mov    -0x28(%rbp),%rdx
  b4:   48 89 10                mov    %rdx,(%rax)
  b7:   48 8b 45 f8             mov    -0x8(%rbp),%rax
  bb:   48 8d 50 08             lea    0x8(%rax),%rdx
  bf:   48 8b 4d f0             mov    -0x10(%rbp),%rcx
  c3:   48 8b 45 e8             mov    -0x18(%rbp),%rax
  c7:   48 89 ce                mov    %rcx,%rsi
  ca:   48 89 c7                mov    %rax,%rdi
  cd:   e8 be 00 00 00          call   0x190
  d2:   48 8b 45 f8             mov    -0x8(%rbp),%rax
  d6:   48 8d 48 08             lea    0x8(%rax),%rcx
  da:   48 8b 55 d8             mov    -0x28(%rbp),%rdx
  de:   48 8b 45 f0             mov    -0x10(%rbp),%rax
  e2:   48 89 ce                mov    %rcx,%rsi
  e5:   48 89 c7                mov    %rax,%rdi
  e8:   e8 2e 02 00 00          call   0x31b
  ed:   48 8b 45 f0             mov    -0x10(%rbp),%rax
  f1:   48 8d 48 08             lea    0x8(%rax),%rcx
  f5:   48 8b 55 f8             mov    -0x8(%rbp),%rdx
  f9:   48 8b 45 e0             mov    -0x20(%rbp),%rax
  fd:   48 89 ce                mov    %rcx,%rsi
 100:   48 89 c7                mov    %rax,%rdi
 103:   e8 02 01 00 00          call   0x20a
 108:   90                      nop
 109:   c9                      leave
 10a:   c3                      ret
```

Before moving forward, let's focus a bit more on the compressed data (since we saw there could be different sections of compressed data — due to the loop style and the fact we found at least 2 zlib signatures).

---
## Identifyng compressed (deflated) data in the binary

Most zlib streams you’ll meet begin with one of these two-byte pairs (same first byte `78`, different compression levels in the second byte):

- `78 01` – very fast / low ratio
- `78 5E` – fast
- `78 9C` – default (most common)
- `78 DA` – best compression

The most common:
- Starts with **`78 9C`** → zlib header
- Ends with **`4C 8A 06 41`** → Adler-32 of the original data (big-endian)

We can adopt a strategy to find the zlib compressed blob in the biinary:

#### Find zlib-compressed blobs in a binary

Let binwalk do the work. Let's install binwalk and necessary component first:

```bash
sudo apt-get install binwalk qpdf  # qpdf provides zlib-flate helper
```

Then run binwalk to identify zlib compressed data:

```bash
binwalk indefinite

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)
4277          0x10B5          Zlib compressed data, default compression
4544          0x11C0          Zlib compressed data, default compression
4677          0x1245          Zlib compressed data, default compression
4799          0x12BF          Zlib compressed data, default compression
5072          0x13D0          Zlib compressed data, default compression
```

As we can see, the starting address of the first compressed data is at `0x10B5`, as identified during the disassembling stage.  
Now we can run the following command to dump the compressed data:

```bash
binwalk -D 'zlib:zlib-flate -uncompress > %e' indefinite
# Extracted files will appear in _indefinite.extracted/
```

So let's `ls` inside the folder and we see:

```bash
ll
drwxrwxr-x cima cima 4.0 KB Wed Sep 10 11:40:05 2025  .
drwxr-xr-x cima cima 4.0 KB Wed Sep 10 11:40:05 2025  ..
.rw-rw-r-- cima cima 267 B  Wed Sep 10 11:40:05 2025  10B5
.rw-rw-r-- cima cima 9.2 KB Wed Sep 10 11:40:05 2025  10B5.zlib
.rw-rw-r-- cima cima 133 B  Wed Sep 10 11:40:05 2025  11C0
.rw-rw-r-- cima cima 8.9 KB Wed Sep 10 11:40:05 2025  11C0.zlib
.rw-rw-r-- cima cima 122 B  Wed Sep 10 11:40:05 2025  1245
.rw-rw-r-- cima cima 8.8 KB Wed Sep 10 11:40:05 2025  1245.zlib
.rw-rw-r-- cima cima 121 B  Wed Sep 10 11:40:05 2025  12BF
.rw-rw-r-- cima cima 8.7 KB Wed Sep 10 11:40:05 2025  12BF.zlib
.rw-rw-r-- cima cima 108 B  Wed Sep 10 11:40:05 2025  13D0
.rw-rw-r-- cima cima 8.4 KB Wed Sep 10 11:40:05 2025  13D0.zlib
```

With this in our hands, we basically have the decompressed executable parts of the code that the child was "missing". What I can do now is write these decompressed bytes back into the binary and see what its real goal is. Let's do it:

---
### Python patcher

I wrote this quick Python script that uses the dumped files obtained with Binwalk to patch a backup copy of our binary:

```python
#!/usr/bin/env python3
import os, sys, re

def is_hex_name(name):  # e.g., "10B5"
    return re.fullmatch(r'[0-9A-Fa-f]+', name) is not None

def main(bin_in, extracted_dir, bin_out):
    with open(bin_in, 'rb') as f:
        data = bytearray(f.read())

    # collect files like 10B5, 11C0, ...
    entries = []
    for name in os.listdir(extracted_dir):
        if is_hex_name(name):
            off = int(name, 16)
            path = os.path.join(extracted_dir, name)
            size = os.path.getsize(path)
            hdr = off - 8
            entries.append((hdr, off, path, size))
    # sort by header offset (just like runtime order)
    entries.sort(key=lambda t: t[0])

    for hdr_off, pay_off, path, size in entries:
        # sanity check: UD2 at header
        if data[hdr_off:hdr_off+2] != b'\x0f\x0b':
            print(f"[!] Warning: no UD2 at 0x{hdr_off:X} (found {data[hdr_off:hdr_off+2].hex()})")
        blob = open(path, 'rb').read()
        if len(blob) != size:
            raise RuntimeError("size mismatch reading " + path)
        print(f"[+] Patching {size} bytes @ 0x{hdr_off:X} from {os.path.basename(path)} (payload @ 0x{pay_off:X})")
        data[hdr_off:hdr_off+size] = blob

    with open(bin_out, 'wb') as f:
        f.write(data)
    print(f"[✓] Wrote patched binary: {bin_out}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input ELF> <extracted_dir> <output ELF>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])

```

let's use it:

```bash
python3 patch_unpacked.py ./indefinite_backup ./_indefinite.extracted ./indefinite_decompressed
[+] Patching 267 bytes @ 0x10AD from 10B5 (payload @ 0x10B5)
[+] Patching 133 bytes @ 0x11B8 from 11C0 (payload @ 0x11C0)
[+] Patching 122 bytes @ 0x123D from 1245 (payload @ 0x1245)
[+] Patching 121 bytes @ 0x12B7 from 12BF (payload @ 0x12BF)
[+] Patching 108 bytes @ 0x13C8 from 13D0 (payload @ 0x13D0)
[✓] Wrote patched binary: ./indefinite_decompressed
```

Now let's see if we’ve done things correctly: let’s reopen this new binary with IDA.

---
### IDA Analysis of unpacked binary

Let’s open IDA and load `indefinite_decompressed`. The binary loads fine, which is a good sign.  
Now, what we want to check is the `do_encrypt_file` function — in the previous (compressed) binary, it showed the `ud2` instruction; now it looks like this:

![Screenshot](Images/Pasted%20image%2020250910152008.png)

YES! Now we see clearly what the child is doing; in pseudocode it does:

```C
__int64 __fastcall do_encrypt_file(const char *argv1_filepath, char *new_filepath, __int64 random_number)
{
  size_t v3; // rax
  __int64 filesize; // rax
  char *dest; // [rsp+10h] [rbp-20h]
  __int64 enc_filesize; // [rsp+20h] [rbp-10h]
  _QWORD *enc_out_buffer; // [rsp+28h] [rbp-8h]

  dest = new_filepath;
  if ( !new_filepath )
  {
    v3 = strlen(argv1_filepath);
    dest = (char *)malloc(v3 + 5);
    strcpy(dest, argv1_filepath);
    strcat(dest, ".enc");
  }
  filesize = get_filesize(argv1_filepath);
  enc_filesize = (filesize & 7) + filesize;
  enc_out_buffer = malloc(enc_filesize + 8);
  *enc_out_buffer = random_number;
  read_file_data(argv1_filepath, enc_filesize, enc_out_buffer + 1);
  do_encryption(enc_filesize, enc_out_buffer + 1, random_number);
  return write_file_data(dest, enc_filesize + 8, enc_out_buffer);
}
```

Remember that `do_encrypt_file` had the following parameters passed:

- `argv_1_filepath`
    
- a `0` flag → now we know this determines whether to create a new file from `argv1_filepath`
    
- a `random_int64` generated number
    

At a quick glance at the function, the most important part is that it calls the function `do_encryption`. Let's follow it:

```C
unsigned __int64 __fastcall do_encryption(
        unsigned __int64 a1_enc_filesize,
        __int64 a2_enc_out_buffer,
        __int64 a3_random_number)
{
  unsigned __int64 result; // rax
  unsigned __int64 i; // [rsp+20h] [rbp-8h]

  for ( i = 0; ; i += 8LL )
  {
    result = i;
    if ( i > a1_enc_filesize )
      break;
    a3_random_number = advance(a3_random_number);
    *(_QWORD *)(a2_enc_out_buffer + i) ^= a3_random_number;
  }
  return result;
}
```

The above also call the function `advance` which is reported below:

```C
__int64 __fastcall advance(__int64 a1_random_number)
{
  __int64 v3; // [rsp+0h] [rbp-38h] BYREF
  unsigned int v4; // [rsp+10h] [rbp-28h]
  unsigned int v5; // [rsp+14h] [rbp-24h]
  unsigned int v6; // [rsp+18h] [rbp-20h]
  int v7; // [rsp+1Ch] [rbp-1Ch]
  int i; // [rsp+20h] [rbp-18h]
  int v9; // [rsp+24h] [rbp-14h]
  __int64 v10; // [rsp+28h] [rbp-10h]
  __int64 *v11; // [rsp+30h] [rbp-8h]

  v3 = a1_random_number;
  v11 = &v3;
  v4 = 8;
  v5 = 0;
  v6 = -1;
  while ( v4 > v5 )
  {
    v7 = *((unsigned __int8 *)v11 + (int)v5);
    v6 ^= v7;
    for ( i = 7; i >= 0; --i )
    {
      v9 = -(v6 & 1);
      v6 = (v6 >> 1) ^ v9 & 0xEDB88320;
    }
    ++v5;
  }
  v10 = ~v6;
  __asm { movbe   rax, [rbp+var_10] }
  return v10 | _RAX;
}
```

This is very clearly the algorithm used to encrypt the file, so we need to find a way to revert the encrypted file we have by studying this algorithm.

Before diving into the decryption process, here is a graphical schema of what the entire binary does step by step:

![Screenshot](Images/Pasted%20image%2020250910162206.png)

### Decryption process:
- Process the payload in 8-byte steps.
- For each block:

```C
state = advance(state);                 // next 64-bit keystream word
block ^= state;                         // XOR 8 bytes
```

- `advance(x)` computes **CRC-32(IEEE)** over the 8 bytes of `x` (little-endian),  
with init `0xFFFFFFFF` and final XOR `~` (exactly what the loop does with  
polynomial `0xEDB88320`). The assembly does a quirky `movbe`/OR,  
but functionally it produces a 64-bit value from that CRC.

- After encrypting, they write **seed + encrypted payload** to disk.

**To resume:**
1. The layout of the encrypted output file is:

```bash
[ 8-byte seed ][ encrypted payload of length T = S + (S mod 8) ]
```

1. The first 8 bytes are the `random_number` seed
2. The payload is the original file bytes (size `S`) padded to `enc_filesize = S + (S & 7) ` (odd padding)

**To decrypt we need:**

- Read the seed (first 8 bytes; little-endian).
- Iterate the payload in 8-byte blocks:
    - `state = advance(state)` (same as encryptor),
    - XOR that 64-bit `state` into the ciphertext block.
        
- When done, remove the weird padding:
    - You know `T = len(cipher_payload)` and `T = S + (S mod 8)`.
    - Recover `S` by trying `r ∈ {0..7}` and picking the unique `S = T − r` that satisfies `S mod 8 = r`.

---
### C decryptor

Let's write a program in C (easier to replicate what the challenge does) to decrypt the encrypted flag file:

```C
// gcc -O2 -std=c11 decrypt_indefinite.c -o decrypt_indefinite
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

static uint32_t crc32_8_le(uint64_t state_le) {
    // Bit-for-bit of the loop in advance(): CRC32(IEEE, reflected), init FFFFFFFF, poly EDB88320, final XOR
    uint32_t v6 = 0xFFFFFFFFu;
    for (int i = 0; i < 8; ++i) {
        uint8_t b = (uint8_t)(state_le & 0xFFu);
        state_le >>= 8;
        v6 ^= b;
        for (int k = 0; k < 8; ++k) {
            if (v6 & 1)
                v6 = (v6 >> 1) ^ 0xEDB88320u;
            else
                v6 >>= 1;
        }
    }
    return ~v6;
}

static uint32_t bswap32(uint32_t x) {
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8)  |
           ((x & 0x00FF0000u) >> 8)  |
           ((x & 0xFF000000u) >> 24);
}

static uint64_t advance_keystream(uint64_t state) {
    // Matches: v10 = ~v6 (low 32); movbe rax,[v10] (=> bswap64(v10)); return v10 | rax;
    // Since v10 has only low 32 bits non-zero, result = (bswap32(crc)<<32) | crc.
    uint32_t crc = crc32_8_le(state);
    uint64_t hi = (uint64_t)bswap32(crc) << 32;
    uint64_t lo = (uint64_t)crc;
    return hi | lo;
}

static size_t recover_original_size(size_t T) {
    // Solve S + (S % 8) = T
    for (size_t r = 0; r < 8; ++r) {
        size_t s = T - r;
        if ((s % 8) == r) return s;
    }
    // Should not happen
    return T;
}

static int read_all(const char *path, uint8_t **buf, size_t *len) {
    *buf = NULL; *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "fopen: %s: %s\n", path, strerror(errno)); return -1; }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { perror("ftell"); fclose(f); return -1; }
    rewind(f);
    uint8_t *p = (uint8_t*)malloc((size_t)sz);
    if (!p) { fprintf(stderr, "malloc failed\n"); fclose(f); return -1; }
    size_t n = fread(p, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { fprintf(stderr, "fread short\n"); free(p); return -1; }
    *buf = p; *len = n; return 0;
}

static int write_all(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "fopen: %s: %s\n", path, strerror(errno)); return -1; }
    size_t n = fwrite(buf, 1, len, f);
    fclose(f);
    if (n != len) { fprintf(stderr, "fwrite short\n"); return -1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s flag.txt.enc flag.txt.dec\n", argv[0]);
        return 1;
    }

    uint8_t *file = NULL; size_t file_len = 0;
    if (read_all(argv[1], &file, &file_len) != 0) return 1;
    if (file_len < 8) { fprintf(stderr, "Input too short\n"); free(file); return 1; }

    // Seed (little-endian 8 bytes)
    uint64_t seed = 0;
    for (int i = 7; i >= 0; --i) { seed = (seed << 8) | file[i]; } // little-endian decode
    const uint8_t *ct = file + 8;
    size_t T = file_len - 8;

    size_t proc = (T / 8) * 8;       // bytes encrypted by XOR
    size_t tail = T - proc;          // left untouched
    size_t S = recover_original_size(T);

    uint8_t *pt = (uint8_t*)malloc(T);
    if (!pt) { fprintf(stderr, "malloc pt failed\n"); free(file); return 1; }

    uint64_t state = seed;
    for (size_t off = 0; off < proc; off += 8) {
        state = advance_keystream(state);
        uint64_t ks = state;
        // XOR 8 bytes
        for (int b = 0; b < 8; ++b) {
            pt[off + b] = ct[off + b] ^ (uint8_t)(ks & 0xFFu);
            ks >>= 8;
        }
    }
    if (tail) {
        memcpy(pt + proc, ct + proc, tail); // untouched
    }

    // Trim to S
    if (write_all(argv[2], pt, S) != 0) {
        free(pt); free(file); return 1;
    }

    fprintf(stderr, "[+] Seed (LE): 0x%016llx\n", (unsigned long long)seed);
    fprintf(stderr, "[+] Cipher payload T=%zu | processed=%zu | tail=%zu | recovered S=%zu\n",
            T, proc, tail, S);

    free(pt);
    free(file);
    return 0;
}
```

```bash
gcc -O2 -std=c11 decrypt_indefinite.c -o decrypt_indefinite
./decrypt_indefinite flag.txt.enc flag.txt.dec
[+] Seed (LE): 0x01e79a6fd89b23a8
[+] Cipher payload T=212 | processed=208 | tail=4 | recovered S=210
```

aaand

```bash
cat flag.txt.dec
At 3730 Galactic Time, we will convene at our outpost the Phey forest, 4 miles from the Annara defense systems. Remember, the password for the bunker d
       │ oor is HTB{unp4ck1ng_th3_s3cr3t,unr4v3ll1ng_th3_c0d3}.
   2   │ !���

```

BOOM!

---
## ✅ Challenges Encountered / Lessons Learned

Throughout this challenge I faced several hurdles:

- **Anti-Debugging:** the combined use of `fork`, `ptrace`, and `wait` blocked standard tracing tools (`ltrace`, `strace`) and forced me to rely on static analysis.
    
- **Heap Corruption Errors:** running the program with the provided encrypted file caused `malloc(): corrupted top size`, which initially looked like a bug but was actually part of the obfuscation.
    
- **Custom PRNG + zlib:** identifying that the first 8 bytes of the ciphertext were the random seed, and that the rest required both XOR decryption and zlib inflation, was the key breakthrough.
    

From this I learned the importance of:

- Cross-verifying static analysis with careful dynamic checks.
    
- Recognizing common anti-debug tricks and adapting around them.
    
- Rebuilding the encryption/decryption logic in my own code rather than trying to brute-force the binary execution.

---
##  🏁 Conclusion

The _Indefinite_ challenge provided a realistic mix of reverse engineering, anti-debugging bypass, and cryptographic reconstruction. By dissecting the binary, identifying the seed usage, and replicating the PRNG + zlib workflow, I was able to fully decrypt `flag.txt.enc` and recover the HTB flag.

This challenge highlighted how a relatively small ELF binary can combine multiple layers of defense (anti-debugging, obfuscation, compression, and pseudo-random keying) to significantly slow down analysis — and how methodical reverse engineering can peel those layers away.

---
## 💡 Additional Notes / Reflections

- This challenge was a good reminder of how **compression libraries** (like zlib) are often embedded into custom schemes, making it important to distinguish between actual encryption and simple compression.
    
- The use of **`process_vm_writev`** was particularly interesting — showing how a program can self-modify or inject into its own child process memory.
    
- I also realized how important it is to **document the workflow clearly**: having a structured write-up with static/dynamic analysis and code reconstruction made the final decryption much easier to explain and replicate.

---

