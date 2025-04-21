# [Headache] – [13/05/2025]
## 🗂️ Overview
- **Objective:** Retrieve the HTB flag
- **Challenge Description:** make the flag.
- **Difficulty:** Medium
- **Target Binary/Task:**
  - **File**: `Headache.zip`  
  - **SHA256**: `5917b4f94025e745e7b87bcaa38291397984bace27f3c86490223e1098c58f90` 

---

## 🛠️ Environment Setup
- **Operating System:** [Kali Linux]
- **External Resources used:**
	- x86 Opcodes and assembly instructions reference: http://ref.x86asm.net/coder32.html
	- Usefull for fast encryption/decryption of bytes: https://md5decrypt.net/en/Xor/ 
- **Tools Used:**
  - **Static**: `File`, `Strings`, `objdump`, `readelf`, `ldd`, `ghidra`, `base64`
  - **Dynamic**: `ltrace`, `strace`, `IDA Free 9.1`
---

## 🔍 Analysis

Please note that the entire analysis is a combination of Static and Dynamic Analysis methods, rather than a sequence of static followed by dynamic. The following is the chronological order of the tools I used:

- [Static] File
- [Dynamic] First Execution Test - to check the normal behavior of the binary (only because I know is not malicious!)
- [Static] Strings
- [Static] objdump
- [Static] readelf
- [Static] ldd
- [Dynamic] ltrace
- [Dynamic] strace
- [Static] Ghidra
- [Dynamic] IDA

### 🛡️ Static Analysis
- **Filename**: `headache`
- **SHA256**: `2d4b1425ad9c8dc78eb37a3647d062b356829a876a770ecd36154f807b7d4a86`
- **File**:
```
headache: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

- **Strings**:
```
/lib64/ld-linux-x86-64.so.2
To/QE
mgUa
libc.so.6
fflush
exit
perror
puts
putchar
stdin
strdup
printf
strtok
mmap
fgets
strlen
stdout
mprotect
malloc
ptrace
close
open
sleep
__cxa_finalize
strcmp
__libc_start_main
sysconf
free
__fxstat
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
ZWZlMjhhH
NjcyZWMxH
Mjk0Y2VmH
Y2U0YjhkH
ZTAzYWFkH
YzI=
bestkeyeH
verforreH
alxd
[]A\A]A^A_
a8c0
7ea1
abe9
c112
0936
15ab
046e
`be9
c112
J9f9
1)Ta1}
3da9
90c1
        f9,
}046-
<69,
uLux
3n15
012d
6"\Rj
{=/Wx9,
n093
3d9fq
/tk0,x
0f%q
9f9d
012d
UD ,
69d9.
akk04
f9da
b112
d093
a15abe90c112d09369d9f9da9a8c046e
Initialising
Enter the key: 
Login Failed!
Login success!
open:
mmap:
mprotect:
;*3$"
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
HTB{not_so_easy_lol}
GCC: (Debian 8.3.0-19) 8.3.0
.data
.text
.shstrtab
```

Alright, it's clear the author is trying to mislead us here — we can see the hardcoded string `HTB{not_so_easy_lol}`, which is obviously a decoy and not the actual flag. I also noticed strings like "Initialising" and "Login" — that feels a bit too straightforward and suspicious to me, especially considering the challenge is rated as medium. Plus, the presence of all those random strings above suggests there's definitely some level of obfuscation going on.

In any case, I won’t treat these clear strings as guaranteed indicators of where to place a breakpoint, but they’re definitely worth keeping in mind for later. I’ve also seen function names like `printf`, `puts`, and `fgets`, though it’s unclear at this stage whether they’re reliable points to break on. Let’s just keep going for now.

- **objdump**:
```
objdump -a -f headache
headache:     file format elf64-x86-64
headache
architecture: i386:x86-64, flags 0x00000140:
DYNAMIC, D_PAGED
start address 0x0000000000001190
```

- **readelf**
```
readelf -a headache
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
  Entry point address:               0x1190
  Start of program headers:          64 (bytes into file)
  Start of section headers:          18856 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           64 (bytes)
  Number of section headers:         4
  Section header string table index: 3

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .data             PROGBITS         0000000000001000  00001000
       0000000000001695  0000000000000000  WA       0     0     4
  [ 2] .text             PROGBITS         0000000000000000  00000000
       0000000000000a60  0000000000000000  AX       0     0     4
  [ 3] .shstrtab         STRTAB           0000000000000000  00004aa8
       0000000000000017  0000000000000000           0     0     4
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
                 0x0000000000000268 0x0000000000000268  R      0x8
  INTERP         0x00000000000002a8 0x00000000000002a8 0x00000000000002a8
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000a60 0x0000000000000a60  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000001695 0x0000000000001695  R E    0x1000
  LOAD           0x0000000000003000 0x0000000000003000 0x0000000000003000
                 0x0000000000000500 0x0000000000000500  R      0x1000
  LOAD           0x0000000000003de0 0x0000000000004de0 0x0000000000004de0
                 0x0000000000000365 0x00000000000003a8  RW     0x1000
  DYNAMIC        0x0000000000003df8 0x0000000000004df8 0x0000000000004df8
                 0x00000000000001e0 0x00000000000001e0  RW     0x8
readelf: Error: no .dynamic section in the dynamic segment
  NOTE           0x00000000000002c4 0x00000000000002c4 0x00000000000002c4
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x000000000000307c 0x000000000000307c 0x000000000000307c
                 0x00000000000000e4 0x00000000000000e4  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000003de0 0x0000000000004de0 0x0000000000004de0
                 0x0000000000000220 0x0000000000000220  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     
   02     .text 
   03     .data 
   04     
   05     
   06     
   07     
   08     
   09     
   10     

Dynamic section at offset 0x3df8 contains 26 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x1000
 0x000000000000000d (FINI)               0x268c
 0x0000000000000019 (INIT_ARRAY)         0x4de0
 0x000000000000001b (INIT_ARRAYSZ)       16 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x4df0
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x308
 0x0000000000000005 (STRTAB)             0x5f0
 0x0000000000000006 (SYMTAB)             0x338
 0x000000000000000a (STRSZ)              278 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x5000
 0x0000000000000002 (PLTRELSZ)           504 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x868
 0x0000000000000007 (RELA)               0x760
 0x0000000000000008 (RELASZ)             264 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffb (FLAGS_1)            Flags: PIE
 0x000000006ffffffe (VERNEED)            0x740
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x706
 0x000000006ffffff9 (RELACOUNT)          4
 0x0000000000000000 (NULL)               0x0

There are no static relocations in this file.
To see the dynamic relocations add --use-dynamic to the command line.
No processor specific unwind information to decode

Histogram for `.gnu.hash' bucket list length (total of 3 buckets):
 Length  Number     % of total  Coverage
      0  1          ( 33.3%)
      1  1          ( 33.3%)     33.3%
      2  1          ( 33.3%)    100.0%

No version information found in this file.

Displaying notes found at file offset 0x000002c4 with length 0x00000044:
  Owner                Data size        Description
  GNU                  0x00000014       NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: e8ce73a1a7b78320a6546f2f5145d88c0d7a6d14
  GNU                  0x00000010       NT_GNU_ABI_TAG (ABI version tag)
    OS: Linux, ABI: 3.2.0

```

I’ve noticed something interesting here: although section header `[1] (.data)` is meant for writable data, the segment itself has executable permissions. That’s definitely unusual and likely a deliberate design choice for the challenge. It hints that part of the code—possibly the INIT routine—is embedded within what would typically be a data segment.

As for the entry point, keep in mind that with PIE (Position-Independent Executable) and multiple segments, execution might begin with a minimal initialization stub, usually set up by the dynamic linker, which then hands off to the actual main routine or its libc wrappers. _So the plan is to set a breakpoint at the entry point and also try to identify where the main routine kicks in, and break there too._

Based on what I’ve seen so far, the binary doesn’t appear to be packed with any known packers, and there are no RWX sections present.

Key reminder: since this binary is compiled as a Position-Independent Executable, the addresses seen in static analysis won’t match those at runtime due to ASLR—so we’ll need to account for that offset when debugging.

Also, the limited number of sections suggests that symbol information has likely been stripped.

- **ldd**:
```
ldd headache
        linux-vdso.so.1 (0x00007ffcf5b8f000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb4a8c04000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fb4a8e1b000)

```

It makes use of an external library. 

I asked ChatGPT to give me a bit more insight into these libraries since, to be honest, I’m still getting familiar with how the Linux process environment is managed. Here’s what it had to say:

- **linux-vdso.so.1**
    
    - **What it is:** A Virtual Dynamic Shared Object provided by the kernel. It contains implementations for system calls, which makes some operations (like getting the current time) faster by bypassing a context switch into the kernel.
        
    - **Reversing Impact:** This is a common presence in Linux executables and does not contain challenge-specific logic. However, it explains why some system calls might seem to be handled through a virtualized library.
        
- **libc.so.6**
    
    - **What it is:** The GNU C Library, which supplies the standard C library functions (such as I/O, string manipulation, memory allocation, etc.).
        
    - **Reversing Impact:** it mainly contains Standard Function Calls. The majority of the binary’s external function calls will be to libc. Knowing this, you can look for calls to functions like `printf`, `scanf`, `puts`, `strcmp`, or even more complex routines such as `malloc` or `system`.
            
- **/lib64/ld-linux-x86-64.so.2**
    
    - **What it is:** This is the dynamic linker/loader. It is responsible for loading and linking shared libraries when the binary starts executing.
        
    - **Reversing Impact:** The dynamic linker’s role means that the binary’s initial steps include calling the loader, which resolves symbols and sets up relocations for functions imported from libc.

Before diving into Ghidra, let’s first run a quick execution test of the binary to observe its behaviour when executed. This should give us an initial idea of what it does and how it reacts at runtime. For now, let’s switch over to some dynamic analysis—we’ll revisit Ghidra later.

- **Ghidra**:
Let’s open Ghidra, create a new project, import the `headace` binary, and launch the CodeBrowser (Dragon) for analysis.

The first task is to identify the entry point. Normally, I’d check the _Symbol Tree_ under the _Functions_ section for entries like `main`, `_start`, or `entry`. However, in this case, no functions are listed—likely because the binary was stripped of symbol information.

Luckily, from the `readelf` output, we know that the entry point relative virtual address (RVA) is `0x1190`, and since Ghidra loaded the binary at base address `0x00100000`, the actual entry point should be at address `0x00101190`.

When manually navigating to `0x00101190` in the _Listing_, this is what I see:  
_(You didn’t paste what you’re seeing—feel free to share that so I can help break it down further.)_

From here, I’d typically start analyzing the bytes manually or force Ghidra to disassemble the area if it hasn't already. You can also try creating a function at that address and observe the flow to see if it leads to libc calls, `__libc_start_main`, or something indicative of where `main` might be indirectly called. 

```
DAT_00101190 XREF[1]: 00100018(*) 
00101190 31 ?? 31h 1 
00101191 ed ?? EDh 
00101192 49 ?? 49h I 
00101193 89 ?? 89h 
00101194 d1 ?? D1h 
00101195 5e ?? 5Eh ^ 
00101196 48 ?? 48h H 
00101197 89 ?? 89h 
00101198 e2 ?? E2h 
00101199 48 ?? 48h H 
0010119a 83 ?? 83h 
0010119b e4 ?? E4h 
0010119c f0 ?? F0h 
0010119d 50 ?? 50h P 
0010119e 54 ?? 54h T 
0010119f 4c ?? 4Ch L 
001011a0 8d ?? 8Dh 
001011a1 05 ?? 05h 
001011a2 ea ?? EAh 
001011a3 0d ?? 0Dh 
001011a4 00 ?? 00h 
001011a5 00 ?? 00h 
001011a6 48 ?? 48h H 
001011a7 8d ?? 8Dh 
001011a8 0d ?? 0Dh 
001011a9 83 ?? 83h 
001011aa 0d ?? 0Dh

```

Sometimes the auto-analysis doesn’t correctly identify the entry point as a function—especially in PIE binaries or if any anti-disassembly tricks are in play. If Ghidra labels it as `DAT_00101190`, that’s a clear sign it didn’t automatically recognize the code structure there.

To fix that, we can manually force Ghidra to interpret that section as code:

- Right-click on address `0x00101190` in the _Listing_ view.
    
- Select **Disassemble**.
    

Now we’re seeing actual disassembly that looks like a proper function—great sign.

At this point, I’d suggest also right-clicking again at `0x00101190` and selecting **Create Function**. This helps Ghidra understand the control flow and allows for better cross-referencing throughout the analysis.

Once that’s done, we can start stepping through the instructions and tracing what this function is doing. If it calls into libc functions like `__libc_start_main`, it might lead us to where the real `main` is hiding.

![[Pasted image 20250413125546.png]]

Exactly—what we’re seeing at the entry point is typical of the initialization code that the dynamic linker or C runtime sets up before transferring control to the actual `main` function.

At address `0x001011b4`, we’ve got this instruction:
`CALL qword ptr [DAT_00104fe0]` 

At first glance, it might look odd because `DAT_00104fe0` resolves to `0x0`, which is clearly not a valid function address. But that makes sense in this static context—the address is meant to be resolved at runtime, probably via the PLT/GOT mechanism. The dynamic linker populates it when the binary is loaded.

But as you rightly pointed out, the real point of interest here isn’t the call target itself, but the **first argument** passed to it, which is typically the address of `main`.

If we look at the calling convention on x86_64 Linux (System V ABI), the first argument to a function call is passed in the `RDI` register. So, just before this call, we’ll likely see something like:

`MOV RDI, DAT_00101faf`
That tells us: the first argument being passed is the address stored at `DAT_00101faf`, which, by convention, should be the address of our real `main` function.

Now, if we navigate to `DAT_00101faf`, dereference it, and go to that address, we’ve likely found `main`. Rename it accordingly, then:

- Right-click the address
    
- Select **Disassemble**, if it’s not already
    
- Then **Create Function**
    

Once Ghidra accepts that block as a function, we should start seeing a clearer structure in the decompiler view, including stack variables, local logic, and calls to standard libc functions.

![[Pasted image 20250413131246.png]]
It's incomplete again, and maybe it's just too time-consuming to manually reconstruct everything in Ghidra. Honestly, it does look obfuscated.

So for now, let’s just keep note of the real `main` function’s address: `0x00101faf` (RVA: `0x1faf`, in case the base address changes in the future), and try opening the binary in IDA to set a breakpoint there.

### 🔥 Dynamic Analysis

- Execution Behavior:
```
┌──(root㉿kali)-[/home/…/Desktop/HTB/Challenges/Headache]
└─# ./headache               
Initialising.....
Enter the key: hola
Login Failed!
```

As soon as the binary is executed, it displays the word `Initialising` and prints dots, one per second. This could be a clue that something is actually being loaded, or it might just be a meaningless sleep.

I measured the duration of the "Initialising" phase, and it consistently lasts around 5 to 6 seconds on each execution. This suggests it's more likely a static sleep rather than actual resource loading, although we’ll need to confirm that later. Also, I didn’t observe any noticeable CPU spike during this phase.

- **ltrace**:
```
┌──(root㉿kali)-[/home/…/Desktop/HTB/Challenges/Headache]
└─# ltrace ./headache Couldn't find .dynsym or .dynstr in "/proc/25303/exe" 

┌──(root㉿kali)-[/home/…/Desktop/HTB/Challenges/Headache]
└─# ..... Enter the key: Login Failed!
```

The error from ltrace — “Couldn't find .dynsym or .dynstr in …/exe” — indicates that ltrace can’t locate the usual dynamic symbol and string tables it relies on to intercept library calls. This is a common issue in CTF challenges or in binaries that have been deliberately stripped or modified for obfuscation.

ltrace typically parses these sections to resolve the names of external library calls at runtime. If those sections are missing or have been stripped, ltrace is unable to map the calls to their function names.

So, what we previously observed with the `strings` command is likely correct: function calls are probably being made dynamically by resolving function addresses at runtime, rather than through static linking. But we’ll need to verify that during runtime.

Let’s now check what `strace` reveals.

- **strace**:
```
┌──(root㉿kali)-[/home/…/Desktop/HTB/Challenges/Headache]
└─# strace ./headache               
execve("./headache", ["./headache"], 0x7ffe80e96fc0 /* 31 vars */) = 0
brk(NULL)                               = 0x55662063b000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f9c77067000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=99190, ...}) = 0
mmap(NULL, 99190, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f9c7704e000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000\237\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2055640, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f9c76e58000
mmap(0x7f9c76e80000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f9c76e80000
mmap(0x7f9c76fe5000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f9c76fe5000
mmap(0x7f9c7703b000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f9c7703b000
mmap(0x7f9c77041000, 52696, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f9c77041000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f9c76e55000
arch_prctl(ARCH_SET_FS, 0x7f9c76e55740) = 0
set_tid_address(0x7f9c76e55a10)         = 29773
set_robust_list(0x7f9c76e55a20, 24)     = 0
rseq(0x7f9c76e56060, 0x20, 0, 0x53053053) = 0
mprotect(0x7f9c7703b000, 16384, PROT_READ) = 0
mprotect(0x556620371000, 4096, PROT_READ) = 0
mprotect(0x7f9c7709c000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f9c7704e000, 99190)           = 0
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
getrandom("\x88\x77\xb4\xb9\x14\x84\x88\xb1", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55662063b000
brk(0x55662065c000)                     = 0x55662065c000
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
fstat(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "Initialising", 12Initialising)            = 12
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, 0x7ffd661d6100) = 0
write(1, ".", 1.)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, 0x7ffd661d6100) = 0
write(1, ".", 1.)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, 0x7ffd661d6100) = 0
write(1, ".", 1.)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, 0x7ffd661d6100) = 0
write(1, ".", 1.)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=1, tv_nsec=0}, 0x7ffd661d6100) = 0
write(1, ".", 1.)                        = 1
write(1, "\n", 1
)                       = 1
fstat(0, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "Enter the key: ", 15Enter the key: )         = 15
read(0, hola
"hola\n", 1024)                 = 5
write(1, "Login Failed!\n", 14Login Failed!
)         = 14
exit_group(1)                           = ?
+++ exited with 1 +++

```

WWe see above some very useful system calls.

The binary writes “Initialising” and then enters a loop where it sleeps for 1 second repeatedly (using `clock_nanosleep`) while printing dots. We had already observed this behaviour during the initial execution test, and it reinforces my suspicion that nothing is actually being loaded or initialised during this stage. However, this sleep-and-wait pattern could also be used as an anti-debugging technique, so it’s worth keeping that in mind.

What’s particularly interesting in the output is the presence of repeated `ptrace` calls:
`ptrace(PTRACE_TRACEME)` returning `-1 EPERM (Operation not permitted)`.
- This is a common anti-debugging technique: the binary checks if it’s already being traced. Under normal circumstances, if nothing is tracing the process, a successful `ptrace(PTRACE_TRACEME)` call should return 0.
    
- The EPERM error suggests that the binary expects this call to fail if it detects a debugger (or some tracing tool) attached. Since ltrace and similar tools can trigger these anti-debugging checks, it’s no surprise we’re seeing unexpected behavior.
    
- It is likely that the key-checking code is conditioned on the result of these checks. If the binary detects that it’s being traced, it might either exit early or deliberately reject valid input.

**Patching the Binary:** we will most likely need to modify the `ptrace(PTRACE_TRACEME)` calls. One approach is to replace the opcode for `ptrace` with NOPs (no-operations), effectively disabling the anti-debugging mechanism and preventing it from interfering with our analysis.

The behaviour observed after the `ptrace` calls should be treated as untrusted. From the moment `ptrace` is executed and detects the presence of tools like `strace`, the binary may alter its execution flow, potentially displaying behaviour that isn’t genuine.

Before continuing with IDA and dynamic analysis at runtime, let’s first take a closer look at the binary statically in Ghidra. We’ll return to IDA afterwards.

- **IDA**:
From our static analysis with Ghidra, we saw that finding the real entry point wasn’t straightforward, but we eventually identified it as `0x1faf` (RVA). So now let’s try opening the binary with IDA.

As soon as we load the binary in IDA, we can see the same entry point we previously analysed in Ghidra.
![[Pasted image 20250413183815.png]]

First things first, let’s place a breakpoint here.

Now, looking at the code above, the instruction `LEA rdi, loc_1FAF` is used to load the address of our `main` function into the `rdi` register, which is then passed to the initialisation routine. Let’s go ahead and rename `loc_1FAF` to `main`, jump to that address, and set a breakpoint there as well.
![[Pasted image 20250413184205.png]]

Also, from the screenshot of the `main` function, we can see that it looks a bit odd and likely obfuscated—definitely not a typical `main` function structure.

With this second breakpoint in place, the next step is to identify other parts of the code that might be useful for our reversing process.

**IMPORTANT NOTE:** at this point, I made the mistake of moving too quickly and overlooking something important that we had already observed during static analysis: namely, that the `main` function appeared to be obfuscated, and that the cleartext string might have been intentionally placed as a decoy. Still, it’s worth reading through the following steps, as even mistakes were part of the overall process of solving the challenge.

Let’s apply the insights from our previous analysis:

1. Remember that the binary likely uses `ptrace()` calls as an anti-debugging mechanism. So, let's try to locate where those `ptrace` calls occur:
    
    - Go to **View → Open Subview → Imports**,
        
    - Select the `ptrace` function and double-click it.
        
    - With `ptrace` selected, go to **Jump → Jump to xref to operand...** — but nothing is found. Most likely, the names have been stripped, so no cross-references are shown and we can’t set a breakpoint directly here.
        
    
    What we need to do instead is intercept these calls dynamically. As soon as the program starts, we should locate the base address of `libc.so.6`, find the `ptrace` function within it, and set a breakpoint there during runtime.
    
2. Next, let’s set a breakpoint where the strings are used:
    
    - Open the **Strings** subview.
        
    - Focus on the `"Initialising"` string.
        
    - Click it, then go to **Jump → List cross references to**.
        
    
    This leads us to a function that uses the string, which appears to be the same one that prompts for the password — the function **sub_13C1**.
 ![[Pasted image 20250413184732.png]]
I’ll place a breakpoint there and rename this function as **password_input**.

We can also observe the loop that sleeps and prints a dot four times, then follows the left branch where the password is requested from the user.

I can see that the code uses `stdin` to capture the input key. Just out of curiosity, I checked for other references to `stdin` to see if there might be another part of the software that takes user input — but there’s nothing else. So it’s likely this is the only function that collects user input, and the function calls here don’t appear to be obfuscated (though we’ll confirm this dynamically later).

Let’s now continue inspecting this function statically — we’ll keep the name **password_input**.

![[Pasted image 20250413190834.png]]
![[Pasted image 20250413190907.png]]

I could have inspected this function in Ghidra as well, but to be honest, I prefer low-level assembly to understand the behaviour — especially at runtime.

What we see above seems to be the main logic that handles user input and checks the password.

Alright, I’ve had enough of static analysis — time to see some action. Let’s get our hands dirty and run a dynamic test in IDA.

The first breakpoint at the start (the entry point, before `main` is called) was successfully hit.

Now, remember that the first thing we need to do is set the breakpoint we couldn’t place statically — inside `libc.so.6`, specifically in the `ptrace` function (to catch any anti-debugging checks in action).  
To do that:

- Go to **Debugger → Debugger Windows → Module List**
    
- Double-click on **libc.so.6**
    
- Search for `ptrace` and set a breakpoint there
    

Next, I did a test run with the `ptrace` breakpoint **disabled** and hit **Run** — just to see if the program would reach `main` without crashing or throwing any errors.  
Interestingly, there was **no crash**, but instead of stopping at the `main` function, it went **straight to the other breakpoint** we placed in the `password_input` function.  
That’s a bit odd — maybe the program detected the debugger and redirected execution to a “fake” password-checking function?

So I stopped the debugger, re-enabled the `ptrace` breakpoint, and restarted the analysis.  
This time, at the entry point, when I hit **Run**, we **did** land on the `ptrace` breakpoint.

Now let’s check the stack trace to figure out **who called `ptrace`**.

On the call stack, I see this:
![[Pasted image 20250413195441.png]]
It was called by the `password_input_function`! So, not part of any initialisation routine — this strongly suggests it’s being used as an anti-debugging trick.

Let’s place a breakpoint at the return address in `headache` at `0x555...53E7` to check what value is returned and confirm who exactly called this.

And in fact, it was called **right at the start** of the `password_input_function`!
![[Pasted image 20250413195732.png]]
The return value in `RAX` was `-1`, which confirms that the process is being traced:  
A return value of `0xFFFFFFFFFFFFFFFF` (i.e. `-1` signed) from `ptrace` indicates that the call failed. Specifically, in the context of `ptrace(PTRACE_TRACEME)`, this failure—commonly due to `EPERM`—means the process is already being traced, such as when running under a debugger. This is a typical anti-debugging mechanism.

Notably, the return value is also stored in a local variable (which I’ve renamed as `isDebuggerPresent`). In a normal, non-debugged execution, the `ptrace` call should return `0`. So, to bypass the check safely, I’ll patch the `RAX` value to `0` before it’s written to the local variable—since we can’t be sure how that value will be used later, or whether it has a default initialisation elsewhere.

When stepping through the code, everything proceeds as expected (just like we saw in the terminal), and the program prompts for the password.  
(As a side note: during step-through, I usually rename any function calls I encounter to improve readability.)

Right after the user inputs the key in the terminal, the code checks the length of the input. If it’s not `0x14` (20 characters), it displays `"Login Faild"`, then moves to the next block.
![[Pasted image 20250416232244.png]]

After the above check is bypassed (for example, by entering a key like `12345678912345678912`), we reach the next block:
![[Pasted image 20250416232430.png]]

We can see that on the left branch, another `"Login Failed!"` is printed if a certain condition isn’t met. Looking at the preceding block, this happens only when the instruction `cmp [rbp+var_8], 13h` evaluates to less than `0x13` (which is 19 in decimal). This value is clearly used as an index — most likely into a buffer.

What’s happening here appears to be a character-by-character check of our input against a value that’s either retrieved or calculated at runtime. It looks like an XOR operation is being performed on each character of some string, and as expected, the stack is involved.

By inspecting the stack — near the location where my input string is stored — I found the string:`bestkeyeverforrealxd`

I tried submitting this as the password, but it results in `"Login Failed"`. It also doesn’t work as an HTB flag.

Additionally, I found this string on the stack:
`ZWZlMjhhNjcyZWZWMjVY2U0YjhZThkZTAzYWkzI=`

This clearly looks like a Base64-encoded string. Let’s decode it using base64 -d:
```
echo 'ZWZlMjhhNjcyZWZWMjVY2U0YjhZThkZTAzYWkzI=' | base64 -d
efe28a672efV25X�M▒�S�FS6�2
```
Tried it as both a password and an HTB flag — no luck.

Looks like the author is messing with us again :)

So, let’s go step by step. Since this is a loop that compares each character of the input with the expected one, we’ll place a breakpoint exactly where the comparison happens. That allows us to read the correct character, which is decrypted and stored in the `dl` register during each iteration.

**Important:** every time we hit this comparison, we need to force the Zero Flag (ZF) to be `1`, otherwise the loop ends and we won’t get the next character.  
To make this smoother, we can patch the conditional jump:  
Replace the `jz` (opcode `74 16`) with `jnz` (`75 16`), so the loop always continues even when the characters match.

From this, we recover the flag in hex:
`48 54 42 7B 77 30 77 5F 74 68 34 74 73 5F 63 30 30 30 6C 7D`
Which translates to:  
`HTB{w0w_th4ts_c000l}`

Tried this on HTB — and again, it’s invalid.

The author is still toying with us.

That said, after submitting `HTB{w0w_th4ts_c000l}` as the password, it does pass the first two checks (length and the char-by-char comparison).
![[Pasted image 20250416233144.png]]

BUT when I reach the new code branch and try to follow it to the end, the process is abruptly terminated by the call: `call sub_5150`.  
So, I need to understand what both calls in this block do — `call sub_5050` and `call sub_5150`. Let’s investigate them:

- The first call (`sub_5050`) is just a dynamic call to `puts`, which prints the string `"Login success!"`.
    
- The second call (`sub_5150`) — after stepping through it — is effectively a call to the `exit()` function. So the program terminates right after printing success.
    

---

**IMPORTANT NOTE:**  
Remember when I said earlier that I made a mistake?  
Well, this entire analysis of the `password_input_function` and its subsequent calls was **the mistake**. Why? Because we still haven’t found a valid HTB flag, and even though the password seems correct, the process **just exits**.

Here’s the issue: if we enter the supposed correct password `HTB{w0w_th4ts_c000l}` in a **non-debugged** environment, it’s **not accepted**. That’s a red flag — it shows that the program’s behaviour changes depending on whether it’s being debugged or not.

This strongly suggests that the code we just reversed is **not** the true logic. It’s likely **fake logic** meant to throw off reverse engineers using a debugger — another intentional red herring.

That brings us to a key realisation:  
The execution path we’ve been following is a **decoy**, and we must have missed an **additional anti-debugging trick** _before_ the call to `password_input_function`.

At this point, the right move is to go **back to the entry point** and thoroughly investigate what other anti-debug techniques might be influencing the runtime behaviour.

I have two alternatives:

1. Try to understand all the code from the start — beginning at the entry point and following the flow through `_libc_start_main`.
    
2. Detect other early anti-debugging mechanisms that have been implemented and are affecting the program’s behaviour. Since `strace` only revealed `ptrace`, I’ll focus on the second option for now — it seems faster and more promising.
    

I realised that the way I originally break-pointed `ptrace` was flawed. In fact, at runtime, if I search for the string `ptrace`, I now find a **direct syscall** being made — and that’s why it wasn’t detected using the previous method. It’s because the `ptrace` function is being invoked **directly via the `syscall` instruction**, bypassing the standard libc call!
![[Pasted image 20250417183900.png]]

That does seem odd — the `ptrace` syscall is located in the `.data` section, which normally shouldn't be executable. But it’s very possible the memory protection is modified at runtime, likely to allow execution in that region. That would definitely explain some of the obfuscation and anti-analysis tactics.

So, I’ll go ahead and place a breakpoint there.

Additionally, since `strace` showed that `mprotect` is being called — which often signals a memory protection change (potentially to enable execution of non-executable sections like `.data`) — I’ll also search for any occurrences of `"mprotect"` and set a breakpoint at the corresponding syscall.

Same approach: search for strings containing `"mprotect"`, locate where the syscall is made directly, and set the breakpoint there.

![[Pasted image 20250417185206.png]]

Remember: the above breakpoints are only valid for the current runtime session. If we restart the program, the addresses of `ptrace` and `mprotect` may change — so we’ll need to re-identify and set them each time.

Now, let’s run the program and see where execution stops:

1. First breakpoint is hit at the very beginning — our entry point.
    
2. Then, control passes to `_libc_start_main`.
    
3. Now, we hit the breakpoint inside `ptrace` — which means we’ve found an **early call** to `ptrace`, even before reaching the `password_input_function` we had previously analysed.
    
The section of code where this breakpoint was triggered is:
![[Pasted image 20250417190931.png]]

This is a **critical** part of the challenge. At a glance, we can already notice several key elements:

- There’s an XOR operation with the immediate value `0x64`.
    
- A direct syscall to `ptrace`, with the result stored in a local variable (which is later passed to the function we initially mislabelled as `libc_start_main`, but is actually the real `main` call).
    
- Some immediate values that appear to represent a string — likely built dynamically.
    
- A string that seems to be a hash.
    
- And, importantly, a call to `main` — so this block of logic runs **before** the actual main function begins execution.
    

Let’s break it down step-by-step:

1. The value in `rdx` is XOR’d with `0x64`. In our case, the XOR of `1` and `0x64` gives us `0x65`, which is the syscall number for `ptrace`.
    
2. A direct syscall is executed with `rax = 0x65`. This confirms a manual, low-level `ptrace` call — very stealthy.
    
3. The return value from the syscall is stored in a local variable.  
    → Here, I manually patch the return value (`-1`) to `0` before it’s saved — just like before — to trick the program into thinking no debugger is attached.
    
4. If we proceed further, we can see the program constructs an immediate value string on the stack. When fully built, it becomes the following Base64-encoded string:

![[Pasted image 20250417204141.png]]
If we decode the Base64 string, we get:  
`efe28a672ec1294cefce4b8de03aadc2` — which definitely looks like a hash (probably MD5 or similar).

---

4. Right after this, there's a call to a function that clearly implements Base64 decoding — let's rename it accordingly. The decoded result is saved into a local variable.
    
5. Then, a hardcoded hash string is loaded into `rdi`, and another function is called. Following into that function reveals it's a helper function that stores the hash and its length into two global variables.  
    → Let’s place **hardware breakpoints** there — if the program is saving it, that means it’ll likely need to **compare or validate** against it later.
    

---

6. Now, after this setup, there's a crucial comparison:  
    At instruction `0x555...555317`, the return value from the earlier `ptrace` syscall is compared to zero.
    

- **If it's not zero**, the code jumps to a different branch — clearly a detour used to mislead reverse engineers.
    
- **If it is zero**, execution continues along the real path.
    

Following the **jump to the "debugger detected" block**, we can clearly see it calls the function we previously reversed — the `password_input_function`. So now it's confirmed:  
👉 All of that earlier reverse engineering was done on a **decoy** function, purposefully planted by the author to throw us off.

---

7. If no debugger is detected, the real execution path begins.  
    It first prints something to stdout, and then loads `rdi` and `rsi` with two addresses:
    

- One of them is the **main** function.
    
- The other points to the `.data` section, though it’s currently undefined.
    

When I try to disassemble or interpret that `.data` section address as code, I see this:
![[Pasted image 20250417205806.png]]

We now need to understand what this function does with the pointer to the `.data` section — so let’s dive into it.

This is a **very important point**: we’re currently inside a code block that makes a call to `mprotect` — right where we previously set a breakpoint! That confirms this function is actively **modifying memory protections at runtime**, but _only_ if **no debugger** is detected.

This is a strong indicator that the function is about to **write or execute something in memory** that was previously marked non-executable — possibly **decrypting or unpacking real code** that’s been hidden or dormant until this point.

So let’s step into this function and carefully analyse what it does. We're likely looking at the real core logic being unpacked — possibly even the actual flag validation mechanism.

![[Pasted image 20250417210622.png]]
As we can see, after the `mprotect` call—which might change the protection settings of a portion of memory—the program uses this memory in the following call. Let's take a closer look at that last call:

![[Pasted image 20250417210757.png]]

`mprotect` is dynamically changing the protection of a section of memory to make it RWX—this is a clear indication of obfuscation and self-modifying code.

The loop we observed earlier is, as expected, modifying a portion of the code.

To understand exactly what's being changed, I’ll step into the execution and inspect the memory. The hardware breakpoints we previously set on the global variable (the one storing the hash and the length) are now being hit. At runtime, I noticed that `var_18` holds the memory address being manipulated—and it turns out the address being modified is `main` itself! So, the behavior of `main` is being altered at runtime. (Remember how it looked obfuscated earlier? This is where it's being decrypted.)

The decryption routine above can be translated into the following equivalent C code:

```
void decrypt_real_main_function(uint8_t *ptr_to_main_baseaddress, uint32_t size)
{
    for (uint32_t index = 0; index < size; index++) 
    {
        uint8_t  cipher   = ptr_to_main_baseaddress[index];
        uint8_t  key_byte = global_hash_string[index % global_hash_length];
        uint8_t  plain    = cipher ^ key_byte;
        ptr_to_main_baseaddress[index] = plain;   // overwrite with decoded byte
    }
}
```

To understand the program’s actual behavior, we need to allow it to modify `main` and then analyze the updated code. Alternatively, we could statically decrypt `main` using the password we found (`a15abe90c112d09369d9f9da9a8c046e`) and then examine the decrypted ELF.

In the following, I’ll proceed with the first approach and continue the dynamic reversing at runtime. However, if you prefer to do it statically, here’s the code to decrypt the `main` function and patch the binary with the decrypted version:


**Patching the Binary**
We can use Pwntools to modify the binary.
```
from pwn import *
e = ELF("./headache", checksec=False)
length = 0x2684 - 0x1faf
```

We can calculate the length by subtracting the main address from the end.
We can then XOR the data, write it back and save it to a new ELF file.

```
orig = e.read(0x1faf, length)
e.write(0x1faf, xor(orig, b"a15abe90c112d09369d9f9da9a8c046e"))
e.save("./headache.patched")
```

Just remember one important thing (which, in my opinion, the HTB walkthrough overlooked but is absolutely fundamental): if you patch the binary as shown above and try to run it again, it won’t work—it will crash. That’s because the patch only decrypts `main`, but when you execute the program, it still attempts to decrypt `main` at runtime. This effectively re-encrypts the function, leading to a crash. So, if you choose this approach, it's strictly for static analysis.

Now, let’s continue with our dynamic approach:

Here is the `main` function before decryption:
![[Pasted image 20250418154826.png]]

Main function after decryption—note that if we choose to analyze the newly decrypted routine at runtime, we must remove any breakpoints set within `main`. Leaving breakpoints inside `main` can interfere with the decryption process and result in an incorrectly decrypted function. Instead, we should set a breakpoint at the point where `main` is about to be called, but not within `main` itself.
![[Pasted image 20250420230401.png]]
![[Pasted image 20250421000508.png]]


By analyzing it step by step, just like we did with the initial `password_input_function`, we can see that at some point it compares the input length with `0x14`. Then, as before, it stores a hardcoded string in local variables: `HTB{w0w_th4ts_c000l}`. The author is clearly still having fun with this—relentlessly!

![[Pasted image 20250421000601.png]]

Anyway, a bit further along, we can see that the following string is built in a local variable (by moving immediate hex values): `SFRCe3RoMXNfMXNfdGgzX2ZsNGd9`.

![[Pasted image 20250421000642.png]]

And shortly after, the `base64_decoder` function is called—so the string above must indeed be Base64. Let's decode it:
```
echo 'SFRCe3RoMXNfMXNfdGgzX2ZsNGd9' | base64 -d            
HTB{th1s_1s_th3_fl4g}  
```

Should we trust it this time? Let's give it a try. And—of course—not working. The author’s still messing with us.

Right after that, more values are loaded into local variables using immediate values:

`29 35 23 1A 15 09 55 15 3E 16 55 12 3E 09 55 13 05 1C 00`

These bytes don't correspond to any obvious ASCII representation.

Then, a pointer to this obfuscated string is passed to a function stored in the `.data` section, which appears to be a custom routine for decrypting the string—most likely our actual flag. It looks like it's simply XORed with the value `0x61`.

So we try decrypting it by XORing each byte with `0x61`, using a site like: [https://md5decrypt.net/en/Xor/](https://md5decrypt.net/en/Xor/)  
And the result is: `HTB{th4t_w4s_h4rd}`

![[Pasted image 20250421000727.png]]

Again, can we trust this is the correct key? Let’s give it a shot. And… another error. I’m starting to get tired of playing along here, friends.

After this part of the code, it moves on and takes a conditional jump based on the result of `ptrace`—which, of course, we had patched to return `0`, so at this point we should be following the correct branch.
![[Pasted image 20250421000858.png]]

And here we are again, landing in another interesting block that’s likely constructing yet another string in local variables using hardcoded immediate values. Then comes a long, heavily obfuscated sequence of arithmetic operations—really messy stuff—that eventually ends with a `cmp`.

This is very likely where the real comparison happens, meaning this is probably the _actual_ place where our input is checked against the correct key.

![[Pasted image 20250420234526.png]]

It’s a long loop of arithmetic operations, but here’s the interesting part: in `byte ptr [rbp-19h]`—right before the final `cmp`—we can actually observe, loop after loop, each character of the FINAL (yes, _very final_) KEY being revealed!

One important note: since we haven’t provided the correct key, the comparison fails due to a length mismatch, which causes some issues. To keep things running smoothly, I patched the `JZ` to `JNZ`—and that let the execution continue without interruption.

**FINAL KEY:**
`HTB{l4yl3_w4s_h3r3!}`

---
### ⚠️ Challenges Encountered / Lessons Learned
- Lacked a bit of understanding of how Linux processes start and how memory management works—definitely something to study in more depth.
    
- Wasn’t aware of common anti-debugging techniques on Linux (e.g., `ptrace` calls).
    
- Set the wrong breakpoint for the `ptrace` call and missed an important early call via direct syscall to ptrace.
    
- Rushed through the analysis at the beginning and didn’t take the time to properly study the `start` function, which led to missing key parts of the code (where the early anti-debug ptrace call happens). Also mistakenly assumed that `password_input_function` was the function called directly at start, when in fact the call goes through `__libc_start_main`.
    
- Need to remember to save backup copies of the IDA database before patching anything at runtime!

---
### ✅ Conclusion
This was my first real challenge reversing a proper obfuscated Linux binary—and I’ve genuinely learned so much. From digging into the ELF file format and understanding how a process is spawned by the kernel, to encountering anti-debugging mechanisms like `ptrace`, and dealing with various layers of obfuscation including Base64 encoding, XORed strings, self-modifying code, and more.

---
### 💡 Additional Notes / Reflections
I need to give myself permission to slow down. When things get tough, that’s where the real learning begins. It’s okay to take time, to hit walls, and to not “get it” right away. Respecting the pace of the process is key to progressing in this field.

Keep reversing, keep digging, and keep sharing. Cheers!

---

