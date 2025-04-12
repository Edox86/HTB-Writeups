# [Debugme] – [12/05/2025]
## Overview
- **Objective:** Retrieve the HTB flag
- **Challenge Description:** A develper is experiementing with different ways to protect their software. They have sent in a windows binary that is suposed to super secureand really hard to debug. Debug and see if you can find the flag.
- **Target Binary/Task:**
  - File: `Debugme.zip`  
  - SHA256: `101a7625cae64e8d17b83443b1b8f453a5af5014ada93e9e4b1418e306d3c394` 

---

## Environment Setup
- **Operating System:** [Windows 10]
- **Tools Used:**
  - Static: `CFF Explorer`, `Ghidra`
  - Dynamic: `IDA Free`
---

## 🔍 Analysis

###  Static Analysis

#### Initial Observations
- **CFF Explorer**:
	- Portable Executable 32-bit (Intel i386)
	- Stripped Relocation Entries
	- Console application (CUI)
	- Not packed
	- *Entry Point:* 0x000010F9 (within `.text` section)
	
	- *Data Directory* contains an import table and TLS — possibly using TLS callbacks for early execution.
	
	- *Sections*: Unusual section names like `/4` suggest it may have been compiled under Linux (confirmed by hex-dump info showing `gcc` metadata).
	  ⚠️BIG WARNING: The four primary sections (`.text`, `.data`, `.rdata`, `.bss`) are all marked as **RWX** — allowing self-modifying behavior. Static analysis is mostly ineffective in this case.
	 `.CRT` section present, indicating CRT usage (confirmed by imports).
	 API calls like `strlen`, `strcmp`, `malloc`, and `calloc` suggest possible memory manipulation or decryption logic.

	- *Imports:* Only `kernel32` and `msvcrt.dll` are imported.
	-
	- *TLS:* very interesting! I don't see anything in the TLS data, but there is a TLS callback with what looks like machine opcodes. If I try to disassemble just this part (with CFF disassembler and specifying as the base address to disassemble the TLS address of the callback) in fact I see `jmp 0x0041482B` --> IT'S A TRAMPOLINE! very strange. basically as soon as a thread starts, before calling the entry point of the thread this assembly instruction (by default from windows) is executed and that jump is made. now let's see where that jump leads: `jmp 0x041c036` to another trampoline, even weirder. let's follow: another strenuous jump...., let's follow. this leads to an infinity of subsequent jmp instructions. For this I am persevering, this is too much to be statically parsed by CFF, I will check where this leads later.
	-![[./Pasted image 20250412212731.png]]
	
	- *strings:* strings of interests that could be hacked to check what kind of anti-debug system is in place: - "Looks like your doing something naughty. Stop it!!! - I heard you like bugs so I put bugs in your debugger so you can have bugs while you debug!!! Seriously though try and find the flag, you will find it in your debugger!!!"
	-
	- No resources found.

- **Ghidra**: Before moving on to dynamic analysis, let's see what we can observe with ghidra. From ghidra I was able to check how the main is called and how it is done via mainCRTStartup (obviously). As I said, the code definitely does something dynamic, so I don't even try to spend much time on ghidra. Let's move on to dynamics with IDA.


---

### Dynamic Analysis

- Execution Behavior:
```
C:\Users\debug\Desktop>debugme.exe
I heard you like bugs so I put bugs in your debugger so you can have bugs while you debug!!!
Seriously though try and find the flag, you will find it in your debugger!!!
```

Okay, we can't do anything here, there is no input. So the challenge is purely dynamic inversion.

- **IDA Free**:  the first thing I did was to set a breakpoint on main, then a breakpoint on mainCRTStartup (which is the PE entry point), but I kept it disabled for the first test just to see if we could get to the next breakpoint set on main (spoiler: we couldn't! so we have to keep it enabled), and another hardware breakpoint on TLS's AddressOfCallback (just in case there is relevant code to watch before the main thread starts). With these breakpoints in place, I run the program, and the first breakpoint activated is the mainCRTStartup breakpoint, which is a single jmp instruction mainCRTStartup_0 - so let's get in and finish here:

![[Pasted image 20250412204755.png]]

The one described above is a clear and typical anti-debugger technique in Windows. What it does is to retrieve the address of the Thread Environment Block from the fs register (offset 30h) and then take the value from offset +2 which should be the isDebuggerPresent field, this value is compared to zero, if the debugger is not present we are fine, the value is zero and we move on, otherwise we skip to the end. To bypass this problem, you need to patch it somehow. Since I do not know if the value of dl will be used later or if it is just redundant, I will modify this zeroing with xor (making its value = 0). I replaced the 2 opcodes at address 408904 that code for `mov al, [eax+2]` with `90 30 C0` that code for `nop` and `xor al, al` instead.
Okay, the first anti-debug trick has been circumvented. Now if I follow the code, eax and edx are reset and another value at offset +68h is read from the TEB: this is the **GdiTebBatch**.
The **GdiTebBatch** structure is used by the graphics subsystem (GDI) to efficiently group multiple drawing calls. Instead of invoking a system call for each individual GDI function, Windows groups these calls into a buffer (GdiTebBatch) to reduce the number of transitions between user mode and kernel mode. This improves the performance of graphics operations.
In our code the value is compared to zero and if it is not zero it jumps to the end of the program, so to move on I have to patch this field as well (because during debugging I got the value 0x70 from that field). So we patch these 3 bytes again, this time to 0x0408922, with `90 30 C0` and move on.
The next block I see is as follows:
![[Pasted image 20250412211253.png]]

as we can see it starts with the `rdtsc` instruction.
#rdtsc #time_based_antidebug
if I remember correctly this is a low level instruction to recover CPU time and can be used to detect debuggers by checking for differences in execution speed: obviously with a debugger the execution speed is much slower, so checking the difference with a normal execution speed can detect the debugger. In fact it looks like it is just used as another anti-debugger trick because we see `rdtsc` called at the beginning (to get the initial CPU time) and then almost at the end (after some instructions have been executed and thus some time has elapsed) where the end_instruction CPU time is fetched again and compared to a value of 0x3E8 (the author of this software decided that that is a good threshold to check if a debugger is present or not), if the elapsed time between start and end is > of 0x3E8, it jumps back to the end and closes. Of course in our case, where we are in a debugger, the procedure will surely fail. So once again, I have to patch it to make sure it works under debug (and not). I can simply modify the `jg` statement at the end with `nop`.
Okay, now we end up in a series of nop instructions. Let's go ahead and see that we end up in a part that takes the address of the `main` function and then enters a loop. The first instruction in the loop is an xor against the hardcoded `5Ch` value of the address retrieved earlier. This is clearly a main decoding routine!
![[Pasted image 20250412213631.png]]

Okay, I simply let it work. I place another breakpoint in the main function that was just decrypted and let IDA work freely again. The new breakpoint in main is now hit. We have to force IDA to parse this part again, otherwise we don't see the instruction correctly (right-click main, click undefined, then right-click again, then code).
I see that the code starts over with an anti-debug trick (check the BeingDebugged flag again).
![[Pasted image 20250412214551.png]]
And then repeat the same anti-debug trick as before. We reapply all the patches.

By doing so and circumventing the anti-debug mechanism, we finally find ourselves in the relevant part of the program, the _n function:
![[Pasted image 20250412214933.png]]

basically does another common technique to compute an immediate value in an undirected way: instead of encoding a value, it computes it at runtime with many arithmetic operations, we see above the first operation: `mov eax, 6A253E2Dh`. If we go on, we see the rest:
```
.text:004016C1 2D FC 29 0C 56                 sub     eax, 560C29FCh
.text:004016C6 50                             push    eax
.text:004016C7 E9 00 00 00 00                 jmp     $+5
.text:004016CC                ; ---------------------------------------------------------------------------
.text:004016CC
.text:004016CC                _yaya:                                  ; CODE XREF: .text:004016C7↑j
.text:004016CC 25 41 41 41 41                 and     eax, 41414141h
.text:004016D1 25 3E 3E 3E 3E                 and     eax, 3E3E3E3Eh
.text:004016D6 B8 2D 3E 25 6A                 mov     eax, 6A253E2Dh
.text:004016DB 2D F4 1B FD 49                 sub     eax, 49FD1BF4h
.text:004016E0 50                             push    eax
.text:004016E1 E9 00 00 00 00                 jmp     $+5
.text:004016E6                ; ---------------------------------------------------------------------------
.text:004016E6
.text:004016E6                _lala:                                  ; CODE XREF: .text:004016E1↑j
.text:004016E6 31 C0                          xor     eax, eax
.text:004016E8 B8 2D 3E 25 6A                 mov     eax, 6A253E2Dh
.text:004016ED 2D FF 24 11 2B                 sub     eax, 2B1124FFh
.text:004016F2 50                             push    eax
.text:004016F3 E9 00 00 00 00                 jmp     $+5
.text:004016F8                ; ---------------------------------------------------------------------------
.text:004016F8
.text:004016F8                _dsfghtgf:                              ; CODE XREF: .text:004016F3↑j
.text:004016F8 25 41 41 41 41                 and     eax, 41414141h
.text:004016FD 25 3E 3E 3E 3E                 and     eax, 3E3E3E3Eh
.text:00401702 B8 2D 3E 25 6A                 mov     eax, 6A253E2Dh
.text:00401707 2D 04 00 19 5E                 sub     eax, 5E190004h
.text:0040170C 50                             push    eax
.text:0040170D E9 00 00 00 00                 jmp     $+5
.text:00401712                ; ---------------------------------------------------------------------------
.text:00401712
.text:00401712                _ertrwe:                                ; CODE XREF: .text:0040170D↑j
.text:00401712 25 41 41 41 41                 and     eax, 41414141h
.text:00401717 25 3E 3E 3E 3E                 and     eax, 3E3E3E3Eh
.text:0040171C B8 2D 3E 25 6A                 mov     eax, 6A253E2Dh
.text:00401721 05 4D D6 E9 0D                 add     eax, 0DE9D64Dh
.text:00401726 50                             push    eax
.text:00401727 E9 00 00 00 00                 jmp     $+5
.text:0040172C                ; ---------------------------------------------------------------------------
.text:0040172C
.text:0040172C                _kjnjk:                                 ; CODE XREF: .text:00401727↑j
.text:0040172C 31 C0                          xor     eax, eax
.text:0040172E B8 2D 3E 25 6A                 mov     eax, 6A253E2Dh
.text:00401733 2D 19 34 00 2B                 sub     eax, 2B003419h
.text:00401738 50                             push    eax
.text:00401739 E9 00 00 00 00                 jmp     $+5
.text:0040173E                ; ---------------------------------------------------------------------------
.text:0040173E
.text:0040173E                _qsacb:                                 ; CODE XREF: .text:00401739↑j
.text:0040173E 25 41 41 41 41                 and     eax, 41414141h
.text:00401743 25 3E 3E 3E 3E                 and     eax, 3E3E3E3Eh
.text:00401748 B8 2D 3E 25 6A                 mov     eax, 6A253E2Dh
.text:0040174D 2D 06 1C 00 3E                 sub     eax, 3E001C06h
.text:00401752 50                             push    eax
.text:00401753 E9 00 00 00 00                 jmp     $+5
.text:00401758                ; ---------------------------------------------------------------------------
.text:00401758
.text:00401758                _tftrtftc:                              ; CODE XREF: .text:00401753↑j
.text:00401758 25 41 41 41 41                 and     eax, 41414141h
.text:0040175D 25 3E 3E 3E 3E                 and     eax, 3E3E3E3Eh
.text:00401762 B8 2D 3E 25 6A                 mov     eax, 6A253E2Dh
.text:00401767 2D 0E 05 AA 42                 sub     eax, 42AA050Eh
.text:0040176C 50                             push    eax
.text:0040176D E9 00 00 00 00                 jmp     $+5
```

But to be honest the most important thing I think is what ends up in the stack after the above code

```
0061FE60  0061FE64  Stack[00001CD0]:0061FE64
0061FE64  277B391F  <-- to here
0061FE68  2C252227  
0061FE6C  3F250A14  
0061FE70  780F147A  
0061FE74  0C0C3E29  
0061FE78  3F14192E  
0061FE7C  20282239  
0061FE80  14191431  
0061FE84  6A253E2D  <-- from here
0061FE88  0061FF50  Stack[00001CD0]:0061FF50
```

More strange assembly instructions follow that seem to do something in the stack:
![[Pasted image 20250412220228.png]]
Obfuscated, because it moves the registers many times but eventually does something on the stack. I'm not even trying to figure out what for now. Let's move on in the code.
The following code is a ret:
![[Pasted image 20250412220348.png]]
Before I go back anywhere, though, I want to inspect the stack.

The current ESP at this point is `0061FE8C` and if I see the stack view I see:
![[Pasted image 20250412220530.png]]
At this point, it is obvious that all the values at the top of the current stack pointer are not random and their hexes remind me of ASCII characters (when I see too many 60-6F hexes, they are probably a string!). so.... is a string?!? on the stack?!? let's see the hex around the ESP address then!

BOOM!!! solved!!!


---
### Challenges Encountered
My Windows virtual machine crashed 2 times, making the whole process very complicated.
IDA no longer showed graphs after the first virtual machine crash, making it more complex to understand the flow.

---
### ✅ Conclusion
It was a fun challenge! It wasn't very difficult to get around, but it was definitely annoying and time consuming. This is definitely a good approach to understanding and beating dynamic anti-debug techniques on Windows! Some level of knowledge of Windows processes is required.

---
### 💡 Additional Notes / Reflections
I did not know that the TEB field of GdiTebBatch could be used as an anti-debug trick on Windows. Actually, I knew that CPU timing could be used as an anti-debug trick, but this is the first time I've seen an implementation of it.

---

