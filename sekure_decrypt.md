# 🧬 Hack The Box - Reversing Challenge Write-Up: [Sekure Decrypt] – [06/05/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** Retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Sekure%2520Decrypt
- **Challenge Description:** Timmy created a secure decryption program
- **Difficulty:** Easy
- **📦 Provided Files**:
  - File: `filename`  
  - Password: `hackthebox`
  - SHA256: `86584f04b8f2eebb07d267b7e625c196cbb86608927701efba0557006688014b`
- **📦 Extracted Files**:
  - Files: `core`, `dec`, `src.c`

---

## ⚙️ Environment Setup
- **Operating System:** Kali Linux
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `ghidra`, `python3`
  - Dynamic: `gdb`

---

## 🔍 Static Analysis

### Initial Observations

```bash
$ file dec
dec: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ file src.c
src.c: C source, ASCII text
```

The C source reveals:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

int encrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);

  if( buffer_len % blocksize != 0 ) { 
    return 1; 
  }

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int decrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);

  if( buffer_len % blocksize != 0 ){ 
    return 1;
  }
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

void* read_file(char* filename, int len) {
  FILE *fp = fopen(filename, "rb");
  void* data = malloc(len);
  fread(data, 1, len, fp);
  fclose(&fp);
  return data;
}

int main(int argc, char* argv[]) // gcc src.c -o dec -lmcrypt -ggdb
{
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = getenv("KEY");
  int keysize = 16;
  char* buffer;
  int buffer_len = 16;

  void *ciphertext = read_file("flag.enc", buffer_len);
  decrypt(ciphertext, buffer_len, IV, key, keysize);
  printf("Decrypted contents: %s\n", ciphertext);

  return 0;
}
```

The binary was compiled with `libmcrypt`.

Based on the provided source, it appears that the C source file was used to generate the binary named dec, which includes the function responsible for encrypting and decrypting a data stream.

If the ELF binary dec was compiled from this source, it should behave as follows (as inferred from the main function): it retrieves a key from an environment variable (which is not available to us, because it was specific to the author's setup), reads a file named flag.enc (an encrypted file that existed in the author's environment), and attempts to decrypt it using the decrypt function. This function appears to implement the Rijndael-128 algorithm (AES) in CBC mode. A similar algorithm is likely used for encrypting the data stream.

### Ghidra Confirmation

To verify that dec was indeed compiled from the provided source, I briefly inspected it using Ghidra. Upon analysis of the ELF binary, the main function does contain:


```c
int main(int argc,char **argv)
{
  uchar *in;
  EVP_PKEY_CTX *ctx;
  char **argv_local;
  int argc_local;
  int keysize;
  int buffer_len;
  char *IV;
  char *key;
  void *ciphertext;
  
  in = (uchar *)getenv("KEY");
  ctx = (EVP_PKEY_CTX *)read_file("flag.enc",0x10);
  decrypt(ctx,(uchar *)0x10,(size_t *)"AAAAAAAAAAAAAAAA",in,0x10);
  printf("Decrypted contents: %s\n",ctx);
  return 0;
}
```

Which is exactly what we observed in _src.c_. I'll attempt to run _dec_ to verify whether it exhibits this expected behavior.

---

## 💻 Dynamic Analysis

Running the binary fails due to a missing library:

```bash
$ ./dec
./dec: error while loading shared libraries: libmcrypt.so.4: cannot open shared object file: No such file or directory
```

To fix this:

```bash
sudo apt update
sudo apt install libmcrypt4
```

Now the binary runs but crashes. Running `./dec` results in a segmentation fault, which occurs because the program doesn't check whether the `"KEY"` environment variable exists before attempting to use it.

---

## 🧠 Core Dump Analysis

Now, let's examine the core file:


```bash
$ file core
core: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from './dec', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: './dec', platform: 'x86_64'
```

*Important observation noted.*

This strongly suggests that the original execution of `dec` on the challenge author's machine **crashed**, likely *after* successfully decrypting the flag, and they provided the resulting core dump.

A core dump retains:

* All mapped memory pages — meaning the **decrypted flag may already exist in plaintext** within the dump.
* The complete set of **environment variables** — including the missing `KEY`.

This is a critical clue: instead of trying to reconstruct the exact runtime environment, **we can extract the relevant data directly from the core dump**.

Let's begin our focused analysis of the core file.

Let's do a quick strings analysis:

```
CORE
CORE
./dec 
IGISCORE
CORE
ELIFCORE
/home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
/home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
/home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
/home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
/home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec
/usr/lib/x86_64-linux-gnu/libc-2.30.so
/usr/lib/x86_64-linux-gnu/libc-2.30.so
/usr/lib/x86_64-linux-gnu/libc-2.30.so
/usr/lib/x86_64-linux-gnu/libc-2.30.so
/usr/lib/x86_64-linux-gnu/libc-2.30.so
/usr/lib/libmcrypt.so.4.4.8
/usr/lib/libmcrypt.so.4.4.8
/usr/lib/libmcrypt.so.4.4.8
/usr/lib/libmcrypt.so.4.4.8
/usr/lib/libmcrypt.so.4.4.8
/usr/lib/x86_64-linux-gnu/ld-2.30.so
/usr/lib/x86_64-linux-gnu/ld-2.30.so
/usr/lib/x86_64-linux-gnu/ld-2.30.so
/usr/lib/x86_64-linux-gnu/ld-2.30.so
/usr/lib/x86_64-linux-gnu/ld-2.30.so
CORE
 invalid pointer
////////////////
nfo: %s
rcmd: C
LINUX
 invalid pointer
////////////////
nfo: %s
rcmd: C
/lib64/ld-linux-x86-64.so.2
232D
libmcrypt.so.4
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
mdecrypt_generic
mcrypt_generic_deinit
mcrypt_module_close
mcrypt_generic_init
mcrypt_enc_get_block_size
mcrypt_module_open
mcrypt_generic
libc.so.6
fopen
__stack_chk_fail
printf
fclose
malloc
getenv
fread
__cxa_finalize
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
rijndael-128
AAAAAAAAAAAAAAAA
flag.enc
Decrypted contents: %s
:*3$"
aliases
ethers
group
gshadow
hosts
initgroups
netgroup
networks
passwd
protocols
publickey
services
shadow
CAk[S
VXISl
qY>Ve
6D<{
#F3m
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
__cxa_finalize
__ctype_b_loc
readdir_r
strdup
__stack_chk_fail
mcrypt_free_p
mcrypt_list_algorithms
realloc
mcrypt_list_modes
mcrypt_check_version
strcmp
mcrypt_enc_get_key_size
mcrypt_generic_init
mcrypt_enc_get_supported_key_sizes
memmove
mcrypt_enc_get_iv_size
mcrypt_generic
mdecrypt_generic
mcrypt_generic_end
mcrypt_module_close
mcrypt_generic_deinit
mcrypt_perror
stderr
fwrite
mcrypt_strerror
mcrypt_free
memset
mlock
malloc
calloc
munlock
strlen
__strncat_chk
__strcat_chk
__stpcpy_chk
__strcpy_chk
mcrypt_enc_set_state
mcrypt_enc_get_state
mcrypt_enc_get_block_size
memcpy
mcrypt_enc_is_block_algorithm
mcrypt_enc_get_algorithms_name
mcrypt_enc_get_modes_name
mcrypt_enc_is_block_mode
mcrypt_enc_mode_has_iv
mcrypt_enc_is_block_algorithm_mode
mcrypt_module_open
mcrypt_enc_self_test
mcrypt_module_self_test
mcrypt_module_algorithm_version
mcrypt_module_mode_version
mcrypt_module_is_block_algorithm
mcrypt_module_is_block_algorithm_mode
mcrypt_module_is_block_mode
mcrypt_module_get_algo_block_size
mcrypt_module_get_algo_key_size
mcrypt_module_get_algo_supported_key_sizes
mcrypt_module_support_dynamic
mcrypt_mutex_register
__memcpy_chk
__sprintf_chk
puts
__printf_chk
memcmp
libc.so.6
libmcrypt.so.4
GLIBC_2.3
GLIBC_2.14
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.3.4
%?/?!
"o;h(Y
T*_}x:
j Bz
u\B&
y7bT
Ab61
T<*2
a.z9
DGt2
&5      M{
yM;-
jMG\^
C?9z
bcKU
!+g\
"%-U^7
PaH?
dv&4
wj-K
.n\
g&H`
~8lI
d^AE
;]>r
^(O= 
W1O     g_?
*,]I
Fv\;
Eub'z
\j#M
SRqDIK
_maz
mn`I:T`H
{OJW
z(~c
5_       
=;&o
~?Pa w
WFgO
(>nH&p
gTzu
|k      .T
B=!&|
!\1c
)eyC
PY?Mb4
VL.k
@x-:
PY?Mb4
VL.k
@x-:
Q/;U
Ab).
y0h6u}
XicV
:2*"
<4,$
>6.&
@80( 
91)!
;3+#
=5-%
?7/'
libmcrypt.so.4
/lib
libmcrypt.so.4
/lib/x86_64-linux-gnu/libc.so.6
libc.so.6
/lib/x86_64-linux-gnu
libc.so.6
uTi7J
|F:m
_rtld_global
__get_cpu_features
_dl_find_dso_for_object
_dl_make_stack_executable
_dl_exception_create
__libc_stack_end
_dl_catch_exception
malloc
_dl_deallocate_tls
_dl_signal_exception
__tunable_get_val
__libc_enable_secure
__tls_get_addr
_dl_get_tls_static_info
calloc
_dl_exception_free
_dl_debug_state
_dl_argv
_dl_allocate_tls_init
_rtld_global_ro
realloc
_dl_rtld_di_serinfo
_dl_mcount
_dl_allocate_tls
_dl_signal_error
_dl_exception_create_format
_r_debug
_dl_catch_error
ld-linux-x86-64.so.2
GLIBC_2.2.5
GLIBC_2.3
GLIBC_2.4
GLIBC_PRIVATE
munmap_chunk(): invalid pointer
sse2
x86_64
avx512_1
i586
i686
haswell
xeon_phi
linux-vdso.so.1
tls/x86_64/x86_64/tls/x86_64/
/lib/libmcrypt.so.4
m:f%
KEY=
x86_64
./dec
CLUTTER_IM_MODULE=ibus
COLORTERM=truecolor
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
DEFAULTS_PATH=/usr/share/gconf/ubuntu.default.path
DESKTOP_SESSION=ubuntu
DISPLAY=:0
GDMSESSION=ubuntu
GNOME_DESKTOP_SESSION_ID=this-is-deprecated
GNOME_SHELL_SESSION_MODE=ubuntu
GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen/bdea3ebb_feb3_4a20_8d27_450e84946bb2
GNOME_TERMINAL_SERVICE=:1.92
GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1
GTK_IM_MODULE=ibus
GTK_MODULES=gail:atk-bridge
HOME=/home/user
IM_CONFIG_PHASE=1
INVOCATION_ID=216e00eccfca4be5b4fcc1e4bb4b53f5
JOURNAL_STREAM=9:59334
KEY=VXISlqY>Ve6D<{#F
LANG=en_US.UTF-8
LOGNAME=root
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
MANAGERPID=1968
MANDATORY_PATH=/usr/share/gconf/ubuntu.mandatory.path
OMF_CONFIG=/home/user/.config/omf
OMF_PATH=/home/user/.local/share/omf
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
PWD=/home/user/Documents/RE/easy/Sekure Decrypt/release/debug
QT4_IM_MODULE=ibus
QT_IM_MODULE=ibus
SESSION_MANAGER=local/ubuntu:@/tmp/.ICE-unix/2262,unix/ubuntu:/tmp/.ICE-unix/2262
SHELL=/usr/bin/fish
SHLVL=4
SSH_AGENT_PID=2156
SSH_AUTH_SOCK=/run/user/1000/keyring/ssh
SUDO_COMMAND=/usr/bin/fish -c tmux
SUDO_GID=1000
SUDO_UID=1000
SUDO_USER=user
TERM=screen-256color
TMUX=/tmp//tmux-0/default,4919,0
TMUX_PANE=%8
USER=root
USERNAME=user
VTE_VERSION=5802
WINDOWPATH=2
XAUTHORITY=/run/user/1000/gdm/Xauthority
XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg
XDG_CURRENT_DESKTOP=ubuntu:GNOME
XDG_DATA_DIRS=/usr/share/ubuntu:/usr/local/share/:/usr/share/:/var/lib/snapd/desktop
XDG_MENU_PREFIX=gnome-
XDG_RUNTIME_DIR=/run/user/1000
XDG_SESSION_CLASS=user
XDG_SESSION_DESKTOP=ubuntu
XDG_SESSION_TYPE=x11
XMODIFIERS=@im=ibus
./dec
bemX
__vdso_gettimeofday
__vdso_time
__vdso_clock_gettime
__vdso_clock_getres
__vdso_getcpu
linux-vdso.so.1
LINUX_2.6
Linux
Linux
AUATS
A\A]]
[A\M
A]]I
[A\]
[A\]
GCC: (Ubuntu 9.2.1-9ubuntu2) 9.2.1 20191008
.shstrtab
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_d
.dynamic
.note
.eh_frame_hdr
.eh_frame
.text
.altinstructions
.altinstr_replacement
.comment
```

Exactly — the crash occurs due to a subtle but critical bug:

In the read_file() function, the code calls:

```C
fclose(&fp);
```

But fclose() expects a FILE *, not a FILE **. Passing the address of the pointer causes undefined behavior, leading to a segmentation fault. That crash happens after the file was read into memory but before the decrypt() function ran — which is perfect for us.

This confirms a few key points:

    flag.enc was successfully loaded into memory.

    It is preserved in the core dump.

    The decryption key (KEY=VXISlqY>Ve6D<{#F) is also present.

    The crash prevented the flag from being printed, but not from being available in memory.

So our task is now clear:

    Extract the encrypted flag (16 bytes) from the core dump using GDB or another memory analysis tool.

    Decrypt it using AES-128-CBC, with the key VXISlqY>Ve6D<{#F.

Ready to proceed — let’s open the core dump in GDB and find where that encrypted buffer is sitting.

```bash
gdb -q ./dec core

Core was generated by `./dec'.
Program terminated with signal SIGABRT, Aborted.
#0  0x00007fca32b0f3eb in ?? ()
(gdb) set pagination off
(gdb) p ciphertext
No symbol "ciphertext" in current context.
(gdb) bt
#0  0x00007fca32b0f3eb in ?? ()
#1  0x0000000000000000 in ?? ()

```
Explanation of the steps so far:

* `-q`: suppresses GDB's startup messages for cleaner output.
* Providing both `./dec` and the core file allows GDB to correlate memory addresses in the dump with source symbols and code lines — critical for meaningful analysis.
* `set pagination off`: disables GDB’s default pausing after each screen of output, so we can see full results without interruptions.
* `bt` (backtrace): shows the call stack at the time of the crash, helping identify exactly where the program failed.

However, in this case, GDB **can’t fully unwind the stack** — likely because the libc version used to build the original binary doesn’t match the one on your system. Without matching debug symbols, GDB struggles to reconstruct the call stack (`read_file → main`), which limits direct tracing.

That said, this isn’t a blocker. We can still proceed by:

* Manually locating the heap or other data regions in memory.
* Searching for the buffer that likely holds the encrypted `flag.enc` contents.
* Dumping it for decryption.

```bash
(gdb) info proc mappings
Mapped address spaces:

Start Addr         End Addr           Size               Offset             File 
0x0000562e29888000 0x0000562e29889000 0x1000             0x0                /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec 
0x0000562e29889000 0x0000562e2988a000 0x1000             0x1000             /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec 
0x0000562e2988a000 0x0000562e2988b000 0x1000             0x2000             /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec 
0x0000562e2988b000 0x0000562e2988c000 0x1000             0x2000             /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec 
0x0000562e2988c000 0x0000562e2988d000 0x1000             0x3000             /home/user/Documents/RE/easy/Sekure Decrypt/release/debug/dec 
0x00007fca32ac9000 0x00007fca32aee000 0x25000            0x0                /usr/lib/x86_64-linux-gnu/libc-2.30.so 
0x00007fca32aee000 0x00007fca32c66000 0x178000           0x25000            /usr/lib/x86_64-linux-gnu/libc-2.30.so 
0x00007fca32c66000 0x00007fca32cb0000 0x4a000            0x19d000           /usr/lib/x86_64-linux-gnu/libc-2.30.so 
0x00007fca32cb0000 0x00007fca32cb3000 0x3000             0x1e6000           /usr/lib/x86_64-linux-gnu/libc-2.30.so 
0x00007fca32cb3000 0x00007fca32cb6000 0x3000             0x1e9000           /usr/lib/x86_64-linux-gnu/libc-2.30.so 
0x00007fca32cba000 0x00007fca32cc0000 0x6000             0x0                /usr/lib/libmcrypt.so.4.4.8 
0x00007fca32cc0000 0x00007fca32cd9000 0x19000            0x6000             /usr/lib/libmcrypt.so.4.4.8 
0x00007fca32cd9000 0x00007fca32ce6000 0xd000             0x1f000            /usr/lib/libmcrypt.so.4.4.8 
0x00007fca32ce6000 0x00007fca32ce8000 0x2000             0x2b000            /usr/lib/libmcrypt.so.4.4.8 
0x00007fca32ce8000 0x00007fca32cea000 0x2000             0x2d000            /usr/lib/libmcrypt.so.4.4.8 
0x00007fca32d12000 0x00007fca32d13000 0x1000             0x0                /usr/lib/x86_64-linux-gnu/ld-2.30.so 
0x00007fca32d13000 0x00007fca32d35000 0x22000            0x1000             /usr/lib/x86_64-linux-gnu/ld-2.30.so 
0x00007fca32d35000 0x00007fca32d3d000 0x8000             0x23000            /usr/lib/x86_64-linux-gnu/ld-2.30.so 
0x00007fca32d3e000 0x00007fca32d3f000 0x1000             0x2b000            /usr/lib/x86_64-linux-gnu/ld-2.30.so 

```

I can't see any heap address to start from, so this could turn into an endless backtracking task and I'm start to think that there is a much easier way to complete the task.
Who cares if we don't know where exactly the encrypted flag's bytes are?!? let's bruteforce everything!

## 🧪 Brute-Scanning the Dump for the Flag

It’s actually much easier to brute-force the HTB flag using the key we have across the entire dump and see if anything comes up. That's possible because we know the pattern of the HTB flag.
Given we have the key, IV, and algorithm, we can brute-force scan the core dump for encrypted blocks and attempt to decrypt.

### Python Script: `scan_core.py`

```python
from Crypto.Cipher import AES
import mmap, os

KEY = b'VXISlqY>Ve6D<{#F'
IV  = b'A' * 16
ecb = AES.new(KEY, AES.MODE_ECB)

with open('core','rb') as f:
    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    size = os.fstat(f.fileno()).st_size

    for offset in range(0, size - 16):
        block = data[offset:offset+16]
        pt = bytes(a ^ b for a,b in zip(ecb.decrypt(block), IV))
        if pt.startswith(b'HTB{'):
            print("Found flag:", pt.decode('ascii', 'ignore'))
            break
```

Let’s run this and… boom! Flag retrieved!


---

## ✅ Challenges Encountered / Lessons Learned

- The core dump can contain some juicy stuff.
- Sometimes it's better to try brute-forcing rather than meticulously locating all the data—especially if we already know the pattern we're looking for.

---

## 🏁 Conclusion

This was a cleverly constructed challenge that mimicked a misconfigured cryptographic tool with a helpful crash. The core dump held both the key and data we needed, and brute-force decryption over memory yielded the flag without needing the original file `flag.enc`.

---

## 💡 Additional Notes / Reflections

- None
