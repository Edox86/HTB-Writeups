# 🧬 Hack The Box - Reversing Challenge Write-Up: [Hissss] – [08/05/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/Hissss
- **Challenge Description:** Can you slither around the authentication?
- **Difficulty:** Easy
- **📦 Provided Files**:
  - File: `Hissss.zip`  
  - Password: `hackthebox`
  - SHA256: `0cf73ce8ec05b911895367bc4eb5a06e82ac0588b2eee79b51a496a696a62138` 
- **📦 Extracted Files**:
  - File: `auth`
  - SHA256: `89b33f1869771400b06799a5a4b3d4a774eb593179cac4dc0720ced96f746b7e`

---

## ⚙️ Environment Setup
- **Operating System:** [Kali Linux]
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`,  `ldd`, `pyinstxtractor`, `decompyle3`

---

## 🔍 Static Analysis

### Initial Observations

### file

```bash
file auth      
auth: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3507aa01d32c34dc8e8c6462b764adb90a82768d, stripped
```

### ldd

```bash
ldd auth     
        linux-vdso.so.1 (0x00007ffd6effb000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f668b76e000)
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f668b74f000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f668b559000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f668b7a7000)
```

### strings

```bash
strings auth
/lib64/ld-linux-x86-64.so.2
mfUa
libdl.so.2
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
dlsym
dlopen
dlerror
libz.so.1
inflateEnd
inflateInit_
inflate
libc.so.6
__xpg_basename
mkdtemp
fflush
strcpy
fchmod
readdir
setlocale
fopen
wcsncpy
strncmp
perror
closedir
ftell
signal
strncpy
mbstowcs
fork
unlink
mkdir
stdin
getpid
kill
strdup
strtok
feof
calloc
strlen
dirname
rmdir
__errno_location
fseek
clearerr
unsetenv
__fprintf_chk
stdout
fclose
__vsnprintf_chk
malloc
strcat
realpath
raise
nl_langinfo
opendir
getenv
stderr
__snprintf_chk
execvp
strncat
__realpath_chk
fileno
fwrite
fread
__memcpy_chk
waitpid
strchr
__vfprintf_chk
__strcpy_chk
__cxa_finalize
__xstat
__strcat_chk
setbuf
strcmp
strerror
__libc_start_main
ferror
stpcpy
snprintf
free
GLIBC_2.2.5
GLIBC_2.3
GLIBC_2.4
GLIBC_2.3.4
u/UH
ob@H
rPL)
[]A\
[]A\
AWAVAUI
[]A\A]A^A_
l$ H
AUATUSH
[]A\A]A^
ATUH
[]A\
t+SH
AWAVI
AUATI
[]A\A]A^A_
[]A\A]A^A_
t$(H
T$0H
L$8L
D$@L
)D$P
)L$`
)T$p
t$(H
T$0H
L$8L
D$@L
)D$P
)L$`
)T$p
T$0H
L$8L
D$@L
)D$P
)L$`
)T$p
T$ H
AVAUATUSH
[]A\A]A^A_
ATUH
,$H;]
<xt'<dtHH
[]A\A]
AWAVAUATUSH
$L;{
[]A\A]A^A_
u$E1
[]A\
[]A\
ATUSH
[]A\
 []A\
AVAUI
ATUSH
[]A\A]A^A_
[]A\
[]A\
ATUH
[]A\A]
ATUH
[]A\
[]A\
AUATI
[]A\A]
AWAVAUATUSH
<Wt/~
[]A\A]A^A_
d$@H
[]A\
AWAVAUI
ATUS
[]A\A]A^A_
AWAVAUATUH
[]A\A]A^A_
AWAVI
[]A\A]A^A_
_MEIXXXX
[]A\
AVAUATUSH
D$(H
[]A\A]A^A_
ATUSH
[]A\A]
[]A\A]
[]A\
AWAVA
ATUH
[]A\A]A^A_
[]A\A]A^A_
Cannot open archive file
Could not read from file
1.2.11
Error %d from inflate: %s
Error decompressing %s
%s could not be extracted!
fopen
fwrite
malloc
Could not read from file.
fread
Error on file
calloc
Cannot read Table of Contents.
Could not allocate read buffer
Error allocating decompression buffer
Error %d from inflateInit: %s
Failed to write all bytes for %s
Could not allocate buffer for TOC.
Cannot allocate memory for ARCHIVE_STATUS
[%d] 
Error copying %s
%s%s%s%s%s%s%s
%s%s%s.pkg
%s%s%s.exe
Archive not found: %s
Error opening archive %s
Error extracting %s
__main__
%s.py
Name exceeds PATH_MAX
__file__
Failed to execute script %s
Could not get __main__ module.
Could not get __main__ module's dict.
Failed to unmarshal code object for %s
_MEIPASS2
Cannot open self %s or archive %s
Py_DontWriteBytecodeFlag
Py_FileSystemDefaultEncoding
Py_FrozenFlag
Py_IgnoreEnvironmentFlag
Py_NoSiteFlag
Py_NoUserSiteDirectory
Py_OptimizeFlag
Py_VerboseFlag
Py_BuildValue
Py_DecRef
Cannot dlsym for Py_DecRef
Py_Finalize
Cannot dlsym for Py_Finalize
Py_IncRef
Cannot dlsym for Py_IncRef
Py_Initialize
Py_SetPath
Cannot dlsym for Py_SetPath
Py_GetPath
Cannot dlsym for Py_GetPath
Py_SetProgramName
Py_SetPythonHome
PyDict_GetItemString
PyErr_Clear
Cannot dlsym for PyErr_Clear
PyErr_Occurred
PyErr_Print
Cannot dlsym for PyErr_Print
PyErr_Fetch
Cannot dlsym for PyErr_Fetch
PyImport_AddModule
PyImport_ExecCodeModule
PyImport_ImportModule
PyList_Append
PyList_New
Cannot dlsym for PyList_New
PyLong_AsLong
PyModule_GetDict
PyObject_CallFunction
PyObject_CallFunctionObjArgs
PyObject_SetAttrString
PyObject_GetAttrString
PyObject_Str
PyRun_SimpleString
PySys_AddWarnOption
PySys_SetArgvEx
PySys_GetObject
PySys_SetObject
PySys_SetPath
PyEval_EvalCode
PyUnicode_FromString
Py_DecodeLocale
PyMem_RawFree
PyUnicode_FromFormat
PyUnicode_Decode
PyUnicode_DecodeFSDefault
PyUnicode_AsUTF8
Cannot dlsym for Py_DontWriteBytecodeFlag
Cannot dlsym for Py_FileSystemDefaultEncoding
Cannot dlsym for Py_FrozenFlag
Cannot dlsym for Py_IgnoreEnvironmentFlag
Cannot dlsym for Py_NoSiteFlag
Cannot dlsym for Py_NoUserSiteDirectory
Cannot dlsym for Py_OptimizeFlag
Cannot dlsym for Py_VerboseFlag
Cannot dlsym for Py_BuildValue
Cannot dlsym for Py_Initialize
Cannot dlsym for Py_SetProgramName
Cannot dlsym for Py_SetPythonHome
Cannot dlsym for PyDict_GetItemString
Cannot dlsym for PyErr_Occurred
Cannot dlsym for PyImport_AddModule
Cannot dlsym for PyImport_ExecCodeModule
Cannot dlsym for PyImport_ImportModule
Cannot dlsym for PyList_Append
Cannot dlsym for PyLong_AsLong
Cannot dlsym for PyModule_GetDict
Cannot dlsym for PyObject_CallFunction
Cannot dlsym for PyObject_CallFunctionObjArgs
Cannot dlsym for PyObject_SetAttrString
Cannot dlsym for PyObject_GetAttrString
Cannot dlsym for PyObject_Str
Cannot dlsym for PyRun_SimpleString
Cannot dlsym for PySys_AddWarnOption
Cannot dlsym for PySys_SetArgvEx
Cannot dlsym for PySys_GetObject
Cannot dlsym for PySys_SetObject
Cannot dlsym for PySys_SetPath
Cannot dlsym for PyEval_EvalCode
PyMarshal_ReadObjectFromString
Cannot dlsym for PyMarshal_ReadObjectFromString
Cannot dlsym for PyUnicode_FromString
Cannot dlsym for Py_DecodeLocale
Cannot dlsym for PyMem_RawFree
Cannot dlsym for PyUnicode_FromFormat
Cannot dlsym for PyUnicode_Decode
Cannot dlsym for PyUnicode_DecodeFSDefault
Cannot dlsym for PyUnicode_AsUTF8
pyi-
out of memory
%s%cbase_library.zip%c%s
_MEIPASS
marshal
loads
mod is NULL - %s
%U?%d
path
Failed to append to sys.path
Failed to convert Wflag %s using mbstowcs (invalid multibyte string)
Path of DLL (%s) length exceeds buffer[%d] space
Error loading Python lib '%s': dlopen: %s
Fatal error: unable to decode the command line argument #%i
Failed to convert progname to wchar_t
Failed to convert pyhome to wchar_t
sys.path (based on %s) exceeds buffer[%d] space
Failed to convert pypath to wchar_t
Failed to convert argv to wchar_t
Error detected starting Python VM.
Failed to get _MEIPASS as PyObject.
Installing PYZ: Could not get sys.path
import sys; sys.stdout.flush();                 (sys.__stdout__.flush if sys.__stdout__                 is not sys.stdout else (lambda: None))()
import sys; sys.stderr.flush();                 (sys.__stderr__.flush if sys.__stderr__                 is not sys.stderr else (lambda: None))()
LD_LIBRARY_PATH
LD_LIBRARY_PATH_ORIG
TMPDIR
pyi-runtime-tmpdir
LISTEN_PID
pyi-bootloader-ignore-signals
/var/tmp
/usr/tmp
TEMP
INTERNAL ERROR: cannot create temporary directory!
WARNING: file already exists but should not: %s
LOADER: failed to allocate argv_pyi: %s
LOADER: failed to strdup argv[%d]: %s
;*3$"
GCC: (Debian 8.3.0-6) 8.3.0
M"6&~ 
K][=4o
Tikj
g/oZ
_I&!
VUwx
 !TU
|eu7R
p'S;a
@LDZ
8,3\~
~;?)FY
tgZL
lvf?
X*3,
i;/F
>-n]
R7yy
uKWz=
7kS=
@_;j
dn].
".lw(";
|nwx
u.C3F
 .TD
'0      ~&
xJ45
ew"N
6 QE0
 a'*
        2]pY
`V)e
...
many other obfuscated strings
...
!o g
,KW9
/Wfu
fW]_E
';}Q
}akS
 kzJ
4Xmr
__future__)
_compat_pickle)
_compression)
_osx_support)
_py_abc)
_pydecimal)
        _strptime)
&_sysconfigdata__linux_x86_64-linux-gnu)
_threading_local)
argparse)
ast)
asyncio)
asyncio.base_events)
asyncio.base_futures)
asyncio.base_subprocess)
asyncio.base_tasks)
asyncio.constants)
asyncio.coroutines)
asyncio.events)
asyncio.exceptions)
asyncio.format_helpers)
asyncio.futures)
asyncio.locks)
asyncio.log)
asyncio.proactor_events)
asyncio.protocols)
asyncio.queues)
asyncio.runners)
asyncio.selector_events)
asyncio.sslproto)
asyncio.staggered)
asyncio.streams)
asyncio.subprocess)
asyncio.tasks)
asyncio.transports)
asyncio.trsock)
asyncio.unix_events)
asyncio.windows_events)
asyncio.windows_utils)
base64)
bdb)
bisect)
bz2)
calendar)
cmd)
code)
codeop)
concurrent)
concurrent.futures)
concurrent.futures._base)
concurrent.futures.process)
concurrent.futures.thread)
configparser)
contextlib)
contextvars)
copy)
csv)
ctypes)
ctypes._endian)
datetime)
decimal)
difflib)
dis)
        distutils)
distutils.log)
doctest)
email)
email._encoded_words)
email._header_value_parser)
email._parseaddr)
email._policybase)
email.base64mime)
email.charset)
email.contentmanager)
email.encoders)
email.errors)
email.feedparser)
email.generator)
email.header)
email.headerregistry)
email.iterators)
email.message)
email.parser)
email.policy)
email.quoprimime)
email.utils)
fnmatch)
ftplib)
genericpath)
getopt)
getpass)
gettext)
glob)
gzip)
hashlib)
i}[
hmac)
html)
html.entities)
http)
http.client)
http.cookiejar)
http.server)
        importlib)
importlib._bootstrap)
importlib._bootstrap_external)
importlib.abc)
importlib.machinery)
importlib.metadata)
importlib.util)
inspect)
logging)
lzma)
        mimetypes)
multiprocessing)
multiprocessing.connection)
multiprocessing.context)
multiprocessing.dummy)
 multiprocessing.dummy.connection)
multiprocessing.forkserver)
multiprocessing.heap)
multiprocessing.managers)
multiprocessing.pool)
multiprocessing.popen_fork)
 multiprocessing.popen_forkserver)
!multiprocessing.popen_spawn_posix)
!multiprocessing.popen_spawn_win32)
multiprocessing.process)
multiprocessing.queues)
multiprocessing.reduction)
multiprocessing.resource_sharer)
 multiprocessing.resource_tracker)
multiprocessing.shared_memory)
multiprocessing.sharedctypes)
multiprocessing.spawn)
multiprocessing.synchronize)
multiprocessing.util)
netrc)
ntpath)
nturl2path)
numbers)
opcode)
optparse)
pathlib)
pdb)
pickle)
pkgutil)
platform)
plistlib)
        posixpath)
pprint)
py_compile)
pydoc)
pydoc_data)
pydoc_data.topics)
queue)
quopri)
random)
runpy)
secrets)
        selectors)
shlex)
shutil)
signal)
socket)
socketserver)
ssl)
stat)
string)
stringprep)
subprocess)
        sysconfig)
tarfile)
tempfile)
textwrap)
        threading)
token)
tokenize)
tracemalloc)
tty)
typing)
unittest)
unittest.async_case)
unittest.case)
unittest.loader)
unittest.main)
unittest.result)
unittest.runner)
unittest.signals)
unittest.suite)
unittest.util)
urllib)
urllib.error)
urllib.parse)
urllib.request)
urllib.response)
webbrowser)
xml)
xml.parsers)
xml.parsers.expat)
xml.sax)
xml.sax._exceptions)
xml.sax.expatreader)
xml.sax.handler)
xml.sax.saxutils)
xml.sax.xmlreader)
xmlrpc)
xmlrpc.client)
zipfile)
        zipimport)
mstruct
mpyimod01_os_path
mpyimod02_archive
mpyimod03_importers
spyiboot01_bootstrap
spyi_rth_multiprocessing
sauth
b_asyncio.cpython-38-x86_64-linux-gnu.so
b_bisect.cpython-38-x86_64-linux-gnu.so
b_blake2.cpython-38-x86_64-linux-gnu.so
b_bz2.cpython-38-x86_64-linux-gnu.so
b_codecs_cn.cpython-38-x86_64-linux-gnu.so
b_codecs_hk.cpython-38-x86_64-linux-gnu.so
b_codecs_iso2022.cpython-38-x86_64-linux-gnu.so
b_codecs_jp.cpython-38-x86_64-linux-gnu.so
b_codecs_kr.cpython-38-x86_64-linux-gnu.so
b_codecs_tw.cpython-38-x86_64-linux-gnu.so
b_contextvars.cpython-38-x86_64-linux-gnu.so
b_csv.cpython-38-x86_64-linux-gnu.so
b_ctypes.cpython-38-x86_64-linux-gnu.so
b_datetime.cpython-38-x86_64-linux-gnu.so
b_decimal.cpython-38-x86_64-linux-gnu.so
b_hashlib.cpython-38-x86_64-linux-gnu.so
b_heapq.cpython-38-x86_64-linux-gnu.so
b_lzma.cpython-38-x86_64-linux-gnu.so
b_md5.cpython-38-x86_64-linux-gnu.so
b_multibytecodec.cpython-38-x86_64-linux-gnu.so
b_multiprocessing.cpython-38-x86_64-linux-gnu.so
b_opcode.cpython-38-x86_64-linux-gnu.so
b_pickle.cpython-38-x86_64-linux-gnu.so
b_posixshmem.cpython-38-x86_64-linux-gnu.so
b_posixsubprocess.cpython-38-x86_64-linux-gnu.so
b_queue.cpython-38-x86_64-linux-gnu.so
b_random.cpython-38-x86_64-linux-gnu.so
b_sha1.cpython-38-x86_64-linux-gnu.so
b_sha256.cpython-38-x86_64-linux-gnu.so
b_sha3.cpython-38-x86_64-linux-gnu.so
b_sha512.cpython-38-x86_64-linux-gnu.so
b_socket.cpython-38-x86_64-linux-gnu.so
b_ssl.cpython-38-x86_64-linux-gnu.so
b_struct.cpython-38-x86_64-linux-gnu.so
barray.cpython-38-x86_64-linux-gnu.so
bbinascii.cpython-38-x86_64-linux-gnu.so
bgrp.cpython-38-x86_64-linux-gnu.so
bld-linux-x86-64.so.2
blibbz2.so.1.0
blibcrypto.so.1.1
blibexpat.so.1
blibffi.so.7
bliblzma.so.5
blibncursesw.so.6
blibpython3.8.so.1.0
blibreadline.so.8
blibssl.so.1.1
blibz.so.1
bmath.cpython-38-x86_64-linux-gnu.so
bmmap.cpython-38-x86_64-linux-gnu.so
bpyexpat.cpython-38-x86_64-linux-gnu.so
breadline.cpython-38-x86_64-linux-gnu.so
bresource.cpython-38-x86_64-linux-gnu.so
bselect.cpython-38-x86_64-linux-gnu.so
btermios.cpython-38-x86_64-linux-gnu.so
bunicodedata.cpython-38-x86_64-linux-gnu.so
bzlib.cpython-38-x86_64-linux-gnu.so
xbase_library.zip
xinclude/python3.8/pyconfig.h
xlib/python3.8/config-3.8-x86_64-linux-gnu/Makefile
zPYZ-00.pyz
&libpython3.8.so.1.0
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
.data.rel.ro
.dynamic
.got.plt
.data
.bss
.comment
pydata

```

The strings I'm seeing above don't resemble those typically found in a standard ELF binary. Instead, there are numerous Python-related strings. In fact, a quick search of these strings confirms that they're exactly what we'd expect from a **PyInstaller-packed** Linux executable.

## The strategy:

This is actually a significant clue, because rather than diving into the stripped C stub in IDA, we can take a different approach:

- **Extract the embedded archive**  
    Use a tool like [pyinstxtractor.py](https://github.com/extremecoders-re/pyinstxtractor) to extract all the `.pyc` modules.
    
- **Decompile the bytecode**  
    After extracting the `.pyc` files, use **decompyle3** to recover the original, readable `.py` source code.
    
- **Analyze the logic**  
    With the source code available, focus on locating authentication routines / key validation —these are likely to contain the flag or the mechanism to bypass the challenge.

But before diving into all of that, let’s start with a basic execution to observe how the binary behaves under normal conditions.

---
## 💻 Execution

```bash
- Execution Behavior
┌──(kali㉿kali)-[~/Downloads/test]
└─$ ./auth                   
Enter password> hola
Sorry! You've entered the wrong password.
```

---

## 📦 PyInstaller Archive Extraction

Ok let's extract the source now:

```bash
git clone https://github.com/extremecoders-re/pyinstxtractor
cd pyinstxtractor
chmod +x pyinstxtractor.py
python3 pyinstxtractor.py ../auth
[+] Processing ../auth
[+] Pyinstaller version: 2.1+
[+] Python version: 3.8
[+] Length of package: 7196547 bytes
[+] Found 68 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: auth.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.8 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: ../auth

```

Output confirms successful extraction and shows relevant `.pyc` modules including `auth.pyc`.
I believe our target file is `auth.pyc`. We can now use a Python decompiler to analyze the `.pyc` files.  

---
## 🔓 Bytecode Decompilation

We use `decompyle3` to convert `auth.pyc` into readable Python source:

```bash
pip install decompyle3
decompyle3 auth_extracted/auth.pyc > auth.py
```

This will give us a readable Python source file:

```python
# decompyle3 version 3.9.2
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.11.9 (main, Apr 10 2024, 13:16:36) [GCC 13.2.0]
# Embedded file name: auth.py
import sys
password = input("Enter password> ")
if len(password) != 12:
    print("Sorry! You've entered the wrong password.")
    sys.exit(0)
if ord(password[0]) != 48 or password[11] != "!" or ord(password[7]) != ord(password[5]) or 143 - ord(password[0]) != ord(password[4]) or ord(password[1]) ^ ord(password[3]) != 30 or ord(password[2]) * ord(password[3]) != 5610 or password[1] != "p" or ord(password[6]) - ord(password[8]) != -46 or ord(password[6]) ^ ord(password[7]) != 64 or ord(password[10]) + ord(password[5]) != 166 or password[11] != "!" or password[10] != str(3):
    print("Sorry, the password is incorrect.")
else:
    print(f"Well Done! HTB{{{password}}}")

# okay decompiling auth.pyc

```

Great! 

---
## 🧩 Password Logic Analysis

Now the challenge is simply to understand what the code is doing.

1. It takes input from the user and stores it in a variable called `password`.
    
2. It checks that the password is exactly 12 characters long. If not, it exits.
    
3. It then verifies each character—using its ASCII value—in a mixed order, comparing them against hardcoded values or other positions within the password.
    
4. If the password passes all checks, it prints it as a valid HTB flag.
    

For example, the first condition `ord(password[0]) != 48` checks whether the first character is `'0'`, since the ASCII value for `'0'` is 48.

To assist with this, I use an Excel sheet: I number each character position and fill in the values as I figure them out.

So, all we need to do is untangle the logic and match the characters with their corresponding ASCII codes. Good luck!

---

## ✅ Challenges Encountered / Lessons Learned
- Recognizing the PyInstaller signature in `strings` saved a lot of effort.
- Understanding and debugging obfuscated ASCII checks in Python is easier when visualized with tools like spreadsheets.
- Using `pyinstxtractor` and `decompyle3` enables fast Python reversing without deep binary reversing.

---

## 🏁 Conclusion
The challenge disguised a Python authentication script inside a stripped ELF using PyInstaller. By extracting, decompiling, and reverse-engineering the password logic, I was able to deduce the correct flag.

---

## 💡 Additional Notes / Reflections
Whenever you see `_MEIPASS` or a lot of Python-related strings in an ELF binary, check for PyInstaller. These challenges are more Python RE than classic ELF reversing.
