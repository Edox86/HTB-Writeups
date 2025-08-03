# 🧬 Hack The Box - Reversing Challenge Write-Up:[WIDE] – [03/08/2025]
***

## 🕵️‍♂️ Challenge Overview
- **Objective:** retrieve the HTB flag
- **Link to the challenge:** https://app.hackthebox.com/challenges/WIDE
- **Challenge Description:** We've received reports that Draeger has stashed a huge arsenal in the pocket dimension Flaggle Alpha. You've managed to smuggle a discarded access terminal to the Widely Inflated Dimension Editor from his headquarters, but the entry for the dimension has been encrypted. Can you make it inside and take control?
- **Difficulty:** Very Easy
- **📦 Provided Files**:
	- File: `WIDE.zip`  
	- Password: `hackthebox`
	- SHA256: `362a8400f67d0bba0927ac161c8a4dcbc5462d9c0a909c421f79ddff3d39f9f7` 
- **📦 Extracted Files**:
 db.ex 
 wide

---

## ⚙️ Environment Setup
- **Operating System:** `Kali Linux`
- **Tools Used:**
  - Static: `file`, `sha256sum`, `strings`, `ldd`
  - Dynamic: `ltrace`, `Ghidra`

---

## 🔍 Static Analysis

#### Initial Observations
- File
```bash
┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ file db.ex    
db.ex: data

┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ file wide 
wide: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=13869bb7ce2c22f474b95ba21c9d7e9ff74ecc3f, not stripped
```

It’s a 64-bit, position-independent, dynamically linked, non-stripped ELF executable for x86-64 Linux (kernel ≥ 3.2), using /lib64/ld-linux-x86-64.so.2 as its loader.
Binary without stripes is good because we can still read the symbols.

- ldd

```bash
┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ ldd wide     
        linux-vdso.so.1 (0x00007fffb9fd7000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc1e4c0a000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fc1e51c2000)
```

It depends solely on the kernel’s vDSO, glibc (libc.so.6), and the standard 64-bit dynamic loader /lib64/ld-linux-x86-64.so.2 at runtime—no other shared libraries are required.

- strings

```bash
┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ strings db.ex 
Primus
people breathe variety practice
Our home dimension
Cheagaz
scene control river importance
The Ice Dimension
Byenoovia
fighting cast it parallel
The Berserk Dimension
Cloteprea
facing motor unusual heavy
The Hungry Dimension
Maraqa
stomach motion sale valuable
The Water Dimension
Aidor
feathers stream sides gate
The Bone Dimension
Flaggle Alpha
admin secret power hidden
HOt*
0ANe
```

Apart from the last two strings, it doesn’t appear to be encrypted. There is another clue here: Flaggle Alpha, which was mentioned earlier in the challenge description, so let’s keep that in mind. Also, it’s close to the word “admin” and that seemingly encrypted final part.

```bash
┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ strings wide         
/lib64/ld-linux-x86-64.so.2
libc.so.6
exit
fopen
ftell
puts
mbstowcs
stdin
printf
strtol
fgets
calloc
fseek
fclose
wcscmp
fread
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
AWAVI
AUATL
[]A\A]A^A_
Which dimension would you like to examine? 
That option was invalid.
[X] That entry is encrypted - please enter your WIDE decryption key: 
[X]                          Key was incorrect                           [X]
Usage: %s db.ex
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[x] There was a problem accessing your database [x]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] %-16s | %-32s | %6s%c%7s [*]
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
wide.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
wcscmp@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
fread@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
mbstowcs@@GLIBC_2.2.5
_edata
fclose@@GLIBC_2.2.5
menu
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
calloc@@GLIBC_2.2.5
__data_start
ftell@@GLIBC_2.2.5
__gmon_start__
strtol@@GLIBC_2.2.5
__dso_handle
_IO_stdin_used
__libc_csu_init
fseek@@GLIBC_2.2.5
__bss_start
main
fopen@@GLIBC_2.2.5
exit@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
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

I see many useful calls where we could set breakpoints in the future. Among these, a few caught my attention (because another file was provided by the challenge—it needs to be opened by the executable, so we can track down fopen). We also see what appears to be the program menu (asking which dimension we want to access, and we’ll probably need to answer with `Flaggle Alpha`), but I also see the program usage: `Usage: %s db.ex`, which means WIDE expects the file db.exe as a parameter. I also see the string `please enter your WIDE decryption key:`, which suggests we need to provide the correct password to decrypt the secrets. And a username seems to be hardcoded: `kr4eq4L2$12xb`.

To be honest, this seems to be a very straightforward challenge (no sign of strong anti-debug tricks or heavily encrypted parts), so I’d rather avoid static analysis with objdump and readelf this time.

Let’s move on to check the execution behavior to get a better overview of its functioning.

---

## 💻 Dynamic Analysis

- Execution Behavior

```bash
┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ ./wide
Usage: ./wide db.ex
                  
┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ ./wide db.ex 
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
[*]                       Displaying Dimensions....                      [*]
[*]       Name       |              Code                |   Encrypted    [*]
[X] Primus           | people breathe variety practice  |                [*]
[X] Cheagaz          | scene control river importance   |                [*]
[X] Byenoovia        | fighting cast it parallel        |                [*]
[X] Cloteprea        | facing motor unusual heavy       |                [*]
[X] Maraqa           | stomach motion sale valuable     |                [*]
[X] Aidor            | feathers stream sides gate       |                [*]
[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
Which dimension would you like to examine? Aidor
Our home dimension
Which dimension would you like to examine? Flaggle Alpha
Our home dimension
Which dimension would you like to examine? Flaggle Alpha
Our home dimension
Which dimension would you like to examine? flaggle 
Our home dimension
Which dimension would you like to examine? flaggle alpha
Our home dimension
Which dimension would you like to examine? primus
Our home dimension
Which dimension would you like to examine? 2
The Berserk Dimension
Which dimension would you like to examine? 3
The Hungry Dimension
Which dimension would you like to examine? 0     
Our home dimension
Which dimension would you like to examine? 1
The Ice Dimension
Which dimension would you like to examine? 7
That option was invalid.
Which dimension would you like to examine? 6
[X] That entry is encrypted - please enter your WIDE decryption key: kr4eq4L2$12xb
[X]                          Key was incorrect                           [X]
Which dimension would you like to examine? 
```

The behavior above confirms that the program requires `db.ex` as a parameter. It then prints the "rules" of the game and the available "dimensions" (choices) that can be accessed. The program appears to be structured around a loop that prints the string `Which dimension would you like to examine?` and waits for user input (likely using `fgets`). It only accepts numeric inputs from 0 (our dimension) up to 6 (the challenge target with the encrypted dimension/secret).

Based on testing the other dimensions, we get a clearer picture of the structure of the `db.ex` file, which seems to be composed of a sequence of: dimension name + dimension description + dimension secret (whether encrypted or not).

So from this, we understand that our goal is to find the correct key to decrypt the final string contained in `db.ex`.

Let’s now use `ltrace` to examine the program’s behavior step by step, aiming to identify which specific functions are called at each stage (and possibly leak some hardcoded comparison values as well).

```bash
┌──(kali㉿kali)-[~/Downloads/rev_wide]
└─$ ltrace ./wide db.ex 
puts("[*] Welcome user: kr4eq4L2$12xb,"...[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]
)                                                                          = 77
puts("[*]    Serving your pocket dimen"...[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]
)                                                                          = 77
fopen("db.ex", "r")                                                                                                  = 0x564abdd306b0
fseek(0x564abdd306b0, 0, SEEK_END)                                                                                   = 0
ftell(0x564abdd306b0)                                                                                                = 1260
fseek(0x564abdd306b0, 0, SEEK_SET)                                                                                   = 0
calloc(7, 180)                                                                                                       = 0x564abdd318a0
fread(0x564abdd318a0, 180, 7, 0x564abdd306b0)                                                                        = 7
fclose(0x564abdd306b0)                                                                                               = 0
puts("[*]                       Displa"...[*]                       Displaying Dimensions....                      [*]
)                                                                          = 77
puts("[*]       Name       |          "...[*]       Name       |              Code                |   Encrypted    [*]
)                                                                          = 77
printf("[X] %-16s | %-32s | %6s%c%7s [*]"..., "Primus", "people breathe variety practice", "", ' ', ""[X] Primus           | people breathe variety practice  |                [*]
)              = 77
printf("[X] %-16s | %-32s | %6s%c%7s [*]"..., "Cheagaz", "scene control river importance", "", ' ', ""[X] Cheagaz          | scene control river importance   |                [*]
)              = 77
printf("[X] %-16s | %-32s | %6s%c%7s [*]"..., "Byenoovia", "fighting cast it parallel", "", ' ', ""[X] Byenoovia        | fighting cast it parallel        |                [*]
)                 = 77
printf("[X] %-16s | %-32s | %6s%c%7s [*]"..., "Cloteprea", "facing motor unusual heavy", "", ' ', ""[X] Cloteprea        | facing motor unusual heavy       |                [*]
)                = 77
printf("[X] %-16s | %-32s | %6s%c%7s [*]"..., "Maraqa", "stomach motion sale valuable", "", ' ', ""[X] Maraqa           | stomach motion sale valuable     |                [*]
)                 = 77
printf("[X] %-16s | %-32s | %6s%c%7s [*]"..., "Aidor", "feathers stream sides gate", "", ' ', ""[X] Aidor            | feathers stream sides gate       |                [*]
)                    = 77
printf("[X] %-16s | %-32s | %6s%c%7s [*]"..., "Flaggle Alpha", "admin secret power hidden", "", '*', ""[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
)             = 77
printf("Which dimension would you like t"...)                                                                        = 43
fgets(Which dimension would you like to examine? 
```

The above confirms the use of several functions: `puts` and `printf` are used to print the menu and other information, while `fopen`, `fseek`, `ftell`, `fread`, and `fclose` handle the `db.ex` file. Specifically, the program reads `db.ex` at the beginning, loads its contents into newly allocated memory, and then closes the file. So after this initial step, `db.ex` is no longer needed since all its data resides in memory.

We also confirm the use of a `fgets` loop to capture user input.

Let’s now observe what happens when the user provides input.

```bash
fgets(Which dimension would you like to examine? 1
"1\n", 32, 0x7fabace2c8e0)                                                                                     = 0x7ffcefae6dd0
strtol("1\n", nil, 10)                                                                                               = 1
puts("The Ice Dimension"The Ice Dimension
)                                                                                            = 18
printf("Which dimension would you like t"...)                                                                        = 43
fgets(Which dimension would you like to examine? 6
"6\n", 32, 0x7fabace2c8e0)                                                                                     = 0x7ffcefae6dd0
strtol("6\n", nil, 10)                                                                                               = 6
printf("[X] That entry is encrypted - pl"...)                                                                        = 69
fgets([X] That entry is encrypted - please enter your WIDE decryption key: hola
"hola\n", 16, 0x7fabace2c8e0)                                                                                  = 0x7ffcefae6dc0
mbstowcs(0x7ffcefae6cc0, 0x7ffcefae6dc0, 16, 0x7ffcefae6dc0)                                                         = 5
wcscmp("hola\n", "sup3rs3cr3tw1d3")                                                                                  = -1
puts("[X]                          Key"...[X]                          Key was incorrect                           [X]
)                                                                          = 77
printf("Which dimension would you like t"...)                                                                        = 43
fgets(Which dimension would you like to examine?
```

This effectively solves the challenge, as the correct key was leaked in plaintext. But let’s break down the output step by step:

- `strtol` is used to convert the user's input from a string to a number—this is likely to branch into a `switch` statement based on the chosen dimension.
    
- The program then prints the name of the selected dimension, outputs the secret stored in the file, and re-enters the `fgets` input loop.
    

If the Flaggle Alpha branch is selected (via digit 6), the program prompts the user to enter a password with another `fgets`. Since we didn’t know the password at first, I entered `hola`. This input was then converted into a wide character string using the `mbstowcs` function and compared with the hardcoded wide character string `sup3rs3cr3tw1d3`.

This is the password required to obtain the secret and complete the challenge: `sup3rs3cr3tw1d3`.

```bash
fgets(Which dimension would you like to examine? 6
"6\n", 32, 0x7fabace2c8e0)                                                                                     = 0x7ffcefae6dd0
strtol("6\n", nil, 10)                                                                                               = 6
printf("[X] That entry is encrypted - pl"...)                                                                        = 69
fgets([X] That entry is encrypted - please enter your WIDE decryption key: sup3rs3cr3tw1d3
"sup3rs3cr3tw1d3", 16, 0x7fabace2c8e0)                                                                         = 0x7ffcefae6dc0
mbstowcs(0x7ffcefae6cc0, 0x7ffcefae6dc0, 16, 0x7ffcefae6dc0)                                                         = 15
wcscmp("sup3rs3cr3tw1d3", "sup3rs3cr3tw1d3")                                                                         = 0
puts("HTB{som3_str1ng5_4r3_w1d3}"HTB{som3_str1ng5_4r3_w1d3}
)                                                                                   = 27
```

I would have been much faster by opening it directly with Ghidra or IDA, but I always go through all the above steps for training and methodological purposes—to practice reading outputs and to train the mind in connecting clues and patterns.

In this case, the challenge centered around the use of wide characters as a form of obfuscation, making it harder to directly reveal the secret using tools like the `strings` command.

For the sake of completeness, let’s take a look at what Ghidra’s `main` function looks like:

- **Ghidra:**

```bash
undefined8 main(int param_1,undefined8 *param_2)
{
  int iVar1;
  FILE *__stream;
  ulong uVar2;
  void *__ptr;
  uint uVar3;
  int local_28;
  
  if (param_1 < 2) {
    printf("Usage: %s db.ex\n",*param_2);
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  puts("[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]");
  puts("[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]");
  __stream = fopen((char *)param_2[1],"r");
  if (__stream == (FILE *)0x0) {
    puts("[x] There was a problem accessing your database [x]");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  fseek(__stream,0,2);
  uVar2 = ftell(__stream);
  fseek(__stream,0,0);
  uVar2 = (uVar2 - uVar2 % 0xb4) / 0xb4;
  iVar1 = (int)uVar2;
  __ptr = calloc((long)iVar1,0xb4);
  fread(__ptr,0xb4,(long)iVar1,__stream);
  fclose(__stream);
  puts("[*]                       Displaying Dimensions....                      [*]");
  puts("[*]       Name       |              Code                |   Encrypted    [*]");
  for (local_28 = 0; local_28 < iVar1; local_28 = local_28 + 1) {
    if (*(int *)((long)__ptr + (long)local_28 * 0xb4) == 0) {
      uVar3 = 0x20;
    }
    else {
      uVar3 = 0x2a;
    }
    printf("[X] %-16s | %-32s | %6s%c%7s [*]\n",(long)__ptr + (long)local_28 * 0xb4 + 4,
           (long)__ptr + (long)local_28 * 0xb4 + 0x14,&DAT_0010132d,(ulong)uVar3,&DAT_0010132d);
  }
  menu(__ptr,uVar2 & 0xffffffff);
  return 0;
}


void menu(long param_1,int param_2)
{
  int iVar1;
  long lVar2;
  undefined8 *puVar3;
  long in_FS_OFFSET;
  uint local_1d4;
  wchar_t local_1c8 [16];
  undefined8 local_188;
  undefined8 local_180;
  undefined8 local_178;
  undefined8 local_170;
  undefined8 local_168;
  undefined8 local_160;
  undefined4 local_158;
  undefined4 uStack_154;
  undefined4 local_150;
  undefined4 uStack_14c;
  undefined4 local_148;
  undefined4 uStack_144;
  undefined4 local_140;
  undefined4 uStack_13c;
  undefined4 local_138;
  undefined4 uStack_134;
  undefined4 local_130;
  undefined4 uStack_12c;
  undefined4 local_128;
  undefined4 uStack_124;
  undefined4 local_120;
  undefined4 uStack_11c;
  undefined4 local_118;
  undefined4 uStack_114;
  undefined4 local_110;
  undefined4 uStack_10c;
  undefined4 local_108;
  undefined4 uStack_104;
  undefined4 local_100;
  undefined4 uStack_fc;
  undefined4 local_f8;
  undefined4 uStack_f4;
  undefined4 local_f0;
  undefined4 uStack_ec;
  undefined4 local_e8;
  undefined4 uStack_e4;
  undefined4 local_e0;
  undefined4 uStack_dc;
  undefined4 local_d8;
  char local_c8 [16];
  char local_b8 [32];
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_b8[0] = '\0';
  local_b8[1] = '\0';
  local_b8[2] = '\0';
  local_b8[3] = '\0';
  local_b8[4] = '\0';
  local_b8[5] = '\0';
  local_b8[6] = '\0';
  local_b8[7] = '\0';
  local_b8[8] = '\0';
  local_b8[9] = '\0';
  local_b8[10] = '\0';
  local_b8[0xb] = '\0';
  local_b8[0xc] = '\0';
  local_b8[0xd] = '\0';
  local_b8[0xe] = '\0';
  local_b8[0xf] = '\0';
  local_b8[0x10] = '\0';
  local_b8[0x11] = '\0';
  local_b8[0x12] = '\0';
  local_b8[0x13] = '\0';
  local_b8[0x14] = '\0';
  local_b8[0x15] = '\0';
  local_b8[0x16] = '\0';
  local_b8[0x17] = '\0';
  local_b8[0x18] = '\0';
  local_b8[0x19] = '\0';
  local_b8[0x1a] = '\0';
  local_b8[0x1b] = '\0';
  local_b8[0x1c] = '\0';
  local_b8[0x1d] = '\0';
  local_b8[0x1e] = '\0';
  local_b8[0x1f] = '\0';
  do {
    while( true ) {
      while( true ) {
        printf("Which dimension would you like to examine? ");
        fgets(local_b8,0x20,stdin);
        lVar2 = strtol(local_b8,(char **)0x0,10);
        iVar1 = (int)lVar2;
        if ((-1 < iVar1) && (iVar1 < param_2)) break;
        puts("That option was invalid.");
      }
      puVar3 = (undefined8 *)(param_1 + (long)iVar1 * 0xb4);
      local_188 = *puVar3;
      local_180 = puVar3[1];
      local_178 = puVar3[2];
      local_170 = puVar3[3];
      local_168 = puVar3[4];
      local_160 = puVar3[5];
      local_158 = (undefined4)puVar3[6];
      uStack_154 = (undefined4)((ulong)puVar3[6] >> 0x20);
      local_150 = (undefined4)puVar3[7];
      uStack_14c = (undefined4)((ulong)puVar3[7] >> 0x20);
      local_148 = (undefined4)puVar3[8];
      uStack_144 = (undefined4)((ulong)puVar3[8] >> 0x20);
      local_140 = (undefined4)puVar3[9];
      uStack_13c = (undefined4)((ulong)puVar3[9] >> 0x20);
      local_138 = (undefined4)puVar3[10];
      uStack_134 = (undefined4)((ulong)puVar3[10] >> 0x20);
      local_130 = (undefined4)puVar3[0xb];
      uStack_12c = (undefined4)((ulong)puVar3[0xb] >> 0x20);
      local_128 = (undefined4)puVar3[0xc];
      uStack_124 = (undefined4)((ulong)puVar3[0xc] >> 0x20);
      local_120 = (undefined4)puVar3[0xd];
      uStack_11c = (undefined4)((ulong)puVar3[0xd] >> 0x20);
      local_118 = (undefined4)puVar3[0xe];
      uStack_114 = (undefined4)((ulong)puVar3[0xe] >> 0x20);
      local_110 = (undefined4)puVar3[0xf];
      uStack_10c = (undefined4)((ulong)puVar3[0xf] >> 0x20);
      local_108 = (undefined4)puVar3[0x10];
      uStack_104 = (undefined4)((ulong)puVar3[0x10] >> 0x20);
      local_100 = (undefined4)puVar3[0x11];
      uStack_fc = (undefined4)((ulong)puVar3[0x11] >> 0x20);
      local_f8 = (undefined4)puVar3[0x12];
      uStack_f4 = (undefined4)((ulong)puVar3[0x12] >> 0x20);
      local_f0 = (undefined4)puVar3[0x13];
      uStack_ec = (undefined4)((ulong)puVar3[0x13] >> 0x20);
      local_e8 = (undefined4)puVar3[0x14];
      uStack_e4 = (undefined4)((ulong)puVar3[0x14] >> 0x20);
      local_e0 = (undefined4)puVar3[0x15];
      uStack_dc = (undefined4)((ulong)puVar3[0x15] >> 0x20);
      local_d8 = *(undefined4 *)(puVar3 + 0x16);
      if ((int)local_188 != 0) break;
      puts((char *)&uStack_154);
    }
    local_98 = CONCAT44(local_150,uStack_154);
    local_90 = CONCAT44(local_148,uStack_14c);
    local_88 = CONCAT44(local_140,uStack_144);
    local_80 = CONCAT44(local_138,uStack_13c);
    local_78 = CONCAT44(local_130,uStack_134);
    local_70 = CONCAT44(local_128,uStack_12c);
    local_68 = CONCAT44(local_120,uStack_124);
    local_60 = CONCAT44(local_118,uStack_11c);
    local_58 = CONCAT44(local_110,uStack_114);
    local_50 = CONCAT44(local_108,uStack_10c);
    local_48 = CONCAT44(local_100,uStack_104);
    local_40 = CONCAT44(local_f8,uStack_fc);
    local_38 = CONCAT44(local_f0,uStack_f4);
    local_30 = CONCAT44(local_e8,uStack_ec);
    local_28 = CONCAT44(local_e0,uStack_e4);
    local_20 = CONCAT44(local_d8,uStack_dc);
    printf("[X] That entry is encrypted - please enter your WIDE decryption key: ");
    fgets(local_c8,0x10,stdin);
    mbstowcs(local_1c8,local_c8,0x10);
    iVar1 = wcscmp(local_1c8,L"sup3rs3cr3tw1d3");
    if (iVar1 == 0) {
      for (local_1d4 = 0;
          (local_1d4 < 0x80 && (*(char *)((long)&local_98 + (long)(int)local_1d4) != '\0'));
          local_1d4 = local_1d4 + 1) {
        *(byte *)((long)&local_98 + (long)(int)local_1d4) =
             *(byte *)((long)&local_98 + (long)(int)local_1d4) ^
             (char)(local_1d4 * 0x1b) + (char)((int)(local_1d4 * 0x1b) / 0xff);
      }
      puts((char *)&local_98);
    }
    else {
      puts("[X]                          Key was incorrect                           [X]");
    }
  } while( true );
}
```

A very easy challenge, but in this case, understanding the entire pseudo C code through Ghidra would have been more time-consuming than using the `ltrace` approach.
