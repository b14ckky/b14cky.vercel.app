---
title: Flare-On 2015 March 2026
published: 2026-03-25
description: Writeup of Flare-On 2015.
tags:
  - Reversing
  - Flare-On
image: images/cover.png
category: Flare-On Reversing Writeups
draft: false
---

- **Category: Malware Analysis and Reverse Engineering**
- **Difficulty: Easy/Medium/Hard**
- File: 2014_FLAREOn_Challenges.zip

# Challenge 1:

## Stage 1 Extracting CAB File 

### Initial Triage


- File Type: PE32+ executable for MS Windows 5.02 (GUI), x86-64
- Size: 183KB
- SHA256: a0b3e6ab4a53bf745319177035017f222634d2601ba8708292d5fbe440467387

### Basic Static Analysis

- Detect it Easy (Die) show that this file is **self-extracted CAB/SFX style packing**, where the executable includes a compressed Microsoft Cabinet file (CAB) and extracts/executes it at runtime and it is just a **wrapper/loader**.
- The `.rsrc` section is compressed, which is why the tool flags **high entropy**, classic sign of packing or encryption.
- Compression algorithm used inside the CAB is **LZX** (as shown), which is common in Microsoft CAB archives.
- So we have to first extract the actual exe from this and analyze it,

![Pasted image 20260325045316.png](images/Pasted_image_20260325045316.png)

![Pasted image 20260325045448.png](images/Pasted_image_20260325045448.png)

- We can extract it using [cabextract](https://www.cabextract.org.uk/) tool, and it will written in `Flare-On_start_2015.exe` file,

```bash
┌──(b14cky㉿DESKTOP-VRSQRAJ)-[~/]
└─$ cabextract Flare-On_start_2015.exe
Extracting cabinet: Flare-On_start_2015.exe
  extracting i_am_happy_you_are_to_playing_the_flareon_challenge.exe

All done, no errors.
```

## Stage 2 Understanding the ASMx86 Compiled EXE

### Initial Triage


- File Type: PE32 executable for MS Windows 4.00 (console), Intel i386
- Size: 2KB
- SHA256: 5d35789ac904bc5f4639119391ad1078f267a157ca153f2906f05df94e557e11

### Basic Static Analysis

- It gives `i_am_happy_you_are_to_playing_the_flareon_challenge.exe`.
- By running `die` on it, and it is written in **assembly**, not C/CPP.
- Also, it has missing DOS Header which means most of the automatic tools fail here because of these setup.

![Pasted image 20260325045717.png](images/Pasted_image_20260325045717.png)

- Running `floss` for strings analysis,

```bash
┌──(b14cky㉿DESKTOP-VRSQRAJ)-[~/]
└─$ /opt/floss i_am_happy_you_are_to_playing_the_flareon_challenge.exe
.
.
.
 ───────────────────────────
  FLOSS STATIC STRINGS (18)
 ───────────────────────────

+----------------------------------+
| FLOSS STATIC STRINGS: ASCII (18) |
+----------------------------------+

.text
.data
Pj*h
Pj2hX!@
h.!@
kernel32.dll
LoadLibraryA
GetProcAddress
GetLastError
GetStdHandle
AttachConsole
WriteConsoleA
WriteFile
ReadFile
Let's start out easy
Enter the password>
You are success
You are failure

+------------------------------------+
| FLOSS STATIC STRINGS: UTF-16LE (0) |
+------------------------------------+
 ─────────────────────────
  FLOSS STACK STRINGS (0)
 ─────────────────────────
 ─────────────────────────
  FLOSS TIGHT STRINGS (0)
 ─────────────────────────
 ───────────────────────────
  FLOSS DECODED STRINGS (0)
 ───────────────────────────
```

- These are the the `kernel32.dll` APIs,
- It can be used for **Dynamic API Resolution** + **I/O Execution Flow**. (Just a hypothesis)

```bash
LoadLibraryA
GetProcAddress
GetLastError
GetStdHandle
AttachConsole
WriteConsoleA
WriteFile
ReadFile
```

- Something related to password/licence checking,

```bash
Let's start out easy
Enter the password>
You are success
You are failure
```

- Now, to confirm the imports i used `pestudio` and indeed it is using those,

![Pasted image 20260325051645.png](images/Pasted_image_20260325051645.png)

### Advance Static Analysis

- So, to analyze it opened it in IDA with manual load because sometimes auto load fails in these kind of binaries, and found that it has only one `start` function is which is doing something, 

![Pasted image 20260325051811.png](images/Pasted_image_20260325051811.png)

- `GetStdHandle()` is called with:
	    - `STD_INPUT_HANDLE` → stdin
	    - `STD_OUTPUT_HANDLE` → stdout
	- Return values (in `EAX`) are saved as handles for input/output.
- I/O Operations
	- `WriteFile()` → prints prompt to console (stdout)
	- `ReadFile()` → reads up to **50 bytes** into `input_buffer` (`0x402158`)

```c
BOOL start()
{
  int v0; // ecx
  HANDLE StdHandle; // [esp+4h] [ebp-Ch]
  HANDLE hFile; // [esp+8h] [ebp-8h]
  DWORD NumberOfBytesWritten; // [esp+Ch] [ebp-4h] BYREF

  StdHandle = GetStdHandle(STD_INPUT_HANDLE);
  hFile = GetStdHandle(STD_OUTPUT_HANDLE);
  WriteFile(
    hFile,
    aLetSStartOutEa,                            // "Let's start out easy\r\nEnter the password>"
    0x2Au,
    &NumberOfBytesWritten,
    nullptr);
  ReadFile(StdHandle, lpBuffer, 0x32u, &NumberOfBytesWritten, nullptr);
  v0 = 0;
  while ( ((unsigned __int8)lpBuffer[v0] ^ 0x7D) == byte_402140[v0] )
  {
    if ( ++v0 >= 24 )
      return WriteFile(
               hFile,
               aYouAreSuccess,                  // "You are success\r\n"
               0x12u,
               &NumberOfBytesWritten,
               nullptr);
  }
  return WriteFile(
           hFile,
           aYouAreFailure,                      // "You are failure\r\n"
           0x12u,
           &NumberOfBytesWritten,
           nullptr);
}
```

- Expected C code,

```c
for (i = 0; i < 24; i++) {
    if ((input[i] ^ 0x7D) != encoded[i]) {
        print("failure");
        return;
    }
}
print("success");
```

- Here is the flow of code,
	1. Print prompt
	2. Read input
	3. For each character:
	    - XOR with `0x7D`
	    - Compare with stored value
	4. If all 24 match → success
	5. Else → failure

- This are the sequence of bytes which are being XORed with key `0x7D`. 

```
1F 8 13 13 4 22 0E 11 4D 0D 18 3D 1B 11 1C 0F 18 50 12 13 53 1E 12 10
```

![Pasted image 20260325052121.png](images/Pasted_image_20260325052121.png)

- Got the flag!!

![Pasted image 20260325051301.png](images/Pasted_image_20260325051301.png)

```yml
bunny_sl0pe@flare-on.com
```
- You can also apply this `IDApython` script which will manually patch the bytes, (only for IDA pro).

```python
import idc

for i in range(0x00402140, 0x00402158):
    b = 0x7D ^ idc.get_wide_byte(i)
    idc.patch_byte(i, b)
```

![Pasted image 20260325054501.png](images/Pasted_image_20260325054501.png)

# Challenge 2:
# Challenge 3:
# Challenge 4:
# Challenge 5:
# Challenge 6:
# Challenge 7:
# Challenge 8:
# Challenge 9:
# Challenge 10:
# Challenge 11:

