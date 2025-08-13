---
title: Crackme - TeRrArIsT's Easy, but interesting for novice August 2025
published: 2025-08-13
description: Writeup of Crackme.
tags:
  - Reversing
  - Crackmes
  - Debugging
  - x64dbg
  - IDA
image: images/cover.png
category: Crackme Reversing Writeups
draft: false
---

# Challenge Info

![Pasted image 20250813185600.png](images/Pasted_image_20250813185600.png)

# File Info

- This is a **64-bit executable file**.

![Pasted image 20250813185643.png](images/Pasted_image_20250813185643.png)
# Testing Inputs

- I started by testing with the string `"TEST"` as input. 
- The program responded with **Access Denied**, which suggests it’s validating the input against a different, predefined string. We can clearly observe this in IDA.

![Pasted image 20250813185843.png](images/Pasted_image_20250813185843.png)

- **IDA View:**

![Pasted image 20250813185855.png](images/Pasted_image_20250813185855.png)

- **Pseudocode (IDA-generated):**

![Pasted image 20250813185941.png](images/Pasted_image_20250813185941.png)

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char Str2[8]; // [rsp+21h] [rbp-2Fh] BYREF
  _BYTE v5[7]; // [rsp+29h] [rbp-27h] BYREF
  char Str1[32]; // [rsp+30h] [rbp-20h] BYREF

  _main(argc, argv, envp);
  *(_DWORD *)v5 = 1129925455;
  *(_DWORD *)&v5[3] = 421010243;
  decrypt(Str2, v5, 42, 7);
  _mingw_printf("Enter password: ");
  _mingw_scanf("%31s", Str1);
  if ( !strcmp(Str1, Str2) )
    puts("Access granted!");
  else
    puts("Access denied!");
  getch();
  return 0;
}
```

- To investigate further, I used **x64dbg** and began searching for **static strings** that could help in pinpointing the password verification logic.  
    Examples include:
    1. `"Access granted!"`
    2. `"Access denied!"`
    3. References to `strcmp`
    4. Other suspicious instructions that might hint at password handling.

![Pasted image 20250813190102.png](images/Pasted_image_20250813190102.png)

- After setting breakpoints, I ran the program until it hit the relevant instruction.

![Pasted image 20250813191420.png](images/Pasted_image_20250813191420.png)

- At this point, I entered the test input string: **`JEEL`**.

![Pasted image 20250813191453.png](images/Pasted_image_20250813191453.png)

- I then continued execution to the section where the **string comparison** occurs.  
    These instructions are particularly interesting because they load the two strings into registers before the `strcmp` call:
    - First string → `RDX` (the user’s input)
    - Second string → `RAX` (the stored, correct password)

![Pasted image 20250813190341.png](images/Pasted_image_20250813190341.png)

- **`strcmp` Call Instruction:**

![Pasted image 20250813190322.png](images/Pasted_image_20250813190322.png)

- **Register values at the moment of comparison:**
    - User’s input: `"JEEL"`
    - Stored password: `"easi123"` — which is the correct key/flag for the program.

![Pasted image 20250813191247.png](images/Pasted_image_20250813191247.png)

![Pasted image 20250813191343.png](images/Pasted_image_20250813191343.png)