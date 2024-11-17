---
title: KPMG CTF Writeups Aug 2024
published: 2024-04-01
description: Some Writeups of KPMG 2024.
tags: [KPMG, Aug 2024]
image: "images/cover.png"
category: CTF Writeup
draft: false
---


# KPMG CTF

# Welcome

![Screenshot 2024-08-11 123235.png](images/Screenshot_2024-08-11_123235.png)

- We can directly cat the flag file from the website terminal,

![Screenshot 2024-08-11 172821.png](images/Screenshot_2024-08-11_172821.png)

# Cloud

## Presign Rains

![Screenshot 2024-08-11 122031.png](images/Screenshot_2024-08-11_122031.png)

- Here, after completing the cloud challenge, I was excited to solve this challenge, but here we got a website link.

![Screenshot 2024-08-11 121823.png](images/31aed4b1-28a1-413b-9e54-02d2d992400e.png)

- From the website, there is no hint related to flag, so I looked at the source code:

![Screenshot 2024-08-11 121832.png](images/d8a90ed0-f0ab-48fa-909e-208ff0d81747.png)

- Here we got the access key and bucket:

`access key →  AKIA33VJAWOZJLLBCU2A`
`bucket: ctf2k24-best`

- First, I thought of using AWS cli, but it also needs a secret key and region. So I tried reconnaissance further, and it led to robots.

![Screenshot 2024-08-11 121852.png](images/83d9f2f4-f3d7-4346-bf29-1ef5303cf54c.png)

 

- Here we got many things. I thought there would be credentials in this directory, but these were the credentials. 
the robot directory:

![Screenshot 2024-08-11 121909.png](images/d2850b70-f761-470c-baf4-ff55f7b03b0e.png)

- Link :- [`https://<bucket-name>.s3.us-east-1.amazonaws.com/flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=<aws access key>%2F20240808%2F<region>%2Fs3%2Faws4_request&X-Amz-Date=<Date>&X-Amz-Expires=<expire-time>&X-Amz-SignedHeaders=host&X-Amz-Signature=](https://ctf2k24-best.s3.us-east-1.amazonaws.com/flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA33VJAWOZJLLBCU2A%2F20240808%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240808T094405Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=5625d8f847a29410e05b91df5628d6d2fa8146eed792c0ae048279798853d1b9)<singature>`
- From this link, it was clear that the credential can be used here, and we will get the flag.
- Credential used here:

`bucket -> ctf2k24-best`

`access key →  AKIA33VJAWOZJLLBCU2A`

`Expires → 604800`

`date → 20240808T094405Z`

`region → us-east-1`

`signature → 5625d8f847a29410e05b91df5628d6d2fa8146eed792c0ae048279798853d1b9`

- Update Link :- [`https://ctf2k24-best.s3.us-east-1.amazonaws.com/flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA33VJAWOZJLLBCU2A%2F20240808%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240808T094405Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=5625d8f847a29410e05b91df5628d6d2fa8146eed792c0ae048279798853d1b9`](https://ctf2k24-best.s3.us-east-1.amazonaws.com/flag.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA33VJAWOZJLLBCU2A%2F20240808%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240808T094405Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=5625d8f847a29410e05b91df5628d6d2fa8146eed792c0ae048279798853d1b9)
- After visiting the link,

![Screenshot 2024-08-11 121954.png](images/Screenshot_2024-08-11_121954.png)

- Here, I thought that I had to use this directory in the link:

![image.png](images/image.png)

- I got an error, then I tried using this directory path on the link they have provided and i got the flag, 🫡

![Screenshot 2024-08-11 122009.png](images/Screenshot_2024-08-11_122009.png)

## Data Valut Duel

![Screenshot 2024-08-11 122022.png](images/Screenshot_2024-08-11_122022.png)

- From the description, I can see that the bucket name is given, which is publicly accessible, but I don’t have the AWS account, so I am not able to use AWS-cli directly, so I searched for this and got this AWS flag from searching.

```bash
aws s3 ls s3://kpmg-ctf1 --no-sign-reques
```

- From this command, I got some info about the bucket, like the available files in it, and one of the files is `rituognriteuonhbiorentgbvhuitrhoirtsnbiuort.txt`.

![image.png](images/image%201.png)

- but without credentials, I can’t access this, so again, I tried to google how I could access it, and I found that using `wget` or `curl`, we can directly access that S3 bucket.

```bash
curl -O https://kpmg-ctf1.s3.ap-south-1.amazonaws.com/rituognriteuonhbiorentgbvhuitrhoirtsnbiuort.txt
```

- Using this command, I can curl the flag directly. hehe Piece of Cake 🫠

![image.png](images/image%202.png)

# OSINT

## Hacking The Admins

![Screenshot 2024-08-11 121938.png](images/Screenshot_2024-08-11_121938.png)

- From the text I guess that we have to search for the name `Raghava Sai Sarva` and I got a LinkedIn link:

![Screenshot 2024-08-11 122125.png](images/Screenshot_2024-08-11_122125.png)

- There is a hash in the description it is a base64 hash:

**`TmV2ZXlgZ29ubmEgZ212ZSB5b3UgdXAKTmV2ZXlgZ29ubmEgbGVOlHlvdSBkb3duCk51dmVylGdvbm5hlHJ1 bmQ
gYW5klGRlc2VydCB5b3UKTmV2ZXlgZ29ubmEgbWFrZSB5b3UgY3J5Ck51dmVylGdvbm5hlHNheSBnb29kYnllCk51dmVylGdvbm5hlHRlbGwgYSBsaWUgYW5klGh 1 cnQgeW91 CgpodHRwczovBBhc3RlYmluLmNvbS9uWm1 ibkJRMyAtlG 1 lb3c=`**

- After decoding using CyberChef:

![Screenshot 2024-08-11 122141.png](images/Screenshot_2024-08-11_122141.png)

- I got a Pastebin link, let go and see what is there in the link:

![Screenshot 2024-08-11 122210.png](images/Screenshot_2024-08-11_122210.png)

- From Previous Pastebin I got LinkedIn link and text that tells me to check the discord of `eren_meow` account,

![image.png](images/image%203.png)

- Here we got a base58 hash:

![image.png](images/image%204.png)

- let's go to the link::

![image.png](images/image%205.png)

- It password Protected so check out the discord account mentioned previously `eren_meow`, then let check the discord:

![image.png](images/image%206.png)

- here we got an hash that is Base58:

![image.png](images/image%207.png)

- Then We open the pastebin using `meowsaurabh123!` password,

![Screenshot 2024-08-11 122922.png](images/Screenshot_2024-08-11_122922.png)

- Here again we got a LinkedIn link and a brainfuck code:

![Screenshot 2024-08-11 122959.png](images/Screenshot_2024-08-11_122959.png)

- In the LinkedIn they have given a `pastebin link`:

![image.png](images/image%208.png)

- I got the flag 🫡

![Screenshot 2024-08-11 123047.png](images/Screenshot_2024-08-11_123047.png)

# Web

## Memorandum Dissolve 5

![Screenshot 2024-08-11 122059.png](images/Screenshot_2024-08-11_122059.png)

- In this Challenge I got an login page:

![Screenshot 2024-08-11 121108.png](images/Screenshot_2024-08-11_121108.png)

- As I first checked the source code of the page(which i think is a best practice), Here, they have provided the test username and password

![Screenshot 2024-08-11 121158.png](images/Screenshot_2024-08-11_121108%201.png)

- after logging in, I got a Welcome page, here I opened the inspect tool, for checking if there is any cookie is being used and i got the session cookie

![Screenshot 2024-08-11 121212.png](images/Screenshot_2024-08-11_121212.png)

- The session looked like it was an md5 hash so i tried to crack it using online decoder([https://md5hashing.net/hash/md5/2cb42f8734ea607eefed3b70af13bbd3](https://md5hashing.net/hash/md5/2cb42f8734ea607eefed3b70af13bbd3)):
- MD5 hash:
    
     `test → 098f6bcd4621 d373cade4e832627b4f6`
    
- As I suspected, the session key is the username so i tried using admin md5 hash as a session key
- MD5 hash:
    
    `admin → 21232f297a57a5a743894aee4a801fc3`
    

![Screenshot 2024-08-11 121457.png](images/Screenshot_2024-08-11_121457.png)

![Screenshot 2024-08-11 121506.png](images/Screenshot_2024-08-11_121506.png)

And we got the Flag. 🫡

# ISC

## Assassins Brotherhood - 1

![Screenshot 2024-08-11 121950.png](images/Screenshot_2024-08-11_121950.png)

- As per the description, we have given the URL, host, and port.
- First, I do the `http://0.cloud.chals.io 27232` And from this, I know that on this port, SSH is running By showing the SSH header, I got.
- After that i try to access the website,

![Screenshot 2024-08-11 120328.png](images/Screenshot_2024-08-11_120328.png)

- After that, I viewed the page source, and I got this from it

![Screenshot 2024-08-11 120340.png](images/Screenshot_2024-08-11_120340.png)

- And I said I knew that one server, SSH, was running, and this statement pointed out the username and password of the `Ezio` user, so i try to connect with SSH,
- Connected Successfully and got flag on `ezio.txt` file, 🫠

![Screenshot 2024-08-11 120528.png](images/Screenshot_2024-08-11_120528.png)

# Crypto

## Micro RSA

![Screenshot 2024-08-11 122040.png](images/Screenshot_2024-08-11_122040.png)

- From this challenge i got values.txt file which contains this information,

```bash
n=124654455290240170438072831687154216330318678151127912274279675542477378324205547190448356708255017687037267403854771170485302392671467974951403923256433631043504787586559727625072674672756729381597771352105733117303538360769540765664178969569213281846028712352533347099724394655235654023223677262377960566427
e=3
c=11127001790949419009337112638492797447460274274218482444358708583659626034144288836997001734324915439994099506833199252902923750945134774986248955381033641128827831707738209340996252344658078512599270181951581644119582075332702905417250405953125
```

- I make a python script which performs `RSA encryption padding attack`,
- Reference - [https://shainer.github.io/crypto/matasano/2017/10/14/rsa-padding-oracle-attack.html](https://shainer.github.io/crypto/matasano/2017/10/14/rsa-padding-oracle-attack.html)

```python
from decimal import *
from tqdm import tqdm

N = Decimal(124654455290240170438072831687154216330318678151127912274279675542477378324205547190448356708255017687037267403854771170485302392671467974951403923256433631043504787586559727625072674672756729381597771352105733117303538360769540765664178969569213281846028712352533347099724394655235654023223677262377960566427)
e = Decimal(3)
c = Decimal(11127001790949419009337112638492797447460274274218482444358708583659626034144288836997001734324915439994099506833199252902923750945134774986248955381033641128827831707738209340996252344658078512599270181951581644119582075332702905417250405953125)

def int_to_ascii(m):
    # Decode to ascii (from https://crypto.stackexchange.com/a/80346)
    m_hex = hex(int(m))[2:-1]  # Number to hex
    m_ascii = "".join(
        chr(int(m_hex[i : i + 2], 16)) for i in range(0, len(m_hex), 2)
    )  # Hex to Ascii
    return m_ascii

# Find padding
getcontext().prec = 280  # Increase precision
padding = 0
for k in tqdm(range(0, 10_000)):
    m = pow(k * N + c, 1 / e)
    m_ascii = int_to_ascii(m)

    if "pico" in m_ascii:
        padding = k
        break

print("Padding: %s" % padding)

# Increase precision further to get entire flag
getcontext().prec = 700

m = pow(padding * N + c, 1 / e)
m_ascii = int_to_ascii(m)
print("Flag: %s" % m_ascii.strip())
```

- After Running this script, I got the flag!!

```bash
KPMG_CTF{sm4ll_e_15_n07_s0_s3cur3}
```

## Crypts Beyond The Wall

![Screenshot 2024-08-11 122048.png](images/Screenshot_2024-08-11_122048.png)

- When I tried to access the website, I got this:

![Screenshot 2024-08-11 121641.png](images/Screenshot_2024-08-11_121641.png)

`Winter is Coming`: If you are a true fan of Game of Thrones, then you know this line:

- Now I try to open the source code, and from that I get this comment:

![Screenshot 2024-08-11 121653.png](images/Screenshot_2024-08-11_121653.png)

- When I tried to decode this encoded base64 string, I got 'Tormund.txt'.

![Screenshot 2024-08-11 121714.png](images/Screenshot_2024-08-11_121714.png)

- Then I tried to access that page, and I got this:

![Screenshot 2024-08-11 121739.png](images/90089407-275f-47cd-8ce0-21fdcbaa082d.png)

- And from that page, I got another `BeyondTheWallsLogs.txt` and a hint `giantsmik` file, which gives me,

![Screenshot 2024-08-11 121759.png](images/419ea733-af89-456e-a1d1-ba9fc3debd3c.png)

- From this image, I got a cipher text, which I think is `vigenere cipher` so I tried to decode it with the key `giantsmilk`.

![Screenshot 2024-08-11 121837.png](images/Screenshot_2024-08-11_121837.png)

- From that, I got `/S3cr3Ts0ftH3Wa1L4nD83YonD.html` and from this file, I got the flag.

![Screenshot 2024-08-11 121903.png](images/aad01799-9b30-44df-81c1-e72bf2cf4ae6.png)

# Mobile

## Android CryptoQuest

![images/Screenshot_2024-08-11_122111.png](images/Screenshot_2024-08-11_122111.png)

- From the description, we got the apk file `mobilechall1.apk`.
- After decompiling the file with [`jadx-gui`](https://github.com/skylot/jadx) software for Windows,.
- After digging around in the decompiled classes and Java files, I found an example. `example.ctfchall` package which contains the class files of the decompiled code, and from this directory, i got the `MainActivity` file, which contains the `half-flag` in encoded format.

![images/image%209.png](images/image%209.png)

- After decoding this base85-encoded string, I got to know that this flag was pointing out something, which is `AndroidManifest.xml` file,

![images/image%2010.png](images/image%2010.png)

- Then check out the `AndroidManifest.xml` file and hurray i got the another part of flag then i decode it with base64 scheme and assemble the flag,

![images/image%2011.png](images/image%2011.png)

![images/image%2012.png](images/image%2012.png)

- Assembling the Flag,

![images/image%2013.png](images/image%2013.png)

# OT

## Modulus bus Station

![Screenshot 2024-08-11 121959.png](images/Screenshot_2024-08-11_121959.png)

- As per decryption, I can understand that I have to use the Modbus client tool to connect with the protocol. After some searching, I found a tool named `modbus_cli`.

```bash
pip install modbus-cli
```

- After installing it, I saw the manual for its usage, and after a while, I knew how to use it and got some raw data bytes in hex.

![Screenshot 2024-08-11 121143.png](images/Screenshot_2024-08-11_121143.png)

![image.png](images/image%2014.png)

- I cleaned up the data in these 3 steps:
    1. First, grep all the hex data and remove other stuff in a file.
    2. Then I convert each bytes hex to ASCII character equivalent.
    3. Then remove all the duplicate bytes from the data.
    4. Then combine all the data.

![image.png](images/image%2015.png)

- Then i try to decode it from CyberChef and i got the flag, 🫠

![image.png](images/image%2016.png)

## mqtt - Master Qutie TT - P1

![Screenshot 2024-08-11 122010.png](images/Screenshot_2024-08-11_122010.png)

- As per the decryption given, we have to access the HVAC system and try to subscribe to all the subtopics.
- So first of all, I don’t know how to access the mqtt service, so I just did a Google search and got the treasure.
- [**`1883: Pentesting MQTT (Mosquitto)`**](https://book.hacktricks.xyz/network-services-pentesting/1883-pentesting-mqtt-mosquitto)
- From this, I know which tool to use and how to use it, so I use `Mosquito.`

```bash
apt-get install mosquitto mosquitto-clients # Install the tool
```

- From Blog, I used the -t option for subscribing to all the subtopics, and from that, I got the flag. 🕺

![Screenshot 2024-08-11 120824.png](images/Screenshot_2024-08-11_120824.png)
