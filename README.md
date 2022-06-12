# WeCTF 2022

Thank you for participating! Please share your writeup at CTFtime https://ctftime.org/event/1546/.

### Run Challenges Locally (WIP, not fully working yet)
```bash
git clone https://github.com/wectf/2022
cd 2022 && docker-compose up
```

### Dino Run

Welcome to WECTF! Play this tiny multiplayer game and get the easy flag.


> Source Code: [dino-run/](https://github.com/wectf/2022/tree/master/dino-run)  
> Local Address (WS): http://localhost:1001  
> Local Address (Frontend): http://localhost:1012  
> Solved Count: 159  
> Points: 10  

Intended Solution: 
* Simply go to the bottom right corner and the flag is alerted.

### Grafana

It looks safe, does it? After all it has a fancy UI so it must be safe.


> Source Code: [grafana/](https://github.com/wectf/2022/tree/master/grafana)  
> Local Address: http://localhost:1002  
> Solved Count: 100  
> Points: 16  
> Attack Type: Directory Traversal  

Intended Solution: 
* A Grafana (v8.3.0) instance is provided and the task is to leak flag at `/tmp/flag`. 
* There is a known vulnerability CVE-2021-43798 that could lead to directory traversal.


PoC:

```bash
curl --path-as-is [TARGET]/public/plugins/alertmanager/../../../../../../../../tmp/flag
```

### Google Wayback


A copycat site of Google in 2001.  

Hint: Do you know Google used to have XSS?  

An admin bot is going to visit the link you provided and your task is to leak the cookie of admin. You can simulate this locally but first navigate to the site, execute JavaScript: `document.cookie = "flag: we{test}"` and finally visit the link that points to your payload. 

> Source Code: [google/](https://github.com/wectf/2022/tree/master/google)  
> Local Address: http://localhost:1003  
> Solved Count: 338  
> Points: 25  
> Attack Type: CSRF, XSS  

Intended Solution: 
* There is an obvious XSS. By posting the query as `"/><img onerror="alert(1)" src=1 />` to `/search.php`, you can excecute arbitrary JavaScript. 
* `/search.php` only accepts POST request with correct ReCAPTCHA response token, otherwise it would die and no JS is executed. Thus, to trigger the XSS, one needs to conduct a CSRF attack that conducts a POST request with correct ReCAPTCHA token solved before manually. 
* ReCAPTCHA token would expire around 30s. As soon as the token is provided, one should immediately conduct a CSRF attack with the token. 


PoC:

```html
<form action="/search.php?q=[XSS PAYLOAD]" method="post" id="f">
<input name="g-recaptcha-response" value="[RESPONSE YOU JUST SOLVED]"/>
<input name="q" value="[XSS PAYLOAD]"/>
</form>
<script>f.submit()</script>
```
Save this as an HTML file and submit the link point to this file to admin bot. 


### Dino Run (Extra Hard)

Isn't the Dino Run too easy? Try out this more difficult one.


> Source Code: [dino-run/](https://github.com/wectf/2022/tree/master/dino-run)  
> Local Address (WS): http://localhost:1004  
> Local Address (Frontend): http://localhost:1013  
> Solved Count: 9  
> Points: 585  
> Attack Type: JWT Token Reuse  

Intended Solution: 
* Whether the dinos are dead is maintained through a signed JWT that the server could verify it is not modified by the users. The signed JWT is updated every move and send back to the user. If the dino is determined to be dead (randomly with likelihood at ~99%), the JWT token would have its attribute `dead` set to true. A dead dino can not move anymore. 
* JWT is properly signed so no JWT modification can be done.
* JWT token can be reused if its attribute `dead` is false. By reusing a JWT token obtained before, one can recover their dino at any past location that your dino is not dead. 
* Repeatedly reusing the JWT token until you are at the bottom right, the flag would be sent to you along with the JWT token. 



### Pkg

Shou hoards a flag in a NodeJS binary and he thinks it is safe. Prove him wrong.


> Source Code: [pkg/](https://github.com/wectf/2022/tree/master/pkg)  
> Solved Count: 8  
> Points: 616  

Intended Solution: 
* A binary is provided. By using `strings [PATH TO BINARY]` to inspect, one can find the complete content of `package.json`, which points to vercel/pkg is the tool used for converting a NodeJS program to a binary. 
* vercel/pkg maintains an offset table at the end of the binary. One can leverage this table to extract content of all JS files. 
* vercel/pkg compiles main.js to V8 bytecode, which is unreadable. However, existence of `private_key.der`, along with the content of `package.json` (importing NodeRSA), can help one guess the flag is encrypted with RSA using that private key and can be decrypted using that private key too. 


### Pkg (Extra Hard)

Shou hoards the flag better with more obfuscation now. He looks scared.  

Hint: How about capturing what is sent to remote server?  

> Source Code: [pkg-hard/](https://github.com/wectf/2022/tree/master/pkg-hard)  
> Solved Count: 3  
> Points: 846  

Intended Solution: 
* Extract all JS files as described before. 
* Option 1 (Dynamic Analysis):
    * Use Frida hook `SSL_read(SSL *ssl, void *buf, int num)` and `SSL_write(SSL *ssl, const void *buf, int num)` to capture HTTPS traffic.
    * Run bytecode in `encryption1.js` V8 VM and find out that encrypt/decrypt methods are just simple one time pad implementation. 
    * Recover the double encrypted flag from remote server.
    * Replace `encryption1.js` with JS that simple console.log the args and run the express app. One can find it is called twice with different OTP when visiting `/check_flag`. 
    * Recover the encrypted flag with hard coded OTP. 

* Option 2 (Static Analysis):
    * Convert all bytecode to instructions and analyze them.
    * Helpful Links: https://swarm.ptsecurity.com/how-we-bypassed-bytenode-and-decompiled-node-js-bytecode-in-ghidra/
    * Helpful V8 Opcode => Instruction Reference: https://github.com/shouc/v8_opcodes & https://chromium.googlesource.com/v8/v8/+/refs/heads/lkgr/src/compiler/opcodes.h



### Request Bin

Request bin has been one of the most helpful tool for Shou during his software (CRUD) engineering career! So, he decided to create yet another one by himself.

Flag is located at /flag

> Source Code: [request-bin/](https://github.com/wectf/2022/tree/master/request-bin)  
> Local Address: http://localhost:1005  
> Solved Count: 21  
> Points: 1610  
> Attack Type: Template Injection  

Intended Solution: 
* You can inject a template at `Custom Formatter` field. 
* Golang template can access and call all public attributes and methods of the struct passed into `templste.Template.Execute`. Here, the struct passed in is `iris.AccessLog.Log`. It has an attribute `Ctx` which is  of`iris.Context` struct type. Using `Ctx`, one can call its function to serve a static file, including the flag. 

PoC:  
Put `{{ .Ctx.ServeFile "/flag" }}` at `Custom Formatter` field. 



### Request Bin (Extra Hard)

I suppose you have already managed to steal Shou's flag. Shou is also aware of this so he hided the flag better. What's more can you accomplish with Shou's buggy app?

> Source Code: [request-bin/](https://github.com/wectf/2022/tree/master/request-bin)  
> Local Address: http://localhost:1006  
> Solved Count: 4  
> Points: 2526  
> Attack Type: Template Injection  

Intended Solution: 
* Different from last one, the flag in this challenge is saved at a random file name. 
* Various attack plans possible.


### Status Page

Shou just heard Grafana can be used as a backdoor. He is scared. So, he developed a simple status page, which he believes is safer, as a replacement of Grafana.  

Flag is of format we{[UUID]@[a-zA-Z0-9!-@\$%\^\(\)=\ \|\\]+}  

> Source Code: [status-page/](https://github.com/wectf/2022/tree/master/status-page)  
> Local Address: http://localhost:1007  
> Solved Count: 6  
> Points: 2311  
> Attack Type: SQL Injection  

Intended Solution: 
* There is SQL injection in parameter `minutes` in `/q` endpoint, which executes SQL at an InfluxDB instance.
* InfluxDB uses a restricted set of SQL. There is no UNION, etc. 
* To leak the flag, one must first leak database name (`SHOW DATABASES`), measurement name (`SHOW MEASUREMENTS ON [DB]`), and the flag (`SELECT * FROM [MEASUREMENT]`). 
* One can append queries using `;` (similar to UNION), but the result of appended queries are not returned (i.e., not visible). 
* The only visible tables are `network.*`. One can use `SELECT INTO` with subquery to insert any leaked data into these tables. 
* `SHOW DATABSE / MEASUREMENTS` cannot be used as a subquery (only `SELECT` can) but same info can be found from a database with name `_internal` (similar to information_schema in MySQL). So, a `SELECT` to coresponding measurement can gives the same info. 
* Combining these together, one can easily get the flag. 


### File.io

Another tool Shou constantly use is file.io, a file sharing website. However, Shou deems it to be an unsecure practice to store his seemingly secret files there. Thus, he developed a copycat of it.

Note: Flag is in the file admin uploaded


> Source Code: [fileio/](https://github.com/wectf/2022/tree/master/fileio)  
> Local Address: http://localhost:1008  
> Solved Count: 2  
> Points: 2815  
> Attack Type: XSS, Open Redirect  

Intended Solution: 
* There are three obvious vulnerabilities:
    * Self-XSS - The filename of uploaded file can be used to insert arbitrary HTML code. However, only you and the receiver can see this. 
    * Open Redirect - `/register_token?back=[ARBITRARY URL]`. The final page that actually conduct redirects is `/sync_token?token=[NEW TOKEN]&back[ARBITRARY URL]`. One can leak this full URL by referrer header at `[ARBITRARY URL]`. However, referrer policy in Chrome states that unless `[ARBITRARY URL]` and redirect initator are at same origin, only domain of redirect initiator is sent. 
    * Client-side Caching - All URL containing string `/files/` would have a header `Cache-Control: max-age=100000` (the response is cached by the browser for 100000s). 
* One of Possible Attack Plans
    * Cache the home page, which contains the file token and user token of admin bot (Token A).
    * Set a new token (Token B) using by opening `/register_token?back=/file_info/[A FILE TOKEN YOU OWN]`. `/file_info` endpoint would log the referrer so that one can gain this token at their side. 
    * Send Token B a file and open the page at the admin bot side. Then, arbitrary JS code can be executed at admin bot side. 
    * Use injected JS to fetch the cached home page and get Token A and file token. 
    * Download the flag using both token. 



### HTTPS Verifier

Just yet another HTTPS verifier that verifies the site enables HTTPS.

Flag is at /flag.

> Source Code: [https_verifier/](https://github.com/wectf/2022/tree/master/https-verifier)  
> Local Address: http://localhost:1009  
> Solved Count: 2  
> Points: 2815  
> Attack Type: TLS Poisoning  

Intended Solution: 
* Conduct TLS Poisoning for localhost:5044, which Logstash is listening. 
* Logstash is vulnerable to Log4Shell. Use TLS Poisoning to inject `[JUNK][YOUR JNDI]\r\n[JUNK]`.



### Flag Checker

Shou just wrote a flag checker. He thinks it is super safe because it comes with TLS, latest H2 protocol, IP restriction, etc.

Note: You can safely ignore the certification check :).
Note: Flag is 48 a-z0-9 characters wrapped with we{...}

Hint: Can you brute force the flag one char by one char? That only needs around 48x34 requests!

Flag is at /flag.

> Source Code: [flag-checker/](https://github.com/wectf/2022/tree/master/flag-checker)  
> Local Address: https://localhost:1010  
> Solved Count: 0  
> Points: 3000  
> Attack Type: Header Injection, Side Channel  

Intended Solution: 
* node-http2 does not properly sanitize the method field, nor does the proxy. You can insert arbitrary headers by setting methods as `GET /[URL YOU WANT TO VISIT]\r\n[HEADERS]\r\n\r\n`. This way you can bypass the IP checker. 
* You can leak the flag one char by one char. By leveraging previous header injection, you can inject a `Connection: Keep-Alive` and repeat each requests thousands of times in one single TCP connection to get very large timing difference (around 2000 reqs for second level difference). For instance, you can find out which is correct first char of the flag by comparing time of two requests with following method field (ignoring OTP for simplicity):  

    flag[3] = a?  
    ```
    GET /check_flag?flag=we{a\r\n
    Connection: Keep-Alive\r\n\r\n
    GET /check_flag?flag=we{a\r\n
    Connection: Keep-Alive\r\n\r\n
    ....
    Repeat 2000 times
    GET
    ```

    flag[3] = b?  
    ```
    GET /check_flag?flag=we{b\r\n
    Connection: Keep-Alive\r\n\r\n
    GET /check_flag?flag=we{b\r\n
    Connection: Keep-Alive\r\n\r\n
    ....
    Repeat 2000 times
    GET
    ```

    If flag is `b`, then second request would take significantly longer time. 
* To avoid JIT optimizatiion, one can use OTP as well as sending requests that divert from the path with timing sensitive requests. 


### Read And Burn
Similarly, Shou does not trust Telegram, Discord, WeChat, etc. He made a super secure chat app that leaves no trace about past messages!

The admin (bot with username "admin") will first view the message containing flag sent from a random user and then purge its account. Finally, you submitted link is visited.

Note: If the page does not function, check whether you are using HTTPS. Also, the challenge is related to service worker. Use a browser that supports service worker.

Hint: Prototype pollution can alter something so that maybe you can read browser cache.
Hint: Do you know the searching function can even search the reponses of URLs included in the messages?

Flag is at /flag.

> Source Code: [readandburn/](https://github.com/wectf/2022/tree/master/readandburn)  
> Local Address: http://127.0.0.1:1011   
> Solved Count: 0  
> Points: 3000  
> Attack Type: Prototype Injection, XS-Leak   
 
Intended Solution: 
* There are three obvious vulnerabilities:
    * Prototype Pollution - `deepyCopyHelper` in service-worker.js is vulnerable to prototype pollution. It is used to copy each message received. Since `POST /api/message/xxx` accepts any JSON, one can make message as a dict and conduct prototype pollution: `{"constructor": {"prototype": {"[TO POLLUTE KEY]": "[TO POLLUTE VALUE]"}}}`.
    * XS-Leak - You can leak any same origin responses in `/search#[q]` endpoint by monitoring the GET request sent. 
* One of Possible Attack Plans
    * Register a new user for admin bot with username A.
    * Send username A a message: `{"constructor": {"prototype": {"headers": {"ETag": "[HASH]"}}}}`, where `[HASH]` is current response of `/api/messages/admin` to hijack headers. Why ETag? If browser sends a ETag having same value as the hash of current response, Express gives 304 Not Modified and browser would return response from cache. This is the only way to read the purged messages of admin. 
    * Send `/api/messages/admin` to username A and conduct XS-Leak at `/search` endpoint. 
