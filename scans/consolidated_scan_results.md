# Wapiti Scan Results
## Content Security Policy Configuration
**Path:** /login.php
**Method:** GET
**Info:** CSP is not set
**Level:** 1
**Parameter:** 
**Referer:** 
**Module:** csp
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
