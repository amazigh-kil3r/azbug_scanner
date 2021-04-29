Azbug Tool Scanner
=========

![Build](https://img.shields.io/badge/Built%20with-Python-Blue)
<a href="">
    ![Tweet](https://img.shields.io/twitter/url?url=https%3A%2F%2Fgithub.com%2Fmaurosoria%2Fdirsearch)
</a>

**Current Release: v2.0 (2021.04.1)**

What is Azbug ?
=======

- Azbug is an awsome tool which is made with python 2 that is switching your manual recon (Discovering, scanning, fuzzing and full recon methodology and more ...) into an automated one, which makes your bug hunting and your life much easier.

- Azbug is being developed by [Trojan Kil3r Amazigh](https://twitter.com/Kil3rdz)

Installation & Usage
=========
### NOTE: Azbug is made with python and requires python2 to run perfectly.
```
git clone https://github.com/Azrecon/Azbug.git
cd Azbug
pip install -r requirements.txt
python Azbug.py
```
Why Azbug?
=========

### As we said this tool has multitasking that's why it's divided into four (4) sections:

- Bugs scanning
  - [01] ~ Sql Blind Time-Bassed [GET]
  - [02] ~ Sql Blind Time-Bassed Via Header
  - [03] ~ Cross site Scripting [XSS]
  - [04] ~ PHP CODE INNJECTION & OS COMAND INNJECTION
  - [05] ~ Server Side Template Injection [SSTI]
  - [06] ~ Open Redirection
  - [07] ~ RFI & Local File Inclusion
  - [08] ~ Host Header Injection
  - [09] ~ Cross-origin resource sharing (CORS)
  - [10] ~ Server-side request forgery (SSRF)
- Domain Gethering
    - [11] ~ Subdomain Finder Online
    - [12] ~ Subdomain Enumiration
    - [13] ~ Nmap Scan Ports Online

- Fuzzing and Discovery
  - [14] ~ Status Checker
  - [15] ~ Path Directory Finder
  - [16] ~ SubDomain TakeOver
  - [17] ~ Scret Key Finder
  - [18] ~ Web Crawlers
  - [19] ~ Waybackurls With Filtres Links
  - [20] ~ Google Map Api KEY Scanner
  - [21] ~ Hidden Parameter Discovery
- Dorking
  - [22] ~ Bing Dorker | Sub Binger
### Azbug Scanner Screen
[![Azbug](https://asciinema.org/a/MaWuJvmjRqNQQJ8zuspt0WygH.svg)](https://asciinema.org/a/S34vc8VuRs07vwrpHiRb7xEtF)

You have a secret payloads?
------------------
- cool! you can add them easily by adding them into the script, it can be done with going to dictionary {} and paste them there, for example XSS:

```
  xss_payload = {"____________________secrect_payload": "_________response_keyword"}
  xss_payload = {"%3Cscript%3Ealert(1)%3C%2Fscript%3E": "<script>alert(1)</script>"}
```
what else ? you need to scan links with cookies ?
-------------------------
- Remember , this small tool is only running with python3
- No worries i got you ;) , i made a small tool that will help you converting your cookie strings into a dictionary ones.
- So to use it simply run cookies_convert.py and  paste your cookie string. 
- Simple example : copy cookies from burpsuite and paste it into cookies_convert.py you will get dictionary output result, copy & paste it into Azbug.py and Start Your Scanning Target.

How to use ??
------------
### How Convert Cookie String To Cookie Dictionnary
[![Cookie_Converter](https://asciinema.org/a/hccYaFiDzgUvS0DgGYpPB4NVg.svg)](https://asciinema.org/a/hccYaFiDzgUvS0DgGYpPB4NVg)

Full Video Of How Using Tool Azbug Scanner :)
[![Azbug](https://cdn..com/logos/hackerone.svg)](https://www.youtube.com/watch?v=f0YtHM2WbBE)

