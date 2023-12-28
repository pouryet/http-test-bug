#sudo apt-get install python-pip #for linux or for install pip in windows search google
#https://t.me/pouryet
#Don't forget to put a star

#pip install requests
#pip install re
#pip install subprocess

import requests
import subprocess
import re

# Target website URL
url = "http://Example.com"

# Send HTTP GET request to the target website
response = requests.get(url)

# Check for unusual HTTP response headers that could indicate a vulnerability
if "X-Frame-Options" not in response.headers:
    print("[WARNING] Missing X-Frame-Options header. The website may be vulnerable to clickjacking attacks.")

# Check for common security vulnerabilities using third-party tools
# SQL Injection
sqlmap_cmd = "sqlmap -u {0} --dbs".format(url)
sqlmap_output = subprocess.check_output(sqlmap_cmd, shell=True)
if "available databases" in sqlmap_output.lower():
    print("[WARNING] The website may be vulnerable to SQL Injection attacks.")

# Cross-Site Scripting (XSS)
xsstrike_cmd = "xsstrike -u {0} -p name".format(url)
xsstrike_output = subprocess.check_output(xsstrike_cmd, shell=True)
if "payload reflected in a tag attribute value" in xsstrike_output.lower():
    print("[WARNING] The website may be vulnerable to Cross-Site Scripting (XSS) attacks.")

# File Inclusion Vulnerabilities
dirbuster_cmd = "dirb {0} -X .php".format(url)
dirbuster_output = subprocess.check_output(dirbuster_cmd, shell=True)
if "directory listing" in dirbuster_output.lower():
    print("[WARNING] The website may be vulnerable to File Inclusion attacks.")

# Check for outdated software or plugins
nmap_cmd = "nmap -p 80 --script http-vuln-* {0}".format(url)
nmap_output = subprocess.check_output(nmap_cmd, shell=True)
if "exploit available" in nmap_output.lower():
    print("[WARNING] The website may be using outdated software or plugins that are vulnerable to known exploits.")

# Check for misconfigurations in the server or application
owasp_zap_cmd = "zap.sh -cmd -quickurl {0} -quickprogress".format(url)
owasp_zap_output = subprocess.check_output(owasp_zap_cmd, shell=True)
if "alerts" in owasp_zap_output.lower():
    print("[WARNING] The website may have misconfigurations in the server or application that can be exploited by attackers.")

# Check for sensitive information leaks
burp_suite_cmd = "java -jar burpsuite.jar --unpause-spider-and-scanner --crawl --scope {0}".format(url)
burp_suite_output = subprocess.check_output(burp_suite_cmd, shell=True)
if "password" in burp_suite_output.lower():
    print("[WARNING] The website may be leaking sensitive information such as passwords.")

# Check for other common vulnerabilities using a vulnerability scanner
nikto_cmd = "nikto -host {0}".format(url)
nikto_output = subprocess.check_output(nikto_cmd, shell=True)
if "information disclosure" in nikto_output.lower():
    print("[WARNING] The website may be disclosing sensitive information.")
if "insecure cookies" in nikto_output.lower():
    print("[WARNING] The website may be using insecure cookies that can be hijacked by attackers.")
if "file upload" in nikto_output.lower():
    print("[WARNING] The website may be vulnerable to file upload attacks.")
if "server-side include" in nikto_output.lower():
    print("[WARNING] The website may be vulnerable to Server-Side Include (SSI) attacks.")
