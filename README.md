# Security_scanner
A python tool that resemble a vulnerability scanner. It looks for SQL injection, XSS and Directory Traversal vulnerabilities and introduce the suitable remediation for each vulnerability. 


# Code Explaination: 
We need to use requests, datetime and json for this tool, so we will recall it at the beginning of the code.

`import requests`  
`from datetime import datetime`  
`import json`  

**requests:** Library to make HTTP requests (GET, POST, etc.).  
**datetime:** To add temporal character when recording gaps.  
**json:** To handle JSON data (reports).  


