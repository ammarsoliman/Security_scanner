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

Security scanner class will be created, including definitions of scanner components such as vulnerability logs, remediation and vulnerability tests.

`class VulnerabilityScanner:`  
    `def __init__(self, target_url, output_file="vulnerability_report.json", report_format="json"):`  
        `self.target_url = target_url`  
        `self.output_file = output_file`  
        `self.report_format = report_format`  
        `self.vulnerabilities = []  # a list for dicoverd vulns`  
        `self.session = requests.Session()  # to create a session for each request `  

`__ init __`: Configure the object with parameters:  
`self`: a reference to the object being created, allowing access to its properties and methods.  
`target_url`: One of the transactions of the object is inserted here the URL link to be scanned security.  
`output_file`: The report file takes the default value of the vulnerability_report.json.  
`report_format`: The report format is an optional coefficient that determines the format by which the report will be saved (such as JSON or TXT) and its default value is "json".  
`Self.vulnerability = []` is a list to save gaps discovered.  
`self.session`: The session requests are used to provide more efficient requests.  

## Log Vulnerabilities Code:  
`def log_vulnerability(self, url, parameter, payload, vuln_type, description):`  
    `entry = {`  
        `"timestamp": datetime.now().isoformat(),  # Create the timestamp`  
        `"url": url,`  
        `"parameter": parameter,  # The targeted parameter`  
        `"payload": payload,  # The used payload`  
        `"vulnerability": vuln_type,  # Vulnerability type`  
        `"description": description,  # Description of the vulnerability`  
        `"remediation": self.get_remediation(vuln_type),  # The remediation`  
    `}`  
    `self.vulnerabilities.append(entry)  # Add the vuln to the list`  
    `print(f"[{vuln_type}] Found at {url} (Parameter: {parameter}, Payload: {payload})")`  

This function records the discovered vulnerabilities as a list containing details:    
Link (url).  
Target parameter name.  
The used payload.  
Vulnerability type.  
Vulnerability description and its remediation.  

## Get Remediation Code:
`def get_remediation(self, vuln_type):`  
    `remediations = {`  
                `"SQL Injection": "Use parameterized queries or stored procedures to prevent SQL injection.",`  
                `"Cross-Site Scripting": "Validate and sanitize user inputs. Use content security policy (CSP).",`  
                `"Directory Traversal": "Validate file paths and restrict access to required directories only.",`  
    `}`  
     `return remediations.get(vuln_type, "No remediation available.")`  
     



