# Security_scanner
A python tool that resemble a vulnerability scanner. It looks for SQL injection, XSS and Directory Traversal vulnerabilities and introduce the suitable remediation for each vulnerability. 


# Code Explaination: 
We need to use requests, datetime and json for this tool, so we will recall it at the beginning of the code.

```python
import requests
from datetime import datetime
import json
```
**requests:** Library to make HTTP requests (GET, POST, etc.).  
**datetime:** To add temporal character when recording gaps.  
**json:** To handle JSON data (reports).  

Security scanner class will be created, including definitions of scanner components such as vulnerability logs, remediation and vulnerability tests.
```python
class VulnerabilityScanner:
    def __init__(self, target_url, output_file="vulnerability_report.json", report_format="json"):
        self.target_url = target_url
        self.output_file = output_file
        self.report_format = report_format
        self.vulnerabilities = []  # a list for dicoverd vulns
        self.session = requests.Session()  # to create a session for each request
```
`__ init __`: Configure the object with parameters:  
`self`: a reference to the object being created, allowing access to its properties and methods.  
`target_url`: One of the transactions of the object is inserted here the URL link to be scanned security.  
`output_file`: The report file takes the default value of the vulnerability_report.json.  
`report_format`: The report format is an optional coefficient that determines the format by which the report will be saved (such as JSON or TXT) and its default value is "json".  
`Self.vulnerability = []` is a list to save gaps discovered.  
`self.session`: The session requests are used to provide more efficient requests.  

## Log Vulnerabilities Code:  
```python
def log_vulnerability(self, url, parameter, payload, vuln_type, description):
    entry = {
        "timestamp": datetime.now().isoformat(),  # Create the timestamp
        "url": url,
        "parameter": parameter,  # The targeted parameter
        "payload": payload,  # The used payload
        "vulnerability": vuln_type,  # Vulnerability type
        "description": description,  # Description of the vulnerability
        "remediation": self.get_remediation(vuln_type),  # The remediation
    } 
    self.vulnerabilities.append(entry)  # Add the vuln to the list
    print(f"[{vuln_type}] Found at {url} (Parameter: {parameter}, Payload: {payload})")
```
This function records the discovered vulnerabilities as a list containing details:    
Link (url).  
Target parameter name.  
The used payload.  
Vulnerability type.  
Vulnerability description and its remediation.  

## Get Remediation Code:
```python
def get_remediation(self, vuln_type):
    remediations = {
                "SQL Injection": "Use parameterized queries or stored procedures to prevent SQL injection.",
                "Cross-Site Scripting": "Validate and sanitize user inputs. Use content security policy (CSP).",
                "Directory Traversal": "Validate file paths and restrict access to required directories only.",
         }
     return remediations.get(vuln_type, "No remediation available.")
```
This function contains remediation steps for each type of vulnerability. If the steps are not defined for a particular type, return a default text.  

## SQL Injection Test:
```python
def test_sql_injection(self):
    print("\n[INFO] Testing for SQL Injection...")
    payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
    for payload in payloads:
        params = {"search": payload} # Set payload 
        try:
            response = self.session.get(self.target_url, params=params, timeout=5)
            if "error" in response.text or "syntax" in response.text:
                self.log_vulnerability(
                    url=response.url,
                    parameter="search",
                    payload=payload,
                    vuln_type="SQL Injection",
                   description="SQL error messages or unintended behavior detected.",
              )
        except Exception as e:
            print(f"[ERROR] SQL Injection test failed: {e}")
```
Here's the definition of SQL injection test function.  
Initially, a text is printed indicating that the test has started.  
A list of payloads was defined to be used in `for` loop where a dictionary called params was created containing the parameters sent with the request.  
Then using self.session.get the GET request is sent to the self.target_url link with the payload within params and wait for five seconds to reply.  
After examining whether there is any word wrong in the received text stored in the response (the presence of the word "error" or "syntax"), the self.log_vulnerability vulnerability registration function will be called and pass the following details:  
`url = response.url` the tested URL.  
`parameter = "search"` the name of the field targeted by the test.  
`payload = payload` that led to detection.  
`vuln_type="SQL Injection"` type of vulnerability.  
`description="SQL error messages or unintended behavior detected."` A description of the loophole.  

If any error occurs during execution, `Except as e:` processes this error so that you store it in e and print the error message.  

## XSS Testing Code:
```python
def test_xss(self):
    print("\n[INFO] Testing for Cross-Site Scripting (XSS)...")
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        params = {"query": payload}
        try:
            response = self.session.get(self.target_url, params=params, timeout=5)
            if payload in response.text:
                self.log_vulnerability(
                    url=response.url,
                    parameter="query",
                    payload=payload,
                    vuln_type="Cross-Site Scripting",
                    description="Payload echoed back without sanitization.",
          )
        except Exception as e:
            print(f"[ERROR] XSS test failed: {e}")
```
In a similar way, this code adds the payload to the "query" parameter and injects it into the URL link and then checks whether the payload exists as in the text received from the response.text. If the payload appears, this means that the application has reintroduced the payload without filtering or revising, indicating an XSS vulnerability.  

## Directory Traversal Test:
```python
def test_directory_traversal(self):
    print("\n[INFO] Testing for Directory Traversal...")
    payloads = ["../../etc/passwd", "../index.html"]
    for payload in payloads:
        params = {"file": payload}
        try:
            response = self.session.get(self.target_url, params=params, timeout=5)
            if "root:x" in response.text or "<html>" in response.text:
                self.log_vulnerability(
                    url=response.url,
                    parameter="file",
                    payload=payload,
                    vuln_type="Directory Traversal",
                    description="Potential file read from the server.",
                )
        except Exception as e:
            print(f"[ERROR] Directory Traversal test failed: {e}")
```
Also, in similar way, payload is being added to the parameter "file" to access to the sensitive paths. After receiving the reply, check whether there is a root: x within the text of the reply message, the vulnerability exists. Example: If we send a request using the payload:  
http://example.com?file=../../etc/passwd  
And the reply was contained: root:x:0:0:root:/root:/bin/bash  
This means that the web application allows navigation between directories and access to sensitive files.  

## Report Generating Code: 
```python
def generate_report(self):
    if self.report_format == "json":
        with open(self.output_file, "w") as f:
            json.dump(self.vulnerabilities, f, indent=4)
        print(f"\n[INFO] Report generated in JSON format: {self.output_file}")
    elif self.report_format == "txt":
        with open(self.output_file.replace(".json", ".txt"), "w") as f:
            for vuln in self.vulnerabilities:
                f.write(json.dumps(vuln, indent=4) + "\n\n")
        print(f"\n[INFO] Report generated in TXT format: {self.output_file.replace('.json', '.txt')}")
    else:
        print("[ERROR] Unsupported report format.")
```
**Report generation function definition:** It generates the report in JSON or TXT format according to the user's choice.

At first, the report type is checked using the if, elif, else conditional tool so that it covers the three possible cases, which are either a JSON report, a TXT report, or an error in the report format.

**In the first case of the `if` conditional tool:**  
A new file is opened for writing to it named `self.output_file`, which was defined at the beginning of the class as taking the default value `vulnerability_report.json` with specifying the writing mode using the `"w"` parameter and storing the file temporarily in `f` to be used within the body of `with` statement, after which the list of vulnerabilities `self.vulnerabilities` is taken and placed in a JSON file in a format specified by the `indent=4` parameter.  
Finally, a text is printed indicating that the report was generated in JSON format and named `vulnerability_report.json`.  
**The second case of the `if` condition tool:**  
If the report is in TXT format, the report will be written in JSON format similar to the first case, and then converted to a TXT report using `self.output_file.replace(".json", ".txt")` .  
**The third case of the `if` condition tool:**  
If a format different from the previous two cases is specified, an error message is printed stating that the format requested by the user is not supported.
     
## Run tests and generate report:  
```python
def run(self):
    print(f"Starting scan on {self.target_url}")
    self.test_sql_injection()
    self.test_xss()
    self.test_directory_traversal()
    self.generate_report()
```
`run` function has defined to run all tests and report generating. 

## Main Code to run:
```python
if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://example.com): ")
    report_format = input("Enter report format (json/txt): ").strip().lower()
    scanner = VulnerabilityScanner(target, report_format=report_format)
    scanner.run()
```
We want to run the file directly and not through another program, so we added an if condition as in the first line to achieve that.  
After that, the user is asked to enter the link that is required to be tested, and then the user is asked what is the format of the required report with removing the extra spaces in the text entered by the user and converting it to lowercase letters to get rid of the problem of uppercase and lowercase letters.  
We defined a new object called scanner to store the input from the user and then run the tests based on the contents of the scanner object.  

# Test the Code:
We tried the python code on the URL https://google-gruyere.appspot.com and chose the report format TXT, then we got the results in the file: vulnerability_report.txt

