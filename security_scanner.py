```python 
import requests
from datetime import datetime
import json


class VulnerabilityScanner:
    def __init__(self, target_url, output_file="vulnerability_report.json", report_format="json"):
        self.target_url = target_url
        self.output_file = output_file
        self.report_format = report_format
        self.vulnerabilities = [] # a list for dicoverd vulns
        self.session = requests.Session()  # to create a session for each request

    def log_vulnerability(self, url, parameter, payload, vuln_type, description):        
        entry = {
            "timestamp": datetime.now().isoformat(), # Create the timestamp
            "url": url,
            "parameter": parameter, # The targeted parameter
            "payload": payload, # The used payload
            "vulnerability": vuln_type, # Vulnerability type
            "description": description, # Description of the vulnerability 
            "remediation": self.get_remediation(vuln_type), # The remediation 
        }
        self.vulnerabilities.append(entry) # Add the vuln to the list
        print(f"[{vuln_type}] Found at {url} (Parameter: {parameter}, Payload: {payload})")

    def get_remediation(self, vuln_type): #introduce remediation according to vulnerability type
        remediations = {
            "SQL Injection": "Use parameterized queries or stored procedures to prevent SQL injection.",
            "Cross-Site Scripting": "Validate and sanitize user inputs. Use content security policy (CSP).",
            "Directory Traversal": "Validate file paths and restrict access to required directories only.",
        }
        return remediations.get(vuln_type, "No remediation available.")

    def test_sql_injection(self): # Test the existance of SQL Injection vulnerability
        print("\n[INFO] Testing for SQL Injection...")
        payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
        for payload in payloads:
            params = {"search": payload}
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

    def test_xss(self): # Test the existance of XXS vulnerability
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

    def test_directory_traversal(self): # Test the existance of Directory Traversal vulnerability
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

    def generate_report(self): # Generating the final report
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

    def run(self): # Runnig tests and report generation
        print(f"Starting scan on {self.target_url}")
        self.test_sql_injection()
        self.test_xss()
        self.test_directory_traversal()
        self.generate_report()


if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://example.com): ")
    report_format = input("Enter report format (json/txt): ").strip().lower()
    scanner = VulnerabilityScanner(target, report_format=report_format)
    scanner.run()
```
