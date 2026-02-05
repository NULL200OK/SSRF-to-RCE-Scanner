# SSRF-to-RCE-Scanner
IT is advanced Python-based security tool designed to automate the detection and exploitation of SSRF (Server-Side Request Forgery) and RCE (Remote Code Execution) vulnerabilities in web application email input fields. This tool follows a systematic methodology to escalate from SSRF detection to full RCE exploitation with minimal false positives.

# 🔍 Detection Capabilities

SSRF Detection: Tests for Server-Side Request Forgery using Burp Collaborator

Command Injection: Tests various injection operators and payloads

Blind OS Injection: Time-based and DNS-based blind command execution

Email Format Variations: Tests payloads in different parts of email addresses

Advanced Payloads: Base64-encoded, Python, Perl, and other execution methods

# ⚡ Technical Features

Baseline Comparison: Establishes normal response patterns to reduce false positives

Smart Payload Generation: Uses ${IFS} instead of spaces to bypass filters

Confidence Levels: High/Medium/Low confidence ratings for findings

Session Management: Maintains cookies and headers for stateful applications

Results Tracking: JSON output for further analysis

Rate Limiting: Configurable delays between requests

# 🎯 Target Applications

Webmail systems (Roundcube, SquirrelMail, etc.)

Login/registration pages

Contact forms with email validation

Any web application with email input fields

# 📦 Installation

# Prerequisites

Python 3.7 or higher

Burp Suite Professional (for Collaborator functionality)

Basic understanding of web application security testing

Quick Installation

# Clone the repository

git clone https://github.com/yourusername/ssrf-to-rce.git](https://github.com/NULL200OK/SSRF-to-RCE-Scanner.git

cd ssrf-to-rce

# Install dependencies

pip install -r requirements.txt

# Burp Collaborator Setup

Open Burp Suite Professional

Go to Burp → Burp Collaborator client

Click "Copy to clipboard" to get your Collaborator domain

Use this domain with the -c flag

# 🚀 Quick Start

# Basic Test

python3 ssrf_rce_tester.py -u "https://target.com/login" -p "email" -c "yourcollaborator.oastify.com"

# Testing Modes

1. Complete Test (Default)

Runs all testing phases sequentially:

python3 ssrf_rce_tester.py -u "https://target.com/login" -p "email" -c "yourpayload.oastify.com"

# Phases:

Baseline establishment

SSRF detection

Command injection testing

All operator testing

Email format variations

Advanced payloads

Blind injection testing

# 2. SSRF Only Test

python3 ssrf_rce_tester.py -u "https://target.com/login" -p "username" -c "test.burpcollaborator.net" --test-only ssrf

# 3. RCE Only Test

python3 ssrf_rce_tester.py -u "https://target.com/signup" -p "email" -c "payload.oastify.com" --test-only rce

# 4. Blind Injection Test

python3 ssrf_rce_tester.py -u "https://webapp.com/contact" -p "contact_email" -c "yourcollaborator.net" --test-only blind

# 5. Advanced Payloads Test

python3 ssrf_rce_tester.py -u "https://app.com/login" -p "user" -c "test.oastify.com" --test-only advanced

## Common Scenarios

# Roundcube Webmail

python3 ssrf_rce_tester.py -u "https://webmail.example.com/?_task=login" -p "_user" -c "yourpayload.oastify.com"

# WordPress Login

python3 ssrf_rce_tester.py -u "https://example.com/wp-login.php" -p "log" -c "payload.burpcollaborator.net"

# Custom Application

python3 ssrf_rce_tester.py -u "https://app.example.com/api/register" -p "email_address" -c "test.oastify.com"

# With Output File

python3 ssrf_rce_tester.py -u "https://target.com/login" -p "email" -c "collaborator.net" -o "scan_results.json" --verbose

# ⚠️ Limitations

# Known Limitations

Requires Burp Collaborator: For SSRF and blind RCE detection

Manual Verification Needed: For SSRF phase confirmation

Rate Limiting: May trigger WAF/IPS if too aggressive

Application Specific: Effectiveness varies by target

False Negatives Possible: Some vulnerabilities may be missed

# 📈 Performance Tips

# For Large-Scale Testing

# Use specific test modes

python3 ssrf_rce_tester.py --test-only ssrf ...

# Increase delays

python3 ssrf_rce_tester.py --delay 1.0 ...

# Use output for batch processing

python3 ssrf_rce_tester.py -o results.json ...

# For Bug Bounty Hunting

# Quick SSRF check

python3 ssrf_rce_tester.py --test-only ssrf -u $URL -p $PARAM -c $COLLAB

# If SSRF found, full test

python3 ssrf_rce_tester.py -u $URL -p $PARAM -c $COLLAB

## Happy hunting! 🎯








