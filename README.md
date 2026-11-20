# Sentinel Web Security Auditor

A defensive, non-intrusive Web Vulnerability Assessment & Security Research tool built for authorized security auditing.

## Features & Use Cases
- **Soft-404 Calibration:** Eliminates false positives by comparing responses against randomized 404 baselines.
- **Live NVD CVE Correlation:** Fingerprints server headers and checks known public CVEs.
- **Security Headers & Cookie Audit:** Detects missing HSTS, CSP, X-Frame-Options, permissive CORS, and insecure cookies.
- **Secret & Sensitive File Discovery:** Identifies exposed `.env`, `.git/HEAD`, API docs, and hardcoded AWS/Google/Private keys.
- **Passive Reflection & Error Analysis:** Uses benign canary tokens to detect unescaped XSS reflection and SQL error signatures safely.
- **Research-Grade Reporting:** Generates `report.html` (Dark-mode dashboard) and `report.json` with CVSS scores, CWE IDs, Business Impact, and Remediation guides.

## Usage
```bash
sentinel-auditor.exe --target https://example.com --authorized
```
> **Disclaimer:** Use strictly on systems you own or have explicit written permission to test.
