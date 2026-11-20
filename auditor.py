import asyncio, aiohttp, argparse, json, re, ssl, socket
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode

CANARY = "s3nt1n3lXssTest99"

CHECKS_META = {
    "HSTS": ("CWE-319", "Medium", "5.3", "Missing Strict-Transport-Security header allows protocol downgrade attacks.", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "CSP": ("CWE-693", "Medium", "5.4", "Missing Content-Security-Policy increases XSS and data injection risk.", "Define a strict Content-Security-Policy header restricting script-src."),
    "XFO": ("CWE-1021", "Low", "4.3", "Missing X-Frame-Options allows Clickjacking inside malicious iframes.", "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
    "CORS": ("CWE-942", "High", "7.5", "Wildcard or reflected CORS origin with credentials leaks sensitive user data.", "Restrict Access-Control-Allow-Origin to trusted domains only."),
    "COOKIE": ("CWE-614", "Medium", "5.0", "Session cookies missing Secure, HttpOnly, or SameSite flags.", "Set Secure, HttpOnly, and SameSite=Strict on all sensitive cookies."),
    "EXPOSED": ("CWE-200", "Critical", "9.1", "Sensitive configuration or repository file is publicly accessible.", "Block access to hidden files (.git, .env) in web server config."),
    "SECRET": ("CWE-798", "Critical", "9.0", "Hardcoded API key or cloud credential exposed in client-side source.", "Revoke exposed key immediately and move secrets to backend env variables."),
    "REFLECT": ("CWE-79", "High", "7.1", "Unescaped user input reflected in HTTP response (Potential XSS vector).", "Apply context-aware HTML output encoding on all user-controlled parameters."),
    "SQLI_ERR": ("CWE-89", "Critical", "9.8", "Database syntax error triggered by benign quote probe (Potential SQLi).", "Use parameterized queries / prepared statements for all DB operations."),
    "CVE": ("CWE-1104", "High", "7.5", "Outdated server/software version matched against known public CVEs.", "Upgrade the detected software component to the latest patched version.")
}

async def check_cve(session, product):
    findings = []
    try:
        url = f"https://nist.gov{product}&resultsPerPage=3"
        async with session.get(url, timeout=8) as r:
            if r.status == 200:
                data = await r.json()
                for item in data.get("vulnerabilities", []):
                    cve_id = item["cve"]["id"]
                    desc = item["cve"]["descriptions"][0]["value"][:180]
                    findings.append((cve_id, desc))
    except Exception:
        pass
    return findings

async def scan(target):
    findings = []
    def add(key, title, evidence):
        cwe, sev, cvss, impact, fix = CHECKS_META[key]
        findings.append({"title": title, "cwe": cwe, "severity": sev, "cvss": cvss, "impact": impact, "remediation": fix, "evidence": evidence})

    conn = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=conn, headers={"User-Agent": "SentinelAuditor/1.0"}) as s:
        # 1. Baseline & Soft-404 Calibration
        async with s.get(urljoin(target, "/nonexistent_404_check_98765"), timeout=10) as r404:
            len_404 = len(await r404.text())

        async with s.get(target, timeout=10) as r:
            body = await r.text()
            hdrs = {k.lower(): v for k, v in r.headers.items()}

            # 2. Security Headers & Cookies
            if "strict-transport-security" not in hdrs: add("HSTS", "Missing HSTS Header", target)
            if "content-security-policy" not in hdrs: add("CSP", "Missing Content-Security-Policy", target)
            if "x-frame-options" not in hdrs: add("XFO", "Missing X-Frame-Options Header", target)
            if hdrs.get("access-control-allow-origin") == "*": add("CORS", "Overly Permissive CORS Policy (*)", "Access-Control-Allow-Origin: *")
            for c in r.headers.getall("Set-Cookie", []):
                if "httponly" not in c.lower() or "secure" not in c.lower():
                    add("COOKIE", "Insecure Cookie Flags", c[:80])

            # 3. Server Fingerprinting & CVE Lookup
            srv = hdrs.get("server", "")
            if "/" in srv:
                cves = await check_cve(s, srv)
                for cid, desc in cves:
                    add("CVE", f"Potential Outdated Component ({srv}) - {cid}", desc)

            # 4. Secret & API Key Leak Detection
            for pat_name, rx in [("AWS Key", r"AKIA[0-9A-Z]{16}"), ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"), ("Private Key", r"-----BEGIN (RSA|EC|PRIVATE) KEY-----")]:
                if re.search(rx, body):
                    add("SECRET", f"Exposed {pat_name} in Response", target)

        # 5. Sensitive File Exposure (Soft-404 Aware)
        for path in ["/.env", "/.git/HEAD", "/swagger.json", "/api-docs"]:
            u = urljoin(target, path)
            async with s.get(u, timeout=8) as rp:
                txt = await rp.text()
                if rp.status == 200 and abs(len(txt) - len_404) > 100 and "<html" not in txt.lower()[:100]:
                    add("EXPOSED", f"Exposed Sensitive Endpoint: {path}", f"HTTP 200 ({len(txt)} bytes) at {u}")

        # 6. Passive Reflection & SQL Error Probe
        sep = "&" if "?" in target else "?"
        async with s.get(f"{target}{sep}q={CANARY}", timeout=8) as rxss:
            if CANARY in await rxss.text():
                add("REFLECT", "Unescaped Input Reflection (Potential XSS)", f"Canary '{CANARY}' reflected in {rxss.url}")

        async with s.get(f"{target}{sep}id=1'", timeout=8) as rsql:
            stxt = await rsql.text()
            if re.search(r"(SQL syntax|mysql_fetch|ORA-01756|PostgreSQL.*ERROR|SQLite3::)", stxt, re.I):
                add("SQLI_ERR", "Database Error Signature Detected (Potential SQLi)", f"SQL error pattern matched at {rsql.url}")

    return findings

def save_reports(target, findings):
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump({"target": target, "date": str(datetime.now()), "findings": findings}, f, indent=2)
    cards = "".join([f"<div style='background:#1e293b;padding:15px;margin:10px 0;border-left:5px solid #ef4444;border-radius:6px'><h3>[{x['severity']}] {x['title']} (CVSS {x['cvss']} | {x['cwe']})</h3><p><b>Impact:</b> {x['impact']}</p><p><b>Evidence:</b> <code>{x['evidence']}</code></p><p><b>Remediation:</b> {x['remediation']}</p></div>" for x in findings])
    html = f"<html><body style='background:#0f172a;color:#f8fafc;font-family:sans-serif;padding:30px'><h1>Sentinel Security Research Report</h1><p>Target: {target} | Total Findings: {len(findings)}</p>{cards or '<p>No vulnerabilities detected.</p>'}</body></html>"
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Sentinel Web Security Auditor")
    p.add_argument("--target", required=True, help="Target URL (e.g. https://example.com)")
    p.add_argument("--authorized", action="store_true", required=True, help="Confirm legal authorization")
    args = p.parse_args()
    res = asyncio.run(scan(args.target))
    save_reports(args.target, res)
    print(f"[+] Scan complete! {len(res)} findings saved to report.html and report.json")
