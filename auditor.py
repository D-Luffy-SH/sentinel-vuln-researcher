import asyncio, aiohttp, argparse, json, re, sys, webbrowser, os, traceback
from datetime import datetime
from urllib.parse import urljoin

CANARY = "s3nt1n3lXssProbe99"
RULES = {
    "HSTS": ("CWE-319", "Medium", "5.3", "Missing HSTS allows protocol downgrade attacks.", "Add Strict-Transport-Security header."),
    "CSP": ("CWE-693", "Medium", "5.4", "Missing Content-Security-Policy increases XSS risk.", "Define a strict Content-Security-Policy header."),
    "XFO": ("CWE-1021", "Low", "4.3", "Missing X-Frame-Options allows Clickjacking.", "Set X-Frame-Options: DENY."),
    "XCTO": ("CWE-16", "Low", "3.7", "Missing X-Content-Type-Options allows MIME sniffing.", "Set X-Content-Type-Options: nosniff."),
    "CORS": ("CWE-942", "High", "7.5", "Permissive CORS policy may expose sensitive API data.", "Restrict Access-Control-Allow-Origin to trusted domains."),
    "COOKIE": ("CWE-614", "Medium", "5.0", "Cookies missing Secure, HttpOnly, or SameSite flags.", "Enforce Secure, HttpOnly, and SameSite=Strict on cookies."),
    "EXPOSED": ("CWE-200", "Critical", "9.1", "Sensitive config or repository file is publicly accessible.", "Block access to hidden files (.git, .env)."),
    "SECRET": ("CWE-798", "Critical", "9.0", "Hardcoded API key or credential exposed in response.", "Revoke exposed key immediately and store secrets server-side."),
    "REFLECT": ("CWE-79", "High", "7.1", "Unescaped user input reflected (Potential XSS).", "Apply context-aware HTML/JS output encoding."),
    "SSTI": ("CWE-1336", "Critical", "9.4", "Template expression evaluated server-side (Potential SSTI).", "Never pass raw input into template engines."),
    "SQLI_ERR": ("CWE-89", "Critical", "9.8", "Database error triggered by benign quote probe (Potential SQLi).", "Use parameterized queries / prepared statements."),
    "OPEN_REDIR": ("CWE-601", "Medium", "6.1", "Unvalidated redirect parameter allows external forwarding.", "Validate redirect URLs against a strict allowlist."),
    "GRAPHQL": ("CWE-200", "Medium", "5.3", "GraphQL Introspection enabled in production.", "Disable GraphQL introspection in production."),
    "CVE": ("CWE-1104", "High", "7.5", "Server version matched known public CVEs.", "Upgrade the detected software to the latest patched version.")
}

async def check_cve(session, product):
    out = []
    try:
        url = f"https://nist.gov{product}&resultsPerPage=3"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
            if r.status == 200:
                data = await r.json()
                for item in data.get("vulnerabilities", []):
                    out.append((item["cve"]["id"], item["cve"]["descriptions"][0]["value"][:180]))
    except Exception:
        pass
    return out

async def scan(target):
    findings, seen = [], set()
    def add(key, title, evidence):
        if f"{key}:{title}:{evidence}" in seen: return
        seen.add(f"{key}:{title}:{evidence}")
        cwe, sev, cvss, impact, fix = RULES[key]
        findings.append({"title": title, "cwe": cwe, "severity": sev, "cvss": cvss, "impact": impact, "remediation": fix, "evidence": evidence})

    timeout = aiohttp.ClientTimeout(total=15)
    conn = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 SentinelAuditor/2.1"}) as s:
        print("[1/5] Calibrating Soft-404 baseline...")
        len_404 = 0
        try:
            async with s.get(urljoin(target, "/_sentinel_404_99182")) as r404:
                len_404 = len(await r404.text(errors="ignore"))
        except Exception:
            pass

        print("[2/5] Analyzing Headers, CORS, Cookies, Secrets & CVE versions...")
        async with s.get(target, headers={"Origin": "https://evil-test.com"}) as r:
            body = await r.text(errors="ignore")
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            if "strict-transport-security" not in hdrs: add("HSTS", "Missing HSTS Header", target)
            if "content-security-policy" not in hdrs: add("CSP", "Missing Content-Security-Policy", target)
            if "x-frame-options" not in hdrs: add("XFO", "Missing X-Frame-Options Header", target)
            if "x-content-type-options" not in hdrs: add("XCTO", "Missing X-Content-Type-Options", target)
            acao = hdrs.get("access-control-allow-origin", "")
            if acao == "*" or "evil-test.com" in acao: add("CORS", "Misconfigured CORS Policy", f"Access-Control-Allow-Origin: {acao}")
            for c in r.headers.getall("Set-Cookie", []):
                if "httponly" not in c.lower() or "secure" not in c.lower(): add("COOKIE", "Insecure Cookie Flags", c[:80])
            for tech in [hdrs.get("server", ""), hdrs.get("x-powered-by", "")]:
                if "/" in tech:
                    for cid, desc in await check_cve(s, tech): add("CVE", f"Outdated Software ({tech}) - {cid}", desc)
            for name, rx in [("AWS Key", r"AKIA[0-9A-Z]{16}"), ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"), ("Private Key", r"-----BEGIN (RSA|EC|PRIVATE) KEY-----"), ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}")]:
                if re.search(rx, body): add("SECRET", f"Leaked {name} in Response", target)

        print("[3/5] Checking exposed files (.env, .git, API docs)...")
        for path in ["/.env", "/.git/HEAD", "/swagger.json", "/openapi.json", "/api-docs", "/backup.zip"]:
            u = urljoin(target, path)
            try:
                async with s.get(u) as rp:
                    txt = await rp.text(errors="ignore")
                    if rp.status == 200 and abs(len(txt) - len_404) > 120 and "<html" not in txt.lower()[:120]:
                        add("EXPOSED", f"Exposed Sensitive File: {path}", f"HTTP 200 ({len(txt)} bytes) at {u}")
            except Exception:
                pass

        print("[4/5] Checking GraphQL introspection...")
        try:
            gql = urljoin(target, "/graphql")
            async with s.post(gql, json={"query": "{__schema{types{name}}}"}) as rg:
                if rg.status == 200 and "__schema" in await rg.text(errors="ignore"): add("GRAPHQL", "GraphQL Introspection Enabled", gql)
        except Exception:
            pass

        print("[5/5] Running passive reflection, SSTI, SQL error & redirect probes...")
        sep = "&" if "?" in target else "?"
        probes = [
            (f"{target}{sep}q=<{CANARY}>", lambda t, h: '<' + CANARY + '>' in t, "REFLECT", "Unescaped Input Reflection (Potential XSS)", f"Canary '{CANARY}' reflected"),
            (f"{target}{sep}tpl={{7*7}}", lambda t, h: "49" in t and "{7*7}" not in t, "SSTI", "Template Expression Evaluated (Potential SSTI)", "'{{7*7}}' evaluated to '49'"),
            (f"{target}{sep}id=1'", lambda t, h: bool(re.search(r"(SQL syntax|mysql_fetch|ORA-01756|PostgreSQL.*ERROR|SQLite3::)", t, re.I)), "SQLI_ERR", "Database Error Disclosed (Potential SQLi)", "SQL error triggered"),
            (f"{target}{sep}next=https://example.org", lambda t, h: "example.org" in h.get("location", ""), "OPEN_REDIR", "Unvalidated Open Redirect", f"Redirected to {''}")
        ]
        for purl, fn, rkey, rtitle, rev in probes:
            try:
                async with s.get(purl, allow_redirects=False) as pr:
                    if fn(await pr.text(errors="ignore"), {k.lower(): v for k, v in pr.headers.items()}): add(rkey, rtitle, f"{rev} at {purl}")
            except Exception:
                pass
    return findings

def save_reports(target, findings):
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda x: order.get(x["severity"], 4))
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ["Critical", "High", "Medium", "Low"]}
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump({"tool": "Sentinel Web Auditor v2.1", "target": target, "date": str(datetime.now()), "summary": counts, "findings": findings}, f, indent=2)
    colors = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#3b82f6"}
    cards = "".join([f"<div style='background:#1e293b;padding:16px;margin:12px 0;border-left:5px solid {colors[x['severity']]};border-radius:6px'><h3 style='margin:0 0 6px;color:{colors[x['severity']]}'>[{x['severity']}] {x['title']} (CVSS {x['cvss']} | {x['cwe']})</h3><p><b>Impact:</b> {x['impact']}</p><p><b>Evidence:</b> <code>{x['evidence']}</code></p><p style='color:#34d399'><b>Remediation:</b> {x['remediation']}</p></div>" for x in findings])
    bar = " | ".join([f"<span style='color:{colors[k]};font-weight:bold'>{k}: {v}</span>" for k, v in counts.items()])
    html = f"<html><body style='background:#0f172a;color:#f8fafc;font-family:Segoe UI,sans-serif;max-width:960px;margin:auto;padding:30px'><h1>Sentinel Web Security Research Report v2.1</h1><p>Target: <b>{target}</b> | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p><div style='background:#1e293b;padding:12px;border-radius:6px;margin-bottom:20px'>{bar}</div>{cards or '<p style=\"color:#34d399\">No vulnerabilities detected.</p>'}</body></html>"
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == '__main__':
    try:
        if len(sys.argv) == 1:
            print('=== Sentinel Web Security Auditor v2.1 ===')
            t = input('Enter Authorized Target URL (e.g. https://example.com): ').strip()
            if not t.startswith('http'): t = 'https://' + t
            if input('Confirm legal authorization (yes/no): ').strip().lower() != 'yes': sys.exit('Aborted.')
            res = asyncio.run(scan(t)); save_reports(t, res)
            print(f'\n[+] Done! Found {len(res)} issues. Opening report.html...')
            webbrowser.open('file://' + os.path.abspath('report.html'))
        else:
            p = argparse.ArgumentParser(); p.add_argument('--target', required=True); p.add_argument('--authorized', action='store_true', required=True); a = p.parse_args()
            res = asyncio.run(scan(a.target)); save_reports(a.target, res); print(f'[+] Done! Found {len(res)} issues.')
    except Exception as e:
        print(f'\n[!] Error: {e}'); traceback.print_exc()
    finally:
        if len(sys.argv) == 1: input('\nPress Enter to exit...')


