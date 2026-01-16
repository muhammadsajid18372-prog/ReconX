#!/usr/bin/env python3
# ============================================
# DOMAIN INTELLIGENCE OSINT FRAMEWORK
# Passive Recon | Pentester Friendly | No API
# ============================================

import socket
import ssl
import requests
import whois
import json
from datetime import datetime
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (OSINT Research Tool)"
}

# --------------------------------------------------
def banner():
    print(r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

====================================================
   ReconX - Domain Intelligence OSINT Framework
   Passive Recon | Pentester Friendly | No API
====================================================
   Author  : Muhammad sajid
   Version : 1.0
   Purpose : Passive Domain Recon & Risk Profiling
====================================================
""")

# --------------------------------------------------
def whois_intel(domain):
    print("\n[+] WHOIS Intelligence")
    try:
        w = whois.whois(domain)
        print(f"  Domain      : {w.domain_name}")
        print(f"  Registrar   : {w.registrar}")
        print(f"  Created     : {w.creation_date}")
        print(f"  Expires     : {w.expiration_date}")
        print(f"  Country     : {w.country}")
        print("  NameServers :")
        for ns in w.name_servers or []:
            print(f"   - {ns}")
        return w
    except Exception as e:
        print(f"  WHOIS lookup failed: {e}")
        return None

# --------------------------------------------------
def hosting_info(domain):
    print("\n[+] Hosting Information")
    try:
        ip = socket.gethostbyname(domain)
        print(f"  IP Address: {ip}")
        return ip
    except:
        print("  Could not resolve IP")
        return None

# --------------------------------------------------
def ssl_info(domain):
    print("\n[+] SSL Certificate")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        print(f"  Issuer       : {dict(x[0] for x in cert['issuer'])}")
        print(f"  Valid From   : {cert['notBefore']}")
        print(f"  Valid Until  : {cert['notAfter']}")
        print("  SAN Domains  :")
        for san in cert.get("subjectAltName", []):
            print(f"   - {san[1]}")
    except Exception as e:
        print(f"  SSL lookup failed: {e}")

# --------------------------------------------------
def security_headers(domain):
    print("\n[+] Security Headers Assessment")
    try:
        r = requests.get(f"https://{domain}", headers=HEADERS, timeout=10)
        headers = r.headers

        checks = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        for h in checks:
            status = "✅ Present" if h in headers else "❌ Missing"
            print(f"  {h}: {status}")
    except:
        print("  Header check failed")

# --------------------------------------------------
def robots_sitemap(domain):
    print("\n[+] Robots / Sitemap Intelligence")

    for path in ["robots.txt", "sitemap.xml"]:
        try:
            r = requests.get(f"https://{domain}/{path}", timeout=5)
            if r.status_code == 200:
                print(f"  {path}: FOUND ({len(r.text)} bytes)")
            else:
                print(f"  {path}: Not Found")
        except:
            print(f"  {path}: Error")

# --------------------------------------------------
def crtsh_subdomains(domain):
    print("\n[+] Passive Subdomains (crt.sh)")
    found = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=15)
        data = json.loads(r.text)

        for entry in data:
            names = entry["name_value"].split("\n")
            for n in names:
                if domain in n:
                    found.add(n.strip())

        for sub in sorted(found):
            print(f"  - {sub}")

        return found
    except Exception as e:
        print(f"  crt.sh lookup failed: {e}")
        return set()

# --------------------------------------------------
def exposure_hints(subs):
    print("\n[+] Passive Exposure Hints")
    risky = ["admin", "test", "beta", "cpanel", "mail", "webmail"]

    for s in subs:
        for r in risky:
            if r in s:
                print(f"  ⚠️ {s}")
                break

# --------------------------------------------------
def email_patterns(domain):
    print("\n[+] Passive Email Pattern Detection")
    emails = [
        f"admin@{domain}",
        f"support@{domain}",
        f"info@{domain}",
        f"contact@{domain}",
        f"sales@{domain}",
        f"security@{domain}"
    ]
    for e in emails:
        print(f"  - {e}")

# --------------------------------------------------
def social_media(domain):
    print("\n[+] Social Media Recon")
    base = domain.split(".")[0]

    platforms = {
        "Facebook": f"https://facebook.com/{base}",
        "Instagram": f"https://instagram.com/{base}",
        "Twitter/X": f"https://twitter.com/{base}",
        "LinkedIn": f"https://linkedin.com/company/{base}"
    }

    for k, v in platforms.items():
        print(f"  - {k}: {v}")

# --------------------------------------------------
def archive_org(domain):
    print("\n[+] Archive.org Exposure Check")
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&limit=5"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and len(r.text) > 20:
            print("  ⚠️ Archived pages found")
            print(f"  🔗 https://web.archive.org/web/*/{domain}")
        else:
            print("  No archive history found")
    except:
        print("  Archive check failed")

# --------------------------------------------------
def risk_assessment(whois_data, subs):
    print("\n[+] Risk Assessment")

    risk = 0

    if whois_data and whois_data.creation_date:
        year = whois_data.creation_date.year if isinstance(whois_data.creation_date, datetime) else whois_data.creation_date[0].year
        if year >= datetime.now().year - 1:
            risk += 3

    if len(subs) > 15:
        risk += 3

    if any(x in s for s in subs for x in ["admin", "test", "beta"]):
        risk += 4

    if risk >= 7:
        print("  Risk Level: HIGH")
    elif risk >= 4:
        print("  Risk Level: MEDIUM")
    else:
        print("  Risk Level: LOW")

    print(f"\n[+] Confidence Score\n  Confidence: {min(100, 50 + risk * 5)}%")

# --------------------------------------------------
def main():
    banner()
    domain = input("Enter domain: ").strip()

    print("\n==============================")
    print(" DOMAIN INTELLIGENCE OSINT")
    print(f" Target: {domain}")
    print("==============================")

    w = whois_intel(domain)
    ip = hosting_info(domain)
    ssl_info(domain)
    security_headers(domain)
    robots_sitemap(domain)
    subs = crtsh_subdomains(domain)
    exposure_hints(subs)
    email_patterns(domain)
    social_media(domain)
    archive_org(domain)
    risk_assessment(w, subs)

    print("\n[Program finished]\n")

# --------------------------------------------------
if __name__ == "__main__":
    main()

