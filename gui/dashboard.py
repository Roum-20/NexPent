import os
import sys
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from web_scanner import sql_injection, xss_scanner, auth_tester, form_scanner
from system_scanner import port_scanner, cve_lookup, subdomain_enum
from utils import code_scanner
from report import html_report, pdf_export

import urllib.parse

st.set_page_config(page_title="AutoVAPT Pro", layout="wide")
st.title("🛡️NexPent-Next generation Pentesting suit")

vulns = []
target = st.text_input("Enter Target URL or IP (e.g., http://example.com/page.php?id=1)")
st.caption("💡 Tip: For SQLi/XSS, include parameters like ?id=1 if testing GET-based injection")

scan_web = st.checkbox("Web Scan (SQL Injection, XSS)")
scan_sys = st.checkbox("System Scan (Full Port Scanning)")
scan_login = st.checkbox("Login Bruteforce")
scan_code = st.checkbox("Static Code Upload Scanner")
scan_cve = st.checkbox("CVE Lookup (NVD API)")
scan_sub = st.checkbox("Subdomain Enumeration")

uploaded_file = st.file_uploader("Upload Code File", type=["php", "js", "py", "html"]) if scan_code else None
cve_keyword = st.text_input("Enter product for CVE lookup", value="apache") if scan_cve else ""

if st.button("Start Scan") and target:
    st.info("🔍 Scanning started...")

    # Add dummy parameter if none present for testing GET scans
    test_url = target
    if scan_web and '?' not in target:
        if target.endswith('/'):
            test_url += "test.php?id=1"
        else:
            test_url += "?id=1"
        st.warning(f"🔧 No parameters in URL. Using test URL: {test_url}")

    # ✅ Web Scanning
    if scan_web:
        st.write("🧪 Web Scanning...")

        sql_get = sql_injection.scan_sql_injection(test_url)
        sql_post = form_scanner.test_post_sqli(target)
        xss_get = xss_scanner.scan_xss(test_url)
        xss_post = form_scanner.test_post_xss(target)

        st.write(f"SQL Injection (GET): {sql_get or '❌ No response'}")
        st.write(f"SQL Injection (POST): {sql_post or '❌ No response'}")
        st.write(f"XSS (GET): {xss_get or '❌ No response'}")
        st.write(f"XSS (POST): {xss_post or '❌ No response'}")

        for result in [sql_get, sql_post, xss_get, xss_post]:
            if result and ("🔥" in result or "vulnerability" in result.lower()):
                vulns.append(result)

    # ✅ Login Bruteforce
    if scan_login:
        st.write("🔐 Testing Login Forms...")
        usernames = ["admin", "test", "user"]
        passwords = ["admin", "123456", "test", "password"]
        login_result = auth_tester.test_login_form(target, usernames, passwords, success_indicator="Welcome")
        st.write(f"Login Result: {login_result}")
        if "weak login" in login_result.lower():
            vulns.append(login_result)

    # ✅ System Scan
    if scan_sys:
        st.write("🔌 Scanning All Ports (1–65535)...")
        ip = target.replace("http://", "").replace("https://", "").split("/")[0]
        ports = port_scanner.scan_ports_with_progress(ip)
        for port in ports:
            vulns.append(f"Open Port Found: {port}")
        st.write(f"Open Ports: {ports}" if ports else "✅ No open ports found.")

    # ✅ CVE Lookup
    if scan_cve and cve_keyword:
        st.write(f"📖 CVEs for '{cve_keyword}'...")
        cves = cve_lookup.lookup_cves(cve_keyword)
        for cve in cves:
            st.write(f"• {cve}")
            if "CVE" in cve:
                vulns.append(f"CVE Found: {cve}")

    # ✅ Subdomain Enumeration
    if scan_sub and "." in target:
        st.write("🌐 Subdomain Enumeration...")
        parsed = urllib.parse.urlparse(target)
        base_domain = parsed.netloc or parsed.path.split("/")[0]
        subs = subdomain_enum.enumerate_subdomains(base_domain)
        st.write(f"Subdomains Found: {subs if subs else '❌ None found'}")
        for sub in subs:
            vulns.append(f"Subdomain Found: {sub}")

    # ✅ Static Code Scanner
    if uploaded_file:
        st.write("📂 Static Code Analysis...")
        try:
            content = uploaded_file.read().decode("utf-8")
            issues = code_scanner.scan_file_content(content)
            for issue in issues:
                vulns.append(issue)
            st.write(f"Issues: {issues}")
        except Exception as e:
            st.error(f"❌ File read error: {e}")

    # ✅ Generate Report
    if vulns:
        st.subheader("🚨 Vulnerabilities Detected")
        for v in vulns:
            st.warning(v)

        os.makedirs("report", exist_ok=True)
        html_report.generate_html_report(vulns)
        pdf_export.export_pdf_from_vulns(vulns)

        with open("report/report.html", "rb") as f:
            st.download_button("📄 Download HTML Report", f, file_name="AutoVAPT_Report.html")

        with open("report/report.pdf", "rb") as f:
            st.download_button("📄 Download PDF Report", f, file_name="AutoVAPT_Report.pdf")
    else:
        st.success("✅ No major vulnerabilities detected.")
