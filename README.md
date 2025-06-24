# NexPent-Next generation Pentesting suit
NexPent is an advanced automated vulnerability assessment and penetration testing (VAPT) toolkit. It supports web app and system scanning with a Streamlit-based dashboard and HTML/PDF reporting.
## 🚀 Features
- 🔍 SQL Injection (GET & POST)
- 💥 Cross-Site Scripting (XSS) Detection
- 🔐 Login Brute-force Tester
- 📂 Static Code Scanner (Upload & Detect Insecure Code)
- 🌐 Subdomain Enumeration
- 🔌 Full Port Scanner (1-65535)
- 📖 CVE Lookup (via NVD API)
- 📊 HTML + PDF Report Generator
## 🖥️ How to Run
1. Install Dependencies
 ```bash
pip install -r requirements.txt
```
2. Launch the Streamlit Dashboard
```bash
  streamlit run gui/dashboard.py
```
🌍 Legally Allowed Websites for Testing
## Target Site	Description
https://testphp.vulnweb.com	
## Test SQLi, XSS, auth bypass, form injection
https://juice-shop.herokuapp.com	OWASP Juice Shop 
## test XSS, brute-force, file upload
⚠️ Note: These targets are publicly available for educational and ethical hacking practice only. Never scan unauthorized websites.
## 📂 Static Code Scanner
Upload PHP, JS, or Python code via the dashboard. The scanner detects:

SQL injection risks

Reflected XSS

Hardcoded credentials

Unsafe file uploads

Dangerous functions like eval()

## 📄 Report Output
After a scan, AutoVAPT Pro generates:

report/report.html

report/report.pdf

Both are downloadable directly from the dashboard.
## 🛑 Disclaimer
This tool is intended for educational and authorized security testing only. The author is not responsible for any misuse.
