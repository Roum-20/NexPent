import socket
import urllib.parse

def extract_domain(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc if parsed.netloc else url

def enumerate_subdomains(domain, subdomains=None):
    domain = extract_domain(domain)

    if not subdomains:
        subdomains = [
            "www", "mail", "ftp", "admin", "webmail", "dev", "test", "staging",
            "api", "vpn", "portal", "beta", "blog", "dashboard", "cpanel"
        ]

    found = []

    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            found.append(subdomain)
        except socket.gaierror:
            continue

    return found
