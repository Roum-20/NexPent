import requests
import urllib.parse

PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(123)</script>",
    "<IMG SRC=\"javascript:alert('XSS');\">",
    "<svg/onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<script>prompt(1)</script>"
]

def scan_xss(url):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    if not query:
        return "❌ No query parameters to test for XSS."

    for param in query:
        for payload in PAYLOADS:
            test_params = query.copy()
            test_params[param] = payload
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if payload.lower() in response.text.lower():
                    return f"🔥 Reflected XSS detected in parameter '{param}' using payload: {payload}"
            except Exception as e:
                continue

    return None
