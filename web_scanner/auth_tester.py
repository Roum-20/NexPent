import requests
from bs4 import BeautifulSoup

def test_login_form(url, usernames, passwords, success_indicator="dashboard"):
    results = []

    try:
        # Get the login form and extract field names
        res = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(res.text, 'html.parser')
        form = soup.find("form")
        if not form:
            return "❌ No form found at the URL."

        action = form.get("action")
        login_url = url if not action or action.startswith("#") else requests.compat.urljoin(url, action)

        inputs = form.find_all("input")
        user_field = None
        pass_field = None

        for inp in inputs:
            if "user" in inp.get("name", "").lower():
                user_field = inp.get("name")
            if "pass" in inp.get("name", "").lower():
                pass_field = inp.get("name")

        if not user_field or not pass_field:
            return "❌ Could not detect username or password fields."

        for username in usernames:
            for password in passwords:
                payload = {
                    user_field: username,
                    pass_field: password
                }

                # Include hidden fields (like CSRF tokens)
                for inp in inputs:
                    name = inp.get("name")
                    value = inp.get("value", "")
                    if name not in payload and name:
                        payload[name] = value

                try:
                    r = requests.post(login_url, data=payload, timeout=5, verify=False)
                    if success_indicator.lower() in r.text.lower():
                        return f"🔥 Weak login: {username}/{password}"
                except requests.RequestException:
                    continue

    except Exception as e:
        return f"❌ Error scanning login: {e}"

    return None

