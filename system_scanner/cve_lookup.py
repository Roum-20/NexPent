import requests
from datetime import datetime, timedelta

def lookup_cves(keyword):
    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Correct ISO 8601 Zulu format: 2025-06-24T18:23:00.000Z
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)

        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        headers = {
            "Content-Type": "application/json"
            # "apiKey": "your_api_key_here"  # Optional
        }

        params = {
            "keywordSearch": keyword,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": "10"
        }

        response = requests.get(base_url, headers=headers, params=params, timeout=15)
        response.raise_for_status()

        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            description = cve.get("descriptions", [{}])[0].get("value", "")
            cves.append(f"{cve_id}: {description[:120]}")

        return cves or ["✅ No recent CVEs found."]
    except Exception as e:
        return [f"❌ Error fetching CVEs: {e}"]
