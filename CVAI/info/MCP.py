import requests

def fetch_msrc_advisory(cve_id):
    url = f"https://api.msrc.microsoft.com/cvrf/v2.0/cve/{cve_id}"
    headers = {"Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return None
    data = response.json()
    # 주요 정보 추출 예시
    advisory = {
        "title": data.get("DocumentTitle", "No title"),
        "impact": data.get("DocumentTracking", {}).get("CurrentReleaseDate", ""),
        "description": data.get("DocumentNotes", [{}])[0].get("Value", ""),
        "affected_products": [p["ProductID"] for p in data.get("ProductTree", {}).get("FullProductName", [])]
    }
    return advisory

# 사용 예시
msrc_info = fetch_msrc_advisory("CVE-2023-12345")
print(msrc_info)
