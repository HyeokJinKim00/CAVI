import requests
from typing import Optional, List, Dict, Any

def fetch_cve_info(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    특정 CVE ID의 상세 정보를 반환합니다.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[ERROR] NVD API 요청 실패: {e}")
        return None

    vulnerabilities = data.get('vulnerabilities', [])
    if not vulnerabilities:
        return None

    cve = vulnerabilities[0]['cve']

    # description에서 영어 우선 추출
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"),
        descriptions[0]["value"] if descriptions else ""
    )

    # CVSS 점수 추출 (v3.1 우선, 없으면 v2)
    cvss = "N/A"
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "N/A")
    elif "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", "N/A")

    # 영향받는 제품 추출
    affected_products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable"):
                    affected_products.append(cpe.get("criteria", ""))

    # Reference 링크 추출
    references = [ref["url"] for ref in cve.get("references", [])]

    # Weaknesses 추출
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            if desc["lang"] == "en":
                weaknesses.append(desc["value"])

    info = {
        "id": cve["id"],
        "description": description,
        "published": cve.get("published"),
        "cvss": cvss,
        "affected_products": affected_products,
        "references": references,
        "weaknesses": weaknesses,
    }
    return info

def fetch_recent_cves(api_key: Optional[str], results_per_page: int = 5) -> List[Dict[str, Any]]:
    """
    NVD API를 통해 최신 N개의 CVE 정보를 받아옵니다.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": results_per_page
    }
    headers = {
        "Accept": "application/json"
    }
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get('vulnerabilities', [])
    except Exception as e:
        print(f"[ERROR] NVD API 요청 실패: {e}")
        return []
