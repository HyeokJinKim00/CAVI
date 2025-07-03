import requests

def search_github_poc(cve_id, github_token=None):
    """
    특정 CVE ID로 GitHub에서 PoC/Exploit 레포지토리를 검색합니다.
    - cve_id가 없으면 빈 리스트 반환
    - description이 None일 때도 안전하게 처리
    """
    if not cve_id:
        return []
    url = "https://api.github.com/search/repositories"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    params = {"q": cve_id}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        results = response.json().get("items", [])
    except Exception as e:
        print(f"[ERROR] GitHub API 요청 실패: {e}")
        return []

    poc_repos = [
        repo["html_url"]
        for repo in results
        if (
            "poc" in repo.get("name", "").lower()
            or "exploit" in (repo.get("description") or "").lower()
        )
    ]
    return poc_repos

def download_github_file(repo_full_name, file_path, ref="main", github_token=None):
    """
    특정 GitHub 저장소의 파일을 다운로드
    repo_full_name: "owner/repo"
    file_path: "경로/파일명.py"
    ref: 브랜치명 또는 커밋 해시
    """
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    url = f"https://raw.githubusercontent.com/{repo_full_name}/{ref}/{file_path}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"파일 다운로드 실패: {url} (status {response.status_code})")