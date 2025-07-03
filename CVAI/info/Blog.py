import requests
from bs4 import BeautifulSoup

def fetch_blog_posts(cve_id):
    # 예시: 구글 검색 결과 크롤링(실제 서비스에선 API 사용 권장)
    query = f"{cve_id} 취약점"
    url = f"https://www.google.com/search?q={query}"
    headers = {"User-Agent": "Mozilla/5.0"}
    resp = requests.get(url, headers=headers)
    posts = []
    if resp.status_code == 200:
        soup = BeautifulSoup(resp.text, "html.parser")
        for g in soup.find_all('div', class_='g'):
            link = g.find('a')
            if link:
                posts.append({"title": link.text, "url": link['href']})
    return posts
