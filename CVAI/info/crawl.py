import requests
from bs4 import BeautifulSoup

def extract_function_info(doc_url, function_name=None):
    """
    공식 문서 URL에서 함수/메서드 시그니처, 설명, 예제 코드(정상/취약) 추출
    function_name이 주어지면 해당 함수만, 없으면 전체 파싱
    """
    response = requests.get(doc_url)
    soup = BeautifulSoup(response.text, "html.parser")
    function_infos = []

    # 문서 구조에 따라 커스텀 필요 (아래는 파이썬 공식문서 예시)
    for dt in soup.find_all("dt"):
        code = dt.find("code")
        if code:
            func_name = code.get_text()
            if function_name and function_name not in func_name:
                continue
            # 설명 추출
            dd = dt.find_next_sibling("dd")
            description = ""
            if dd:
                desc_p = dd.find("p")
                if desc_p:
                    description = desc_p.get_text()
            # 예제 코드 추출
            normal_example = ""
            vuln_example = ""
            for pre in dd.find_all("pre"):
                code_text = pre.get_text()
                # 간단한 기준: "취약" 또는 "bad"가 들어가면 취약 예시로 간주
                if "취약" in code_text or "bad" in code_text.lower():
                    vuln_example = code_text
                else:
                    normal_example = code_text
            function_infos.append({
                "name": func_name,
                "description": description,
                "normal_example": normal_example,
                "vuln_example": vuln_example
            })
    return function_infos

# 필요하다면 alias로도 사용 가능
crawl_official_docs = extract_function_info
