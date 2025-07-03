import os
from dotenv import load_dotenv
from info.crawl import extract_function_info  # 기존 함수 그대로 사용
import google.generativeai as genai

# .env에서 환경변수 불러오기
load_dotenv()
gemini_api_key = os.getenv("GEMINI_API_KEY")

def make_llm_prompt(function_infos):
    """
    함수 정보 리스트를 받아 LLM에 보낼 프롬프트 생성
    """
    prompt = "아래 함수 시그니처와 설명을 참고해, 정상 사용법, 취약한 사용법, 보안상 주의사항을 각각 JSON 형태로 정리해줘.\n"
    for info in function_infos:
        prompt += f"\n[시그니처]\n{info['signature']}\n[설명]\n{info['description']}\n"
    prompt += "\n---\n정답:"
    return prompt

def call_gemini_api(prompt, api_key):
    """
    Gemini API를 호출해 답변을 받음
    """
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    model = genai.GenerativeModel("gemini-2.5-flash")  # 최신 모델명 사용
    response = model.generate_content(prompt)
    return response.text

if __name__ == "__main__":
    doc_url = "https://docs.python.org/3/library/os.html"
    function_name = "system"

    # 1. 공식 문서에서 함수 정보 추출
    function_infos = extract_function_info(doc_url, function_name)

    # 2. LLM 프롬프트 생성
    prompt = make_llm_prompt(function_infos)
    print("==== Gemini 프롬프트 ====")
    print(prompt)

    # 3. Gemini API 호출 및 결과 출력
    if gemini_api_key:
        answer = call_gemini_api(prompt, gemini_api_key)
        print("==== Gemini 응답 ====")
        print(answer)
    else:
        print("GEMINI_API_KEY 환경변수가 설정되지 않았습니다.")

def make_code_analysis_prompt(code, cve_info=None, func_infos=None):
    prompt = (
        "아래는 소스코드, 관련 CVE 정보, 그리고 공식 문서에서 추출한 함수 설명입니다.\n"
        "이 정보를 바탕으로 코드 내에 존재하는 취약점을 구체적으로 분석해줘.\n"
        "- 취약점이 발생하는 함수/라인/블록을 특정해주고, 원인과 영향을 설명해줘.\n"
        "- 취약점이 없다면 그렇게 말해주고, 있다면 PoC 코드 초안도 함께 제시해줘.\n"
    )
    if cve_info:
        prompt += f"\n[CVE 정보]\n{cve_info}\n"
    if func_infos:
        for info in func_infos:
            prompt += f"\n[함수 시그니처] {info.get('signature','')}\n[설명] {info.get('description','')}\n"
    prompt += f"\n[소스코드]\n{code}\n"
    prompt += "\n---\n정답:"
    return prompt

def make_victim_code_prompt(cve_info=None, func_infos=None):
    prompt = (
        "아래는 CVE 정보와 공식 문서에서 추출한 함수 설명입니다.\n"
        "이 취약점이 실제로 발생하는 상황을 재현할 수 있는 최소한의 victim(취약) 코드를 만들어줘.\n"
        "- PoC 코드가 이 victim 코드를 공격 대상으로 삼을 수 있어야 해.\n"
        "- victim 코드는 간단하고, 취약점이 명확히 드러나야 해.\n"
    )
    if cve_info:
        prompt += f"\n[CVE 정보]\n{cve_info}\n"
    if func_infos:
        for info in func_infos:
            prompt += f"\n[함수 시그니처] {info.get('signature','')}\n[설명] {info.get('description','')}\n"
    prompt += "\n---\nVictim 코드:"
    return prompt

if __name__ == "__main__":
    prompt = """
아래 텍스트에서 취약점의 이름, 영향받는 소프트웨어, 취약점 설명, CVSS 점수, 참고 링크를 JSON 형태로 추출하세요.

CVE-2023-44832: D-Link DIR-823G A1V1.0.2B05 was discovered to contain a buffer overflow via the MacAddress parameter in the SetWanSettings function. 
공격자는 특수하게 조작된 요청을 통해 임의 코드를 실행할 수 있습니다. 
공식 참고: https://www.dlink.com/en/security-bulletin/
CVSS 점수: 7.5

JSON:
"""
    answer = call_gemini_api(prompt, gemini_api_key)
    print("==== Gemini 응답 ====")
    print(answer)

