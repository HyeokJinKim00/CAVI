"""
import os
import json
import re
from dotenv import load_dotenv
from info.NVD import fetch_cve_info
from info.Git import search_github_poc, download_github_file
from info.crawl import extract_function_info
from info.MCP import fetch_msrc_advisory
from info.LLM import (
    make_llm_prompt, call_gemini_api,
    make_code_analysis_prompt, make_victim_code_prompt
)
from info.vector_db import build_vector_db, rag_query
from info.docker_util import write_dockerfile, run_poc_in_docker, cleanup_docker_artifacts, save_result_log

# 환경변수 로딩
load_dotenv()

def extract_python_code(text):
    match = re.search(r'``````', text)
    if match:
        return match.group(1).strip()
    return text.strip()

def collect_all_info(cve_id, github_token=None, nvd_api_key=None, doc_url=None):
    nvd = fetch_cve_info(cve_id, nvd_api_key)
    github = search_github_poc(cve_id, github_token)
    docs = extract_function_info(doc_url) if doc_url else []
    mcp = fetch_msrc_advisory(cve_id)
    return {
        "NVD": nvd,
        "GitHub": github,
        "Docs": docs,
        "MCP": mcp
    }

if __name__ == "__main__":
    # 환경변수에서 값 불러오기
    cve_id = os.getenv("CVE_ID", "")
    github_token = os.getenv("GITHUB_TOKEN")
    nvd_api_key = os.getenv("NVD_API_KEY")
    doc_url = os.getenv("DOC_URL", "")
    gemini_api_key = os.getenv("GEMINI_API_KEY")

    # CVE_ID가 반드시 입력되어야 실행
    if not cve_id:
        print("CVE_ID 환경변수를 .env에 입력해 주세요. 예: CVE_ID=CVE-2023-44832")
        exit(1)

    # === Phase 1: 핵심 정보 수집 및 RAG ===
    info = collect_all_info(
        cve_id,
        github_token=github_token,
        nvd_api_key=nvd_api_key,
        doc_url=doc_url
    )
    with open("phase1_info.json", "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    print("\n[Phase 1] 핵심 정보 수집 결과가 phase1_info.json에 저장되었습니다.")

    # RAG 예시
    if info.get("Docs"):
        doc_texts = [d["description"] for d in info["Docs"] if d.get("description")]
        if doc_texts and gemini_api_key:
            collection, embedder = build_vector_db(doc_texts)
            query = "os.system 함수의 보안상 주의사항은?"
            answer = rag_query(query, collection, embedder, gemini_api_key)
            with open("phase1_rag.txt", "w", encoding="utf-8") as f:
                f.write(answer)
            print("[Phase 1] RAG 기반 질의응답 결과가 phase1_rag.txt에 저장되었습니다.")

    # === Phase 2: 코드 분석 및 PoC 생성 엔진 ===
    code_analysis_result = None
    if github_token and gemini_api_key:
        repo = "python/cpython"
        file_path = "Lib/os.py"
        branch = "main"
        try:
            code = download_github_file(repo, file_path, branch, github_token)
            cve_info = info.get("NVD")
            func_infos = info.get("Docs")
            prompt = make_code_analysis_prompt(
                code,
                cve_info=cve_info,
                func_infos=func_infos
            )
            code_analysis_result = call_gemini_api(prompt, gemini_api_key)
            with open("phase2_code_analysis.txt", "w", encoding="utf-8") as f:
                f.write(code_analysis_result)
            print("[Phase 2] 코드 분석 결과가 phase2_code_analysis.txt에 저장되었습니다.")
        except Exception as e:
            print("[Phase 2] GitHub 코드 다운로드/분석 오류:", e)

    # === Phase 3: Victim 코드, PoC 코드, Docker 자동 검증 ===
    if gemini_api_key:
        cve_info = info.get("NVD")
        func_infos = info.get("Docs")
        victim_prompt = make_victim_code_prompt(cve_info, func_infos)
        victim_code_raw = call_gemini_api(victim_prompt, gemini_api_key)
        victim_code = extract_python_code(victim_code_raw)
        with open("phase3_victim.py", "w", encoding="utf-8") as f:
            f.write(victim_code)
        print("[Phase 3] Victim 코드가 phase3_victim.py에 저장되었습니다.")

        poc_prompt = (
            "아래 victim.py 코드를 공격하는 PoC(Proof of Concept) 코드를 만들어줘.\n"
            "취약점이 정상적으로 트리거되는 예시를 보여주고, PoC 코드는 가능한 한 간단하게 작성해줘.\n"
            "설명 없이 코드만, 그리고 반드시 파이썬 코드만 반환해줘. 마크다운이나 주석, 설명문 없이 코드만 출력해.\n"
            "\n[victim.py 코드]\n"
            f"{victim_code}\n"
        )
        if code_analysis_result:
            poc_prompt += (
                "\n[코드 분석 결과]\n"
                f"{code_analysis_result}\n"
            )
        poc_prompt += "\n---\nPoC 코드:"

        poc_code_raw = call_gemini_api(poc_prompt, gemini_api_key)
        poc_code = extract_python_code(poc_code_raw)
        with open("phase3_poc.py", "w", encoding="utf-8") as f:
            f.write(poc_code)
        print("[Phase 3] PoC 코드가 phase3_poc.py에 저장되었습니다.")

        write_dockerfile()
        print("\n==== Docker 기반 PoC 자동 검증 실행 ====")
        result = run_poc_in_docker()
        with open("phase3_docker_result.txt", "w", encoding="utf-8") as f:
            f.write(result)
        print("[Phase 3] Docker 실행 결과가 phase3_docker_result.txt에 저장되었습니다.")

        success_indicator = 'Exploit Success'
        failure_indicator = 'Exploit Failed'

        if success_indicator in result:
            print("정답: 성공")
        elif failure_indicator in result:
            print("정답: 실패")
        else:
            print("정답: 판단 불가 (로그 확인 필요)")

        cleanup_docker_artifacts()

            
"""

'''

'''