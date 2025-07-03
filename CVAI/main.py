import os
import json
import re
from dotenv import load_dotenv
from info.NVD import fetch_cve_info
from info.Git import search_github_poc, download_github_file
from info.crawl import extract_function_info
from info.MCP import fetch_msrc_advisory
from info.ExploitDB import fetch_exploitdb_info
from info.Blog import fetch_blog_posts
from info.LLM import call_gemini_api
from info.vector_db import build_vector_db, rag_query
from info.docker_util import write_dockerfile, run_poc_in_docker, cleanup_docker_artifacts

load_dotenv()

def extract_python_code(text):
    match = re.search(r'``````', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()

def collect_all_info(cve_id, github_token=None, nvd_api_key=None, doc_url=None):
    nvd = fetch_cve_info(cve_id, nvd_api_key)
    github = search_github_poc(cve_id, github_token)
    exploitdb = fetch_exploitdb_info(cve_id)
    blogs = fetch_blog_posts(cve_id)
    docs = extract_function_info(doc_url) if doc_url else []
    mcp = fetch_msrc_advisory(cve_id)
    return {
        "NVD": nvd,
        "GitHub": github,
        "ExploitDB": exploitdb,
        "Blogs": blogs,
        "Docs": docs,
        "MCP": mcp
    }

def find_github_source_file(github_pocs):
    if not github_pocs or not isinstance(github_pocs, list):
        return None, None, None
    for poc in github_pocs:
        repo = poc.get('repo')
        file_path = poc.get('file_path')
        branch = poc.get('branch', 'main')
        if file_path and file_path.endswith('.py'):
            return repo, file_path, branch
    return None, None, None

def make_code_analysis_prompt(code, cve_info=None, func_infos=None):
    prompt = "[소스코드]\n" + code + "\n"
    if func_infos:
        for func in func_infos:
            prompt += f"\n[공식문서: {func.get('name','')}]"
            prompt += f"\n정상 사용법: {func.get('normal_example','')}"
            prompt += f"\n취약 사용법: {func.get('vuln_example','')}"
    if cve_info:
        prompt += f"\n[CVE 정보]\n{cve_info}\n"
    prompt += ("\n\n이 코드에서 외부 입력부터 취약점이 발생하는 지점까지의 데이터 흐름을 추적하고, "
               "취약점의 근본 원인과 공격 벡터를 분석해줘.")
    return prompt

def make_vuln_code_prompt(cve_info, func_infos):
    prompt = (
        "아래 CVE 정보와 공식 문서의 취약 예시를 참고해서, "
        "취약점이 발생하는 최소 기능의 파이썬 취약 예시 코드를 만들어줘. "
        "설명 없이 코드만 출력해.\n"
    )
    if cve_info:
        prompt += f"\n[CVE 정보]\n{cve_info}\n"
    if func_infos:
        for func in func_infos:
            prompt += f"\n[공식문서: {func.get('name','')}]"
            prompt += f"\n취약 사용법: {func.get('vuln_example','')}"
    prompt += "\n---\n취약 코드 예시:"
    return prompt

def make_victim_code_prompt(cve_info, func_infos):
    prompt = (
        "아래 CVE 정보와 공식 문서의 취약 예시를 참고해서, "
        "취약점이 발생하는 최소 기능의 파이썬 victim.py 애플리케이션을 만들어줘. "
        "설명 없이 코드만 출력해.\n"
    )
    if cve_info:
        prompt += f"\n[CVE 정보]\n{cve_info}\n"
    if func_infos:
        for func in func_infos:
            prompt += f"\n[공식문서: {func.get('name','')}]"
            prompt += f"\n취약 사용법: {func.get('vuln_example','')}"
    prompt += "\n---\nvictim.py 코드:"
    return prompt

def make_poc_prompt(victim_code, code_analysis_result, func_infos):
    prompt = (
        "아래 victim.py 코드를 공격하는 PoC(Proof of Concept) 코드를 만들어줘.\n"
        "공식 문서의 함수 사용법, 코드 분석 결과, 취약점 원리, 공격 벡터를 모두 참고해서 "
        "실제 공격이 재현되는 PoC 코드를 만들어줘. 설명 없이 파이썬 코드만 출력해.\n"
        "\n[victim.py 코드]\n" + victim_code + "\n"
    )
    if func_infos:
        for func in func_infos:
            prompt += f"\n[공식문서: {func.get('name','')}]"
            prompt += f"\n정상 사용법: {func.get('normal_example','')}"
            prompt += f"\n취약 사용법: {func.get('vuln_example','')}"
    if code_analysis_result:
        prompt += "\n[코드 분석 결과]\n" + code_analysis_result + "\n"
    prompt += "\n---\nPoC 코드:"
    return prompt

if __name__ == "__main__":
    cve_id = os.getenv("CVE_ID", "")
    github_token = os.getenv("GITHUB_TOKEN")
    nvd_api_key = os.getenv("NVD_API_KEY")
    doc_url = os.getenv("DOC_URL", "")
    gemini_api_key = os.getenv("GEMINI_API_KEY")

    if not cve_id:
        print("CVE_ID 환경변수를 .env에 입력해 주세요. 예: CVE_ID=CVE-2023-44832")
        exit(1)

    # Phase 1: 정보 수집 및 RAG
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
            query = "이 취약점의 근본 원인은 무엇인가?"
            answer = rag_query(query, collection, embedder, gemini_api_key)
            with open("phase1_rag.txt", "w", encoding="utf-8") as f:
                f.write(answer)
            print("[Phase 1] RAG 기반 질의응답 결과가 phase1_rag.txt에 저장되었습니다.")

    # Phase 2: 취약 소스코드 자동 다운로드 및 분석
    code_analysis_result = None
    source_code = None
    repo, file_path, branch = find_github_source_file(info.get("GitHub"))
    func_infos = info.get("Docs")
    cve_info = info.get("NVD")
    if repo and file_path and gemini_api_key:
        try:
            print(f"[Phase 2] GitHub에서 취약 소스코드 다운로드: {repo} / {file_path} / {branch}")
            source_code = download_github_file(repo, file_path, branch, github_token)
            with open("phase2_source_code.py", "w", encoding="utf-8") as f:
                f.write(source_code)
            print("[Phase 2] 취약 소스코드가 phase2_source_code.py에 저장되었습니다.")

            prompt = make_code_analysis_prompt(
                source_code,
                cve_info=cve_info,
                func_infos=func_infos
            )
            code_analysis_result = call_gemini_api(prompt, gemini_api_key)
            with open("phase2_code_analysis.txt", "w", encoding="utf-8") as f:
                f.write(code_analysis_result)
            print("[Phase 2] 코드 분석 결과가 phase2_code_analysis.txt에 저장되었습니다.")
        except Exception as e:
            print(f"[Phase 2] GitHub 코드 다운로드/분석 오류: {e}")
            print("[Phase 2] 자동 분석 실패. 공식 정보만으로 취약 코드 예시를 생성합니다.")
            source_code = None
    else:
        print("[Phase 2] GitHub에서 취약 소스코드를 자동으로 찾지 못했습니다.")
        print("공식 정보만으로 취약 코드 예시를 생성합니다.")
        source_code = None

    # Phase 2-2: 소스코드가 없을 때 LLM이 취약 코드 예시 생성
    if not source_code and gemini_api_key:
        vuln_code_prompt = make_vuln_code_prompt(cve_info, func_infos)
        vuln_code_raw = call_gemini_api(vuln_code_prompt, gemini_api_key)
        source_code = extract_python_code(vuln_code_raw)
        with open("phase2_vuln_code_example.py", "w", encoding="utf-8") as f:
            f.write(source_code)
        print("[Phase 2] LLM이 생성한 취약 코드 예시가 phase2_vuln_code_example.py에 저장되었습니다.")

        prompt = make_code_analysis_prompt(
            source_code,
            cve_info=cve_info,
            func_infos=func_infos
        )
        code_analysis_result = call_gemini_api(prompt, gemini_api_key)
        with open("phase2_code_analysis.txt", "w", encoding="utf-8") as f:
            f.write(code_analysis_result)
        print("[Phase 2] 코드 분석 결과가 phase2_code_analysis.txt에 저장되었습니다.")

    # Phase 3: Victim 코드, PoC 코드, Docker 자동 검증
    if gemini_api_key:
        victim_prompt = make_victim_code_prompt(cve_info, func_infos)
        victim_code_raw = call_gemini_api(victim_prompt, gemini_api_key)
        victim_code = extract_python_code(victim_code_raw)
        with open("phase3_victim.py", "w", encoding="utf-8") as f:
            f.write(victim_code)
        print("[Phase 3] Victim 코드가 phase3_victim.py에 저장되었습니다.")

        poc_prompt = make_poc_prompt(victim_code, code_analysis_result, func_infos)
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
