import importlib
docker = importlib.import_module("docker")
import os

def write_dockerfile():
    dockerfile_content = (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY victim.py .\n"
        "COPY poc.py .\n"
        "CMD [\"python\", \"poc.py\"]\n"
    )
    with open("Dockerfile", "w", encoding="utf-8") as f:
        f.write(dockerfile_content)

def run_poc_in_docker():
    try:
        client = docker.from_env()
        image, build_logs = client.images.build(path=".", tag="poc-test", rm=True)
        container = client.containers.run("poc-test", detach=True)
        result = container.logs(stdout=True, stderr=True).decode()
        container.remove()
        return result
    except Exception as e:
        return f"[오류] Docker 자동 검증 중 예외 발생: {e}"

def cleanup_docker_artifacts():
    for fname in ["Dockerfile", "victim.py", "poc.py"]:
        if os.path.exists(fname):
            os.remove(fname)
    try:
        client = docker.from_env()
        client.images.remove("poc-test", force=True)
    except Exception:
        pass

def save_result_log(result, filename="docker_poc_result.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(result)

if __name__ == "__main__":
    result = run_poc_in_docker()
    print("Docker 기반 PoC 실행 결과:\n", result)
    save_result_log(result)
