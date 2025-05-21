from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, send_file
from main import main
import threading
import os
import logging
from unittest.mock import patch 
import shutil

# 🔥 /logs 경로 제외용 필터 클래스
class ExcludeLogsFilter(logging.Filter):
    def filter(self, record):
        return '/logs' not in record.getMessage()

# 기존 핸들러 제거 (중복 방지)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# 🔧 핸들러 설정 및 필터 적용
file_handler = logging.FileHandler("fuzzer.log")
file_handler.addFilter(ExcludeLogsFilter())

stream_handler = logging.StreamHandler()
stream_handler.addFilter(ExcludeLogsFilter())

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[file_handler, stream_handler]
)

logger = logging.getLogger(__name__)


app = Flask(__name__)

fuzzer_done = False
fuzzer_data = {
    "urls": [],
    "results": [],
    "vulnerabilities": [],
    "attempts": []
}
log_start_pos = 0  # 크롤링 시작 시점의 로그 파일 위치
os.makedirs("results", exist_ok=True)  # 폴더 없으면 자동 생성

@app.route('/')
def home():
    return render_template('home.html')


@app.route("/loading", methods=["POST"])
def loading():
    global fuzzer_done, log_start_pos

    target_url = request.form.get("target_url")
    try:
        max_depth = int(request.form.get("max_depth", 1))
    except ValueError:
        return "크롤링 깊이는 숫자로 입력해주세요.", 400

    if not target_url:
        return "URL이 필요합니다.", 400

    try:
        with open("fuzzer.log", "rb") as f:
            f.seek(0, 2)
            log_start_pos = f.tell()
    except FileNotFoundError:
        log_start_pos = 0

    fuzzer_done = False

    def run_async():
        global fuzzer_done, fuzzer_data

        with patch('builtins.input', side_effect=[target_url, str(max_depth)]):
        # 💡 fuzzer를 직접 받아오게 main() 수정 필요
            urls, results, vulns, attempts = main()

        fuzzer_data["urls"] = urls
        fuzzer_data["results"] = results
        fuzzer_data["vulnerabilities"] = vulns
        fuzzer_data["attempts"] = attempts
        
        open("fuzzer.log", "w").close()
        open("results/fuzzer_logs.txt", "w").close()

        with patch('builtins.input', side_effect=[target_url, str(max_depth)]):
            main()

        try:
            shutil.copyfile("fuzzer.log", "results/fuzzer_logs.txt")
            print("[*] 로그 복사 완료")
        except Exception as e:
            print("[!] 로그 복사 실패:", e)

        fuzzer_done = True

    threading.Thread(target=run_async).start()

    return render_template("loading.html") 

@app.route("/logs")
def get_logs():
    global log_start_pos

    try:
        with open("fuzzer.log", "rb") as f:
            f.seek(log_start_pos)
            new_logs = f.read().decode("utf-8", errors="ignore")
    except FileNotFoundError:
        new_logs = "[INFO] 로그 파일이 아직 생성되지 않았습니다."

    return jsonify({
        "logs": new_logs,
        "done": fuzzer_done
    })

@app.route("/result")
def result():
    # fuzzer_data에서 취약점 정보를 가져옵니다.
    vulnerabilities = fuzzer_data["vulnerabilities"]
    attempts = fuzzer_data["attempts"]

    # result.html 템플릿에 데이터를 전달하여 렌더링
    return render_template(
        "result.html",
        vulnerabilities=vulnerabilities,
        attempts=attempts
    )


# pdf 다운로드
@app.route('/download-pdf')
def download_pdf():
    return send_file("results/fuzzer_report.pdf", as_attachment=True)

# 로그 다운로드
@app.route('/download-logs')
def download_logs():
    try:
        with open("results/fuzzer_logs.txt", "r", encoding="utf-8") as out:
            return send_file("results/fuzzer_logs.txt", as_attachment=True)

    except Exception as e:
        return f"로그 파일 다운로드 중 오류 발생: {e}", 500


if __name__ == "__main__":
    app.run(debug=True, port=5001)