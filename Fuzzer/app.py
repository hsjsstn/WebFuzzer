from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, send_file
from fuzzer import run_fuzzer
from report import generate_pdf_report
import threading
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("fuzzer.log"),
        logging.StreamHandler()
    ]
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

    # 로그 시작 지점 기록
    try:
        with open("fuzzer.log", "rb") as f:
            f.seek(0, 2)
            log_start_pos = f.tell()
    except FileNotFoundError:
        log_start_pos = 0

    fuzzer_done = False

    # 기존 fuzzer_logs.txt 파일 초기화
    open("results/fuzzer_logs.txt", "w").close()


    def run_async():
        urls, results, vulns, attempts = run_fuzzer(target_url, max_depth)
        global fuzzer_data
        fuzzer_data["urls"] = urls
        fuzzer_data["results"] = results
        fuzzer_data["vulnerabilities"] = vulns
        fuzzer_data["attempts"] = attempts

        generate_pdf_report(
            crawled_urls=urls,
            extraction_results=results,
            vulnerabilities=vulns,
            attempts=attempts,
            output_path="results/fuzzer_report.pdf"
        )

        # 현재 로그 시작 시점 이후 로그만 백업
        try:
            os.makedirs("results", exist_ok=True)
            with open("fuzzer.log", "rb") as src:
                src.seek(log_start_pos)
                recent_logs = src.read().decode("utf-8", errors="ignore")
            with open("results/fuzzer_logs.txt", "w", encoding="utf-8") as dst:
                dst.write(recent_logs)
            logger.info("[*] 로그 백업 완료: fuzzer_logs.txt")
        except Exception as e:
            logger.error(f"[!] 로그 파일 복사 중 오류: {e}")

        global fuzzer_done
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
    return render_template(
        "result.html",
        vulnerabilities=fuzzer_data["vulnerabilities"],
        attempts=fuzzer_data["attempts"]
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