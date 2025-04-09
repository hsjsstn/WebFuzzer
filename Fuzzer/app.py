from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fuzzer import run_fuzzer  
from report import generate_pdf_report
import threading 
import time
import os


app = Flask(__name__)
start_log_line = 0  # 이 시점부터 로그 표시

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/start', methods=['POST'])
def start():
    url = request.form['target_url']
    # 크롤링 및 퍼징 시작
    result_data = run_fuzzer(url)
    generate_pdf_report(result_data)
    return redirect(url_for('loading'))

@app.route("/loading", methods=["POST"])
def loading():
    global fuzzer_done, log_start_pos
    target_url = request.form.get("target_url")
    max_depth = int(request.form.get("max_depth", 1))  # 기본값 1

    if not target_url:
        return "URL이 필요합니다.", 400
    
    try:
        max_depth = int(request.form.get("max_depth", 1))
    except ValueError:
        return "크롤링 깊이는 숫자로 입력해주세요.", 400

    # 로그 파일 위치 저장 (로딩 이후 생성된 로그만 보여주기 위해)
    try:
        with open("fuzzer.log", "rb") as f:
            f.seek(0, 2)
            log_start_pos = f.tell()
    except FileNotFoundError:
        log_start_pos = 0

    fuzzer_done = False

    def run_async():
        urls, results, vulns, attempts = run_fuzzer(target_url, max_depth)
        generate_pdf_report(
            crawled_urls=urls,
            extraction_results=results,
            vulnerabilities=vulns,
            attempts=attempts,
            output_path="fuzzer_report.pdf"
        )
        global fuzzer_done
        fuzzer_done = True

    threading.Thread(target=run_async).start()

    return render_template("loading.html")

def check_fuzzing_done():
    try:
        with open("fuzzer.log", "r", encoding="utf-8") as f:
            logs = f.read()
            return "[*] Flask에서 퍼징 완료." in logs
    except FileNotFoundError:
        return False
    
@app.route('/logs')
def get_logs():
    try:
        with open("fuzzer.log", "r", encoding="utf-8") as log_file:
            all_logs = log_file.readlines()
            logs = ''.join(all_logs[start_log_line:])
    except FileNotFoundError:
        logs = "로깅 파일이 아직 생성되지 않았습니다."

    return jsonify({
        "logs": logs,
        "done": check_fuzzing_done()
    })

@app.route('/result')
def result():
    return render_template('result.html')

@app.route('/download')
def download():
    return send_file("results/result.pdf", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, port=5001)