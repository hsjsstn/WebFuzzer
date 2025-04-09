from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fuzzer import run_fuzzer  
from report import generate_pdf_report
from threading import Thread
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

@app.route('/loading', methods=['POST'])
def loading():
    global start_log_line
    # 로그 시작 라인 저장
    with open("fuzzer.log", "r", encoding="utf-8") as f:
        start_log_line = len(f.readlines())

    # 퍼저 실행 시작
    url = request.form.get("target_url")
    run_fuzzer(url)
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