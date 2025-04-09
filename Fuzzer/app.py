from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fuzzer import run_fuzzer  
from report import generate_pdf_report
import threading
import os

app = Flask(__name__)
LOG_FILE_PATH = "fuzzer.log"

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
    target_url = request.form["target_url"]

    # 퍼저 실행을 별도 쓰레드에서
    def run_background():
        run_fuzzer(target_url)  # 네 퍼저 함수

    threading.Thread(target=run_background).start()

    return render_template("loading.html")

@app.route('/result')
def result():
    return render_template('result.html')

@app.route('/download')
def download():
    return send_file("results/result.pdf", as_attachment=True)


@app.route("/logs")
def get_logs():
    try:
        with open(LOG_FILE_PATH, "r") as f:
            lines = f.readlines()
        return jsonify(logs=lines[-30:])  # 최근 30줄만
    except Exception as e:
        return jsonify(logs=[f"[ERROR] 로그 불러오기 실패: {e}"])

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)