from flask import Flask, render_template, request, redirect, url_for, send_file
from fuzzer import run_fuzzer  
from report import generate_pdf_report
import os

app = Flask(__name__)

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
    url = request.form['target_url']  # home.html에서 보내는 input name="target_url"
    urls = run_fuzzer(url)  # 여기서 fuzzer 실행
    return render_template('loading.html', urls=urls)

@app.route('/result')
def result():
    return render_template('result.html')

@app.route('/download')
def download():
    return send_file("results/result.pdf", as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)