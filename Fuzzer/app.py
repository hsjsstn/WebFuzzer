from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash, session,  make_response
from main import main
import threading
import os
import logging
import shutil
from server import api_bp
import sqlite3
from flask_bcrypt import Bcrypt
import re
from functools import wraps

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
app.register_blueprint(api_bp)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-secret-key")  # 세션용

bcrypt = Bcrypt(app)

def get_db():
    conn = sqlite3.connect("webfuzzer.db")
    conn.row_factory = sqlite3.Row
    return conn

fuzzer_done = False
fuzzer_data = {
    "urls": [],
    "results": [],
    "vulnerabilities": [],
    "attempts": []
}
log_start_pos = 0  # 크롤링 시작 시점의 로그 파일 위치
os.makedirs("results", exist_ok=True)  # 폴더 없으면 자동 생성

# 로그인 여부 확인
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # JavaScript alert와 함께 로그인 페이지로 리디렉션
            response = make_response("""
                <script>
                    alert("로그인이 필요한 서비스입니다.");
                    window.location.href = "/login";
                </script>
            """)
            return response
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/start')
@login_required
def start():
    return render_template('start.html')

@app.route("/loading", methods=["POST"])
def loading():
    global fuzzer_done, log_start_pos

    target_url = request.form.get("target_url")
    try:
        max_depth = int(request.form.get("max_depth", 1))
    except ValueError:
        return "크롤링 깊이는 숫자로 입력해주세요.", 400

    selected_payloads = request.form.getlist("payloads")

    if not target_url:
        return "URL이 필요합니다.", 400

    # 퍼징 전에 로그 초기화
    try:
        with open("fuzzer.log", "w") as f:
            f.truncate()
        log_start_pos = 0
    except Exception as e:
        print(f"[!] 로그 초기화 실패: {e}")
        log_start_pos = 0

    fuzzer_done = False

    def run_async():
        global fuzzer_done, fuzzer_data

        try:
            urls, results, vulns, attempts = main(target_url, max_depth, selected_payloads)

            fuzzer_data["urls"] = urls
            fuzzer_data["results"] = results
            fuzzer_data["vulnerabilities"] = vulns
            fuzzer_data["attempts"] = attempts

            # 퍼징 후 로그 복사만 (초기화 X)
            shutil.copyfile("fuzzer.log", "results/fuzzer_logs.txt")
            print("[*] 로그 복사 완료")
        except Exception as e:
            print(f"[!] 비동기 fuzzer 실행 중 오류: {e}")

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

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm"]

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash("유효한 이메일을 입력해주세요.")
            return render_template("signup.html")

        if len(email) < 8:
            flash("이메일은 최소 8자 이상이어야 합니다.")
            return render_template("signup.html")

        if len(password) < 8:
            flash("비밀번호는 최소 8자 이상이어야 합니다.")
            return render_template("signup.html")

        if password != confirm:
            flash("비밀번호가 일치하지 않습니다.")
            return render_template("signup.html")

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cur.fetchone():
            flash("이미 가입된 이메일입니다.")
            return render_template("signup.html")

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        cur.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, hashed_pw))
        db.commit()
        db.close()

        return redirect("/login")

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        db.close()

        if user and bcrypt.check_password_hash(user["password"], password):
            session["user"] = user["email"]
            return redirect("/")
        
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, port=5001)
