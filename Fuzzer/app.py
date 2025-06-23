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

fuzzer_result_id = None  #result id 변수

# 로그인 여부 확인
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
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

@app.route("/loading", methods=["POST", "GET"])
def loading():
    global fuzzer_done, log_start_pos
    
    if request.method == "GET":
        # 직접 GET 요청 시 에러 안내 or 리다이렉트
        flash("⚠️ 퍼징 요청이 없습니다.")
        return redirect(url_for('start'))

    target_url = request.form.get("target_url")
    user_id = session.get("user_id") 

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

    def run_async(user_id):
        global fuzzer_done, fuzzer_data, fuzzer_result_id

        try:
            urls, results, vulns, attempts = main(target_url, max_depth, selected_payloads)

            fuzzer_data["urls"] = urls
            fuzzer_data["results"] = results
            fuzzer_data["vulnerabilities"] = vulns
            fuzzer_data["attempts"] = attempts

            shutil.copyfile("fuzzer.log", "results/fuzzer_logs.txt")
            print("[*] 로그 복사 완료")

            # ✅ DB에 저장
            db = get_db()
            cur = db.cursor()
            cur.execute("""
                INSERT INTO results (user_id, target_url, vuln_count, report_path, log_path, visibility)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                target_url,
                len(vulns),
                "results/fuzzer_report.pdf",
                "results/fuzzer_logs.txt",
                "private"
            ))
            result_id = cur.lastrowid

            for v in vulns:
                cur.execute("""
                    INSERT INTO vulnerabilities (result_id, form, type, payload)
                    VALUES (?, ?, ?, ?)
                """, (
                    result_id,
                    v.get("form", ""),
                    v.get("type", ""),
                    v.get("payload", "")
                ))

            for a in attempts:
                cur.execute("""
                    INSERT INTO attempts (result_id, form, payload, response, is_successful)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    result_id,
                    a.get("form", ""),
                    a.get("payload", ""),
                    a.get("response", ""),
                    a.get("is_successful", False)
                ))

            db.commit()
            db.close()

            fuzzer_result_id = result_id  # INSERT 완료 후에 result_id 저장

        except Exception as e:
            print(f"[!] 비동기 fuzzer 실행 중 오류: {e}")

        fuzzer_done = True

    threading.Thread(target=run_async, args=(user_id,)).start()

    return render_template("loading.html", result_id=None)

@app.route("/logs")
def get_logs():
    global log_start_pos
    global fuzzer_result_id

    try:
        with open("fuzzer.log", "rb") as f:
            f.seek(log_start_pos)
            new_logs = f.read().decode("utf-8", errors="ignore")
    except FileNotFoundError:
        new_logs = "[INFO] 로그 파일이 아직 생성되지 않았습니다."

    return jsonify({
        "logs": new_logs,
        "done": fuzzer_done,
        "result_id": fuzzer_result_id
    })

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
            session["user_id"] = user["id"] 
            return redirect("/")
        
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

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

@app.route("/history")
@login_required
def history():
    db = get_db()
    user_id = session.get("user_id")

    results = db.execute(
        "SELECT * FROM results WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()

    return render_template("history.html", results=results)

@app.route("/result/<int:result_id>")
def view_result(result_id):
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT * FROM results WHERE id = ?", (result_id,))
    result = cur.fetchone()
    if not result:
        return "결과를 찾을 수 없습니다.", 404

    visibility = result["visibility"]
    user_id = session.get("user_id")

    if visibility == "private" and result["user_id"] != user_id:
        return "접근 권한이 없습니다.", 403

    cur.execute("SELECT form, type, payload FROM vulnerabilities WHERE result_id = ?", (result_id,))
    vulnerabilities = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT form, payload, response, is_successful FROM attempts WHERE result_id = ?", (result_id,))
    attempts = [dict(row) for row in cur.fetchall()]

    vulnCounts = {}
    for v in vulnerabilities:
        t = v.get("type", "unknown")
        vulnCounts[t] = vulnCounts.get(t, 0) + 1

    return render_template("result.html",
        vulnerabilities=vulnerabilities,
        attempts=attempts,
        vulnCounts=vulnCounts,
        result=result
    )

@app.route("/results")
def view_results():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT id, target_url, created_at, vuln_count, visibility
        FROM results
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (session["user"],))
    rows = cur.fetchall()

    return render_template("results_list.html", results=rows)

@app.route("/download-pdf")
def download_pdf():
    return send_file("results/fuzzer_report.pdf", as_attachment=True)

@app.route("/download-logs")
def download_logs():
    return send_file("results/fuzzer_logs.txt", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
