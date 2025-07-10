# Web Fuzzer Tool

웹 애플리케이션의 입력 폼을 자동으로 탐지하고, 다양한 페이로드를 활용해 보안 취약점을 테스트하는 웹 퍼저(Web Fuzzer)입니다.
크롤링과 퍼징을 자동화하고, 결과를 리포트로 제공하여 취약점 진단과 보고서 생성을 동시에 지원합니다.

---

## 📌 주요 기능
- 크롤러: 입력 폼이 있는 페이지를 자동 탐색
- 퍼저: SQLi, XSS 등의 페이로드를 자동 삽입하여 테스트
- 결과 리포트: 탐지된 취약점을 정리하여 HTML/PDF 형태로 제공
- 웹 인터페이스: Flask 기반 UI로 결과를 조회하고 관리 가능
- DVWA, 테스트 페이지 등 연동 테스트 지원

---

## 🛠 기술 스택
- Backend: Python 3.13, Flask
- Frontend: HTML, CSS (Tailwind + Custom CSS), Jinja2
- Crawler/Fuzzer: Requests, BeautifulSoup
- 기타: SQLite (결과 저장), Docker (테스트 환경 구성)

---

## 🚀 실행 방법
1.	의존성 설치:
 ```
pip install -r requirements.txt
```
2.	서버 실행:
```
python3 app.py
```
3.	웹 접속:
```
http://localhost:5001
```

---

## 🧪 테스트 환경
- DVWA (Damn Vulnerable Web Application)
- 의도적으로 취약한 테스트 페이지
 
