import asyncio
import urllib.robotparser
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from crawler.static_crawler import StaticCrawler
from crawler.dynamic_crawler import crawl_dynamic
from fuzzing.async_fuzzer import AsyncFuzzer
from reporting.report_generator import generate_pdf_report

def print_banner():
    print("""
=================================================
   🕷️ WebFuzzer CLI - Intelligent Vulnerability Scanner
=================================================
    """)

# get_user_inputs 함수는 직접 호출하지 않고, main()에서 인자로 받아 처리하도록 변경
# def get_user_inputs():
#     base_url = input("🌐 크롤링 시작 URL (예: http://localhost:4280): ").strip()
#     if not base_url.startswith("http"):
#         base_url = "http://" + base_url
#
#     max_depth = int(input("🔁 최대 크롤링 깊이 (예: 2): ").strip())
#
#     all_categories = ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'ssti', 'open_redirect', 'csrf']
#     print("\n🛡️  사용 가능한 페이로드 유형:")
#     for c in all_categories:
#         print(f" - {c}")
#
#     selected_input = input("\n🎯 사용할 페이로드 유형 (콤마로 구분): ").strip()
#     selected_categories = [c.strip() for c in selected_input.split(',') if c.strip() in all_categories]
#
#     if not selected_categories:
#         print("❌ 유효한 페이로드 유형이 없습니다. 종료합니다.")
#         exit(1)
#
#     return base_url, max_depth, selected_categories

# 🔧 main() 함수가 인자를 직접 받도록 수정
def main(base_url=None, max_depth=None, selected_categories=None):
    print_banner()

    # Flask에서 직접 받은 인자가 없다면, 기존 입력 방식 유지
    if base_url is None or max_depth is None or selected_categories is None:
        # base_url, max_depth, selected_categories = get_user_inputs()
        base_url = input("🌐 크롤링 시작 URL (예: http://localhost:4280): ").strip()
        if not base_url.startswith("http"):
            base_url = "http://" + base_url

        max_depth = int(input("🔁 최대 크롤링 깊이 (예: 2): ").strip())

        all_categories = ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'ssti', 'open_redirect', 'csrf']
        print("\n🛡️  사용 가능한 페이로드 유형:")
        for c in all_categories:
            print(f" - {c}")

        selected_input = input("\n🎯 사용할 페이로드 유형 (콤마로 구분): ").strip()
        selected_categories = [c.strip() for c in selected_input.split(',') if c.strip() in all_categories]

        if not selected_categories:
            print("❌ 유효한 페이로드 유형이 없습니다. 종료합니다.")
            exit(1)

    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(urljoin(base_url, '/robots.txt'))
    try:
        rp.read()
    except:
        print("⚠️ robots.txt 로드 실패, 무시하고 진행합니다.")

    print("\n🔎 정적 크롤링 중...")
    static_urls = StaticCrawler(base_url, rp).crawl()

    print("\n🎥 동적 크롤링 중...")
    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)

    visited, extraction = set(), []

    entry_url = list(static_urls)[0] if static_urls else base_url
    crawl_dynamic(driver, entry_url, max_depth, visited, extraction, rp)

    driver.quit()

    print("\n📝 폼 수집 중...")
    forms = []
    for result in extraction:
        forms.extend(result['forms'])
        for field in result['independent_inputs']:
            if field.get('name'):
                forms.append({'action': result['url'], 'method': 'get', 'inputs': [field]})

    print("\n🚀 퍼징 시작...")
    if forms:
        fuzzer = AsyncFuzzer(forms, selected_categories)
        asyncio.run(fuzzer.run())
    else:
        print("⚠️ 퍼징할 폼이 없습니다.")
        fuzzer = AsyncFuzzer(forms, selected_categories)
        fuzzer.vulnerabilities, fuzzer.attempts = [], []

    print("\n📄 PDF 리포트 생성 중...")
    import os
    os.makedirs("results", exist_ok=True)
    generate_pdf_report(
        crawled_urls=static_urls.union(visited),
        extraction_results=extraction,
        vulnerabilities=fuzzer.vulnerabilities,
        attempts=fuzzer.attempts,
        output_path="results/fuzzer_report.pdf"
    )

    print("\n✅ 퍼징 완료 및 리포트 저장됨: results/fuzzer_report.pdf")

    return list(static_urls.union(visited)), extraction, fuzzer.vulnerabilities, fuzzer.attempts

if __name__ == "__main__":
    main()