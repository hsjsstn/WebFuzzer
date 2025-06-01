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

def get_user_inputs():
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

    return base_url, max_depth, selected_categories

def main():
    print_banner()
    base_url, max_depth, selected_categories = get_user_inputs()

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

    # 동적 크롤링은 최초 진입점 하나로부터 queue 기반 탐색
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

