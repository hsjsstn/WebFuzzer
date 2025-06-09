import asyncio
import logging
import os
import sys
import urllib.robotparser
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from crawler.static_crawler import StaticCrawler
from crawler.dynamic_crawler import crawl_dynamic
from fuzzing.async_fuzzer import AsyncFuzzer
from reporting.report_generator import generate_pdf_report

os.makedirs("results", exist_ok=True)
log_path = "results/fuzzer_logs.txt"

# 커스텀 포맷터 클래스
class CustomFormatter(logging.Formatter):
    def __init__(self, fmt_with_ts, fmt_without_ts):
        super().__init__()
        self.fmt_with_ts = logging.Formatter(fmt_with_ts)
        self.fmt_without_ts = logging.Formatter(fmt_without_ts)

    def format(self, record):
        msg = record.getMessage().strip()  # 앞뒤 공백/줄바꿈 제거
        # 특정 태그가 포함된 로그에만 타임스탬프 출력
        if any(tag in msg for tag in ['[StaticCrawler]', '[DynamicCrawler]', '[AsyncFuzzer]']):
            return self.fmt_with_ts.format(record)
        else:
            return self.fmt_without_ts.format(record)

# 로거 세팅
logger = logging.getLogger("WebFuzzer")
logger.setLevel(logging.INFO)

if logger.hasHandlers():
    logger.handlers.clear()

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

file_handler = logging.FileHandler(log_path, encoding='utf-8')
file_handler.setLevel(logging.INFO)

fmt_with_ts = '%(asctime)s - %(levelname)s - %(message)s'
fmt_without_ts = '%(message)s'

custom_formatter = CustomFormatter(fmt_with_ts, fmt_without_ts)

console_handler.setFormatter(custom_formatter)
file_handler.setFormatter(custom_formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)


def print_banner():
    logger.info(
        "\n=================================================\n"
        "   🕷️ WebFuzzer CLI - Intelligent Vulnerability Scanner\n"
        "================================================="
    )


def main(base_url=None, max_depth=None, selected_categories=None):
    print_banner()

    if base_url is None or max_depth is None or selected_categories is None:
        base_url = input("🌐 크롤링 시작 URL (예: http://localhost:4280): ").strip()
        if not base_url.startswith("http"):
            base_url = "http://" + base_url

        max_depth = int(input("🔁 최대 크롤링 깊이 (예: 2): ").strip())

        all_categories = ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'ssti', 'open_redirect', 'csrf']

        logger.info("🛡️  사용 가능한 페이로드 유형:")
        categories_text = "\n".join(f"- {c}" for c in all_categories)
        logger.info(categories_text)

        selected_input = input("\n🎯 사용할 페이로드 유형 (콤마로 구분): ").strip()
        selected_categories = [c.strip() for c in selected_input.split(',') if c.strip() in all_categories]

        if not selected_categories:
            logger.error("❌ 유효한 페이로드 유형이 없습니다. 종료합니다.")
            exit(1)

    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(urljoin(base_url, '/robots.txt'))
    try:
        rp.read()
    except:
        logger.warning("⚠️ robots.txt 로드 실패, 무시하고 진행합니다.")

    logger.info("🔎 정적 크롤링 중...")
    static_urls = StaticCrawler(base_url, rp).crawl()

    logger.info("🎥 동적 크롤링 중...")
    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)

    visited, extraction = set(), []
    entry_url = list(static_urls)[0] if static_urls else base_url
    crawl_dynamic(driver, entry_url, max_depth, visited, extraction, rp)

    driver.quit()

    logger.info("📝 폼 수집 중...")
    forms = []
    for result in extraction:
        forms.extend(result['forms'])
        for field in result['independent_inputs']:
            if field.get('name'):
                forms.append({'action': result['url'], 'method': 'get', 'inputs': [field]})

    logger.info("🚀 퍼징 시작...")
    if forms:
        fuzzer = AsyncFuzzer(forms, selected_categories)
        asyncio.run(fuzzer.run())
    else:
        logger.warning("⚠️ 퍼징할 폼이 없습니다.")
        fuzzer = AsyncFuzzer(forms, selected_categories)
        fuzzer.vulnerabilities, fuzzer.attempts = [], []

    logger.info("📄 PDF 리포트 생성 중...")
    generate_pdf_report(
        crawled_urls=static_urls.union(visited),
        extraction_results=extraction,
        vulnerabilities=fuzzer.vulnerabilities,
        attempts=fuzzer.attempts,
        output_path="results/fuzzer_report.pdf"
    )

    logger.info("✅ 퍼징 완료 및 리포트 저장됨: results/fuzzer_report.pdf")

    return list(static_urls.union(visited)), extraction, fuzzer.vulnerabilities, fuzzer.attempts


if __name__ == "__main__":
    main()