from crawler.static_crawler import StaticCrawler
from crawler.dynamic_crawler import crawl_dynamic
from fuzzing.async_fuzzer import AsyncFuzzer
from reporting.report_generator import generate_pdf_report
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import urllib.robotparser
from urllib.parse import urljoin
import asyncio

def main():
    base_url = input("크롤링 시작 URL: ").strip()
    max_depth = int(input("최대 크롤링 깊이: ").strip())

    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(urljoin(base_url, '/robots.txt'))
    rp.read()

    static = StaticCrawler(base_url, rp).crawl()

    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)

    visited, extraction = set(), []
    for url in static:
        crawl_dynamic(driver, url, max_depth, visited, extraction, rp)

    driver.quit()

    forms = []
    for result in extraction:
        forms.extend(result['forms'])
        for field in result['independent_inputs']:
            if field['name']:
                forms.append({'action': result['url'], 'method': 'get', 'inputs': [field]})

    if forms:
        fuzzer = AsyncFuzzer(forms)
        asyncio.run(fuzzer.run())
    else:
        fuzzer = AsyncFuzzer(forms)
        fuzzer.vulnerabilities, fuzzer.attempts = [], []

    generate_pdf_report(static.union(visited), extraction, fuzzer.vulnerabilities, fuzzer.attempts)

    return list(static.union(visited)), extraction, fuzzer.vulnerabilities, fuzzer.attempts

if __name__ == "__main__":
    main()
