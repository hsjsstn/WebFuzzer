from urllib.parse import urlparse, urljoin, urldefrag
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from bs4 import BeautifulSoup
from collections import deque
from utils.logger import get_logger
import time

logger = get_logger()

def normalize_url(url):
    return urldefrag(url.rstrip('/'))[0]

def extract_urls_dynamic(driver, base_url):
    urls = set()
    try:
        links = driver.find_elements(By.TAG_NAME, "a")
        for link in links:
            href = link.get_attribute("href")
            if href and urlparse(href).scheme in ['http', 'https']:
                if urlparse(base_url).netloc == urlparse(href).netloc:
                    urls.add(normalize_url(href))
    except Exception as e:
        logger.error(f"[DynamicCrawler] URL 추출 오류: {e}")
    return urls

def extract_forms_dynamic(driver, current_url):
    forms, independent_inputs = [], []
    try:
        soup = BeautifulSoup(driver.page_source, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action') or current_url
            method = form.get('method', 'get').lower()
            inputs = [
                {'tag': i.name, 'type': i.get('type', i.name), 'name': i.get('name')}
                for i in form.find_all(['input', 'textarea'])
            ]
            
            if any(i.get('name') for i in inputs):
                forms.append({'action': urljoin(current_url, action), 'method': method, 'inputs': inputs})

        for i in soup.find_all(['input', 'textarea']):
            if not i.find_parent('form') and i.get('name'):
                independent_inputs.append({'tag': i.name, 'type': i.get('type', i.name), 'name': i.get('name')})
    except Exception as e:
        logger.error(f"[DynamicCrawler] 폼 추출 오류: {e}")
    return forms, independent_inputs


def crawl_dynamic(driver, base_url, max_depth, visited_urls, extraction_results, robot_parser=None):
    queue = deque([(normalize_url(base_url), 0)])

    while queue:
        current_url, depth = queue.popleft()
        if depth > max_depth or current_url in visited_urls:
            continue

        if depth == 0:
            logger.info("[DynamicCrawler] Start.")

        try:
            driver.set_page_load_timeout(10)
            driver.get(current_url)
            time.sleep(1.5)

            real_url = normalize_url(driver.current_url)
            if robot_parser and not robot_parser.can_fetch('*', real_url):
                logger.info(f"[DynamicCrawler] robots.txt 차단됨: {real_url}")
                continue

            if real_url in visited_urls:
                continue

            visited_urls.add(real_url)
            logger.info(f"[DynamicCrawler] 방문: {real_url}")

            forms, inputs = extract_forms_dynamic(driver, real_url)
            extraction_results.append({'url': real_url, 'forms': forms, 'independent_inputs': inputs})

            for u in extract_urls_dynamic(driver, base_url):
                if u not in visited_urls:
                    queue.append((u, depth + 1))

        except Exception as e:
            logger.error(f"[DynamicCrawler] 오류: {e}")

    return extraction_results  # 마지막에 반환 추가

