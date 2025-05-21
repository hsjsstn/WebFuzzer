from urllib.parse import urlparse, urljoin
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from collections import deque
from utils.logger import get_logger

logger = get_logger()

def extract_urls_dynamic(driver, base_url):
    urls = set()
    try:
        links = driver.find_elements(By.TAG_NAME, "a")
        for link in links:
            href = link.get_attribute("href")
            if href and urlparse(href).scheme in ['http', 'https']:
                if urlparse(base_url).netloc == urlparse(href).netloc:
                    urls.add(href.rstrip('/'))
    except Exception as e:
        logger.error(f"[DynamicCrawler] URL 추출 오류: {e}")
    return urls

def extract_forms_dynamic(driver, current_url):
    forms, independent_inputs = [], []
    try:
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        soup = BeautifulSoup(driver.page_source, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action') or current_url
            method = form.get('method', 'get').lower()
            inputs = [{'tag': i.name, 'type': i.get('type', i.name), 'name':i.get('name')} for i in form.find_all(['input', 'textarea'])]
            forms.append({'action': urljoin(current_url, action), 'method': method, 'inputs': inputs})

        for i in soup.find_all(['input', 'textarea']):
            if not i.find_parent('form'):
                independent_inputs.append({'tag':i.name, 'type':i.get('type', i.name), 'name':i.get('name')})

    except Exception as e:
        logger.error(f"[DynamicCrawler] 폼 추출 오류: {e}")
    return forms, independent_inputs

def crawl_dynamic(driver, base_url, max_depth, visited_urls, extraction_results, robot_parser=None):
    queue = deque([(base_url, 0)])
    while queue:
        current_url, depth = queue.popleft()
        if depth > max_depth or current_url in visited_urls:
            continue
        try:
            driver.get(current_url)
            real_url = driver.current_url
            if robot_parser and not robot_parser.can_fetch('*', real_url):
                continue
            visited_urls.add(real_url)

            forms, inputs = extract_forms_dynamic(driver, real_url)
            extraction_results.append({'url': real_url, 'forms': forms, 'independent_inputs':inputs})

            for u in extract_urls_dynamic(driver, base_url):
                if u not in visited_urls:
                    queue.append((u, depth + 1))
        except Exception as e:
            logger.error(f"[DynamicCrawler] 크롤링 중 오류: {e}")