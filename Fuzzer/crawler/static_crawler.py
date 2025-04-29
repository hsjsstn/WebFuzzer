from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from collections import deque
from utils.logger import get_logger

logger = get_logger()

class StaticCrawler:
    def __init__(self, base_url, robot_parser=None):
        self.base_url = base_url
        self.robot_parser = robot_parser
        self.visited = set()
        self.to_visit = deque([base_url])
        self.urls = set()

    def is_valid_url(self, url):
        parsed = urlparse(url)
        if parsed.netloc != urlparse(self.base_url).netloc:
            return False
        if parsed.scheme not in ['http', 'https']:
            return False
        if self.robot_parser and not self.robot_parser.can_fetch('*', url):
            logger.info(f"robots.txt 금지 URL : {url}")
            return False
        return True

    def crawl(self):
        while self.to_visit:
            url = self.to_visit.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            try:
                logger.info(f"[StaticCrawler] 방문 중: {url}")
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200:
                    logger.warning(f"Status Code is Wrong!!: {resp.status_code} - {url}")
                    continue
                soup = BeautifulSoup(resp.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    new_url = urljoin(self.base_url, link['href']).rstrip('/')
                    if self.is_valid_url(new_url) and new_url not in self.visited:
                        self.urls.add(new_url)
                        self.to_visit.append(new_url)
            except Exception as e:
                logger.error(f"[StaticCrawler] Request Falied: {url}, Error: {e}")
                continue
        return self.urls

