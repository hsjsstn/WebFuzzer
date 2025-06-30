import aiohttp
import asyncio
import json
import os
import html
import re
import time
from lxml import html as lxml_html
from urllib.parse import urljoin, urlparse
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

async def login_to_dvwa(session, base_url, username="admin", password="password", security="low"):
    login_url = f"{base_url.rstrip('/')}/login.php"
    index_url = f"{base_url.rstrip('/')}/index.php"

    try:
        # 1. 로그인 페이지에서 user_token 추출
        async with session.get(login_url, timeout=15) as resp:
            login_page_html = await resp.text()
            match = re.search(r'name="user_token"\s+value="([a-zA-Z0-9]+)"', login_page_html)
            token = match.group(1) if match else None
            if token:
                logger.debug(f"[Login] user_token found: {token}")
            else:
                logger.warning("[Login] user_token not found, proceeding without it")

        # 2. security 쿠키 명시적 세팅
        session.cookie_jar.update_cookies({"security": security})

        # 3. 로그인 시도 (user_token 있으면 포함)
        payload = {
            "username": username,
            "password": password,
            "Login": "Login",
        }
        if token:
            payload["user_token"] = token

        async with session.post(login_url, data=payload, timeout=15, allow_redirects=True) as login_resp:
            logger.debug(f"[Login] POST status: {login_resp.status}")
            logger.debug(f"[Login] Set-Cookie: {login_resp.headers.get('Set-Cookie', '')}")
            logger.debug(f"[Login] Cookies after POST: {session.cookie_jar.filter_cookies(base_url)}")

        # 4. index.php에서 로그인 성공 여부 확인
        async with session.get(index_url, timeout=15) as index_resp:
            index_html = await index_resp.text()

            # DVWA 로그인 성공 시 하단에 다음과 같은 메시지가 반드시 존재함
            # <div class="message">You have logged in as 'admin'</div>
            # 또는 <em>Username:</em> admin
            # 또는 <h1>Welcome to Damn Vulnerable Web Application!</h1>
            success_patterns = [
                rf"You have logged in as '{re.escape(username)}'",
                rf"<em>Username:</em>\s*{re.escape(username)}",
                r"Welcome to Damn Vulnerable Web Application"
            ]
            for pat in success_patterns:
                if re.search(pat, index_html, re.IGNORECASE):
                    logger.info(f"[Login] Success! Login marker found for user '{username}'")
                    return True

            logger.error(f"[Login] Failed: no login marker found for user '{username}' in index.php")
            return False

    except Exception as e:
        logger.error(f"[Login] Exception: {repr(e)}")
        return False

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_absolute_action_url(base_url, action):
    if not action or str(action).strip() in ['', '#', '/']:
        return base_url
    if action.startswith('http://') or action.startswith('https://'):
        return action
    return urljoin(base_url, action)

class AdaptivePayloadGenerator:
    def __init__(self, initial_payloads):
        self.payloads = initial_payloads
        self.success_rate = {payload: 0 for category in initial_payloads.values() for payload in category}

    def update_success(self, payload, detected):
        self.success_rate[payload] = self.success_rate.get(payload, 0) * 0.9 + (100 if detected else 0)

    def get_priority_payloads(self):
        return sorted(self.success_rate.keys(), key=lambda p: self.success_rate.get(p, 0), reverse=True)[:50]

class CoverageTracker:
    def __init__(self):
        self.covered_paths = set()

    def update(self, coverage_data):
        new_paths = set(coverage_data) - self.covered_paths
        self.covered_paths.update(new_paths)
        return len(new_paths)

class AsyncFuzzer:
    def __init__(self, forms, selected_categories, payload_path='payloads.json', concurrency=3, base_url=None):
        self.forms = forms
        self.concurrency = concurrency
        self.vulnerabilities = []
        self.attempts = []
        self.payloads = self.load_selected_payloads(payload_path, selected_categories)
        self.payload_generator = AdaptivePayloadGenerator(self.payloads)
        self.coverage_tracker = CoverageTracker()
        self.current_max_coverage = 0
        self.baselines = {}
        self.base_url = base_url

    def load_selected_payloads(self, path, selected_categories):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                all_payloads = json.load(f)
                filtered = {k: v for k, v in all_payloads.items() if k in selected_categories}
                logger.info(f"Selected payload categories: {', '.join(filtered.keys())}")
                return filtered
        else:
            logger.error(f"payloads.json not found: {path}")
            return {}

    async def get_code_coverage(self, session):
        try:
            coverage_url = f"{self.base_url.rstrip('/')}/coverage.php"
            async with session.get(coverage_url) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error(f"Failed to get coverage data: {e}")
        return []

    async def prioritize_payload(self, payload):
        self.payload_generator.update_success(payload, True)

    async def establish_baseline(self, session, form):
        if not any(i.get('name') for i in form['inputs']):
            logger.warning("No input fields → skipping baseline")
            return

        benign_data = {
            i['name']: "SAFE_VALUE"
            for i in form['inputs'] if i.get('name')
        }

        if not benign_data:
            logger.warning("benign_data is empty → skipping")
            return

        action = get_absolute_action_url(self.base_url, form.get('action', ''))
        parsed = urlparse(action)

        if not parsed.scheme.startswith('http'):
            logger.warning(f"Invalid action URL: {action}, skipping")
            return

        try:
            async with session.post(action, data=benign_data, timeout=20) as resp:
                content = await resp.text()
                return {
                    'status': resp.status,
                    'length': len(content),
                    'content': content,
                    'elapsed': float(resp.headers.get('X-Response-Time', 0) or 0)
                }
        except Exception as e:
            logger.error(f"[Baseline request failed] URL: {action}, data: {benign_data}, reason: {repr(e)}")
            return None

    def content_differ(self, text1, text2, threshold=0.2):
        if not text1 or not text2:
            return False
        dist = levenshtein_distance(text1, text2)
        max_len = max(len(text1), len(text2))
        return (dist / max_len) > threshold

    # --- Vulnerability detection logic ---
    def detect_sqli(self, text, payload, baseline, status, elapsed):
        error_patterns = [
            r"you have an error in your sql syntax", r"unclosed quotation mark", r"warning.*mysql",
            r"pg_query\(\):", r"ORA-\d+", r"syntax error.*sql", r"unexpected end of SQL command"
        ]
        if any(re.search(p, text, re.IGNORECASE) for p in error_patterns):
            return "SQL Injection"
        if baseline and (status != baseline['status'] or self.content_differ(text, baseline['content'])):
            return "SQL Injection (Differential)"
        if 'sleep' in payload.lower() and baseline and elapsed > baseline.get('elapsed', 0) + 4:
            return "Blind SQL Injection (Time-Based)"
        return None

    def detect_xss(self, text, payload, baseline):
        if not text or not payload:
            return None

        if payload in text:
            try:
                soup = BeautifulSoup(text, 'html.parser')
                for script in soup.find_all("script"):
                    if payload in script.decode_contents():
                        return "XSS (script block)"
                for tag in soup.find_all(True):
                    for attr_key, attr_val in tag.attrs.items():
                        if isinstance(attr_val, str) and payload in attr_val:
                            return "XSS (attribute injection)"
                        elif isinstance(attr_val, list) and any(payload in v for v in attr_val):
                            return "XSS (attribute list injection)"
                if any(payload in str(tag) for tag in soup.find_all()):
                    return "XSS (HTML tag injection)"
            except Exception as e:
                logger.warning(f"[XSS Parser] Parsing Failed: BeautifulSoup : {e}")

        if html.escape(payload) in text and baseline and self.content_differ(text, baseline['content']):
            return "XSS (encoded context)"

        if baseline and self.content_differ(text, baseline['content']):
            snippet = text[max(0, text.find(payload) - 30):text.find(payload) + 50]
            if any(x in snippet for x in ['<script', 'onerror=', 'alert(', '<svg', 'onload=']):
                return "XSS (pattern-based heuristic)"
        return None

    def detect_command_injection(self, text, payload, baseline, elapsed):
        command_indicators = [
            "Directory of", "bytes free", "Volume Serial Number",
            "root:x:0:0", "drwxr-xr-x", "total [0-9]+"
        ]
        if any(re.search(p, text) for p in command_indicators):
            return "Command Injection"
        if ('sleep' in payload or 'ping' in payload) and baseline and elapsed > baseline.get('elapsed', 0) + 3:
            return "Command Injection (Time-Based)"
        if baseline and self.content_differ(text, baseline['content']):
            return "Command Injection (Differential)"
        return None

    def detect_path_traversal(self, text, payload, baseline):
        if "root:x" in text and baseline and self.content_differ(text, baseline['content']):
            return "Path Traversal"
        return None

    def detect_ssti(self, text, payload):
        if "{{49}}" in text or "${49}" in text or "49" in text:
            return "SSTI"
        return None

    def detect_open_redirect(self, text, payload, status, resp_headers):
        location = resp_headers.get('Location', '')
        if status in [301, 302, 303, 307, 308] and location and not location.startswith(self.base_url):
            return "Open Redirect"
        return None

    def detect_csrf(self, text, payload, baseline):
        if baseline and self.content_differ(text, baseline['content']):
            if any(k in text.lower() for k in ['csrf', 'token missing', 'unauthorized']):
                return "CSRF"
        return None

    def calculate_confidence(self, score, response_time):
        time_factor = min(1.0, response_time / 5.0)
        return min(100, int(score * (1 + 0.3 * time_factor)))

    def extract_evidence(self, text, payload):
        idx = text.find(payload)
        if idx == -1:
            return text[:200]
        start = max(0, idx - 50)
        end = min(len(text), idx + 50)
        return text[start:end]

    async def analyze_response(self, text, payload, form, status, category, elapsed, session, resp_headers):
        action = get_absolute_action_url(self.base_url, form.get('action', ''))
        baseline = self.baselines.get(action)
        found = None

        coverage_data = await self.get_code_coverage(session)
        new_coverage = self.coverage_tracker.update(coverage_data)
        if new_coverage > self.current_max_coverage:
            self.current_max_coverage = new_coverage
            await self.prioritize_payload(payload)

        if category == 'sql_injection':
            found = self.detect_sqli(text, payload, baseline, status, elapsed)
        elif category == 'xss':
            found = self.detect_xss(text, payload, baseline)
        elif category == 'command_injection':
            found = self.detect_command_injection(text, payload, baseline, elapsed)
        elif category == 'path_traversal':
            found = self.detect_path_traversal(text, payload, baseline)
        elif category == 'ssti':
            found = self.detect_ssti(text, payload)
        elif category == 'open_redirect':
            found = self.detect_open_redirect(text, payload, status, resp_headers)
        elif category == 'csrf':
            found = self.detect_csrf(text, payload, baseline)

        result = found or 'No vulnerability detected'
        confidence = self.calculate_confidence(100, elapsed) if found else 0
        evidence = self.extract_evidence(text, payload) if found else ""
        self.attempts.append({
            'form_action': action,
            'payload': payload,
            'category': category,
            'result': result,
            'status': status,
            'elapsed': round(elapsed, 2)
        })

        if found:
            self.vulnerabilities.append({
                'type': found,
                'confidence': confidence,
                'evidence': evidence,
                'payload': payload,
                'form': action,
                'response_code': status
            })
        elif confidence < 50 and found:
            self.vulnerabilities.append({
                'type': "Manual verification required",
                'confidence': confidence,
                'evidence': evidence,
                'payload': payload,
                'form': action,
                'response_code': status
            })

    async def fuzz_form(self, session, form, payload, category):
        data = {i['name']: (payload if i.get('type') == 'text' else 'test') for i in form['inputs'] if i.get('name')}
        method = form.get('method', 'get').lower()
        action = get_absolute_action_url(self.base_url, form.get('action', ''))
        logger.info(f"[AsyncFuzzer] Request action URL: {action}")

        parsed = urlparse(action)
        if not parsed.scheme.startswith('http'):
            logger.warning(f"Invalid action URL: {action}, skipping")
            return

        try:
            if action not in self.baselines:
                baseline = await self.establish_baseline(session, {'action': action, 'inputs': form['inputs']})
                if baseline:
                    self.baselines[action] = baseline

            start_time = time.time()
            if method == 'post':
                async with session.post(action, data=data) as resp:
                    text = await resp.text()
                    elapsed = time.time() - start_time
                    await self.analyze_response(text, payload, form, resp.status, category, elapsed, session, resp.headers)
            else:
                async with session.get(action, params=data) as resp:
                    text = await resp.text()
                    elapsed = time.time() - start_time
                    await self.analyze_response(text, payload, form, resp.status, category, elapsed, session, resp.headers)
        except asyncio.TimeoutError:
            cookies = session.cookie_jar.filter_cookies(action)
            logger.error(f"[TimeoutError] URL: {action}, Cookies: {cookies}")
            self.attempts.append({'form_action': action, 'payload': payload, 'category': category, 'result': 'Timeout', 'status': 'N/A', 'elapsed': 0})
        except Exception as e:
            logger.error(f"[Request failed] URL: {action}, Error: {repr(e)}")
            self.attempts.append({'form_action': action, 'payload': payload, 'category': category, 'result': 'Failed', 'status': 'N/A', 'elapsed': 0})
        await asyncio.sleep(0.2)

    def mutate_payload(self, payload):
        if self.payload_generator.success_rate.get(payload, 0) > 70:
            return self.apply_high_impact_mutations(payload)
        else:
            return self.apply_diverse_mutations(payload)

    def apply_high_impact_mutations(self, payload):
        return payload * 2

    def apply_diverse_mutations(self, payload):
        return payload[::-1]

    async def run(self):
        logger.info("[AsyncFuzzer] Start")
        connector = aiohttp.TCPConnector(limit=self.concurrency)

        async with aiohttp.ClientSession(connector=connector) as session:
            logged_in = await login_to_dvwa(session, self.base_url)
            if not logged_in:
                logger.warning("[Login] Failed. Stopping fuzzing.")
                return []

            for form in self.forms:
                for category, payloads in self.payloads.items():
                    for payload in payloads:
                        await self.fuzz_form(session, form, payload, category)

        logger.info(f"[AsyncFuzzer] Vulnerability scan complete! {len(self.vulnerabilities)} issues found.")
        return self.vulnerabilities

