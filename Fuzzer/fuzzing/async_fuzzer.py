import aiohttp
import asyncio
import json
import os
import html
import re
import time
from utils.logger import get_logger

logger = get_logger()

class AsyncFuzzer:
    def __init__(self, forms, selected_categories, payload_path='payloads.json', concurrency=5):
        self.forms = forms
        self.concurrency = concurrency
        self.vulnerabilities = []
        self.attempts = []
        self.payloads = self.load_selected_payloads(payload_path, selected_categories)

    def load_selected_payloads(self, path, selected_categories):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                all_payloads = json.load(f)
                filtered = {k: v for k, v in all_payloads.items() if k in selected_categories}
                logger.info(f"선택된 페이로드 카테고리: {', '.join(filtered.keys())}")
                return filtered
        else:
            logger.error(f"payloads.json 없음: {path}")
            return {}

    async def fuzz_form(self, session, form, payload, category):
        data = {i['name']: (payload if i.get('type') == 'text' else 'test') for i in form['inputs'] if i.get('name')}
        method = form.get('method', 'get').lower()
        action = form.get('action', '')

        try:
            start_time = time.time()
            if method == 'post':
                async with session.post(action, data=data) as resp:
                    text = await resp.text()
                    elapsed = time.time() - start_time
                    await self.analyze_response(text, payload, form, resp.status, category, elapsed)
            else:
                async with session.get(action, params=data) as resp:
                    text = await resp.text()
                    elapsed = time.time() - start_time
                    await self.analyze_response(text, payload, form, resp.status, category, elapsed)
        except asyncio.TimeoutError:
            self.attempts.append({'form_action': action, 'payload': payload, 'category': category, 'result': 'Timeout', 'status': 'N/A', 'elapsed': 0})
        except Exception as e:
            logger.error(f"요청 실패: {e}")
            self.attempts.append({'form_action': action, 'payload': payload, 'category': category, 'result': '실패', 'status': 'N/A', 'elapsed': 0})
        await asyncio.sleep(0.2)

    async def analyze_response(self, text, payload, form, status, category, elapsed):
        action = form['action']
        found = None

        if category == 'sql_injection':
            found = self.detect_sqli(text)
        elif category == 'xss':
            found = self.detect_xss(text, payload)
        elif category == 'command_injection':
            found = self.detect_command_injection(text)
        elif category == 'path_traversal':
            found = self.detect_path_traversal(text)
        elif category == 'ssti':
            found = self.detect_ssti(text)
        elif category == 'open_redirect':
            found = self.detect_open_redirect(text)
        elif category == 'csrf':
            found = self.detect_csrf(text, form['action'])

        result = found or '취약점 없음'
        self.attempts.append({
            'form_action': action,
            'payload': payload,
            'category': category,
            'result': result,
            'status': status,
            'elapsed': round(elapsed, 2)
        })

        if found:
            self.vulnerabilities.append({'type': found, 'payload': payload, 'form': action, 'response_code': status})

    def detect_sqli(self, text):
        patterns = [
            r"you have an error in your sql syntax", r"unclosed quotation mark", r"warning.*mysql",
            r"pg_query\(\):", r"ORA-\d+", r"syntax error.*sql", r"unexpected end of SQL command"
        ]
        return "SQL Injection" if any(re.search(p, text, re.IGNORECASE) for p in patterns) else None

    def detect_xss(self, text, payload):
        decoded = html.unescape(text.lower())
        if payload.lower() in decoded:
            return "XSS"
        if any(x in decoded for x in ["<script", "alert(", "onerror=", "onload="]):
            return "XSS"
        return None

    def detect_command_injection(self, text):
        return "Command Injection" if any(s in text for s in ["uid=", "gid=", "root:x", "/bin/sh", "/etc/passwd"]) else None

    def detect_path_traversal(self, text):
        return "Path Traversal" if any(p in text.lower() for p in ["root:x", "/etc/shadow", "..%2f", "..\\..\\"]) else None

    def detect_ssti(self, text):
        return "SSTI" if any(re.search(r, text) for r in [r"\{\{.*?\}\}", r"\$\{.*?\}"]) else None

    def detect_open_redirect(self, text):
        lowered = text.lower()
        return "Open Redirect" if any(re.search(r, lowered) for r in [r'window\.location\s*=\s*\"http', r'location\.href\s*=\s*\"http']) else None

    def detect_csrf(self, text, action_url):
        if any(k in text.lower() for k in ['csrf', 'token missing', 'unauthorized']) and 'set' in action_url:
            return "CSRF"
        return None

    async def run(self):
        logger.info("[AsyncFuzzer] Start")
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self.fuzz_form(session, form, payload, category)
                for form in self.forms
                for category, payloads in self.payloads.items()
                for payload in payloads
            ]
            await asyncio.gather(*tasks)

