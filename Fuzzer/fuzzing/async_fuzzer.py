import aiohttp
import asyncio
import json
import os
from utils.logger import get_logger

logger = get_logger()

class AsyncFuzzer:
    def __init__(self, forms, payload_path='payloads.json', concurrency=10):
        self.forms = forms
        self.concurrency = concurrency
        self.vulnerabilities = []
        self.attempts = []
        self.payloads = self.load_payloads(payload_path)

    def load_payloads(self, path):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            logger.error(f"payloads.json 없음: {path}")
            return {}

    async def fuzz_form(self, session, form, payload):
        data = {i['name']: (payload if i['type'] == 'text' else 'test') for i in form['inputs'] if i['name']}
        try:
            if form['method'] == 'post':
                async with session.post(form['action'], data=data) as resp:
                    await self.analyze_response(await resp.text(), payload, form, resp.status)
            else:
                async with session.get(form['action'], params=data) as resp:
                    await self.analyze_response(await resp.text(), payload, form, resp.status)
            await asyncio.sleep(0.2)
        except Exception as e:
            logger.error(f"요청 실패: {e}")
            self.attempts.append({'form_action': form['action'], 'payload': payload, 'result': '요청 실패'})

    async def analyze_response(self, text, payload, form, status):
        found = None
        if any(err in text.lower() for err in ['error', 'sql', 'syntax']):
            found = 'SQL Injection'
        elif payload in text:
            found = 'XSS'
        if found:
            self.vulnerabilities.append({'type': found, 'payload': payload, 'form': form['action'], 'response_code': status})
        self.attempts.append({'form_action': form['action'], 'payload': payload, 'result': found or '취약점 없음'})

    async def run(self):
        logger.info("[AsyncFuzzer] Start ")

        connector = aiohttp.TCPConnector(limit=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fuzz_form(session, form, payload) for form in self.forms for category in self.payloads.values() for payload in category]
            await asyncio.gather(*tasks)


