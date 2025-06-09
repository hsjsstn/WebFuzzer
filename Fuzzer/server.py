from flask import Blueprint, request, jsonify
import os
import json
from collections import defaultdict
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1"
)

api_bp = Blueprint("api_bp", __name__)

@api_bp.route("/ai-summary", methods=["POST"])
def ai_summary():
    try:
        user_content = request.json.get("content", "")
        MAX_CHAR_LENGTH = 8000

        # 길이 초과 시: 유형별 개수만 추출
        if len(user_content) > MAX_CHAR_LENGTH:
            try:
                parsed = json.loads(user_content)
                summary = defaultdict(int)
                for item in parsed:
                    vuln_type = item.get("type")
                    if vuln_type:
                        summary[vuln_type] += 1

                summarized_content = ", ".join(
                    f"{count}개의 {vuln_type}" for vuln_type, count in summary.items()
                )
                user_content = summarized_content

            except Exception as parse_err:
                user_content = "입력 데이터가 너무 길고, JSON 파싱에 실패했습니다."

        prompt = f"""
다음은 웹 퍼징을 통해 수집된 취약점 데이터입니다.

{user_content}

위 데이터를 기반으로 각 취약점 유형별로 요약하고, 공통된 영향과 대응 방안을 **한국어로** 간결하게 서술해 주세요.

예: "10가지의 XSS와 4가지의 SSTI가 발견되었습니다. 이들 취약점은 (공통된 영향)을 유발할 수 있으며, 이에 대한 대응으로는 (간단한 대응책)이 있습니다."

항목별 나열 없이, 유형별로 묶어서 **한국어로** 요약해 주세요.
"""

        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": "당신은 웹 보안 전문가입니다."},
                {"role": "user", "content": prompt}
            ]
        )

        result_text = response.choices[0].message.content
        return jsonify({"summary": result_text})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500