import os
import json
import time
from typing import Optional, Dict, Any, List

import requests

# Simple DeepSeek chat interface
# Env:
#  - AI_API_KEY
#  - AI_MODEL (default: deepseek-chat-v3.1)

DEEPSEEK_API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions")
AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
AI_MODEL = os.getenv("AI_MODEL", "deepseek-chat-v3.1").strip()


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {AI_API_KEY}" if AI_API_KEY else "",
        "Content-Type": "application/json",
    }


def _system_prompt() -> str:
    # Friendly, non-technical, and does not reveal infrastructure details.
    return (
        "You are a helpful assistant that diagnoses and fixes Telegram bot deployment issues."
        " Speak simply and kindly. Do NOT mention Docker, containers, or internal hosting details."
        " Focus on concrete, actionable steps the user can take: checking imports, installing packages,"
        " verifying entry file names, fixing syntax/runtime errors, and ensuring the correct bot token."
        " If the user provides error messages, explain likely causes and give exact commands where helpful."
        " Keep suggestions concise and in bullet points if multiple steps are needed."
        " Use English and short Hinglish where appropriate."
    )


def _build_messages(system_prompt: str, user_context: str) -> List[Dict[str, str]]:
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_context},
    ]


def suggest_fix(context: str, max_tokens: int = 400) -> Optional[str]:
    """
    Ask DeepSeek to suggest a fix given a textual context (errors, file names, hints).
    Returns suggestion string or None if unavailable.
    """
    if not AI_API_KEY:
        return None

    payload = {
        "model": AI_MODEL or "deepseek-chat-v3.1",
        "messages": _build_messages(_system_prompt(), context),
        "temperature": 0.2,
        "max_tokens": max_tokens,
    }

    try:
        resp = requests.post(DEEPSEEK_API_URL, headers=_headers(), data=json.dumps(payload), timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        choice = (data.get("choices") or [{}])[0]
        msg = (choice.get("message") or {}).get("content")
        if not msg:
            return None
        # Trim excessive whitespace
        return msg.strip()
    except Exception:
        return None