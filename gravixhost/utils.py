from datetime import datetime
from typing import Optional, Union

import asyncio
import json
import urllib.request
import urllib.error
import re


def escape(text: str) -> str:
    # Minimal escape for HTML
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def bold(text: str) -> str:
    return f"<b>{escape(text)}</b>"


def italic(text: str) -> str:
    return f"<i>{escape(text)}</i>"


def underline(text: str) -> str:
    return f"<u>{escape(text)}</u>"


def strike(text: str) -> str:
    return f"<s>{escape(text)}</s>"


def code(text: str) -> str:
    # Inline monospace
    return f"<code>{escape(text)}</code>"


def pre(text: str) -> str:
    # Block monospace
    return f"<pre>{escape(text)}</pre>"


def human_dt(dt: Optional[datetime]) -> str:
    if not dt:
        return "Not Applicable"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def normalize_token(text: Optional[str]) -> Optional[str]:
    """
    Extract and normalize a Telegram bot token from arbitrary user input.

    Examples handled:
    - "123456:ABC-DEF..." (plain token)
    - "TOKEN = '123456:ABC-DEF...'"
    - "BOT_TOKEN=123456:ABC-DEF..."
    - "Here is my token: 123456:ABC-DEF..."
    - Quotes, spaces, newlines around the token
    """
    if not text:
        return None
    s = str(text).strip()

    # If it looks like KEY=VALUE, peel off VALUE
    if "=" in s and not s.strip().startswith(("http://", "https://")):
        # keep right-hand side only
        rhs = s.split("=", 1)[1].strip()
        s = rhs

    # Remove surrounding quotes if present
    s = s.strip().strip("'\"").strip()

    # Search for the token pattern anywhere in the string
    m = re.search(r"(\d+:[A-Za-z0-9_-]{10,})", s)
    if m:
        return m.group(1).strip()

    # If entire string might be the token but has extra spaces
    s2 = re.sub(r"\s+", "", s)
    m2 = re.search(r"(\d+:[A-Za-z0-9_-]{10,})", s2)
    if m2:
        return m2.group(1).strip()

    return None


def is_valid_token_format(token: str) -> bool:
    # BotFather token format validation
    # Pattern: <digits>:<alphanumeric/underscore/hyphen>, variable length
    return bool(re.match(r"^\d+:[A-Za-z0-9_-]+$", (token or "").strip()))


def _check_token_online(token: str, timeout: float = 5.0) -> Union[bool, None]:
    # Use Telegram getMe to validate token; do this in a thread to avoid blocking loop
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return bool(data.get("ok"))
    except urllib.error.HTTPError as e:
        # 401 Unauthorized -> invalid token
        if e.code == 401:
            return False
        # Other HTTP errors: treat as inconclusive
        return None
    except Exception:
        # Network error or DNS failure -> inconclusive
        return None


async def is_valid_token(token: str) -> bool:
    """
    Validate token by quick format check and then confirm via Telegram getMe.
    Using urllib in a background thread to avoid blocking.
    If online validation is inconclusive (no network), fall back to format validation only.
    """
    # Always normalize first
    norm = normalize_token(token)
    if not norm or not is_valid_token_format(norm):
        return False
    online_ok = await asyncio.to_thread(_check_token_online, norm.strip())
    if online_ok is None:
        return True
    return bool(online_ok)