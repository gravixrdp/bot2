import os
import shutil
import subprocess
import sys
import signal
import ast
import re
import tempfile
import time
from typing import Optional, Tuple, List

from docker import from_env as docker_from_env, errors as docker_errors

from ..config import UPLOADS_DIR, RUNTIME_CPU_LIMIT, RUNTIME_MEM_LIMIT, RUNTIME_NETWORK
from ..storage import log_event, get_settings
from .ai_assistant import suggest_fix

# ---- Token rewriting utilities ------------------------------------------------

_ENV_KEYS_DEFAULT = ["TELEGRAM_TOKEN", "BOT_TOKEN", "TOKEN", "TELEGRAM_BOT_TOKEN"]


def _env_read_expr(env_keys: List[str]) -> ast.AST:
    """
    Build AST expression: os.getenv(k1) or os.getenv(k2) or ... or ""
    """
    keys = env_keys or _ENV_KEYS_DEFAULT
    # os.getenv(keys[0])
    expr: ast.AST = ast.Call(
        func=ast.Attribute(value=ast.Name(id="os", ctx=ast.Load()), attr="getenv", ctx=ast.Load()),
        args=[ast.Constant(value=keys[0])],
        keywords=[]
    )
    for k in keys[1:]:
        expr = ast.BoolOp(
            op=ast.Or(),
            values=[
                expr,
                ast.Call(
                    func=ast.Attribute(value=ast.Name(id="os", ctx=ast.Load()), attr="getenv", ctx=ast.Load()),
                    args=[ast.Constant(value=k)],
                    keywords=[]
                ),
            ],
        )
    # Fallback empty string
    expr = ast.BoolOp(op=ast.Or(), values=[expr, ast.Constant(value="")])
    return expr


class _TokenRewriter(ast.NodeTransformer):
    """
    Rewrites token assignments and constructor arguments to read from environment.
    - VAR = "123456:ABC-DEF..."  -> VAR = os.getenv(...) or ""
    - VAR = "YOUR_BOT_TOKEN_HERE" -> VAR = os.getenv(...) or VAR
    - Bot(VAR) / Bot(token=VAR) / ApplicationBuilder().token(VAR) -> token env-read
    """
    def __init__(self, env_keys: Optional[List[str]] = None, candidate_vars: Optional[List[str]] = None):
        super().__init__()
        self.env_keys = env_keys or _ENV_KEYS_DEFAULT
        self.candidate_vars = set(v for v in (candidate_vars or []) if isinstance(v, str))
        self.need_import_os = False

    def _is_token_literal(self, s: str) -> bool:
        if not isinstance(s, str):
            return False
        # Exact token-like pattern
        if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", s):
            return True
        # Common placeholders
        low = s.lower()
        return "bot_token" in low or "token" in low or "your_bot_token" in low

    def _env_expr(self) -> ast.AST:
        self.need_import_os = True
        return _env_read_expr(self.env_keys)

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        try:
            target = node.targets[0]
            var_name = target.id if isinstance(target, ast.Name) else None
            # Replace assignment to candidate or literal tokens
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                if self._is_token_literal(node.value.value) or (var_name and var_name in self.candidate_vars):
                    return ast.Assign(targets=node.targets, value=self._env_expr())
            if var_name and var_name in self.candidate_vars and isinstance(node.value, ast.Call):
                # VAR = getenv(...)
                if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "getenv":
                    return ast.Assign(targets=node.targets, value=self._env_expr())
                if isinstance(node.value.func, ast.Name) and node.value.func.id == "getenv":
                    return ast.Assign(targets=node.targets, value=self._env_expr())
        except Exception:
            pass
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> ast.AST:
        try:
            # ApplicationBuilder().token(ARG)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "token":
                if node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and self._is_token_literal(arg0.value):
                        node.args[0] = self._env_expr()
                    elif isinstance(arg0, ast.Name) and (arg0.id in self.candidate_vars or arg0.id.upper() in self.candidate_vars):
                        node.args[0] = self._env_expr()
                for kw in node.keywords or []:
                    if kw.arg and kw.arg.lower() == "token":
                        kw.value = self._env_expr()

            # Bot(...), TeleBot(...), Client(...): positional 0 or keyword 'token'
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in {"Bot", "TeleBot", "Client"}:
                if node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and self._is_token_literal(arg0.value):
                        node.args[0] = self._env_expr()
                    elif isinstance(arg0, ast.Name) and (arg0.id in self.candidate_vars or arg0.id.upper() in self.candidate_vars):
                        node.args[0] = self._env_expr()
                for kw in node.keywords or []:
                    if kw.arg and kw.arg.lower() == "token":
                        val = kw.value
                        if isinstance(val, ast.Constant) and isinstance(val.value, str) and self._is_token_literal(val.value):
                            kw.value = self._env_expr()
                        elif isinstance(val, ast.Name) and (val.id in self.candidate_vars or val.id.upper() in self.candidate_vars):
                            kw.value = self._env_expr()
        except Exception:
            pass
        return self.generic_visit(node)


def _fix_common_syntax_issues(code: str) -> str:
    """
    Heuristic fixes for common user-code syntax issues that prevent AST parsing.
    - f-strings with single-quoted outer string and dict-key access inside braces:
      f'Something {d['key']}' -> f"Something {d['key']}"
    Only applies to single-line literals to avoid overreach.
    """
    try:
        # Replace occurrences where an f'...{...['...']...}...' is present on a single line
        pattern = re.compile(r"""f'([^'\n]*\{[^}\n]*\[[\"'][^]\n]*\][^}\n]*\}[^'\n]*)'""")
        return pattern.sub(r'f"\1"', code)
    except Exception:
        return code


def rewrite_token_in_code(code: str, env_keys: Optional[List[str]] = None, candidate_vars: Optional[List[str]] = None) -> str:
    """
    Return a modified code string with token reads redirected to environment.
    Ensures 'import os' exists if needed.
    """
    # Pre-fix common syntax issues to improve parse success
    code_prefixed = _fix_common_syntax_issues(code)
    try:
        tree = ast.parse(code_prefixed)
        rewriter = _TokenRewriter(env_keys=env_keys, candidate_vars=candidate_vars)
        new_tree = rewriter.visit(tree)
        ast.fix_missing_locations(new_tree)
        new_code = ast.unparse(new_tree)
        # Prepend import os if needed and not present
        if rewriter.need_import_os and "import os" not in new_code:
            new_code = "import os\n" + new_code
        return new_code
    except Exception:
        # Fallback: prepend an env token shim and keep the pre-fixed code
        shim = (
            "import os\n"
            "_t = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or os.getenv('TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') or ''\n"
            "TOKEN = _t or globals().get('TOKEN','')\n"
            "BOT_TOKEN = _t or globals().get('BOT_TOKEN','')\n"
        )
        return shim + "\n" + code_prefixed

# Defaults aligned with requested hosting flow
DEFAULT_BASE_IMAGE = "python:3.11-slim"
AIOGRAM_V2_IMAGE = "python:3.9-slim"
DEFAULT_CPU_QUOTA = 100000           # 100% CPU
DEFAULT_MEM_LIMIT = "512m"
DEFAULT_PIDS_LIMIT = 100
BUILD_TIMEOUT_SECS = 300


# Map common import names to their PyPI package equivalents
# This helps when users write code like "import telebot" but the pip package is "pyTelegramBotAPI"
_PYPI_MAP = {
    "telebot": "pyTelegramBotAPI",
    "telegram": "python-telegram-bot",  # PTB provides 'telegram' module
    "PIL": "pillow",
    "cv2": "opencv-python",
    "dotenv": "python-dotenv",
    "bs4": "beautifulsoup4",
    "yaml": "pyyaml",
    "Crypto": "pycryptodome",
    "sklearn": "scikit-learn",
    "httplib2": "httplib2",
    "httpx": "httpx",
    "aiohttp": "aiohttp",
    # Common mismatches / case variants
    "OpenSSL": "pyOpenSSL",
    "configparser": "configparser",
    "ConfigParser": None,  # stdlib in py3 under 'configparser' - skip auto-install
    "HTMLParser": None,    # stdlib in py3 under 'html.parser' - skip auto-install
    "Queue": None,         # stdlib in py3 under 'queue'
    "StringIO": None,      # stdlib in py3 under 'io'
}

# Modules that should never be attempted to install via pip (stdlib, meta, placeholders)
_BLACKLIST = {
    # Python 3 stdlib (common)
    "__builtin__", "builtins", "__future__", "typing", "dataclasses", "asyncio",
    "sys", "os", "json", "re", "time", "datetime", "pathlib", "subprocess", "logging",
    "itertools", "functools", "collections", "math", "random", "hashlib", "hmac",
    "base64", "threading", "multiprocessing", "urllib", "http", "email", "sqlite3",
    "csv", "statistics", "enum", "types", "contextlib", "tempfile", "zipfile",
    "tarfile", "shutil", "glob", "fnmatch", "importlib", "inspect", "traceback",
    "argparse", "getopt", "site", "builtins", "io", "pickle", "socket", "select",
    "ssl", "struct", "json", "re", "math", "decimal", "fractions", "numbers",
    "abc", "array", "atexit", "binascii", "bisect", "bz2", "calendar", "cgi",
    "codecs", "colorsys", "compileall", "concurrent", "ctypes", "difflib",
    "distutils", "doctest", "enum", "errno", "faulthandler", "filecmp", "fileinput",
    "gc", "getopt", "getpass", "gettext", "gzip", "heapq", "hmac", "html", "html.parser",
    "http.client", "http.server", "imaplib", "ipaddress", "keyword", "linecache",
    "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "mimetypes",
    "mmap", "msvcrt", "netrc", "nis", "nntplib", "ntpath", "operator", "optparse",
    "os.path", "plistlib", "platform", "poplib", "posix", "pprint", "pty", "pwd",
    "py_compile", "queue", "quopri", "reprlib", "resource", "sched", "secrets",
    "selectors", "shelve", "shlex", "signal", "site", "smtpd", "smtplib", "sndhdr",
    "socketserver", "sqlite3", "ssl", "stat", "statistics", "string", "stringprep",
    "sunau", "symtable", "sysconfig", "tabnanny", "telnetlib", "tempfile", "termios",
    "textwrap", "threading", "timeit", "tkinter", "token", "tokenize", "trace",
    "tracemalloc", "turtle", "types", "typing", "unicodedata", "unittest", "urllib",
    "uuid", "venv", "warnings", "wave", "weakref", "webbrowser", "xml", "xmlrpc",
    "zipapp", "zipfile", "zoneinfo",
    # Python 2-only names that should not be pip-installed
    "Queue", "StringIO", "ConfigParser", "HTMLParser", "httplib", "urlparse",
    "cookielib", "cPickle", "SimpleHTTPServer", "BaseHTTPServer", "SocketServer",
    "htmlentitydefs", "imp", "dummy_thread", "dummy_threading",
}


def ensure_user_dir(user_id: int) -> str:
    path = os.path.join(UPLOADS_DIR, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path


def new_bot_workspace(user_id: int, bot_id: str) -> str:
    base = ensure_user_dir(user_id)
    path = os.path.join(base, bot_id)
    os.makedirs(path, exist_ok=True)
    return path


def save_upload(user_id: int, bot_id: str, file_name: str, content: bytes) -> str:
    path = new_bot_workspace(user_id, bot_id)
    file_path = os.path.join(path, file_name)
    with open(file_path, "wb") as f:
        f.write(content)
    # If zip, extract
    if file_name.lower().endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            zip_ref.extractall(path)
        os.remove(file_path)
    return path


def _normalize_requirement(name: str) -> Optional[str]:
    """
    Normalize an import/module name or raw requirement line to a PyPI-installable requirement.
    - Maps common import names to their actual PyPI package
    - Filters obviously invalid placeholders (e.g., '%(module)s')
    - Skips stdlib and blacklisted module names
    - Skips suspicious names (uppercase module names) unless explicitly mapped
    """
    if not name:
        return None
    s = name.strip()
    if not s or s.startswith("#"):
        return None
    # Skip obvious placeholders from mis-templated requirements
    if "%(" in s and ")s" in s:
        return None
    # If the line looks like a valid pinned requirement (contains space is suspicious)
    if " " in s:
        # Spaces in requirement lines are usually invalid, skip them
        return None
    # If it's already a requirement spec (contains ==, >=, etc.) keep it
    for sep in ("==", ">=", "<=", "~=", ">", "<", "!="):
        if sep in s:
            return s
    # Otherwise treat as a module/import name and map if needed
    base = s.split(".")[0]
    # Skip private/dunder and blacklisted names
    if base.startswith("_") or base in _BLACKLIST:
        return None
    # Heuristic: skip names that contain uppercase letters unless we have an explicit map
    if any(c.isupper() for c in base) and base not in _PYPI_MAP:
        return None
    # Map common aliases
    mapped = _PYPI_MAP.get(base, base)
    if mapped is None:
        return None
    # Final guard: basic sanity check to avoid clearly invalid package names
    import re
    # Allow mixed-case names (e.g., pyTelegramBotAPI). PyPI is case-insensitive.
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$", mapped):
        return None
    return mapped


def detect_framework(code: str) -> Tuple[str, List[str]]:
    """
    Detect common Telegram bot frameworks and discover candidate token env/var names.
    Returns (framework_key, candidate_names)
    candidate_names can include variable identifiers and environment variable keys.
    """
    framework = "unknown"
    candidates: List[str] = ["TOKEN", "BOT_TOKEN", "TELEGRAM_TOKEN", "TELEGRAM_BOT_TOKEN"]

    # Helper: add unique, safe names
    def _add(name: Optional[str]):
        if not name:
            return
        s = str(name).strip().strip("'\"")
        if not s:
            return
        # Basic sanity for env/var names
        import re as _re
        if not _re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s):
            return
        if s not in candidates:
            candidates.append(s)

    try:
        tree = ast.parse(code)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        if "aiogram" in imports:
            framework = "aiogram_v2" if "executor.start_polling" in code else "aiogram_v3"
        elif "telebot" in imports:
            framework = "pytelegrambotapi"
        elif "telegram" in imports:
            framework = "python-telegram-bot"
        elif "pyrogram" in imports:
            framework = "pyrogram"

        # Scan assignments like VAR = "123456:ABC-DEF..." or VAR = os.getenv("NAME")
        for node in ast.walk(tree):
            try:
                if isinstance(node, ast.Assign) and node.targets:
                    # Target name
                    target = node.targets[0]
                    var_name = target.id if isinstance(target, ast.Name) else None

                    # Right-hand side
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        s = node.value.value
                        if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", s):
                            _add(var_name)
                    elif isinstance(node.value, ast.Call):
                        # os.getenv("NAME")
                        if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "getenv":
                            if node.value.args and isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str):
                                _add(node.value.args[0].value)
                                _add(var_name)
                        elif isinstance(node.value.func, ast.Name) and node.value.func.id == "getenv":
                            if node.value.args and isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str):
                                _add(node.value.args[0].value)
                                _add(var_name)
                # Detect constructor usage and pull the arg source
                if isinstance(node, ast.Call):
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr

                    # aiogram Bot(...), telebot.TeleBot(...), ApplicationBuilder().token(...)
                    if func_name in {"Bot", "TeleBot", "Client"}:
                        # First positional or keyword 'token'
                        tok_expr = None
                        if node.args:
                            tok_expr = node.args[0]
                        for kw in getattr(node, "keywords", []):
                            if kw.arg and kw.arg.lower() == "token":
                                tok_expr = kw.value
                                break
                        if isinstance(tok_expr, ast.Name):
                            _add(tok_expr.id)
                        elif isinstance(tok_expr, ast.Call):
                            # getenv in constructor
                            if isinstance(tok_expr.func, ast.Attribute) and tok_expr.func.attr == "getenv":
                                if tok_expr.args and isinstance(tok_expr.args[0], ast.Constant) and isinstance(tok_expr.args[0].value, str):
                                    _add(tok_expr.args[0].value)
                            elif isinstance(tok_expr.func, ast.Name) and tok_expr.func.id == "getenv":
                                if tok_expr.args and isinstance(tok_expr.args[0], ast.Constant) and isinstance(tok_expr.args[0].value, str):
                                    _add(tok_expr.args[0].value)
                    # python-telegram-bot: ApplicationBuilder().token(VAR).build()
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "token":
                        if node.args:
                            tok_expr = node.args[0]
                            if isinstance(tok_expr, ast.Name):
                                _add(tok_expr.id)
                            elif isinstance(tok_expr, ast.Constant) and isinstance(tok_expr.value, str):
                                # hardcoded token literal (can't override), ignore
                                pass
                            elif isinstance(tok_expr, ast.Call):
                                if isinstance(tok_expr.func, ast.Attribute) and tok_expr.func.attr == "getenv":
                                    if tok_expr.args and isinstance(tok_expr.args[0], ast.Constant) and isinstance(tok_expr.args[0].value, str):
                                        _add(tok_expr.args[0].value)
            except Exception:
                # Be robust to AST weirdness
                pass

    except Exception:
        # Fallback regex-based detection to add a few more names
        for pattern in [
            r'([A-Za-z_]\w*)\s*=\s*["\']([0-9]+:[A-Za-z0-9_-]+)["\']',
            r'os\.getenv\(\s*["\']([A-Za-z_]\w*)["\']\s*\)',
        ]:
            for m in re.finditer(pattern, code):
                _add(m.group(1))

    # Also regex scan for common variations users might write
    for pattern in [
        r'\bTOKEN\b',
        r'\bBOT_?TOKEN\b',
        r'\bTELEGRAM_?TOKEN\b',
        r'\bAPI_?TOKEN\b',
        r'\bMY_?BOT_?TOKEN\b',
    ]:
        for m in re.finditer(pattern, code, flags=re.IGNORECASE):
            _add(m.group(0))

    # Normalize casing duplicates (keep original plus uppercase variant)
    uniq = []
    seen = set()
    for n in candidates:
        if n not in seen:
            uniq.append(n)
            seen.add(n)
    candidates = uniq
    return framework, candidates


def guess_requirements(framework: str) -> List[str]:
    fmap = {
        "aiogram_v2": "aiogram<3.0",
        "aiogram_v3": "aiogram>=3.0",
        "pytelegrambotapi": "pyTelegramBotAPI",
        # PTB v21.x required for KeyboardButtonRequestUser/Chat, etc.
        "python-telegram-bot": "python-telegram-bot>=21.0",
        "pyrogram": "pyrogram",
    }
    return [fmap[framework]] if framework in fmap else []


# Simplified analyzer to mirror the provided script's behavior
def analyze_code(code: str) -> tuple[str, str, List[str]]:
    """
    Return (framework, token_var, reqs_guess) using a lightweight approach
    like the reference script.
    """
    # Framework detection (light)
    framework = "unknown"
    try:
        tree = ast.parse(code)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split('.')[0])
        if 'aiogram' in imports:
            framework = 'aiogram_v2' if 'executor.start_polling' in code else 'aiogram_v3'
        elif 'telebot' in imports:
            framework = 'pytelegrambotapi'
        elif 'telegram' in imports:
            framework = 'python-telegram-bot'
        elif 'pyrogram' in imports:
            framework = 'pyrogram'
    except Exception:
        pass

    # Token variable guess
    token_var = "TOKEN"
    for pattern in [
        r'([a-zA-Z_]\w*)\s*=\s*["\']([0-9]+:[a-zA-Z0-9_-]+)["\']',
        r'([a-zA-Z_]\w*)\s*=\s*os\.getenv'
    ]:
        m = re.search(pattern, code)
        if m:
            token_var = m.group(1)
            break

    reqs = guess_requirements(framework)
    return framework, token_var, reqs


def build_and_run_from_code(
    uid: int,
    name: str,
    code: str,
    reqs: List[str],
    framework: str,
    token_var: str,
    token: str,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Advanced single-file builder:
    - Rewrite token reads to use environment (so user doesn't need to paste token in code).
    - Use the same runner/Dockerfile as multi-file to inject token safely.
    - Pass TELEGRAM_TOKEN at runtime instead of baking ENV into the image.
    - Short health check; surface concise error logs if it exits immediately.
    """
    temp_dir = None
    client = docker_from_env()
    try:
        temp_dir = tempfile.mkdtemp()

        # Rewrite code to read token from environment where possible and fix common syntax issues
        try:
            framework_detected, candidate_names = detect_framework(code)
            # If framework detection disagrees with provided, keep provided 'framework' for base image choice.
            _ = framework_detected
            code = rewrite_token_in_code(code, env_keys=_ENV_KEYS_DEFAULT, candidate_vars=candidate_names)
        except Exception:
            code = _fix_common_syntax_issues(code)

        # Write code and requirements
        with open(os.path.join(temp_dir, "bot.py"), "w", encoding="utf-8") as f:
            f.write(code)
        with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(reqs) if reqs else "")

        # Write runner + Dockerfile like the hardened path
        write_runner_and_dockerfile(temp_dir, entry="bot.py", requirements=reqs)

        image_tag = f"hostbot_{uid}_{name}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")
        container_name = f"hostbot_{uid}_{name}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")

        # Build image
        client.images.build(path=temp_dir, tag=image_tag, rm=True)

        # Ensure network exists or use default bridge
        network = RUNTIME_NETWORK
        if network:
            try:
                nets = client.networks.list(names=[network])
                if not nets:
                    client.networks.create(name=network)
                    log_event(f"Created missing Docker network: {network}")
            except Exception:
                log_event(f"Could not verify/create network '{network}', proceeding with defaults.")
                network = None

        # Run container with TELEGRAM_TOKEN env and resource limits
        container = client.containers.run(
            image_tag,
            name=container_name,
            detach=True,
            environment={
                "TELEGRAM_TOKEN": token,
                "BOT_TOKEN": token,
                "TOKEN": token,
                "TELEGRAM_BOT_TOKEN": token,
                token_var: token if token_var else token,
            },
            cpu_quota=DEFAULT_CPU_QUOTA,
            mem_limit=DEFAULT_MEM_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            network=network if network else None,
            restart_policy={"Name": "no"},
        )

        rid = container.id

        # Short health check: if it exits immediately, extract helpful error
        try:
            time.sleep(2)
            container.reload()
            status = getattr(container, "status", "")
            if status != "running":
                exit_code = None
                try:
                    container.reload()
                    exit_code = container.attrs.get("State", {}).get("ExitCode")
                except Exception:
                    exit_code = None

                logs = get_runtime_logs(rid, tail=800) or ""
                lines = logs.splitlines() if logs else []
                filtered = [l for l in lines if not l.startswith("gravix_runner:")]
                short_err = ""
                for line in filtered:
                    if any(k in line for k in ("Traceback", "SyntaxError", "Error", "Exception", "Unauthorized", "InvalidToken", "ValueError", "RuntimeError")):
                        short_err = line.strip()
                        break
                if not short_err and filtered:
                    for line in reversed(filtered):
                        if line.strip():
                            short_err = line.strip()
                            break
                if not short_err:
                    short_err = "process exited without error logs — ensure your bot starts a polling loop (e.g., app.run_polling())"

                msg = f"{short_err} (exit code {exit_code if exit_code is not None else '?'})"
                log_event(f"Runtime crashed {rid} for {name}: {msg}")
                try:
                    client.api.remove_container(rid, force=True)
                except Exception:
                    pass
                return False, None, f"runtime_error: {msg}"
        except Exception:
            pass

        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return True, rid, None
    except docker_errors.BuildError:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return False, None, "build_error"
    except Exception as e:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return False, None, f"{str(e)[:200]}"


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def _parse_requirements_lines(text: str) -> List[str]:
    """
    Parse requirement-style lines, preserving version pins, handling -r includes lightly,
    and skipping comments or obviously invalid placeholders.
    """
    if not text:
        return []
    reqs: List[str] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        # Skip options commonly present in requirements files which we don't want to pass through
        if s.startswith(("-", "--")):
            # Handle -r otherfile.txt includes very simply: ignore here (workspace scanning will pick that file too)
            if s.startswith("-r") or s.startswith("--requirement"):
                continue
            # Safety: skip unknown pip options to avoid breaking builds
            continue
        norm = _normalize_requirement(s)
        if norm:
            reqs.append(norm)
    return reqs


def _parse_pyproject(text: str) -> List[str]:
    """
    Extract dependencies from pyproject.toml for Poetry or PEP 621 projects.
    Very light TOML parsing via regex to avoid extra deps.
    """
    if not text:
        return []
    reqs: List[str] = []
    try:
        # Poetry [tool.poetry.dependencies]
        block = re.search(r"(?s)\\[tool\\.poetry\\.dependencies\\](.+?)(\\n\\[|\\Z)", text)
        if block:
            body = block.group(1)
            for m in re.finditer(r"(?m)^\\s*([A-Za-z0-9_.+-]+)\\s*=\\s*['\"]?([^'\"\\n]+)['\"]?", body):
                name = m.group(1)
                ver = m.group(2).strip()
                # Skip python itself
                if name.lower() == "python":
                    continue
                spec = f"{name}{('==' + ver) if re.match(r'^\\d', ver) else ver if ver else ''}".strip()
                norm = _normalize_requirement(spec) or _normalize_requirement(name)
                if norm:
                    reqs.append(norm)
        # PEP 621 [project] dependencies = [...]
        arr = re.search(r"(?s)\\[project\\][^\\[]*?dependencies\\s*=\\s*\\[(.+?)\\]", text)
        if arr:
            body = arr.group(1)
            for m in re.finditer(r"['\"]([^'\"]+)['\"]", body):
                spec = m.group(1).strip()
                norm = _normalize_requirement(spec)
                if norm:
                    reqs.append(norm)
    except Exception:
        pass
    return reqs


def _parse_setup_cfg(text: str) -> List[str]:
    """
    Extract install_requires from setup.cfg.
    """
    if not text:
        return []
    reqs: List[str] = []
    try:
        block = re.search(r"(?s)\\[options\\](.+?)(\\n\\[|\\Z)", text)
        if block:
            body = block.group(1)
            ir = re.search(r"(?s)install_requires\\s*=\\s*(.+?)(\\n\\w|\\Z)", body)
            if ir:
                lines = ir.group(1)
                for raw in lines.splitlines():
                    s = raw.strip().strip(",")
                    if not s or s.startswith("#"):
                        continue
                    norm = _normalize_requirement(s)
                    if norm:
                        reqs.append(norm)
    except Exception:
        pass
    return reqs


def _parse_pipfile(text: str) -> List[str]:
    """
    Extract packages from Pipfile (TOML-like).
    """
    if not text:
        return []
    reqs: List[str] = []
    try:
        for section in ("\\[packages\\]", "\\[dev-packages\\]"):
            block = re.search(rf"(?s){section}(.+?)(\\n\\[|\\Z)", text)
            if block:
                body = block.group(1)
                for m in re.finditer(r"(?m)^\\s*([A-Za-z0-9_.+-]+)\\s*=\\s*['\\\"]?([^'\\\"\\n]+)['\\\"]?", body):
                    name = m.group(1)
                    ver = m.group(2).strip()
                    spec = f"{name}{('==' + ver) if re.match(r'^\\d', ver) else ver if ver else ''}".strip()
                    norm = _normalize_requirement(spec) or _normalize_requirement(name)
                    if norm:
                        reqs.append(norm)
    except Exception:
        pass
    return reqs


def detect_requirements(workspace: str) -> List[str]:
    """
    Advanced dependency detection:
    - Parse Python files via AST (fallback regex) to collect import roots.
    - Read multiple manifest files: requirements*.txt, pyproject.toml, setup.cfg, Pipfile.
    - Map common import aliases to PyPI names, preserving version pins from manifests.
    - Filter stdlib/blacklisted modules and deduplicate.
    """
    import_names = set()

    def collect_imports_ast(py_path: str):
        try:
            src = _read_text(py_path)
            if src is None:
                return
            tree = ast.parse(src, filename=py_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        base = (alias.name or "").split(".")[0]
                        if base:
                            import_names.add(base)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        base = node.module.split(".")[0]
                        if base:
                            import_names.add(base)
        except Exception:
            # Ignore parse errors in user code; we'll try regex next
            collect_imports_regex(py_path)

    def collect_imports_regex(py_path: str):
        src = _read_text(py_path)
        if not src:
            return
        try:
            # import x, import x as y, from x import y
            for m in re.finditer(r"(?m)^[ \t]*import[ \t]+([A-Za-z_][A-Za-z0-9_\.]*)", src):
                base = m.group(1).split(".")[0]
                if base:
                    import_names.add(base)
            for m in re.finditer(r"(?m)^[ \t]*from[ \t]+([A-Za-z_][A-Za-z0-9_\.]*)[ \t]+import[ \t]+", src):
                base = m.group(1).split(".")[0]
                if base:
                    import_names.add(base)
        except Exception:
            pass

    # Walk all python files
    for root, _, files in os.walk(workspace):
        for f in files:
            if f.endswith(".py"):
                collect_imports_ast(os.path.join(root, f))

    # Requirements collected from manifests
    reqs_from_manifests: List[str] = []
    # requirements.txt + common variants
    for filename in ("requirements.txt", "requirements.in", "requirements.dev.txt"):
        path = os.path.join(workspace, filename)
        if os.path.exists(path):
            text = _read_text(path)
            reqs_from_manifests += _parse_requirements_lines(text or "")

    # pyproject.toml
    pyproject_path = os.path.join(workspace, "pyproject.toml")
    if os.path.exists(pyproject_path):
        reqs_from_manifests += _parse_pyproject(_read_text(pyproject_path) or "")

    # setup.cfg
    setup_cfg_path = os.path.join(workspace, "setup.cfg")
    if os.path.exists(setup_cfg_path):
        reqs_from_manifests += _parse_setup_cfg(_read_text(setup_cfg_path) or "")

    # Pipfile
    pipfile_path = os.path.join(workspace, "Pipfile")
    if os.path.exists(pipfile_path):
        reqs_from_manifests += _parse_pipfile(_read_text(pipfile_path) or "")

    # Map imports to PyPI names
    reqs_from_imports: List[str] = []
    for base in import_names:
        norm = _normalize_requirement(base)
        if norm:
            reqs_from_imports.append(norm)

    # Framework-specific ensures
    if "telebot" in import_names:
        reqs_from_imports.append("pyTelegramBotAPI")
    if "telegram" in import_names:
        # Pin PTB to >=21 for new APIs
        reqs_from_imports.append("python-telegram-bot>=21.0")
    if "aiogram" in import_names:
        # Prefer aiogram>=3 unless legacy v2 is detected elsewhere
        reqs_from_imports.append("aiogram>=3.0")

    # Merge and deduplicate, preserving pins from manifests where available
    final: List[str] = []
    seen_lower = set()

    def add_spec(spec: str):
        s = (spec or "").strip()
        if not s:
            return
        key = s.lower()
        if key not in seen_lower:
            final.append(s)
            seen_lower.add(key)

    # Manifests first (more authoritative)
    for r in reqs_from_manifests:
        add_spec(r)
    # Then imports-based guesses
    for r in reqs_from_imports:
        add_spec(r)

    # Sort for stability
    return sorted(final)


def write_runner_and_dockerfile(workspace: str, entry: Optional[str] = None, requirements: Optional[List[str]] = None):
    """
    Write a single Python runner and a valid Dockerfile (with proper newlines).
    This removes duplicated writes and ensures clean contents.
    """
    entry_file = entry or "bot.py"

    # Python runner: injects token into globals so common patterns like BOT_TOKEN/TOKEN work
    runner_py = os.path.join(workspace, "gravix_runner.py")
    runner_code = f"""import os, runpy, sys, subprocess, threading, time, re

token = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or os.getenv('TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') or ''
# Expose in env for libraries that read from environment
os.environ['BOT_TOKEN'] = token
os.environ['TELEGRAM_TOKEN'] = token
os.environ['TOKEN'] = token
os.environ['TELEGRAM_BOT_TOKEN'] = token
# Prepare globals so user code can reference BOT_TOKEN or TOKEN directly
init_globals = {{'BOT_TOKEN': token, 'TOKEN': token, 'TELEGRAM_TOKEN': token}}
# Ensure current working directory is the app root
os.chdir(os.path.dirname(__file__))

# Heartbeat thread to confirm liveness in logs
def _heartbeat():
    while True:
        try:
            print('gravix_runner: heartbeat alive')
        except Exception:
            pass
        time.sleep(30)
threading.Thread(target=_heartbeat, daemon=True).start()

# Run the user's entry file and capture its global namespace
print('gravix_runner: entry={entry_file} token_len=%d' % (len(token)))
def _try_run():
    # Return the globals dict resulting from executing the user script
    return runpy.run_path('{entry_file}', init_globals=init_globals)

def _autostart(globs):
    # Try to auto-start common frameworks using objects found in the executed script's globals.
    g = globs or {}
    vals = list(g.values())

    # pyTelegramBotAPI: TeleBot/AsyncTeleBot
    try:
        for v in vals:
            if hasattr(v, 'infinity_polling') or hasattr(v, 'polling'):
                try:
                    if hasattr(v, 'infinity_polling'):
                        print('gravix_runner: auto-start TeleBot.infinity_polling()')
                        v.infinity_polling()
                        return True
                    print('gravix_runner: auto-start TeleBot.polling()')
                    v.polling(none_stop=True)
                    return True
                except Exception as e:
                    print('gravix_runner: polling failed:', e)
    except Exception:
        pass

    # python-telegram-bot: Application.run_polling(), Updater.start_polling()
    try:
        for v in vals:
            if hasattr(v, 'run_polling'):
                try:
                    print('gravix_runner: auto-start Application.run_polling()')
                    v.run_polling()
                    return True
                except Exception as e:
                    print('gravix_runner: run_polling failed:', e)
            if hasattr(v, 'start_polling'):
                try:
                    print('gravix_runner: auto-start Updater.start_polling()')
                    v.start_polling()
                    if hasattr(v, 'idle'):
                        v.idle()
                    return True
                except Exception as e:
                    print('gravix_runner: start_polling failed:', e)
    except Exception:
        pass

    # Pyrogram: Client.run() or start()+idle()
    try:
        for v in vals:
            if hasattr(v, 'run'):
                try:
                    print('gravix_runner: auto-start Pyrogram.Client.run()')
                    v.run()
                    return True
                except Exception as e:
                    print('gravix_runner: run failed:', e)
            if hasattr(v, 'start') and hasattr(v, 'idle'):
                try:
                    print('gravix_runner: auto-start Pyrogram.Client.start()+idle()')
                    v.start()
                    v.idle()
                    return True
                except Exception as e:
                    print('gravix_runner: start+idle failed:', e)
    except Exception:
        pass

    return False

try:
    g = _try_run()
    # If the user script returns immediately, attempt to auto-start common frameworks
    started = _autostart(g)
    if not started:
        print('gravix_runner: user script finished (no long-running loop)')
    sys.exit(0)
except ModuleNotFoundError as e:
    missing = getattr(e, 'name', None)
    if not missing and 'No module named' in str(e):
        m = re.search(r"No module named ['\\\"]([^'\\\"]+)['\\\"]", str(e))
        if m:
            missing = m.group(1)
    _MAP = {{
        'telebot': 'pyTelegramBotAPI',
        'telegram': 'python-telegram-bot',
        'PIL': 'pillow',
        'cv2': 'opencv-python',
        'bs4': 'beautifulsoup4',
        'yaml': 'pyyaml',
        'Crypto': 'pycryptodome',
        'OpenSSL': 'pyOpenSSL',
    }}
    pkg = _MAP.get(missing)
    if pkg:
        print('gravix_runner: auto-installing %s for missing module %s' % (pkg, missing))
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg])
            g = _try_run()
            started = _autostart(g)
            if not started:
                print('gravix_runner: user script finished (no long-running loop)')
            sys.exit(0)
        except Exception:
            import traceback; traceback.print_exc(); sys.exit(1)
    else:
        raise
except SystemExit:
    raise
except Exception:
    import traceback
    traceback.print_exc()
    sys.exit(1)
"""
    with open(runner_py, "w", encoding="utf-8", newline="\n") as f:
        f.write(runner_code)

    # Shell runner (compatibility)
    runner_sh = os.path.join(workspace, "gravix_runner.sh")
    with open(runner_sh, "w", encoding="utf-8", newline="\n") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("set -e\n")
        f.write('export BOT_TOKEN="${TELEGRAM_TOKEN}"\n')
        f.write("python gravix_runner.py\n")
    os.chmod(runner_sh, 0o755)

    # Write autodetected requirements file (preferred)
    req_auto_path = None
    if requirements:
        req_auto_path = os.path.join(workspace, "requirements.autodetected.txt")
        with open(req_auto_path, "w", encoding="utf-8", newline="\n") as rf:
            rf.write("\n".join(requirements))
        # Also ensure a requirements.txt exists for user code
        req_txt_path = os.path.join(workspace, "requirements.txt")
        if not os.path.exists(req_txt_path):
            try:
                with open(req_txt_path, "w", encoding="utf-8", newline="\n") as rtf:
                    rtf.write("\n".join(requirements))
            except Exception:
                pass

    # Decide run mode from settings
    try:
        settings = get_settings()
        run_mode = str(settings.get("run_mode", "runner")).lower()
    except Exception:
        run_mode = "runner"

    # Write a valid Dockerfile
    dockerfile = os.path.join(workspace, "Dockerfile")
    with open(dockerfile, "w", encoding="utf-8", newline="\n") as f:
        f.write("FROM python:3.11-slim\n")
        f.write("WORKDIR /app\n")
        f.write("COPY . /app\n")
        # Basic system deps that frequently help builds (kept minimal)
        f.write("RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*\n")
        f.write("RUN pip install --no-cache-dir --upgrade pip\n")
        # Prefer installing autodetected requirements first (clean set)
        if req_auto_path:
            f.write("RUN pip install -r requirements.autodetected.txt\n")
        # Then try user requirements if present
        f.write("RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\n")
        # Ensure unbuffered output and make /app available on import path for multi-file projects
        f.write("ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app\n")
        if run_mode == "direct":
            # Directly run user's entry, token is available via env (BOT_TOKEN/TOKEN/TELEGRAM_TOKEN)
            f.write(f'CMD ["python", "-u", "/app/{entry_file}"]\n')
        else:
            # Use the Python runner to ensure token injection works for simple scripts
            f.write('CMD ["python", "/app/gravix_runner.py"]\n')


def _docker_available() -> bool:
    try:
        client = docker_from_env()
        client.ping()
        return True
    except Exception:
        return False


def _run_locally(workspace: str, entry: Optional[str], token: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Local runner is disabled by design. We only support Docker-based isolation.
    """
    return False, None, "docker_unavailable"


def build_and_run(user_id: int, bot_id: str, token: str, workspace: str, entry: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Hardened build+run:
    - Detect framework and imports
    - Rewrite token reads to environment
    - Always run via a stable runner that injects token into globals (BOT_TOKEN/TOKEN/TELEGRAM_TOKEN)
    - Include user's requirements.txt (sanitized) plus detected/guessed requirements
    - Pass TELEGRAM_TOKEN at run time to avoid relying on Dockerfile ENV
    """
    if not _docker_available():
        log_event("Docker not available. Aborting deployment.")
        return False, None, "docker_unavailable"

    # Read the bot code from the workspace (entry file or the first .py we can find)
    code = None
    entry_file = entry
    try:
        if not entry_file:
            # Prefer bot.py at root if present
            candidate = os.path.join(workspace, "bot.py")
            if os.path.exists(candidate):
                entry_file = "bot.py"
            else:
                # Find any .py file (fallback)
                for f in os.listdir(workspace):
                    if f.endswith(".py"):
                        entry_file = f
                        break
        if entry_file:
            with open(os.path.join(workspace, entry_file), "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
    except Exception:
        code = None

    if not code:
        return False, None, "no_entry_py"

    framework, candidate_names = detect_framework(code)
    # Prefer full workspace detection; fallback to framework guess
    try:
        full_reqs = detect_requirements(workspace)
    except Exception:
        full_reqs = []
    reqs = full_reqs or guess_requirements(framework)
    # Ensure PTB is pinned to >=21.0 if detected
    if any(r.lower().startswith("python-telegram-bot") for r in reqs):
        reqs = [r for r in reqs if not r.lower().startswith("python-telegram-bot")]
        reqs.append("python-telegram-bot>=21.0")

    temp_dir = None
    client = docker_from_env()
    try:
        temp_dir = tempfile.mkdtemp()
        # Rewrite code to read token from environment where possible and fix common syntax issues
        try:
            code = rewrite_token_in_code(code, env_keys=_ENV_KEYS_DEFAULT, candidate_vars=candidate_names)
        except Exception:
            code = _fix_common_syntax_issues(code)

        # Write code and requirements to temp dir
        with open(os.path.join(temp_dir, "bot.py"), "w", encoding="utf-8") as f:
            f.write(code)
        with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(reqs) if reqs else "")

        # Write runner and Dockerfile (stable path)
        write_runner_and_dockerfile(temp_dir, entry="bot.py", requirements=reqs)

        image_tag = f"hostbot_{user_id}_{bot_id}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")
        container_name = f"hostbot_{user_id}_{bot_id}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")

        # Build image
        # Note: docker-py build() doesn't accept a 'timeout' kw in some versions; omit to avoid TypeError
        client.images.build(path=temp_dir, tag=image_tag, rm=True)

        # Ensure network exists or use default bridge
        network = RUNTIME_NETWORK
        if network:
            try:
                nets = client.networks.list(names=[network])
                if not nets:
                    client.networks.create(name=network)
                    log_event(f"Created missing Docker network: {network}")
            except Exception:
                log_event(f"Could not verify/create network '{network}', proceeding with defaults.")
                network = None

        # Run container with TELEGRAM_TOKEN env and resource limits
        container = client.containers.run(
            image_tag,
            name=container_name,
            detach=True,
            environment={
                # Primary token env
                "TELEGRAM_TOKEN": token,
                # Common aliases to maximize compatibility
                "BOT_TOKEN": token,
                "TOKEN": token,
                "TELEGRAM_BOT_TOKEN": token,
            },
            cpu_quota=DEFAULT_CPU_QUOTA,
            mem_limit=DEFAULT_MEM_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            network=network if network else None,
            # Do not auto-restart; if user code exits quickly we want to surface the error and stop
            restart_policy={"Name": "no"},
        )

        runtime_id = container.id
        # Short health check: if the container crashes immediately, surface error to user
        try:
            time.sleep(2)
            container.reload()
            status = getattr(container, "status", "")
            if status != "running":
                # Read exit code if available to distinguish normal exit vs error
                exit_code = None
                try:
                    container.reload()
                    exit_code = container.attrs.get("State", {}).get("ExitCode")
                except Exception:
                    exit_code = None

                logs = get_runtime_logs(runtime_id, tail=800) or ""
                lines = logs.splitlines() if logs else []
                # Filter out runner noise lines
                filtered = [l for l in lines if not l.startswith("gravix_runner:")]
                # Extract a concise error line
                short_err = ""
                for line in filtered:
                    if any(k in line for k in ("Traceback", "SyntaxError", "Error", "Exception", "Unauthorized", "InvalidToken", "ValueError", "RuntimeError")):
                        short_err = line.strip()
                        break
                if not short_err and filtered:
                    # Use last non-empty line (not from runner)
                    for line in reversed(filtered):
                        if line.strip():
                            short_err = line.strip()
                            break
                # If still nothing useful, provide guidance
                if not short_err:
                    short_err = "process exited without error logs — ensure your bot starts a polling loop (e.g., app.run_polling())"

                # Choose message based on exit code
                msg = f"{short_err} (exit code {exit_code if exit_code is not None else '?'})"
                log_event(f"Runtime crashed {runtime_id} for {bot_id}: {msg}")
                # Stop and remove failed container (no restart policy)
                try:
                    client.api.remove_container(runtime_id, force=True)
                except Exception:
                    pass
                return False, None, f"runtime_error: {msg}"
        except Exception:
            # If health check fails, proceed with success but logs will show details
            pass

        log_event(f"Runtime started {runtime_id} for {bot_id} (framework={framework})")
        return True, runtime_id, None
    except docker_errors.BuildError:
        return False, None, "build_error"
    except Exception as e:
        log_event(f"Build/run failed for {bot_id}: {e}")
        return False, None, str(e)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def stop_runtime(runtime_id: str) -> bool:
    try:
        if runtime_id.startswith("proc:"):
            pid = int(runtime_id.split(":", 1)[1])
            os.kill(pid, signal.SIGTERM)
            return True
        # Docker container id
        client = docker_from_env()
        try:
            client.api.stop(runtime_id, timeout=10)
        except Exception:
            pass
        try:
            client.api.remove_container(runtime_id, force=True)
        except Exception:
            pass
        return True
    except Exception:
        return False


def restart_runtime(runtime_id: str) -> bool:
    try:
        if runtime_id.startswith("proc:"):
            # Not supported for local process
            return False
        client = docker_from_env()
        client.api.restart(runtime_id)
        return True
    except Exception:
        return False


def remove_image(image_tag: str) -> bool:
    try:
        client = docker_from_env()
        client.images.remove(image=image_tag, force=True)
        return True
    except Exception:
        return False


def remove_workspace(workspace: str):
    try:
        shutil.rmtree(workspace, ignore_errors=True)
    except Exception:
        pass


def get_runtime_logs(runtime_id: str, tail: int = 200) -> Optional[str]:
    """
    Fetch recent logs from a Docker container.
    Returns a string or None if not available.
    """
    try:
        if runtime_id.startswith("proc:"):
            return None
        client = docker_from_env()
        logs = client.api.logs(runtime_id, tail=tail, stdout=True, stderr=True)
        if isinstance(logs, (bytes, bytearray)):
            try:
                return logs.decode("utf-8", errors="replace")
            except Exception:
                return logs.decode("latin1", errors="replace")
        return str(logs)
    except Exception:
        return None