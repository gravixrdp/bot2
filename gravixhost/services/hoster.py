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

# ---- Token discovery across workspace -----------------------------------------

def collect_token_vars(workspace: str) -> List[str]:
    """
    Scan all .py files to collect likely token variable names and env keys.
    """
    candidates: List[str] = []
    def _add(name: Optional[str]):
        if not name:
            return
        s = str(name).strip().strip("'\"")
        if not s:
            return
        import re as _re
        if not _re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s):
            return
        if s not in candidates:
            candidates.append(s)

    try:
        for root, _, files in os.walk(workspace):
            for f in files:
                if not f.endswith(".py"):
                    continue
                p = os.path.join(root, f)
                try:
                    src = open(p, "r", encoding="utf-8", errors="ignore").read()
                except Exception:
                    src = ""
                try:
                    tree = ast.parse(src, filename=p)
                except Exception:
                    tree = None

                if tree:
                    for node in ast.walk(tree):
                        try:
                            if isinstance(node, ast.Assign) and node.targets:
                                target = node.targets[0]
                                var_name = target.id if isinstance(target, ast.Name) else None
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    s = node.value.value
                                    if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", s):
                                        _add(var_name)
                                elif isinstance(node.value, ast.Call):
                                    func = node.value.func
                                    if isinstance(func, ast.Attribute) and func.attr == "getenv":
                                        if node.value.args and isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str):
                                            _add(node.value.args[0].value)
                                            _add(var_name)
                                    elif isinstance(func, ast.Name) and func.id == "getenv":
                                        if node.value.args and isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str):
                                            _add(node.value.args[0].value)
                                            _add(var_name)
                            if isinstance(node, ast.Call):
                                func_name = None
                                if isinstance(node.func, ast.Name):
                                    func_name = node.func.id
                                elif isinstance(node.func, ast.Attribute):
                                    func_name = node.func.attr
                                if func_name in {"Updater", "Bot", "TeleBot", "Client"}:
                                    tok_expr = None
                                    if node.args:
                                        tok_expr = node.args[0]
                                    for kw in getattr(node, "keywords", []):
                                        if kw.arg and kw.arg.lower() == "token":
                                            tok_expr = kw.value
                                            break
                                    if isinstance(tok_expr, ast.Name):
                                        _add(tok_expr.id)
                                if isinstance(node.func, ast.Attribute) and node.func.attr == "token":
                                    if node.args:
                                        arg0 = node.args[0]
                                        if isinstance(arg0, ast.Name):
                                            _add(arg0.id)
                        except Exception:
                            pass
                try:
                    for m in re.finditer(r"([A-Za-z_]\w*)\s*=\s*['\"]([0-9]+:[A-Za-z0-9_-]+)['\"]", src):
                        _add(m.group(1))
                    for m in re.finditer(r"os\.getenv\(\s*['\"]([A-Za-z_]\w*)['\"]\s*\)", src):
                        _add(m.group(1))
                    for m in re.finditer(r"(?:Updater|Bot|TeleBot|Client)\s*\(\s*([A-Za-z_]\w*)\s*[\),]", src):
                        _add(m.group(1))
                    for m in re.finditer(r"ApplicationBuilder\(\)\.token\(\s*([A-Za-z_]\w*)\s*\)", src):
                        _add(m.group(1))
                except Exception:
                    pass
    except Exception:
        pass

    for common in ["TOKEN", "BOT_TOKEN", "TELEGRAM_TOKEN", "TELEGRAM_BOT_TOKEN", "API_TOKEN", "MY_BOT_TOKEN", "TG_TOKEN"]:
        _add(common)

    uniq = []
    seen = set()
    for n in candidates:
        if n not in seen:
            uniq.append(n)
            seen.add(n)
    return uniq

# ---- Token rewriting utilities ------------------------------------------------

_ENV_KEYS_DEFAULT = ["TELEGRAM_TOKEN", "BOT_TOKEN", "TOKEN", "TELEGRAM_BOT_TOKEN"]

def _env_read_expr(env_keys: List[str]) -> ast.AST:
    keys = env_keys or _ENV_KEYS_DEFAULT
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
    expr = ast.BoolOp(op=ast.Or(), values=[expr, ast.Constant(value="")])
    return expr


class _TokenRewriter(ast.NodeTransformer):
    def __init__(self, env_keys: Optional[List[str]] = None, candidate_vars: Optional[List[str]] = None):
        super().__init__()
        self.env_keys = env_keys or _ENV_KEYS_DEFAULT
        self.candidate_vars = set(v for v in (candidate_vars or []) if isinstance(v, str))
        self.need_import_os = False

    def _is_token_literal(self, s: str) -> bool:
        if not isinstance(s, str):
            return False
        if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", s):
            return True
        low = s.lower()
        return "bot_token" in low or "token" in low or "your_bot_token" in low

    def _env_expr(self) -> ast.AST:
        self.need_import_os = True
        return _env_read_expr(self.env_keys)

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        try:
            target = node.targets[0]
            var_name = target.id if isinstance(target, ast.Name) else None
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                if self._is_token_literal(node.value.value) or (var_name and var_name in self.candidate_vars):
                    return ast.Assign(targets=node.targets, value=self._env_expr())
            if var_name and var_name in self.candidate_vars and isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "getenv":
                    return ast.Assign(targets=node.targets, value=self._env_expr())
                if isinstance(node.value.func, ast.Name) and node.value.func.id == "getenv":
                    return ast.Assign(targets=node.targets, value=self._env_expr())
        except Exception:
            pass
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> ast.AST:
        try:
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

            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in {"Bot", "TeleBot", "Client", "Updater"}:
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
    try:
        pattern = re.compile(r"""f'([^'\n]*\{[^}\n]*\[[\"'][^]\n]*\][^}\n]*\}[^'\n]*)'""")
        return pattern.sub(r'f"\1"', code)
    except Exception:
        return code


def rewrite_token_in_code(code: str, env_keys: Optional[List[str]] = None, candidate_vars: Optional[List[str]] = None) -> str:
    code_prefixed = _fix_common_syntax_issues(code)
    try:
        tree = ast.parse(code_prefixed)
        rewriter = _TokenRewriter(env_keys=env_keys, candidate_vars=candidate_vars)
        new_tree = rewriter.visit(tree)
        ast.fix_missing_locations(new_tree)
        new_code = ast.unparse(new_tree)
        if rewriter.need_import_os and "import os" not in new_code:
            new_code = "import os\n" + new_code
        return new_code
    except Exception:
        shim = (
            "import os\n"
            "_t = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or os.getenv('TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') or ''\n"
            "TOKEN = _t or globals().get('TOKEN','')\n"
            "BOT_TOKEN = _t or globals().get('BOT_TOKEN','')\n"
        )
        return shim + "\n" + code_prefixed

# ---- Requirements normalization and detection ---------------------------------

def _normalize_requirement(name: str) -> Optional[str]:
    """
    Normalize an import/module name or raw requirement line to a PyPI-installable requirement.
    - Filters out stdlib and meta modules that should not be installed
    - Maps common aliases to real PyPI package names
    - Skips vague namespaces like 'google' (we add specific sdk like google-genai separately)
    """
    if not name:
        return None
    s = name.strip()
    if not s or s.startswith("#"):
        return None
    # Skip obvious templating placeholders
    if "%(" in s and ")s" in s:
        return None
    # Spaces in requirement lines are usually invalid
    if " " in s:
        return None
    # Already a requirement spec
    for sep in ("==", ">=", "<=", "~=", ">", "<", "!="):
        if sep in s:
            return s
    base = s.split(".")[0]
    # Broad stdlib blacklist and meta names
    _BLACKLIST = {
        # Python stdlib and meta modules (common)
        "os", "sys", "json", "re", "time", "pathlib", "typing", "dataclasses", "asyncio",
        "base64", "io", "logging", "sqlite3", "subprocess", "signal",
        "datetime", "collections", "functools", "itertools", "math", "random", "hashlib",
        "hmac", "threading", "multiprocessing", "http", "email", "urllib", "traceback",
        "argparse", "enum", "types", "contextlib", "tempfile", "zipfile", "tarfile",
        "shutil", "glob", "fnmatch", "importlib", "inspect",
        # Generic/vague namespaces to skip (handled via specific packages elsewhere)
        "google",
    }
    if base.startswith("_") or base in _BLACKLIST:
        return None
    # Map common aliases to PyPI packages
    _PYPI_MAP = {
        "telebot": "pyTelegramBotAPI",
        "telegram": "python-telegram-bot",
        "PIL": "pillow",
        "cv2": "opencv-python",
        "dotenv": "python-dotenv",
        "bs4": "beautifulsoup4",
        "yaml": "pyyaml",
        "Crypto": "pycryptodome",
        "OpenSSL": "pyOpenSSL",
    }
    mapped = _PYPI_MAP.get(base, base)
    import re as _re
    if not _re.match(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$", mapped):
        return None
    return mapped

# Defaults and resource limits
DEFAULT_CPU_QUOTA = 100000
DEFAULT_MEM_LIMIT = "512m"
DEFAULT_PIDS_LIMIT = 100

# ---- Upload/save --------------------------------------------------------------

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
    if file_name.lower().endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            # Prevent Zip Slip: ensure all members extract within 'path'
            for member in zip_ref.infolist():
                member_path = os.path.join(path, member.filename)
                if not os.path.realpath(member_path).startswith(os.path.realpath(path) + os.sep) and os.path.realpath(member_path) != os.path.realpath(path):
                    # Skip unsafe entry
                    continue
                # Create parent dirs and write file/dir
                if member.is_dir():
                    os.makedirs(os.path.realpath(member_path), exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(os.path.realpath(member_path)), exist_ok=True)
                    with zip_ref.open(member, "r") as src, open(os.path.realpath(member_path), "wb") as dst:
                        shutil.copyfileobj(src, dst)
        os.remove(file_path)
    return path

# ---- Analyzer (framework + token var + PTB version) ---------------------------

def detect_framework(code: str) -> Tuple[str, List[str]]:
    framework = "unknown"
    candidates: List[str] = ["TOKEN", "BOT_TOKEN", "TELEGRAM_TOKEN", "TELEGRAM_BOT_TOKEN"]
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
    except Exception:
        pass
    return framework, candidates

def analyze_code(code: str) -> tuple[str, str, List[str]]:
    framework, _ = detect_framework(code)
    token_var = "TOKEN"
    for pattern in [
        r"([a-zA-Z_]\w*)\s*=\s*['\"]([0-9]+:[a-zA-Z0-9_-]+)['\"]",
        r"([a-zA-Z_]\w*)\s*=\s*os\.getenv",
    ]:
        m = re.search(pattern, code)
        if m:
            token_var = m.group(1)
            break
    reqs: List[str] = []
    if framework == "python-telegram-bot":
        uses_updater = bool(re.search(r"\bUpdater\b", code)) or ("use_context=True" in code)
        uses_appbuilder = bool(re.search(r"\bApplicationBuilder\b", code)) or bool(re.search(r"from\s+telegram\.ext\s+import\s+filters", code))
        reqs = ["python-telegram-bot==13.15"] if uses_updater and not uses_appbuilder else ["python-telegram-bot>=21.0"]
    elif framework == "pytelegrambotapi":
        reqs = ["pyTelegramBotAPI"]
    elif framework.startswith("aiogram"):
        reqs = ["aiogram<3.0" if framework == "aiogram_v2" else "aiogram>=3.0"]
    elif framework == "pyrogram":
        reqs = ["pyrogram"]
    return framework, token_var, reqs

# ---- Requirements detector ----------------------------------------------------

def detect_requirements(workspace: str) -> List[str]:
    import_names = set()
    ptb_hint_v13 = False
    ptb_hint_v21 = False
    google_genai_hint = False

    def collect_imports_ast(py_path: str):
        nonlocal ptb_hint_v13, ptb_hint_v21, google_genai_hint
        try:
            src = open(py_path, "r", encoding="utf-8", errors="ignore").read()
            tree = ast.parse(src, filename=py_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        full = alias.name or ""
                        base = full.split(".")[0]
                        if base:
                            import_names.add(base)
                        if full.startswith("google.genai"):
                            google_genai_hint = True
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        full = node.module
                        base = full.split(".")[0]
                        if base:
                            import_names.add(base)
                        if full.startswith("google.genai") or re.search(r"from\s+google\s+import\s+genai", src):
                            google_genai_hint = True
            if "telegram" in import_names or "telegram" in src:
                if re.search(r"\bUpdater\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+.*Updater", src) or ("use_context=True" in src):
                    ptb_hint_v13 = True
                if re.search(r"\bApplicationBuilder\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+filters", src):
                    ptb_hint_v21 = True
        except Exception:
            collect_imports_regex(py_path)

    def collect_imports_regex(py_path: str):
        nonlocal ptb_hint_v13, ptb_hint_v21, google_genai_hint
        try:
            src = open(py_path, "r", encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r"(?m)^[ \t]*import[ \t]+([A-Za-z_][A-Za-z0-9_\.]*)", src):
                full = m.group(1)
                base = full.split(".")[0]
                if base:
                    import_names.add(base)
                if full.startswith("google.genai"):
                    google_genai_hint = True
            for m in re.finditer(r"(?m)^[ \t]*from[ \t]+([A-Za-z_][A-Za-z0-9_\.]*)[ \t]+import[ \t]+([A-Za-z_][A-Za-z0-9_]*)", src):
                full = m.group(1)
                base = full.split(".")[0]
                if base:
                    import_names.add(base)
                if full == "google" and m.group(2) == "genai":
                    google_genai_hint = True
            if "telegram" in import_names or "telegram" in src:
                if re.search(r"\bUpdater\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+.*Updater", src) or ("use_context=True" in src):
                    ptb_hint_v13 = True
                if re.search(r"\bApplicationBuilder\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+filters", src):
                    ptb_hint_v21 = True
        except Exception:
            pass

    for root, _, files in os.walk(workspace):
        for f in files:
            if f.endswith(".py"):
                collect_imports_ast(os.path.join(root, f))

    reqs = set()
    for base in import_names:
        norm = _normalize_requirement(base)
        if norm:
            reqs.add(norm)

    req_path = os.path.join(workspace, "requirements.txt")
    if os.path.exists(req_path):
        try:
            for line in open(req_path, "r", encoding="utf-8", errors="ignore"):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                norm = _normalize_requirement(s)
                if norm:
                    reqs.add(norm)
        except Exception:
            pass

    if "telebot" in import_names:
        reqs.add("pyTelegramBotAPI")

    ptb_items = [r for r in reqs if r.lower().startswith("python-telegram-bot")]
    if ("telegram" in import_names or ptb_hint_v13 or ptb_hint_v21):
        if not ptb_items:
            if ptb_hint_v13 and not ptb_hint_v21:
                reqs.add("python-telegram-bot==13.15")
            else:
                reqs.add("python-telegram-bot>=21.0")
        else:
            adjusted = set()
            for item in ptb_items:
                low = item.lower()
                if any(sep in low for sep in ("==", ">=", "<=", "~=", ">", "<", "!=")):
                    adjusted.add(item)
                else:
                    if ptb_hint_v13 and not ptb_hint_v21:
                        adjusted.add("python-telegram-bot==13.15")
                    else:
                        adjusted.add("python-telegram-bot>=21.0")
                reqs.discard(item)
            for a in adjusted:
                reqs.add(a)

    if google_genai_hint:
        reqs.add("google-genai")

    return sorted(reqs)

# ---- Runner and Dockerfile writer --------------------------------------------

def write_runner_and_dockerfile(workspace: str, entry: Optional[str] = None, requirements: Optional[List[str]] = None):
    entry_file = entry or "bot.py"
    try:
        token_vars = collect_token_vars(workspace)
    except Exception:
        token_vars = ["TOKEN", "BOT_TOKEN", "TELEGRAM_TOKEN", "TELEGRAM_BOT_TOKEN"]
    runner_py = os.path.join(workspace, "gravix_runner.py")
    token_vars_literal = "[" + ",".join(repr(n) for n in token_vars) + "]"

    # Build runner code using a safe template and literal placeholder replacement (no .format on the template)
    runner_tpl = """import os, runpy, sys, subprocess, threading, time, re, pathlib

token = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or os.getenv('TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') or ''
token_vars = __TOKEN_VARS__

# Expose token in env under common names and discovered names
for name in set(token_vars + ['BOT_TOKEN', 'TOKEN', 'TELEGRAM_TOKEN', 'TELEGRAM_BOT_TOKEN']):
    try:
        os.environ[name] = token
    except Exception:
        pass

# Prepare globals so user code can reference these directly
init_globals = {}
for name in set(token_vars + ['BOT_TOKEN', 'TOKEN', 'TELEGRAM_TOKEN', 'TELEGRAM_BOT_TOKEN']):
    init_globals[name] = token

os.chdir(os.path.dirname(__file__))

try:
    _SRC = pathlib.Path('__ENTRY_FILE__').read_text(encoding='utf-8', errors='ignore')
except Exception:
    _SRC = ''

def _heartbeat():
    while True:
        try:
            print('gravix_runner: heartbeat alive')
        except Exception:
            pass
        time.sleep(30)

threading.Thread(target=_heartbeat, daemon=True).start()

def _auto_install_for_missing(missing: str) -> bool:
    base = (missing or '').split('.')[0]
    M = {
        'telebot': 'pyTelegramBotAPI',
        'telegram': 'python-telegram-bot',
        'PIL': 'pillow',
        'cv2': 'opencv-python',
        'bs4': 'beautifulsoup4',
        'yaml': 'pyyaml',
        'dotenv': 'python-dotenv',
        'Crypto': 'pycryptodome',
        'OpenSSL': 'pyOpenSSL',
        'lxml': 'lxml',
        'requests': 'requests',
        'aiohttp': 'aiohttp',
        'pytz': 'pytz',
        'tornado': 'tornado',
        'apscheduler': 'APScheduler',
        'APScheduler': 'APScheduler',
        'cryptography': 'cryptography',
        'certifi': 'certifi',
        'charset_normalizer': 'charset-normalizer',
        'idna': 'idna',
        'urllib3': 'urllib3',
        'numpy': 'numpy',
        'pandas': 'pandas',
        'matplotlib': 'matplotlib',
        'scipy': 'scipy',
        'pyyaml': 'pyyaml',
        'google.genai': 'google-genai',
        'google': 'google-genai' if ('google.genai' in _SRC or re.search(r'from\\s+google\\s+import\\s+genai', _SRC)) else None,
    }
    candidates = []
    mapped_full = M.get(missing)
    if mapped_full:
        candidates.append(mapped_full)
    mapped_base = M.get(base)
    if mapped_base and mapped_base not in candidates:
        candidates.append(mapped_base)
    if missing and missing not in candidates:
        candidates.append(missing)
    if base and base not in candidates:
        candidates.append(base)
    for pkg in candidates:
        if not pkg:
            continue
        try:
            print(f'gravix_runner: installing {pkg} for missing import {missing}')
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg])
            return True
        except Exception as _e:
            print(f'gravix_runner: failed to install {pkg}: {_e}')
            continue
    return False

def _auto_start_from_namespace(ns: dict) -> bool:
    \"\"\"
    Best-effort autostart for common frameworks if user script didn't start polling itself.
    - python-telegram-bot v21+: ns['application'].run_polling()
    - python-telegram-bot v13: ns['updater'].start_polling(); ns['updater'].idle()
    - pyTelegramBotAPI: ns['bot'].infinity_polling() or .polling()
    - pyrogram: ns['app'] or ns['client'] with .run() or .start() + idle loop
    Returns True if something was started.
    \"\"\"
    obj = ns.get('application')
    try:
        if obj and hasattr(obj, 'run_polling') and callable(obj.run_polling):
            print('gravix_runner: autostart — application.run_polling()')
            obj.run_polling()
            return True
    except Exception:
        pass
    obj = ns.get('updater')
    try:
        if obj and hasattr(obj, 'start_polling'):
            print('gravix_runner: autostart — updater.start_polling()')
            obj.start_polling()
            if hasattr(obj, 'idle') and callable(obj.idle):
                obj.idle()
            else:
                while True:
                    time.sleep(60)
            return True
    except Exception:
        pass
    obj = ns.get('bot')
    try:
        if obj and hasattr(obj, 'infinity_polling') and callable(obj.infinity_polling):
            print('gravix_runner: autostart — bot.infinity_polling()')
            obj.infinity_polling()
            return True
        if obj and hasattr(obj, 'polling') and callable(obj.polling):
            print('gravix_runner: autostart — bot.polling()')
            obj.polling()
            return True
    except Exception:
        pass
    for name in ('app', 'client'):
        obj = ns.get(name)
        try:
            if obj and hasattr(obj, 'run') and callable(obj.run):
                print(f'gravix_runner: autostart — {name}.run()')
                obj.run()
                return True
            if obj and hasattr(obj, 'start') and callable(obj.start):
                print(f'gravix_runner: autostart — {name}.start() + idle loop')
                obj.start()
                while True:
                    time.sleep(60)
                return True
        except Exception:
            pass
    return False

def _try_run() -> bool:
    ns = runpy.run_path('__ENTRY_FILE__', init_globals=init_globals)
    if isinstance(ns, dict):
        started = _auto_start_from_namespace(ns)
        if started:
            return True
    return False

print(f"gravix_runner: entry __ENTRY_FILE__ token_len={len(token)}")

while True:
    try:
        if _try_run():
            # If autostart engaged, we only reach here on termination
            print('gravix_runner: autostarted service terminated')
            sys.exit(0)
        else:
            print('gravix_runner: user script finished (no long-running loop)')
            sys.exit(0)
    except ImportError as e:
        msg = str(e)
        if 'telegram.ext' in msg and ('Filters' in msg or 'Updater' in msg):
            try:
                print('gravix_runner: detected PTB API mismatch, installing python-telegram-bot==13.15')
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'python-telegram-bot==13.15'])
                continue
            except Exception:
                import traceback; traceback.print_exc(); sys.exit(1)
        missing = getattr(e, 'name', None)
        if not missing and 'No module named' in msg:
            m = re.search(r"No module named ['\\\"]([^'\\\"]+)['\\\"]", msg)
            if m:
                missing = m.group(1)
        if missing and _auto_install_for_missing(missing):
            continue
        raise
    except ModuleNotFoundError as e:
        missing = getattr(e, 'name', None)
        if not missing and 'No module named' in str(e):
            m = re.search(r"No module named ['\\\"]([^'\\\"]+)['\\\"]", str(e))
            if m:
                missing = m.group(1)
        if missing and _auto_install_for_missing(missing):
            continue
        else:
            raise
    except SystemExit:
        raise
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
"""
    # Replace placeholders safely without invoking str.format on the template
    runner_code = runner_tpl.replace("__ENTRY_FILE__", entry_file).replace("__TOKEN_VARS__", token_vars_literal)

    with open(runner_py, "w", encoding="utf-8", newline="\n") as f:
        f.write(runner_code)

    dockerfile = os.path.join(workspace, "Dockerfile")
    with open(dockerfile, "w", encoding="utf-8", newline="\n") as f:
        f.write("FROM python:3.11-slim\n")
        f.write("WORKDIR /app\n")
        f.write("COPY . /app\n")
        f.write("RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*\n")
        f.write("RUN pip install --no-cache-dir --upgrade pip\n")
