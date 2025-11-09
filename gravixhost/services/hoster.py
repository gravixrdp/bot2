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
import subprocess

from ..config import UPLOADS_DIR, RUNTIME_CPU_LIMIT, RUNTIME_MEM_LIMIT, RUNTIME_NETWORK
from ..storage import log_event, get_settings
from ..utils import escape
from .ai_assistant import suggest_fix

# ---- Advanced Token Detection and Extraction -----------------------------------------

def extract_token_from_code(code: str) -> Optional[str]:
    """
    Smart token extraction from code - tries multiple methods.
    Returns actual token string if found, None otherwise.
    """
    if not code:
        return None
    
    # Method 1: Direct token pattern match
    token_pattern = r'["\']([0-9]+:[A-Za-z0-9_-]{30,})["\']'
    matches = re.findall(token_pattern, code)
    for match in matches:
        if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", match):
            return match
    
    # Method 2: AST-based extraction
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            # Look for assignments with token values
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check if value is a constant string matching token pattern
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", val):
                                return val
                        # Check for string concatenation
                        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                            # Try to reconstruct token from parts
                            try:
                                left = ast.literal_eval(node.value.left) if isinstance(node.value.left, (ast.Constant, ast.Str)) else ""
                                right = ast.literal_eval(node.value.right) if isinstance(node.value.right, (ast.Constant, ast.Str)) else ""
                                combined = str(left) + str(right)
                                if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", combined):
                                    return combined
                            except:
                                pass
    except:
        pass
    
    # Method 3: Look in common config patterns
    config_patterns = [
        r'TOKEN\s*[:=]\s*["\']([0-9]+:[A-Za-z0-9_-]+)["\']',
        r'BOT_TOKEN\s*[:=]\s*["\']([0-9]+:[A-Za-z0-9_-]+)["\']',
        r'TELEGRAM_TOKEN\s*[:=]\s*["\']([0-9]+:[A-Za-z0-9_-]+)["\']',
        r'API_TOKEN\s*[:=]\s*["\']([0-9]+:[A-Za-z0-9_-]+)["\']',
        r'token\s*[:=]\s*["\']([0-9]+:[A-Za-z0-9_-]+)["\']',
    ]
    for pattern in config_patterns:
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            token = match.group(1)
            if re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", token):
                return token
    
    return None


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
    """
    Fix common syntax issues that cause problems during AST parsing.
    - Fix f-strings with unmatched quotes/brackets
    - Fix common f-string quote issues
    """
    try:
        # Fix f-strings with single quotes containing brackets that break parsing
        # Pattern: f'...{...[...]}...' -> f"...{...[...]}..."
        pattern1 = re.compile(r"""f'([^'\n]*\{[^}\n]*\[[\"'][^]\n]*\][^}\n]*\}[^'\n]*)'""")
        code = pattern1.sub(r'f"\1"', code)
        
        # Fix f-strings with unmatched parentheses/quotes
        # Handle cases like: f'url = {chan if chan.startswith("http") else f"https://t.me/{chan.lstrip("@")}"}'
        # or: url = chan if chan.startswith('http') else f'https://t.me/{chan.lstrip('@')}'
        lines = code.split('\n')
        fixed_lines = []
        for line in lines:
            # Check if line has f-string with problematic patterns
            if "f'" in line or 'f"' in line:
                # Check for problematic patterns: nested quotes with parentheses
                # Pattern: f'...{...(...'...')...}'
                try:
                    # Fix f-strings with single quotes containing nested single quotes in parentheses
                    # Example: f'...{chan.lstrip('@')}...' -> f"...{chan.lstrip('@')}..."
                    if "f'" in line and "'" in line[line.find("f'"):] and "(" in line:
                        # Count quotes to see if we have unmatched ones
                        f_start = line.find("f'")
                        if f_start >= 0:
                            # Find the matching closing quote
                            quote_start = f_start + 1  # After 'f'
                            depth = 0
                            in_string = False
                            quote_char = None
                            fixed_line = line
                            
                            # Try a simpler approach: if f-string has single quotes and parentheses, convert to double quotes
                            # But only if safe to do so
                            if re.search(r"f'[^']*\{[^}]*\([^']*'[^)]*\)[^}]*\}[^']*'", line):
                                # Convert f' to f" and matching closing quote
                                fixed_line = line.replace("f'", 'f"', 1)
                                # Find and replace the last unmatched single quote
                                # This is a heuristic - find the quote that closes the f-string
                                last_quote = fixed_line.rfind("'")
                                if last_quote > f_start:
                                    # Check if it's not escaped and likely the closing quote
                                    if last_quote > 0 and fixed_line[last_quote-1] != '\\':
                                        fixed_line = fixed_line[:last_quote] + '"' + fixed_line[last_quote+1:]
                            line = fixed_line
                except Exception:
                    pass  # If we can't fix it, leave it as is
            fixed_lines.append(line)
        return '\n'.join(fixed_lines)
    except Exception:
        return code


def rewrite_token_in_code(code: str, env_keys: Optional[List[str]] = None, candidate_vars: Optional[List[str]] = None) -> str:
    """
    Rewrite token assignments in code to use environment variables.
    If rewriting fails, return original code with token shim.
    Smart: Skip rewriting if token already uses os.getenv to avoid ast.unparse issues.
    """
    # Check if token already uses os.getenv - if so, skip rewriting to avoid issues
    if re.search(r'os\.getenv\s*\([^)]*TOKEN|BOT_TOKEN|TELEGRAM_TOKEN', code, re.IGNORECASE):
        # Token already uses environment variables, just add shim if needed
        if "import os" not in code:
            shim = "import os\n"
            return shim + code
        return code
    
    # First, validate the original code has no syntax errors
    try:
        ast.parse(code)
    except SyntaxError as e:
        # Code has syntax errors - try to fix common issues first
        code_prefixed = _fix_common_syntax_issues(code)
        try:
            # Try parsing again after fixes
            ast.parse(code_prefixed)
            code = code_prefixed
        except SyntaxError:
            # Still has syntax errors - return original with shim
            # The syntax error will be caught later during validation
            shim = (
                "import os\n"
                "_t = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or os.getenv('TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') or ''\n"
                "TOKEN = _t or globals().get('TOKEN','')\n"
                "BOT_TOKEN = _t or globals().get('BOT_TOKEN','')\n"
            )
            return shim + "\n" + code
    
    code_prefixed = _fix_common_syntax_issues(code)
    try:
        tree = ast.parse(code_prefixed)
        rewriter = _TokenRewriter(env_keys=env_keys, candidate_vars=candidate_vars)
        new_tree = rewriter.visit(tree)
        ast.fix_missing_locations(new_tree)
        new_code = ast.unparse(new_tree)
        
        # Fix f-string bracket issues that ast.unparse might have introduced
        new_code = fix_fstring_brackets(new_code)
        
        # Validate the rewritten code - try multiple times with fixes
        max_validation_retries = 3
        for retry in range(max_validation_retries):
            try:
                ast.parse(new_code)
                break  # Success, exit retry loop
            except SyntaxError as parse_err:
                if retry < max_validation_retries - 1:
                    # Try fixing again
                    new_code = fix_fstring_brackets(new_code)
                    continue
                else:
                    # Final retry failed - return original with shim
                    log_event(f"Token rewrite failed after {max_validation_retries} retries: {parse_err}")
                    shim = (
                        "import os\n"
                        "_t = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or os.getenv('TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') or ''\n"
                        "TOKEN = _t or globals().get('TOKEN','')\n"
                        "BOT_TOKEN = _t or globals().get('BOT_TOKEN','')\n"
                    )
                    return shim + "\n" + code_prefixed
        if rewriter.need_import_os and "import os" not in new_code:
            new_code = "import os\n" + new_code
        return new_code
    except SyntaxError:
        # Syntax error during rewriting - return original with shim
        shim = (
            "import os\n"
            "_t = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or os.getenv('TOKEN') or os.getenv('TELEGRAM_BOT_TOKEN') or ''\n"
            "TOKEN = _t or globals().get('TOKEN','')\n"
            "BOT_TOKEN = _t or globals().get('BOT_TOKEN','')\n"
        )
        return shim + "\n" + code_prefixed
    except Exception:
        # Other errors during rewriting - return original with shim
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

def detect_entry_file(workspace: str) -> str:
    """
    Detect the entry Python file in a workspace.
    Prefers: bot.py, app.py, main.py, then any top-level .py file.
    """
    candidates = ["bot.py", "app.py", "main.py"]
    for c in candidates:
        p = os.path.join(workspace, c)
        if os.path.exists(p):
            return c
    # Find any top-level .py file
    tops = []
    any_py = None
    for root, _, files in os.walk(workspace):
        for f in files:
            if f.endswith(".py"):
                if any_py is None:
                    any_py = os.path.relpath(os.path.join(root, f), workspace)
                if os.path.abspath(root) == os.path.abspath(workspace):
                    tops.append(f)
    if tops:
        return tops[0]
    return any_py or "bot.py"


def clone_github_repo(user_id: int, bot_id: str, repo_url: str) -> Optional[str]:
    """
    Clone a GitHub repository to workspace.
    Supports: https://github.com/user/repo, https://github.com/user/repo.git, github.com/user/repo
    """
    try:
        import git
        from git import Repo
    except ImportError:
        log_event(f"GitPython not installed. Install with: pip install gitpython")
        return None
    
    path = new_bot_workspace(user_id, bot_id)
    
    # Normalize GitHub URL
    repo_url = repo_url.strip()
    if not repo_url.startswith(("http://", "https://")):
        if repo_url.startswith("github.com"):
            repo_url = "https://" + repo_url
        else:
            repo_url = "https://github.com/" + repo_url.lstrip("/")
    
    # Remove .git suffix if present (Repo.clone_from handles it)
    if repo_url.endswith(".git"):
        repo_url = repo_url[:-4]
    
    # Ensure it's a GitHub URL
    if "github.com" not in repo_url:
        return None
    
    try:
        # Clone repository
        log_event(f"Cloning GitHub repo: {repo_url} for bot {bot_id}")
        repo = Repo.clone_from(repo_url + ".git", path, depth=1)
        log_event(f"Successfully cloned repo to {path}")
        return path
    except git.exc.GitCommandError as e:
        log_event(f"Failed to clone repo {repo_url}: {e}")
        return None
    except Exception as e:
        log_event(f"Error cloning repo {repo_url}: {e}")
        return None


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

def analyze_code(code: str) -> tuple[str, str, List[str], Optional[str]]:
    """
    Advanced code analysis:
    Returns: (framework, token_var, requirements, extracted_token)
    extracted_token is the actual token string if found in code, None otherwise
    """
    framework, _ = detect_framework(code)
    
    # Smart token variable detection
    token_var = "TOKEN"
    extracted_token = extract_token_from_code(code)
    
    # Try to find token variable name
    patterns = [
        r"([a-zA-Z_]\w*)\s*=\s*['\"]([0-9]+:[a-zA-Z0-9_-]+)['\"]",  # var = "token"
        r"([a-zA-Z_]\w*)\s*=\s*os\.getenv",  # var = os.getenv(...)
        r"([a-zA-Z_]\w*)\s*[:=]\s*['\"]([0-9]+:[a-zA-Z0-9_-]+)['\"]",  # var: "token"
        r"(?:TOKEN|BOT_TOKEN|TELEGRAM_TOKEN)\s*=\s*([a-zA-Z_]\w*)",  # TOKEN = var
    ]
    for pattern in patterns:
        m = re.search(pattern, code, re.IGNORECASE)
        if m:
            token_var = m.group(1)
            break
    
    # Smart requirements detection based on framework
    reqs: List[str] = []
    
    if framework == "python-telegram-bot":
        uses_updater = bool(re.search(r"\bUpdater\b", code)) or ("use_context=True" in code)
        uses_appbuilder = bool(re.search(r"\bApplicationBuilder\b", code)) or bool(re.search(r"from\s+telegram\.ext\s+import\s+filters", code))
        # Try to detect version from imports
        if re.search(r"from\s+telegram\.ext\s+import\s+.*Updater", code) and not uses_appbuilder:
            reqs = ["python-telegram-bot==13.15"]
        elif uses_appbuilder or re.search(r"from\s+telegram\s+import\s+Update", code):
            reqs = ["python-telegram-bot>=21.0"]
        else:
            reqs = ["python-telegram-bot>=21.0"]  # Default to v21+
    elif framework == "pytelegrambotapi":
        reqs = ["pyTelegramBotAPI"]
    elif framework.startswith("aiogram"):
        # Detect aiogram version more precisely
        if "from aiogram import Bot, Dispatcher" in code or "from aiogram.filters import" in code:
            reqs = ["aiogram>=3.0"]
        elif "from aiogram import Bot, types" in code or "executor.start_polling" in code:
            reqs = ["aiogram<3.0"]
        else:
            reqs = ["aiogram>=3.0"] if framework == "aiogram_v3" else ["aiogram<3.0"]
    elif framework == "pyrogram":
        reqs = ["pyrogram"]
    elif framework == "telethon":
        reqs = ["telethon"]
    elif framework == "unknown":
        # Try to detect from imports
        if "telebot" in code.lower() or "import telebot" in code:
            reqs = ["pyTelegramBotAPI"]
        elif "telegram" in code.lower() and "import telegram" in code:
            reqs = ["python-telegram-bot>=21.0"]
    
    return framework, token_var, reqs, extracted_token

# ---- Requirements detector ----------------------------------------------------

def detect_requirements(workspace: str) -> List[str]:
    """
    Advanced requirements detection:
    - Scans all Python files
    - Detects imports from code
    - Checks requirements.txt
    - Maps common aliases
    - Handles version conflicts
    """
    import_names = set()
    ptb_hint_v13 = False
    ptb_hint_v21 = False
    google_genai_hint = False
    aiogram_v2_hint = False
    aiogram_v3_hint = False

    def collect_imports_ast(py_path: str):
        nonlocal ptb_hint_v13, ptb_hint_v21, google_genai_hint, aiogram_v2_hint, aiogram_v3_hint
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
                        # Aiogram version detection
                        if full == "aiogram" or full.startswith("aiogram."):
                            if "from aiogram.filters" in src or "from aiogram import Bot, Dispatcher" in src:
                                aiogram_v3_hint = True
                            elif "executor.start_polling" in src or "from aiogram import Bot, types" in src:
                                aiogram_v2_hint = True
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        full = node.module
                        base = full.split(".")[0]
                        if base:
                            import_names.add(base)
                        if full.startswith("google.genai") or re.search(r"from\s+google\s+import\s+genai", src):
                            google_genai_hint = True
                        # Aiogram detection
                        if full.startswith("aiogram"):
                            if "filters" in [n.name for n in (node.names or [])]:
                                aiogram_v3_hint = True
                            elif "executor" in [n.name for n in (node.names or [])]:
                                aiogram_v2_hint = True
            # Python-telegram-bot version detection
            if "telegram" in import_names or "telegram" in src:
                if re.search(r"\bUpdater\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+.*Updater", src) or ("use_context=True" in src):
                    ptb_hint_v13 = True
                if re.search(r"\bApplicationBuilder\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+filters", src) or re.search(r"from\s+telegram\s+import\s+Update", src):
                    ptb_hint_v21 = True
        except Exception:
            collect_imports_regex(py_path)

    def collect_imports_regex(py_path: str):
        nonlocal ptb_hint_v13, ptb_hint_v21, google_genai_hint, aiogram_v2_hint, aiogram_v3_hint
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
                # Aiogram detection
                if full.startswith("aiogram"):
                    if "filters" in m.group(2):
                        aiogram_v3_hint = True
                    elif "executor" in m.group(2):
                        aiogram_v2_hint = True
            # Python-telegram-bot detection
            if "telegram" in import_names or "telegram" in src:
                if re.search(r"\bUpdater\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+.*Updater", src) or ("use_context=True" in src):
                    ptb_hint_v13 = True
                if re.search(r"\bApplicationBuilder\b", src) or re.search(r"from\s+telegram\.ext\s+import\s+filters", src) or re.search(r"from\s+telegram\s+import\s+Update", src):
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
    
    # Aiogram version-specific requirements
    if aiogram_v2_hint and not aiogram_v3_hint:
        reqs.discard("aiogram>=3.0")
        reqs.add("aiogram<3.0")
    elif aiogram_v3_hint:
        reqs.discard("aiogram<3.0")
        reqs.add("aiogram>=3.0")
    
    # Additional common packages detection
    if "numpy" in import_names:
        reqs.add("numpy")
    if "pandas" in import_names:
        reqs.add("pandas")
    if "requests" in import_names:
        reqs.add("requests")
    if "aiohttp" in import_names:
        reqs.add("aiohttp")
    if "pymongo" in import_names or "motor" in import_names:
        reqs.add("pymongo")
    if "sqlalchemy" in import_names:
        reqs.add("sqlalchemy")
    if "redis" in import_names:
        reqs.add("redis")
    if "pillow" in import_names or "PIL" in import_names:
        reqs.add("pillow")
    if "beautifulsoup4" in import_names or "bs4" in import_names:
        reqs.add("beautifulsoup4")

    return sorted(reqs)

# ---- Runner and Dockerfile writer --------------------------------------------

def fix_fstring_brackets(code: str) -> str:
    """
    Fix f-string bracket issues that cause 'unmatched [' errors.
    Comprehensive fix for all f-string bracket patterns.
    Handles: {expr}[literal], nested brackets, brackets in expressions, etc.
    """
    if not code:
        return code
    
    # First validate - if code parses fine, return as-is
    try:
        ast.parse(code)
        return code
    except SyntaxError as e:
        # Only fix if there's a syntax error related to f-strings or brackets
        error_str = str(e).lower()
        if 'f-string' not in error_str and 'unmatched' not in error_str and '[' not in error_str:
            return code
        # Log the error for debugging
        log_event(f"Fixing f-string bracket issue: {e}")
    
    lines = code.split('\n')
    fixed_lines = []
    
    def fix_fstring_line(line: str) -> str:
        """Fix a single line containing f-strings with bracket issues."""
        original = line
        
        # Process f-strings character by character to handle nested cases
        result = []
        i = 0
        in_fstring_double = False
        in_fstring_single = False
        fstring_start = -1
        brace_depth = 0
        quote_char = None
        
        while i < len(line):
            char = line[i]
            
            # Detect f-string start (f" or f')
            if i < len(line) - 1:
                if line[i:i+2] == 'f"' and not in_fstring_double and not in_fstring_single:
                    in_fstring_double = True
                    fstring_start = i
                    quote_char = '"'
                    result.append('f"')
                    i += 2
                    continue
                elif line[i:i+2] == "f'" and not in_fstring_double and not in_fstring_single:
                    in_fstring_single = True
                    fstring_start = i
                    quote_char = "'"
                    result.append("f'")
                    i += 2
                    continue
            
            # Inside f-string
            if in_fstring_double or in_fstring_single:
                # Track brace depth
                if char == '{':
                    brace_depth += 1
                    result.append(char)
                elif char == '}':
                    brace_depth -= 1
                    result.append(char)
                    
                    # After closing brace, check for bracket
                    if brace_depth == 0 and i + 1 < len(line) and line[i + 1] == '[':
                        # Found {expr}[pattern] - need to fix
                        # Find the bracket content
                        bracket_start = i + 1
                        bracket_end = bracket_start + 1
                        bracket_depth = 1
                        
                        # Find matching closing bracket
                        while bracket_end < len(line) and bracket_depth > 0:
                            if line[bracket_end] == '[':
                                bracket_depth += 1
                            elif line[bracket_end] == ']':
                                bracket_depth -= 1
                            bracket_end += 1
                        
                        if bracket_depth == 0:
                            # Found complete bracket pattern
                            bracket_content = line[bracket_start + 1:bracket_end - 1]
                            
                            # Convert: {expr}[content] -> {expr}" + "[content]" + f"
                            if quote_char == '"':
                                result.append('" + "[' + bracket_content + ']" + f"')
                            else:
                                result.append("' + '[" + bracket_content + "]' + f'")
                            
                            i = bracket_end
                            continue
                
                # Check for closing quote
                if char == quote_char:
                    # Check if it's escaped
                    if i > 0 and line[i-1] == '\\':
                        result.append(char)
                    else:
                        # End of f-string
                        in_fstring_double = False
                        in_fstring_single = False
                        fstring_start = -1
                        quote_char = None
                        brace_depth = 0
                        result.append(char)
                else:
                    result.append(char)
            else:
                # Outside f-string, just copy
                result.append(char)
            
            i += 1
        
        fixed = ''.join(result)
        
        # Additional pass: fix any remaining {expr}[...] patterns using regex
        # This handles cases the character-by-character parser might miss
        if ('f"' in fixed or "f'" in fixed) and '[' in fixed:
            # More aggressive regex-based fix - handle ALL bracket patterns
            if 'f"' in fixed:
                # Find all f-strings and fix brackets - multiple passes for nested cases
                for _ in range(5):  # Multiple passes for nested brackets
                    def fix_fstring_content(match):
                        f_content = match.group(1)
                        # Replace {expr}[...] patterns - handle nested brackets too
                        fixed_content = re.sub(
                            r'(\{[^}]*\})\[([^\]]*)\]',
                            lambda m: m.group(1) + '" + "[' + m.group(2) + ']" + f"',
                            f_content
                        )
                        return 'f"' + fixed_content + '"'
                    
                    new_fixed = re.sub(r'f"([^"]*(?:"[^"]*")*[^"]*)"', fix_fstring_content, fixed)
                    if new_fixed == fixed:
                        break
                    fixed = new_fixed
            
            if "f'" in fixed:
                for _ in range(5):  # Multiple passes for nested brackets
                    def fix_fstring_content_single(match):
                        f_content = match.group(1)
                        fixed_content = re.sub(
                            r"(\{[^}]*\})\[([^\]]*)\]",
                            lambda m: m.group(1) + "' + '[" + m.group(2) + "]' + f'",
                            f_content
                        )
                        return "f'" + fixed_content + "'"
                    
                    new_fixed = re.sub(r"f'([^']*(?:'[^']*')*[^']*)'", fix_fstring_content_single, fixed)
                    if new_fixed == fixed:
                        break
                    fixed = new_fixed
        
        return fixed
    
    # Process each line - check ALL lines with f-strings, not just those with brackets
    # because ast.unparse might introduce brackets
    for line in lines:
        if 'f"' in line or "f'" in line:
            # Always process f-strings to catch any bracket issues
            if '[' in line:
                fixed_line = fix_fstring_line(line)
            else:
                # Even without brackets, check if line parses correctly
                try:
                    test_code = f"x = {line}"
                    ast.parse(test_code)
                    fixed_line = line
                except SyntaxError:
                    # Has syntax error, try to fix
                    fixed_line = fix_fstring_line(line)
            fixed_lines.append(fixed_line)
        else:
            fixed_lines.append(line)
    
    fixed_code = '\n'.join(fixed_lines)
    
    # Validate and retry if needed
    max_retries = 5  # Increased retries
    for retry in range(max_retries):
        try:
            ast.parse(fixed_code)
            return fixed_code
        except SyntaxError as e:
            error_line_num = getattr(e, 'lineno', None)
            error_msg = str(e).lower()
            
            if retry < max_retries - 1 and error_line_num and 1 <= error_line_num <= len(fixed_lines):
                problematic = fixed_lines[error_line_num - 1]
                
                # Ultra-aggressive fix for f-string bracket issues
                if ('f-string' in error_msg or 'unmatched' in error_msg) and ('f"' in problematic or "f'" in problematic):
                    # Try multiple fix strategies
                    original_problematic = problematic
                    
                    # Strategy 1: Fix {expr}[...] patterns
                    if '[' in problematic:
                        if 'f"' in problematic:
                            # Multiple passes for nested cases
                            for _ in range(10):
                                new_prob = re.sub(
                                    r'(\{[^}]*\})\[([^\]]*)\]',
                                    r'\1" + "[\2]" + f"',
                                    problematic
                                )
                                if new_prob == problematic:
                                    break
                                problematic = new_prob
                        
                        if "f'" in problematic:
                            for _ in range(10):
                                new_prob = re.sub(
                                    r"(\{[^}]*\})\[([^\]]*)\]",
                                    r"\1' + '[\2]' + f'",
                                    problematic
                                )
                                if new_prob == problematic:
                                    break
                                problematic = new_prob
                    
                    # Strategy 2: If still problematic, try converting f-string to format()
                    if problematic == original_problematic and ('f"' in problematic or "f'" in problematic):
                        # Last resort: escape brackets or convert
                        # For now, just log and try the regex fix one more time
                        log_event(f"Attempting aggressive fix on line {error_line_num}")
                    
                    fixed_lines[error_line_num - 1] = problematic
                    fixed_code = '\n'.join(fixed_lines)
                    continue
            
            # If we can't fix it after all retries, log and return
            if retry == max_retries - 1:
                log_event(f"Warning: Could not fully fix f-string bracket issue after {max_retries} retries: {e}")
                # Return the best attempt we have
                break
    
    return fixed_code

def validate_python_syntax(code: str, file_path: str = "bot.py") -> Tuple[bool, Optional[str]]:
    """
    Validate Python code syntax before deployment.
    Returns (is_valid, error_message)
    """
    try:
        ast.parse(code)
        return True, None
    except SyntaxError as e:
        error_msg = f"Syntax Error in {file_path}:\n"
        error_msg += f"Line {e.lineno}: {e.text}\n"
        error_msg += f"Error: {e.msg}\n"
        if e.offset:
            error_msg += f"Position: {e.offset}"
        return False, error_msg
    except Exception as e:
        return False, f"Code validation error: {str(e)}"

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

# Ensure we're using venv Python if available
_venv_python = '/app/venv/bin/python'
_venv_pip = '/app/venv/bin/pip'
_venv_exists = os.path.exists(_venv_python) and os.path.exists(_venv_pip)

if _venv_exists:
    # Verify venv is working and add to PATH
    try:
        venv_bin = '/app/venv/bin'
        if venv_bin not in os.environ.get('PATH', ''):
            os.environ['PATH'] = venv_bin + ':' + os.environ.get('PATH', '')
        # Ensure sys.executable points to venv python if we're running from venv
        if sys.executable != _venv_python and os.path.exists(_venv_python):
            # Note: We can't change sys.executable at runtime, but CMD should handle this
            # Just ensure PATH is set correctly
            pass
    except Exception:
        pass

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
            # Use venv pip if available, otherwise system pip
            pip_cmd = '/app/venv/bin/pip' if os.path.exists('/app/venv/bin/pip') else [sys.executable, '-m', 'pip']
            if isinstance(pip_cmd, str):
                subprocess.check_call([pip_cmd, 'install', pkg])
            else:
                subprocess.check_call(pip_cmd + ['install', pkg])
            return True
        except Exception as _e:
            print(f'gravix_runner: failed to install {pkg}: {_e}')
            continue
    return False

def _auto_start_from_namespace(ns: dict) -> bool:
    # Best-effort autostart for common frameworks if user script didn't start polling itself.
    # - python-telegram-bot v21+: ns['application'].run_polling() or obj.app.run_polling()
    # - python-telegram-bot v13: ns['updater'].start_polling(); ns['updater'].idle()
    # - pyTelegramBotAPI: ns['bot'].infinity_polling() or .polling()
    # - pyrogram: ns['app'] or ns['client'] with .run() or .start() + idle loop
    # - Class instances with .app attribute (e.g., VPSTerminalBot.app)
    # Returns True if something was started.
    # Check direct application object
    obj = ns.get('application')
    try:
        if obj and hasattr(obj, 'run_polling') and callable(obj.run_polling):
            print('gravix_runner: autostart — application.run_polling()')
            obj.run_polling()
            return True
    except Exception as e:
        print(f'gravix_runner: autostart application failed: {e}')
    
    # Check for class instances with .app attribute (e.g., VPSTerminalBot)
    for var_name in ['bot', 'app', 'client', 'application']:
        obj = ns.get(var_name)
        if obj:
            # Check if object has .app attribute (class instance)
            try:
                if hasattr(obj, 'app'):
                    app_obj = getattr(obj, 'app')
                    # Check if .app is Application object
                    if hasattr(app_obj, 'run_polling') and callable(app_obj.run_polling):
                        print(f'gravix_runner: autostart — {var_name}.app.run_polling()')
                        app_obj.run_polling()
                        return True
            except Exception as e:
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
    except Exception as e:
        print(f'gravix_runner: autostart updater failed: {e}')
    
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
    except Exception as e:
        print(f'gravix_runner: autostart bot failed: {e}')
    
    # Check for Pyrogram bots (app.run() is blocking)
    for name in ('app', 'client'):
        obj = ns.get(name)
        if obj:
            try:
                # Pyrogram Client.run() is blocking and should be called directly
                if hasattr(obj, 'run') and callable(obj.run):
                    print(f'gravix_runner: autostart — {name}.run() (Pyrogram)')
                    obj.run()
                    return True
                # Pyrogram Client.start() + idle loop
                if hasattr(obj, 'start') and callable(obj.start):
                    print(f'gravix_runner: autostart — {name}.start() + idle loop')
                    obj.start()
                    while True:
                        time.sleep(60)
                    return True
            except Exception as e:
                print(f'gravix_runner: autostart {name} failed: {e}')
    
    return False

def _check_has_blocking_call() -> bool:
    # Check if script already has blocking calls like infinity_polling()
    try:
        src = pathlib.Path('__ENTRY_FILE__').read_text(encoding='utf-8', errors='ignore')
        blocking_patterns = [
            r'\\.infinity_polling\\(\\)',
            r'\\.polling\\(\\)',
            r'\\.run_polling\\(\\)',
            r'\\.start_polling\\(\\)',
            r'\\.idle\\(\\)',
            r'\\.run\\(\\)',
            r'\\.start\\(\\)',
        ]
        for pattern in blocking_patterns:
            if re.search(pattern, src):
                return True
    except Exception:
        pass
    return False

def _try_run() -> bool:
    has_blocking = _check_has_blocking_call()
    
    # Ensure venv is properly activated before running
    if _venv_exists:
        # Verify venv python is in PATH
        venv_bin = '/app/venv/bin'
        if venv_bin not in os.environ.get('PATH', ''):
            os.environ['PATH'] = venv_bin + ':' + os.environ.get('PATH', '')
        # Set VIRTUAL_ENV environment variable
        os.environ['VIRTUAL_ENV'] = '/app/venv'
    
    try:
        # Run the script - if it has blocking calls, runpy.run_path will block
        ns = runpy.run_path('__ENTRY_FILE__', init_globals=init_globals)
        # If we reach here, script finished (didn't block)
        if isinstance(ns, dict):
            # Check if bot object exists and might need autostart
            # Check all possible bot object locations
            bot_obj = None
            for key in ['bot', 'application', 'updater', 'app', 'client']:
                obj = ns.get(key)
                if obj:
                    # Check if it's a bot object or has bot attributes
                    if hasattr(obj, 'run_polling') or hasattr(obj, 'start_polling') or hasattr(obj, 'infinity_polling') or hasattr(obj, 'polling') or hasattr(obj, 'run') or hasattr(obj, 'start'):
                        bot_obj = obj
                        break
                    # Check if it's a class instance with .app attribute
                    if hasattr(obj, 'app'):
                        app_attr = getattr(obj, 'app')
                        if app_attr and (hasattr(app_attr, 'run_polling') or hasattr(app_attr, 'start_polling')):
                            bot_obj = app_attr
                            break
            
            # If no bot object found, try to find and instantiate bot classes
            if not bot_obj:
                # Look for bot classes (e.g., VPSTerminalBot, MyBot, etc.)
                for key, value in ns.items():
                    if isinstance(value, type) and key.endswith(('Bot', 'bot')):
                        try:
                            # Try to instantiate the class
                            instance = value()
                            if hasattr(instance, 'app'):
                                app_obj = getattr(instance, 'app')
                                if app_obj and hasattr(app_obj, 'run_polling'):
                                    print(f'gravix_runner: found bot class {key}, instantiating and starting...')
                                    app_obj.run_polling()
                                    return True
                        except Exception as e:
                            print(f'gravix_runner: failed to instantiate {key}: {e}')
            
            if bot_obj or has_blocking:
                # Script has blocking calls but returned - might be async or not started
                # Try autostart first
                print('gravix_runner: script finished, attempting autostart...')
                started = _auto_start_from_namespace(ns)
                if started:
                    print('gravix_runner: autostart successful')
                    return True
                # If autostart didn't work but has blocking calls, wait anyway
                if has_blocking:
                    print('gravix_runner: detected blocking call in script but autostart failed, waiting...')
                    while True:
                        time.sleep(60)
                else:
                    # No blocking calls detected, try autostart one more time
                    print('gravix_runner: retrying autostart...')
                    started = _auto_start_from_namespace(ns)
                    if started:
                        return True
            else:
                # Try autostart anyway - might find bot in namespace
                print('gravix_runner: attempting autostart from namespace...')
                # More aggressive search - check all namespace items
                for key, value in list(ns.items()):
                    # Skip builtins, types, and modules
                    if not value or isinstance(value, (type, type(__builtins__), type(os), type(sys))):
                        continue
                    # Skip string, int, etc.
                    if isinstance(value, (str, int, float, bool, list, dict, tuple, set)):
                        continue
                    
                    try:
                        # Check if it's a bot object directly
                        if hasattr(value, 'run_polling') and callable(value.run_polling):
                            print(f'gravix_runner: found bot object in {key}, starting...')
                            value.run_polling()
                            return True
                        # Check if it has .app attribute
                        elif hasattr(value, 'app'):
                            app_obj = getattr(value, 'app')
                            if app_obj and hasattr(app_obj, 'run_polling') and callable(app_obj.run_polling):
                                print(f'gravix_runner: found bot.app in {key}, starting...')
                                app_obj.run_polling()
                                return True
                        # Check for other bot methods
                        elif hasattr(value, 'start_polling') and callable(value.start_polling):
                            print(f'gravix_runner: found updater in {key}, starting...')
                            value.start_polling()
                            if hasattr(value, 'idle'):
                                value.idle()
                            else:
                                while True:
                                    time.sleep(60)
                            return True
                        elif hasattr(value, 'infinity_polling') and callable(value.infinity_polling):
                            print(f'gravix_runner: found bot in {key}, starting infinity_polling...')
                            value.infinity_polling()
                            return True
                        elif hasattr(value, 'polling') and callable(value.polling):
                            print(f'gravix_runner: found bot in {key}, starting polling...')
                            value.polling()
                            return True
                    except Exception as e:
                        # Silently continue to next object
                        pass
                
                # Try to find and instantiate bot classes
                for key, value in list(ns.items()):
                    if isinstance(value, type) and (key.endswith(('Bot', 'bot')) or 'Bot' in key or 'bot' in key):
                        try:
                            instance = value()
                            if hasattr(instance, 'app'):
                                app_obj = getattr(instance, 'app')
                                if app_obj and hasattr(app_obj, 'run_polling') and callable(app_obj.run_polling):
                                    print(f'gravix_runner: found bot class {key}, instantiating and starting...')
                                    app_obj.run_polling()
                                    return True
                            elif hasattr(instance, 'run_polling') and callable(instance.run_polling):
                                print(f'gravix_runner: found bot class {key}, instantiating and starting...')
                                instance.run_polling()
                                return True
                        except Exception as e:
                            # Silently continue
                            pass
                
                # Final attempt with standard autostart
                started = _auto_start_from_namespace(ns)
                if started:
                    return True
                
                # Don't print error - just continue to final attempt in main loop
    except SyntaxError as e:
        print(f'gravix_runner: syntax error in script: {e}')
        raise
    except KeyboardInterrupt:
        # User interruption, exit cleanly
        raise SystemExit(0)
    except Exception as e:
        # Even if exception occurred, try to start bot from namespace
        print(f'gravix_runner: exception during script execution: {type(e).__name__}: {str(e)[:200]}')
        try:
            # Try to reload namespace and start bot
            ns = runpy.run_path('__ENTRY_FILE__', init_globals=init_globals)
            if isinstance(ns, dict):
                print('gravix_runner: attempting autostart after exception...')
                started = _auto_start_from_namespace(ns)
                if started:
                    print('gravix_runner: autostart successful after exception')
                    return True
                # If autostart didn't work, try comprehensive search
                for key, value in list(ns.items()):
                    if not value or isinstance(value, (type, type(__builtins__), type(os), type(sys), str, int, float, bool, list, dict, tuple, set)):
                        continue
                    try:
                        # Check for Pyrogram app.run() - this is blocking
                        if hasattr(value, 'run') and callable(value.run):
                            print(f'gravix_runner: found {key}.run(), starting Pyrogram bot...')
                            value.run()
                            return True
                        # Check for other bot methods
                        if hasattr(value, 'run_polling') and callable(value.run_polling):
                            print(f'gravix_runner: found {key}.run_polling(), starting...')
                            value.run_polling()
                            return True
                        elif hasattr(value, 'app'):
                            app_obj = getattr(value, 'app')
                            if app_obj and hasattr(app_obj, 'run_polling') and callable(app_obj.run_polling):
                                print(f'gravix_runner: found {key}.app.run_polling(), starting...')
                                app_obj.run_polling()
                                return True
                        elif hasattr(value, 'start_polling') and callable(value.start_polling):
                            print(f'gravix_runner: found {key}.start_polling(), starting...')
                            value.start_polling()
                            if hasattr(value, 'idle'):
                                value.idle()
                            else:
                                while True:
                                    time.sleep(60)
                            return True
                        elif hasattr(value, 'infinity_polling') and callable(value.infinity_polling):
                            print(f'gravix_runner: found {key}.infinity_polling(), starting...')
                            value.infinity_polling()
                            return True
                        elif hasattr(value, 'polling') and callable(value.polling):
                            print(f'gravix_runner: found {key}.polling(), starting...')
                            value.polling()
                            return True
                    except Exception as start_err:
                        # Continue to next object
                        pass
        except Exception as reload_err:
            print(f'gravix_runner: could not reload namespace after exception: {reload_err}')
        
        # If script has blocking calls, wait in case bot is running
        if has_blocking:
            print(f'gravix_runner: script has blocking calls, waiting in case bot is running...')
            while True:
                time.sleep(60)
        
        # If not recoverable and no blocking calls, return False to try again
        return False
    return False

# Validate token before starting
if not token or len(token) < 20:
    print(f'gravix_runner: WARNING - token seems invalid (len={len(token)})')
    print('gravix_runner: continuing anyway - bot may fail to start')

print(f"gravix_runner: entry __ENTRY_FILE__ token_len={len(token)}")

while True:
    try:
        if _try_run():
            # If autostart engaged, we only reach here on termination
            print('gravix_runner: autostarted service terminated')
            sys.exit(0)
        else:
            # Check if script has blocking calls - if so, wait
            has_blocking = _check_has_blocking_call()
            if has_blocking:
                print('gravix_runner: script has blocking calls, waiting...')
                while True:
                    time.sleep(60)
            else:
                # Before exiting, try one more aggressive autostart attempt
                print('gravix_runner: user script finished, attempting final autostart...')
                bot_started = False
                try:
                    ns = runpy.run_path('__ENTRY_FILE__', init_globals=init_globals)
                    if isinstance(ns, dict):
                        # Try to find and start any bot objects - comprehensive search
                        for key, value in list(ns.items()):
                            # Skip builtins, types, and simple types
                            if not value or isinstance(value, (type, type(__builtins__), type(os), type(sys), str, int, float, bool, list, dict, tuple, set)):
                                continue
                            
                            try:
                                # Check for Pyrogram app.run() first - this is blocking
                                if hasattr(value, 'run') and callable(value.run):
                                    print(f'gravix_runner: final attempt - starting {key}.run() (Pyrogram)...')
                                    value.run()
                                    bot_started = True
                                    break
                                # Check direct bot object
                                elif hasattr(value, 'run_polling') and callable(value.run_polling):
                                    print(f'gravix_runner: final attempt - starting {key}...')
                                    value.run_polling()
                                    bot_started = True
                                    break
                                # Check .app attribute
                                elif hasattr(value, 'app'):
                                    app_obj = getattr(value, 'app')
                                    if app_obj and hasattr(app_obj, 'run_polling') and callable(app_obj.run_polling):
                                        print(f'gravix_runner: final attempt - starting {key}.app...')
                                        app_obj.run_polling()
                                        bot_started = True
                                        break
                                # Check other bot methods
                                elif hasattr(value, 'start_polling') and callable(value.start_polling):
                                    print(f'gravix_runner: final attempt - starting {key} (updater)...')
                                    value.start_polling()
                                    if hasattr(value, 'idle'):
                                        value.idle()
                                    else:
                                        while True:
                                            time.sleep(60)
                                    bot_started = True
                                    break
                                elif hasattr(value, 'infinity_polling') and callable(value.infinity_polling):
                                    print(f'gravix_runner: final attempt - starting {key} (infinity_polling)...')
                                    value.infinity_polling()
                                    bot_started = True
                                    break
                                elif hasattr(value, 'polling') and callable(value.polling):
                                    print(f'gravix_runner: final attempt - starting {key} (polling)...')
                                    value.polling()
                                    bot_started = True
                                    break
                            except Exception as e:
                                # Continue to next object
                                pass
                        
                        # Try to find and instantiate bot classes
                        if not bot_started:
                            for key, value in list(ns.items()):
                                if isinstance(value, type) and (key.endswith(('Bot', 'bot')) or 'Bot' in key or 'bot' in key):
                                    try:
                                        instance = value()
                                        if hasattr(instance, 'app'):
                                            app_obj = getattr(instance, 'app')
                                            if app_obj and hasattr(app_obj, 'run_polling') and callable(app_obj.run_polling):
                                                print(f'gravix_runner: final attempt - instantiating {key} and starting...')
                                                app_obj.run_polling()
                                                bot_started = True
                                                break
                                        elif hasattr(instance, 'run_polling') and callable(instance.run_polling):
                                            print(f'gravix_runner: final attempt - instantiating {key} and starting...')
                                            instance.run_polling()
                                            bot_started = True
                                            break
                                    except Exception as e:
                                        # Continue to next class
                                        pass
                except Exception as e:
                    # If script can't be reloaded, that's okay
                    pass
                
                if bot_started:
                    # Bot started successfully, wait indefinitely
                    print('gravix_runner: bot started successfully, waiting...')
                    while True:
                        time.sleep(60)
                else:
                    # If still not started, wait anyway in case bot is running in background
                    print('gravix_runner: no bot object found, but waiting in case bot is running...')
                    while True:
                        time.sleep(60)
    except ImportError as e:
        msg = str(e)
        if 'telegram.ext' in msg and ('Filters' in msg or 'Updater' in msg):
            try:
                print('gravix_runner: detected PTB API mismatch, installing python-telegram-bot==13.15')
                # Use venv pip if available
                pip_cmd = '/app/venv/bin/pip' if os.path.exists('/app/venv/bin/pip') else [sys.executable, '-m', 'pip']
                if isinstance(pip_cmd, str):
                    subprocess.check_call([pip_cmd, 'install', 'python-telegram-bot==13.15'])
                else:
                    subprocess.check_call(pip_cmd + ['install', 'python-telegram-bot==13.15'])
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

    # Optimize requirements - remove duplicates and combine
    final_reqs = []
    if requirements:
        seen = set()
        for req in requirements:
            # Extract package name (before ==, >=, etc.)
            pkg_name = req.split("==")[0].split(">=")[0].split("<=")[0].split(">")[0].split("<")[0].split("~=")[0].strip().lower()
            if pkg_name and pkg_name not in seen:
                seen.add(pkg_name)
                final_reqs.append(req)
    
    dockerfile = os.path.join(workspace, "Dockerfile")
    # Write requirements file first if needed
    if final_reqs:
        req_auto_path = os.path.join(workspace, "requirements.autodetected.txt")
        with open(req_auto_path, "w", encoding="utf-8", newline="\n") as rf:
            rf.write("\n".join(final_reqs))
    
    with open(dockerfile, "w", encoding="utf-8", newline="\n") as f:
        f.write("FROM python:3.11-slim\n")
        f.write("WORKDIR /app\n")
        # Copy only requirements first for better caching
        if final_reqs:
            f.write("COPY requirements.autodetected.txt /app/\n")
        # Copy requirements.txt only if it exists
        req_txt_path = os.path.join(workspace, "requirements.txt")
        if os.path.exists(req_txt_path):
            f.write("COPY requirements.txt /app/\n")
        else:
            f.write("RUN touch /app/requirements.txt\n")
        # Install build tools only if needed (for packages with C extensions)
        f.write("RUN apt-get update && apt-get install -y --no-install-recommends \\\n")
        f.write("    gcc g++ make libffi-dev libssl-dev && \\\n")
        f.write("    rm -rf /var/lib/apt/lists/*\n")
        # Upgrade pip and create virtual environment
        f.write("RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \\\n")
        f.write("    python -m venv /app/venv && \\\n")
        f.write("    /app/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel\n")
        # Activate venv in PATH and install dependencies
        f.write("ENV PATH=\"/app/venv/bin:$PATH\"\n")
        f.write("ENV VIRTUAL_ENV=\"/app/venv\"\n")
        f.write("RUN /app/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel")
        if final_reqs:
            f.write(" && \\\n    /app/venv/bin/pip install --no-cache-dir -r requirements.autodetected.txt")
        f.write(" && \\\n    (/app/venv/bin/pip install --no-cache-dir -r requirements.txt || true)\n")
        # Remove build tools after installation to reduce image size
        f.write("RUN apt-get purge -y gcc g++ make && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*\n")
        # Copy application code
        f.write("COPY . /app\n")
        f.write("ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app\n")
        f.write("ENV PYTHONDONTWRITEBYTECODE=1\n")
        # Use venv python for running
        f.write('CMD ["/app/venv/bin/python", "/app/gravix_runner.py"]\n')

# ---- Docker availability ------------------------------------------------------

def _get_docker_client():
    """
    Get Docker client with sudo fallback if permission denied.
    Returns docker client or None if Docker is not available.
    """
    try:
        client = docker_from_env()
        client.ping()
        return client
    except docker_errors.DockerException as e:
        if "permission denied" in str(e).lower() or "connect: permission denied" in str(e).lower():
            # Try with sudo
            try:
                # Use subprocess to call docker with sudo
                result = subprocess.run(['sudo', 'docker', 'info'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    log_event("Docker accessible with sudo. Consider adding user to docker group.")
                    # Return a client that will use sudo for operations
                    # For now, return None and let caller handle sudo commands
                    return None
            except Exception:
                pass
            log_event("Docker permission denied. User may need to be in docker group or use sudo.")
        return None
    except Exception:
        return None

def _docker_available() -> bool:
    """
    Check if Docker is available and accessible.
    Returns True if Docker daemon is reachable, False otherwise.
    """
    client = _get_docker_client()
    return client is not None

# ---- Single-file build and run ------------------------------------------------

def build_and_run_from_code(
    uid: int,
    name: str,
    code: str,
    reqs: List[str],
    framework: str,
    token_var: str,
    token: str,
    extra_env: Optional[dict] = None,
) -> Tuple[bool, Optional[str], Optional[str]]:
    # Validate token is not empty
    if not token or not token.strip():
        return False, None, "Token Error:\nBot token is missing or empty.\n\nPlease provide a valid bot token from @BotFather."
    
    temp_dir = None
    client = _get_docker_client()
    if client is None:
        return False, None, "Docker Unavailable:\nCannot connect to Docker daemon.\n\nPlease check:\n• Docker is installed and running\n• User has Docker permissions\n• Try: sudo systemctl start docker"
    try:
        temp_dir = tempfile.mkdtemp()
        # Prepare bot.py with token rewrite
        rewritten_code = rewrite_token_in_code(code, env_keys=_ENV_KEYS_DEFAULT, candidate_vars=[token_var])
        
        # Fix f-string bracket issues before validation
        rewritten_code = fix_fstring_brackets(rewritten_code)
        
        # Validate syntax before writing
        is_valid, syntax_error = validate_python_syntax(rewritten_code, "bot.py")
        if not is_valid:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            return False, None, f"Code Syntax Error:\n\n{syntax_error}\n\nPlease fix the syntax error in your code and try again."
        
        with open(os.path.join(temp_dir, "bot.py"), "w", encoding="utf-8") as f:
            f.write(rewritten_code)
        # Requirements
        with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(reqs) if reqs else "")
        # Runner + Dockerfile
        write_runner_and_dockerfile(temp_dir, entry="bot.py", requirements=reqs)

        image_tag = f"hostbot_{uid}_{name}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")
        container_name = image_tag

        # Build with detailed progress logging and timeout
        log_event(f"Building Docker image for bot {name} (user {uid})...")
        build_log_output = []
        build_start_time = time.time()
        build_timeout = 600  # 10 minutes max
        
        try:
            # Build Docker image (without stream for compatibility)
            log_event(f"Starting Docker build for {name}...")
            image, build_logs = client.images.build(
                path=temp_dir,
                tag=image_tag,
                rm=True,
                quiet=False,
                pull=False
            )
            
            # Parse build logs
            for log_item in build_logs:
                # Check timeout
                if time.time() - build_start_time > build_timeout:
                    log_event(f"Build timeout after {build_timeout}s for {name}")
                    raise TimeoutError(f"Build timeout after {build_timeout} seconds")
                
                # Handle different log formats
                if isinstance(log_item, dict):
                    if 'stream' in log_item:
                        log_line = log_item['stream'].strip()
                        if log_line:
                            build_log_output.append(log_line)
                            if 'Step' in log_line or 'ERROR' in log_line or 'error' in log_line.lower() or 'pip install' in log_line.lower():
                                log_event(f"Build: {log_line[:200]}")
                    elif 'error' in log_item or 'errorDetail' in log_item:
                        error_msg = log_item.get('error', log_item.get('errorDetail', {}).get('message', str(log_item)))
                        build_log_output.append(f"ERROR: {error_msg}")
                        log_event(f"Docker build error: {error_msg[:300]}")
                        raise docker_errors.BuildError(str(error_msg), build_log_output)
                elif isinstance(log_item, str):
                    build_log_output.append(log_item)
                    if 'Step' in log_item or 'ERROR' in log_item or 'error' in log_item.lower():
                        log_event(f"Build: {log_item[:200]}")
            
            build_duration = int(time.time() - build_start_time)
            log_event(f"Docker image built successfully: {image_tag} (took {build_duration}s)")
        except TimeoutError as timeout_err:
            error_msg = str(timeout_err)
            log_event(f"Docker build timeout for {name}: {error_msg}")
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            return False, None, f"Build Timeout:\nBuild took longer than {build_timeout} seconds.\n\nPossible causes:\n• Large dependencies downloading\n• Slow network connection\n• Server resource constraints\n\nPlease try again or contact support."
        except docker_errors.BuildError as build_err:
            error_detail = '\n'.join(build_log_output[-20:]) if build_log_output else str(build_err)
            log_event(f"Docker build failed for {name}: {error_detail[:500]}")
            raise
        except Exception as build_err:
            error_msg = str(build_err)
            log_event(f"Docker build exception for {name}: {error_msg[:300]}")
            raise

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

        container = client.containers.run(
            image_tag,
            name=container_name,
            detach=True,
            environment={
                "TELEGRAM_TOKEN": token,
                "BOT_TOKEN": token,
                "TOKEN": token,
                "TELEGRAM_BOT_TOKEN": token,
                **(extra_env or {}),
            },
            cpu_quota=DEFAULT_CPU_QUOTA,
            mem_limit=DEFAULT_MEM_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            network=network if network else None,
            restart_policy={"Name": "no"},
        )
        rid = container.id
        log_event(f"Runtime started {rid} for {uid}/{name} (framework={framework})")
        
        # Wait and verify container is actually running AND bot started successfully
        # Check multiple times with increasing wait intervals to ensure bot fully starts
        max_attempts = 5
        wait_intervals = [5, 5, 5, 5, 5]  # Total ~25 seconds
        bot_started = False
        last_error = None
        
        for attempt in range(max_attempts):
            time.sleep(wait_intervals[attempt])
            try:
                container.reload()
                
                if container.status != 'running':
                    # Container exited, get logs to show error
                    logs = container.logs(stdout=True, stderr=True, tail=100).decode('utf-8', errors='ignore')
                    error_lines = []
                    for line in logs.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('gravix_runner: heartbeat') or 'detected blocking' in line.lower():
                            continue
                        # Filter out our internal messages
                        if 'gravix_runner:' in line and ('entry' in line or 'waiting' in line.lower()):
                            continue
                        if any(keyword in line.lower() for keyword in ['error', 'exception', 'traceback', 'syntaxerror', 'nameerror', 'failed', 'unboundlocalerror', 'attributeerror']):
                            error_lines.append(line)
                        elif 'Traceback' in line or 'File "' in line:
                            error_lines.append(line)
                    
                    # Extract last error if no specific error lines found
                    if not error_lines:
                        # Get last non-heartbeat, non-internal lines
                        all_lines = [l.strip() for l in logs.split('\n') 
                                    if l.strip() 
                                    and not l.strip().startswith('gravix_runner: heartbeat')
                                    and 'detected blocking' not in l.lower()
                                    and not ('gravix_runner:' in l and ('entry' in l or 'waiting' in l.lower()))]
                        error_lines = all_lines[-10:] if all_lines else ["Container exited immediately"]
                    
                    error_msg = '\n'.join(error_lines[-15:])  # Last 15 lines
                    log_event(f"Runtime failed for {uid}/{name}: Container exited with status {container.status} (attempt {attempt + 1}/{max_attempts})")
                    container.remove(force=True)
                    if temp_dir:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    return False, None, f"Runtime Error:\n{error_msg}\n\nPlease check your code for syntax errors or runtime issues."
                else:
                    # Container is running - check if bot actually started successfully
                    logs = container.logs(stdout=True, stderr=True, tail=50).decode('utf-8', errors='ignore')
                    
                    # Check for heartbeat (this confirms bot started)
                    has_heartbeat = 'heartbeat alive' in logs or 'gravix_runner: heartbeat' in logs
                    
                    # Check for blocking call detection (means bot is actually running with blocking call)
                    has_blocking_detected = 'detected blocking call' in logs.lower()
                    
                    # Check for actual errors (excluding blocking call messages which are informational)
                    # Filter out blocking call messages from error detection
                    actual_error_keywords = ['error', 'exception', 'traceback', 'syntaxerror', 'nameerror', 'unboundlocalerror', 'attributeerror', 'importerror', 'modulenotfounderror', 'failed']
                    has_actual_errors = False
                    error_lines = []
                    
                    # Check each line for actual errors, but ignore blocking call related messages
                    for line in logs.split('\n'):
                        line_lower = line.lower()
                        # Skip blocking call messages and heartbeat messages
                        if 'detected blocking call' in line_lower or 'heartbeat' in line_lower:
                            continue
                        # Skip runner internal messages
                        if 'gravix_runner:' in line and ('entry' in line_lower or 'waiting' in line_lower or 'autostart' in line_lower):
                            continue
                        # Check for actual errors
                        if any(keyword in line_lower for keyword in actual_error_keywords):
                            if 'traceback' in line_lower or 'file "' in line_lower:
                                has_actual_errors = True
                                error_lines.append(line.strip())
                    
                    # If heartbeat exists, bot is running - blocking call message is just informational
                    if has_heartbeat:
                        if has_blocking_detected:
                            # Bot is running with blocking call - this is normal and expected
                            bot_started = True
                            log_event(f"Bot {uid}/{name} confirmed running with heartbeat and blocking call detected (attempt {attempt + 1}/{max_attempts})")
                            break
                        elif not has_actual_errors:
                            # Bot is running successfully without blocking call issues
                            bot_started = True
                            log_event(f"Bot {uid}/{name} confirmed running with heartbeat (attempt {attempt + 1}/{max_attempts})")
                            break
                        elif has_actual_errors:
                            # Has heartbeat but also errors - might be unstable, check again
                            log_event(f"Bot {uid}/{name} has heartbeat but also errors - checking again (attempt {attempt + 1}/{max_attempts})")
                            last_error = '\n'.join(error_lines[-10:]) if error_lines else "Bot has errors but is running"
                    elif has_blocking_detected and container.status == 'running':
                        # Blocking call detected but no heartbeat yet - wait longer, might be starting
                        log_event(f"Bot {uid}/{name} has blocking call detected but no heartbeat yet - waiting longer (attempt {attempt + 1}/{max_attempts})")
                    elif has_actual_errors:
                        # Actual errors without heartbeat - might crash
                        error_lines = [l for l in logs.split('\n') if any(kw in l.lower() for kw in actual_error_keywords)]
                        last_error = '\n'.join(error_lines[-10:])
                        log_event(f"Bot {uid}/{name} has errors in logs (attempt {attempt + 1}/{max_attempts}): {last_error[:200]}")
                        # Continue checking - might recover
                    
            except Exception as e:
                # If we can't check status, log but continue checking
                try:
                    log_event(f"Could not verify container status for {uid}/{name} (attempt {attempt + 1}/{max_attempts}): {str(e)[:200]}")
                except:
                    pass
        
        # Final verification: if we didn't confirm bot started, check one more time
        if not bot_started:
            try:
                container.reload()
                if container.status == 'running':
                    logs = container.logs(stdout=True, stderr=True, tail=100).decode('utf-8', errors='ignore')
                    has_heartbeat = 'heartbeat alive' in logs or 'gravix_runner: heartbeat' in logs
                    has_blocking_detected = 'detected blocking call' in logs.lower()
                    
                    # Check for actual errors (excluding blocking call messages)
                    actual_error_keywords = ['error', 'exception', 'traceback', 'failed']
                    has_actual_errors = False
                    error_lines = []
                    for line in logs.split('\n'):
                        line_lower = line.lower()
                        # Skip blocking call and heartbeat messages
                        if 'detected blocking call' in line_lower or 'heartbeat' in line_lower:
                            continue
                        if 'gravix_runner:' in line and ('entry' in line_lower or 'waiting' in line_lower or 'autostart' in line_lower):
                            continue
                        if any(keyword in line_lower for keyword in actual_error_keywords):
                            if 'traceback' in line_lower or 'file "' in line_lower:
                                has_actual_errors = True
                                if 'gravix_runner:' not in line or 'heartbeat' not in line:
                                    error_lines.append(line.strip())
                    
                    # If heartbeat exists, bot is running - blocking call is normal
                    if has_heartbeat:
                        bot_started = True
                        log_event(f"Bot {uid}/{name} confirmed running in final check")
                    elif has_blocking_detected:
                        # Blocking call detected - bot is likely running, accept it
                        bot_started = True
                        log_event(f"Bot {uid}/{name} confirmed running with blocking call in final check")
                    else:
                        # Get error details for user
                        if has_actual_errors or not has_heartbeat:
                            if not error_lines and not has_heartbeat:
                                error_lines = ["Bot did not start successfully. No heartbeat detected. Check your code logic."]
                            
                            last_error = '\n'.join(error_lines[-15:]) if error_lines else "Bot failed to start. Check logs for details."
                else:
                    last_error = f"Container exited with status: {container.status}"
            except Exception as e:
                try:
                    log_event(f"Final check failed for {uid}/{name}: {str(e)[:200]}")
                except:
                    pass
        
        # Only return success if bot actually started
        if not bot_started:
            log_event(f"Bot {uid}/{name} failed to start properly after {max_attempts} attempts")
            try:
                container.remove(force=True)
            except:
                pass
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            error_msg = last_error or "Bot did not start successfully. No heartbeat detected after multiple checks. Please verify your bot code is correct and starts properly."
            return False, None, f"Runtime Error:\n{error_msg}\n\nPlease check your code for issues and ensure your bot starts correctly."
        
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        log_event(f"Bot {uid}/{name} successfully started and verified!")
        return True, rid, None
    except docker_errors.BuildError as e:
        error_msg = str(e)
        # Try to extract build logs from exception
        build_logs = getattr(e, 'build_log', None) if hasattr(e, 'build_log') else None
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        # Extract useful error information
        if build_logs:
            if isinstance(build_logs, list):
                error_lines = [line for line in build_logs if isinstance(line, str) and ('ERROR' in line or 'error' in line.lower() or 'failed' in line.lower())]
                detailed_error = '\n'.join(error_lines[-10:]) if error_lines else str(e)[:500]
            else:
                detailed_error = str(build_logs)[:500]
        else:
            error_lines = error_msg.split('\n')
            relevant_lines = [line for line in error_lines if 'ERROR' in line or 'error' in line.lower() or 'failed' in line.lower()][-5:]
            detailed_error = '\n'.join(relevant_lines) if relevant_lines else error_msg[:500]
        return False, None, f"Build Error:\n{detailed_error}\n\nPossible fixes:\n• Check your requirements.txt\n• Verify Python syntax in your code\n• Ensure all imports are correct\n• Check Dockerfile syntax"
    except docker_errors.APIError as e:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return False, None, f"Docker API Error: {str(e)[:300]}\n\nPlease try again or contact support."
    except Exception as e:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        error_type = type(e).__name__
        error_msg = str(e)
        # Create user-friendly error message
        if "permission denied" in error_msg.lower():
            return False, None, "Permission Error:\nDocker permissions issue. Please contact admin."
        elif "no space left" in error_msg.lower() or "disk full" in error_msg.lower():
            return False, None, "Storage Error:\nServer storage full. Please contact admin."
        elif "network" in error_msg.lower() or "connection" in error_msg.lower():
            return False, None, f"Network Error:\n{error_msg[:200]}\n\nPlease check your internet connection and try again."
        else:
            # Log our internal errors but don't expose them to users
            log_event(f"Internal error in build_and_run_from_code for {uid}/{name}: {error_type}: {error_msg[:300]}")
            # Generic error message - don't expose internal error details
            return False, None, "Deployment Error:\nAn error occurred during deployment. Please try again or contact support if the issue persists."

# ---- Full workspace build and run --------------------------------------------

def build_and_run(user_id: int, bot_id: str, token: str, workspace: str, entry: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    # Validate token is not empty
    if not token or not token.strip():
        return False, None, "Token Error:\nBot token is missing or empty.\n\nPlease provide a valid bot token from @BotFather."
    
    if not _docker_available():
        log_event("Docker not available. Aborting deployment.")
        return False, None, "docker_unavailable"

    code = None
    entry_file = entry
    try:
        if not entry_file:
            candidate = os.path.join(workspace, "bot.py")
            if os.path.exists(candidate):
                entry_file = "bot.py"
            else:
                for f in os.listdir(workspace):
                    if f.endswith(".py"):
                        entry_file = f
                        break
        if entry_file:
            code = open(os.path.join(workspace, entry_file), "r", encoding="utf-8", errors="ignore").read()
    except Exception:
        code = None

    if not code:
        return False, None, "no_entry_py"

    framework, candidate_names = detect_framework(code)
    try:
        full_reqs = detect_requirements(workspace)
    except Exception:
        full_reqs = []
    reqs = full_reqs or (["python-telegram-bot>=21.0"] if framework == "python-telegram-bot" else [])

    temp_dir = None
    client = _get_docker_client()
    if client is None:
        return False, None, "Docker Unavailable:\nCannot connect to Docker daemon.\n\nPlease check:\n• Docker is installed and running\n• User has Docker permissions\n• Try: sudo systemctl start docker"
    try:
        temp_dir = tempfile.mkdtemp()
        
        # Copy all files from workspace to temp_dir (smart copy)
        try:
            for root, dirs, files in os.walk(workspace):
                # Skip hidden directories and common ignore patterns
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'venv', 'env', '.git']]
                for file in files:
                    if file.startswith('.'):
                        continue
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, workspace)
                    dst_path = os.path.join(temp_dir, rel_path)
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    shutil.copy2(src_path, dst_path)
        except Exception as copy_err:
            log_event(f"Warning: Could not copy all files from workspace: {copy_err}")
            # Continue with just entry file if copy fails
        
        # Process entry file: rewrite token and fix issues
        entry_path = os.path.join(temp_dir, entry_file or "bot.py")
        if os.path.exists(entry_path):
            try:
                code = open(entry_path, "r", encoding="utf-8", errors="ignore").read()
                code = rewrite_token_in_code(code, env_keys=_ENV_KEYS_DEFAULT, candidate_vars=candidate_names)
                # Fix f-string bracket issues before validation
                code = fix_fstring_brackets(code)
                
                # Validate syntax before writing
                is_valid, syntax_error = validate_python_syntax(code, entry_file or "bot.py")
                if not is_valid:
                    if temp_dir:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    return False, None, f"Code Syntax Error:\n\n{syntax_error}\n\nPlease fix the syntax error in your code and try again."
                
                # Write processed code back
                with open(entry_path, "w", encoding="utf-8") as f:
                    f.write(code)
            except Exception as proc_err:
                log_event(f"Warning: Could not process entry file: {proc_err}")
        
        # Ensure requirements.txt exists
        reqs_path = os.path.join(temp_dir, "requirements.txt")
        if not os.path.exists(reqs_path) or os.path.getsize(reqs_path) == 0:
            with open(reqs_path, "w", encoding="utf-8") as f:
                f.write("\n".join(reqs) if reqs else "")
        else:
            # Merge with detected requirements
            try:
                existing_reqs = []
                with open(reqs_path, "r", encoding="utf-8", errors="ignore") as f:
                    existing_reqs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
                # Combine and deduplicate
                all_reqs = list(set(existing_reqs + reqs))
                with open(reqs_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(all_reqs))
            except Exception:
                pass
        
        # Write runner and Dockerfile
        write_runner_and_dockerfile(temp_dir, entry=entry_file or "bot.py", requirements=reqs)

        image_tag = f"hostbot_{user_id}_{bot_id}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")
        container_name = image_tag

        # Build with detailed progress logging and timeout
        log_event(f"Building Docker image for bot {bot_id} (user {user_id})...")
        build_log_output = []
        build_start_time = time.time()
        build_timeout = 600  # 10 minutes max
        
        try:
            # Build Docker image (without stream for compatibility)
            log_event(f"Starting Docker build for {bot_id}...")
            image, build_logs = client.images.build(
                path=temp_dir,
                tag=image_tag,
                rm=True,
                quiet=False,
                pull=False
            )
            
            # Parse build logs
            for log_item in build_logs:
                # Check timeout
                if time.time() - build_start_time > build_timeout:
                    log_event(f"Build timeout after {build_timeout}s for {bot_id}")
                    raise TimeoutError(f"Build timeout after {build_timeout} seconds")
                
                # Handle different log formats
                if isinstance(log_item, dict):
                    if 'stream' in log_item:
                        log_line = log_item['stream'].strip()
                        if log_line:
                            build_log_output.append(log_line)
                            if 'Step' in log_line or 'ERROR' in log_line or 'error' in log_line.lower() or 'pip install' in log_line.lower():
                                log_event(f"Build: {log_line[:200]}")
                    elif 'error' in log_item or 'errorDetail' in log_item:
                        error_msg = log_item.get('error', log_item.get('errorDetail', {}).get('message', str(log_item)))
                        build_log_output.append(f"ERROR: {error_msg}")
                        log_event(f"Docker build error: {error_msg[:300]}")
                        raise docker_errors.BuildError(str(error_msg), build_log_output)
                elif isinstance(log_item, str):
                    build_log_output.append(log_item)
                    if 'Step' in log_item or 'ERROR' in log_item or 'error' in log_item.lower():
                        log_event(f"Build: {log_item[:200]}")
            
            build_duration = int(time.time() - build_start_time)
            log_event(f"Docker image built successfully: {image_tag} (took {build_duration}s)")
        except TimeoutError as timeout_err:
            error_msg = str(timeout_err)
            log_event(f"Docker build timeout for {bot_id}: {error_msg}")
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            return False, None, f"Build Timeout:\nBuild took longer than {build_timeout} seconds.\n\nPossible causes:\n• Large dependencies downloading\n• Slow network connection\n• Server resource constraints\n\nPlease try again or contact support."
        except docker_errors.BuildError as build_err:
            error_detail = '\n'.join(build_log_output[-20:]) if build_log_output else str(build_err)
            log_event(f"Docker build failed for {bot_id}: {error_detail[:500]}")
            raise
        except Exception as build_err:
            error_msg = str(build_err)
            log_event(f"Docker build exception for {bot_id}: {error_msg[:300]}")
            raise

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

        container = client.containers.run(
            image_tag,
            name=container_name,
            detach=True,
            environment={
                "TELEGRAM_TOKEN": token,
                "BOT_TOKEN": token,
                "TOKEN": token,
                "TELEGRAM_BOT_TOKEN": token,
            },
            cpu_quota=DEFAULT_CPU_QUOTA,
            mem_limit=DEFAULT_MEM_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            network=network if network else None,
            restart_policy={"Name": "no"},
        )
        runtime_id = container.id
        log_event(f"Runtime started {runtime_id} for {bot_id} (framework={framework})")
        
        # Wait and verify container is actually running AND bot started successfully
        # Check multiple times with increasing wait intervals to ensure bot fully starts
        max_attempts = 5
        wait_intervals = [5, 5, 5, 5, 5]  # Total ~25 seconds
        bot_started = False
        last_error = None
        
        for attempt in range(max_attempts):
            time.sleep(wait_intervals[attempt])
            try:
                container.reload()
                
                if container.status != 'running':
                    # Container exited, get logs to show error
                    logs = container.logs(stdout=True, stderr=True, tail=100).decode('utf-8', errors='ignore')
                    error_lines = []
                    for line in logs.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('gravix_runner: heartbeat') or 'detected blocking' in line.lower():
                            continue
                        # Filter out our internal messages
                        if 'gravix_runner:' in line and ('entry' in line or 'waiting' in line.lower()):
                            continue
                        if any(keyword in line.lower() for keyword in ['error', 'exception', 'traceback', 'syntaxerror', 'nameerror', 'failed', 'unboundlocalerror', 'attributeerror']):
                            error_lines.append(line)
                        elif 'Traceback' in line or 'File "' in line:
                            error_lines.append(line)
                    
                    # Extract last error if no specific error lines found
                    if not error_lines:
                        # Get last non-heartbeat, non-internal lines
                        all_lines = [l.strip() for l in logs.split('\n') 
                                    if l.strip() 
                                    and not l.strip().startswith('gravix_runner: heartbeat')
                                    and 'detected blocking' not in l.lower()
                                    and not ('gravix_runner:' in l and ('entry' in l or 'waiting' in l.lower()))]
                        error_lines = all_lines[-10:] if all_lines else ["Container exited immediately"]
                    
                    error_msg = '\n'.join(error_lines[-15:])  # Last 15 lines
                    log_event(f"Runtime failed for {bot_id}: Container exited with status {container.status} (attempt {attempt + 1}/{max_attempts})")
                    container.remove(force=True)
                    if temp_dir:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    return False, None, f"Runtime Error:\n{error_msg}\n\nPlease check your code for syntax errors or runtime issues."
                else:
                    # Container is running - check if bot actually started successfully
                    logs = container.logs(stdout=True, stderr=True, tail=50).decode('utf-8', errors='ignore')
                    
                    # Check for heartbeat (this confirms bot started)
                    has_heartbeat = 'heartbeat alive' in logs or 'gravix_runner: heartbeat' in logs
                    
                    # Check for blocking call detection (means bot is actually running with blocking call)
                    has_blocking_detected = 'detected blocking call' in logs.lower()
                    
                    # Check for actual errors (excluding blocking call messages which are informational)
                    # Filter out blocking call messages from error detection
                    actual_error_keywords = ['error', 'exception', 'traceback', 'syntaxerror', 'nameerror', 'unboundlocalerror', 'attributeerror', 'importerror', 'modulenotfounderror', 'failed']
                    has_actual_errors = False
                    error_lines = []
                    
                    # Check each line for actual errors, but ignore blocking call related messages
                    for line in logs.split('\n'):
                        line_lower = line.lower()
                        # Skip blocking call messages and heartbeat messages
                        if 'detected blocking call' in line_lower or 'heartbeat' in line_lower:
                            continue
                        # Skip runner internal messages
                        if 'gravix_runner:' in line and ('entry' in line_lower or 'waiting' in line_lower or 'autostart' in line_lower):
                            continue
                        # Check for actual errors
                        if any(keyword in line_lower for keyword in actual_error_keywords):
                            if 'traceback' in line_lower or 'file "' in line_lower:
                                has_actual_errors = True
                                error_lines.append(line.strip())
                    
                    # If heartbeat exists, bot is running - blocking call message is just informational
                    if has_heartbeat:
                        if has_blocking_detected:
                            # Bot is running with blocking call - this is normal and expected
                            bot_started = True
                            log_event(f"Bot {bot_id} confirmed running with heartbeat and blocking call detected (attempt {attempt + 1}/{max_attempts})")
                            break
                        elif not has_actual_errors:
                            # Bot is running successfully without blocking call issues
                            bot_started = True
                            log_event(f"Bot {bot_id} confirmed running with heartbeat (attempt {attempt + 1}/{max_attempts})")
                            break
                        elif has_actual_errors:
                            # Has heartbeat but also errors - might be unstable, check again
                            log_event(f"Bot {bot_id} has heartbeat but also errors - checking again (attempt {attempt + 1}/{max_attempts})")
                            last_error = '\n'.join(error_lines[-10:]) if error_lines else "Bot has errors but is running"
                    elif has_blocking_detected and container.status == 'running':
                        # Blocking call detected but no heartbeat yet - wait longer, might be starting
                        log_event(f"Bot {bot_id} has blocking call detected but no heartbeat yet - waiting longer (attempt {attempt + 1}/{max_attempts})")
                    elif has_actual_errors:
                        # Actual errors without heartbeat - might crash
                        error_lines = [l for l in logs.split('\n') if any(kw in l.lower() for kw in actual_error_keywords)]
                        last_error = '\n'.join(error_lines[-10:])
                        log_event(f"Bot {bot_id} has errors in logs (attempt {attempt + 1}/{max_attempts}): {last_error[:200]}")
                        # Continue checking - might recover
                    
            except Exception as e:
                # If we can't check status, log but continue checking
                log_event(f"Could not verify container status for {bot_id} (attempt {attempt + 1}/{max_attempts}): {str(e)[:200]}")
        
        # Final verification: if we didn't confirm bot started, check one more time
        if not bot_started:
            try:
                container.reload()
                if container.status == 'running':
                    logs = container.logs(stdout=True, stderr=True, tail=100).decode('utf-8', errors='ignore')
                    has_heartbeat = 'heartbeat alive' in logs or 'gravix_runner: heartbeat' in logs
                    has_blocking_detected = 'detected blocking call' in logs.lower()
                    
                    # Check for actual errors (excluding blocking call messages)
                    actual_error_keywords = ['error', 'exception', 'traceback', 'failed']
                    has_actual_errors = False
                    error_lines = []
                    for line in logs.split('\n'):
                        line_lower = line.lower()
                        # Skip blocking call and heartbeat messages
                        if 'detected blocking call' in line_lower or 'heartbeat' in line_lower:
                            continue
                        if 'gravix_runner:' in line and ('entry' in line_lower or 'waiting' in line_lower or 'autostart' in line_lower):
                            continue
                        if any(keyword in line_lower for keyword in actual_error_keywords):
                            if 'traceback' in line_lower or 'file "' in line_lower:
                                has_actual_errors = True
                                if 'gravix_runner:' not in line or 'heartbeat' not in line:
                                    error_lines.append(line.strip())
                    
                    # If heartbeat exists, bot is running - blocking call is normal
                    if has_heartbeat:
                        bot_started = True
                        log_event(f"Bot {bot_id} confirmed running in final check")
                    elif has_blocking_detected:
                        # Blocking call detected - bot is likely running, accept it
                        bot_started = True
                        log_event(f"Bot {bot_id} confirmed running with blocking call in final check")
                    else:
                        # Get error details for user
                        if has_actual_errors or not has_heartbeat:
                            if not error_lines and not has_heartbeat:
                                error_lines = ["Bot did not start successfully. No heartbeat detected. Check your code logic."]
                            
                            last_error = '\n'.join(error_lines[-15:]) if error_lines else "Bot failed to start. Check logs for details."
                else:
                    last_error = f"Container exited with status: {container.status}"
            except Exception as e:
                log_event(f"Final check failed for {bot_id}: {str(e)[:200]}")
        
        # Only return success if bot actually started
        if not bot_started:
            log_event(f"Bot {bot_id} failed to start properly after {max_attempts} attempts")
            try:
                container.remove(force=True)
            except:
                pass
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
            error_msg = last_error or "Bot did not start successfully. No heartbeat detected after multiple checks. Please verify your bot code is correct and starts properly."
            return False, None, f"Runtime Error:\n{error_msg}\n\nPlease check your code for issues and ensure your bot starts correctly."
        
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        log_event(f"Bot {bot_id} successfully started and verified!")
        return True, runtime_id, None
    except docker_errors.BuildError as e:
        error_msg = str(e)
        # Try to extract build logs from exception
        build_logs = getattr(e, 'build_log', None) if hasattr(e, 'build_log') else None
        log_event(f"Build failed for {bot_id}: {error_msg[:300]}")
        # Extract relevant error lines
        if build_logs:
            if isinstance(build_logs, list):
                error_lines = [line for line in build_logs if isinstance(line, str) and ('ERROR' in line or 'error' in line.lower() or 'failed' in line.lower())]
                detailed_error = '\n'.join(error_lines[-10:]) if error_lines else str(e)[:500]
            else:
                detailed_error = str(build_logs)[:500]
        else:
            error_lines = error_msg.split('\n')
            relevant_lines = [line for line in error_lines if 'ERROR' in line or 'error' in line.lower() or 'failed' in line.lower() or 'WARNING' in line][-5:]
            detailed_error = '\n'.join(relevant_lines) if relevant_lines else error_msg[:500]
        return False, None, f"Build Error:\n{detailed_error}\n\nPossible fixes:\n• Check your requirements.txt\n• Verify Python syntax in your code\n• Ensure all imports are correct\n• Check Dockerfile syntax"
    except docker_errors.APIError as e:
        log_event(f"Docker API error for {bot_id}: {e}")
        return False, None, f"Docker API Error:\n{str(e)[:300]}\n\nPlease try again or contact support."
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        log_event(f"Build/run failed for {bot_id}: {error_type} - {error_msg}")
        # Create user-friendly error message
        if "permission denied" in error_msg.lower():
            return False, None, "Permission Error:\nDocker permissions issue. Please contact admin."
        elif "no space left" in error_msg.lower() or "disk full" in error_msg.lower():
            return False, None, "Storage Error:\nServer storage full. Please contact admin."
        elif "network" in error_msg.lower() or "connection" in error_msg.lower():
            return False, None, f"Network Error:\n{error_msg[:200]}\n\nPlease check your internet connection and try again."
        elif "no_entry_py" in error_msg or "no_entry_py" == error_msg:
            return False, None, "Entry File Error:\nNo Python file found in your code.\n\nPlease ensure:\n• Your code has a .py file (bot.py, main.py, etc.)\n• File is not empty\n• File has valid Python syntax"
        elif "docker_unavailable" in error_msg:
            return False, None, "Docker Unavailable:\nDocker service is not available.\n\nPlease contact admin or try again later."
        else:
            return False, None, f"Error ({error_type}):\n{error_msg[:300]}\n\nPossible fixes:\n• Check your code syntax\n• Verify all dependencies in requirements.txt\n• Ensure your bot token is valid\n• Try again after a few minutes"
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)

# ---- Runtime helpers ----------------------------------------------------------

def stop_runtime(runtime_id: str) -> bool:
    try:
        client = _get_docker_client()
        if client is None:
            return False
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
        client = _get_docker_client()
        if client is None:
            return False
        client.api.restart(runtime_id)
        return True
    except Exception:
        return False

def remove_image(image_tag: str) -> bool:
    try:
        client = _get_docker_client()
        if client is None:
            return False
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
    try:
        client = _get_docker_client()
        if client is None:
            return None
        logs = client.api.logs(runtime_id, tail=tail, stdout=True, stderr=True)
        if isinstance(logs, (bytes, bytearray)):
            try:
                return logs.decode("utf-8", errors="replace")
            except Exception:
                return logs.decode("latin1", errors="replace")
        return str(logs)
    except Exception:
        return None
