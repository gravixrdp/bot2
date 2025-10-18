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


def detect_framework(code: str) -> Tuple[str, str]:
    """
    Detect common Telegram bot frameworks from code and try to discover token var name.
    Returns (framework_key, token_var_name)
    """
    framework, token_var = "unknown", "TOKEN"
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

    for pattern in [
        r'([a-zA-Z_]\w*)\s*=\s*["\']([0-9]+:[a-zA-Z0-9_-]+)["\']',
        r'([a-zA-Z_]\w*)\s*=\s*os\.getenv',
    ]:
        m = re.search(pattern, code)
        if m:
            token_var = m.group(1)
            break
    return framework, token_var


def guess_requirements(framework: str) -> List[str]:
    fmap = {
        "aiogram_v2": "aiogram<3.0",
        "aiogram_v3": "aiogram>=3.0",
        "pytelegrambotapi": "pyTelegramBotAPI",
        "python-telegram-bot": "python-telegram-bot",
        "pyrogram": "pyrogram",
    }
    return [fmap[framework]] if framework in fmap else []


def detect_requirements(workspace: str) -> List[str]:
    """
    Detect dependencies by parsing Python files with AST for import statements.
    Optionally include filtered requirements from requirements.txt that match actual imports.
    """
    import_names = set()

    def collect_imports(py_path: str):
        try:
            with open(py_path, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read(), filename=py_path)
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
            # Ignore parse errors in user code
            pass

    for root, _, files in os.walk(workspace):
        for f in files:
            if f.endswith(".py"):
                collect_imports(os.path.join(root, f))

    reqs = set()
    # Map imports to PyPI names
    for base in import_names:
        norm = _normalize_requirement(base)
        if norm:
            reqs.add(norm)

    # Filter requirements.txt lines to only include things related to detected imports
    req_path = os.path.join(workspace, "requirements.txt")
    if os.path.exists(req_path):
        try:
            with open(req_path, "r") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    # Quick sanity: skip ultra-short names like "a"
                    if len(s) < 2 and "==" not in s:
                        continue
                    # Extract base name left side before any specifier
                    base = re.split(r"[<>=!~ ]", s)[0].split(".")[0]
                    # Only include if its base matches an import we saw (or explicit mapping)
                    base_mapped = _PYPI_MAP.get(base, base)
                    if (
                        base in import_names
                        or (isinstance(base_mapped, str) and base_mapped in reqs)
                        or s.lower().startswith("pytelegrambotapi")
                        or s.lower().startswith("python-telegram-bot")
                    ):  # allow explicit common packages
                        norm = _normalize_requirement(s)
                        if norm:
                            reqs.add(norm)
        except Exception:
            pass

    return sorted(reqs)


def write_runner_and_dockerfile(workspace: str, entry: Optional[str] = None, requirements: Optional[List[str]] = None):
    # Runner executes the detected entry file; token is passed via TELEGRAM_TOKEN env var
    entry_file = entry or "bot.py"

    # Python runner: injects token into globals so common patterns like BOT_TOKEN/TOKEN work
    runner_py = os.path.join(workspace, "gravix_runner.py")
    runner_code = f"""import os, runpy, sys, subprocess, threading, time, re

token = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or ''
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

# Run the user's entry file in this process
print('gravix_runner: entry={entry_file} token_len=%d' % (len(token)))
def _try_run():
    runpy.run_path('{entry_file}', init_globals=init_globals)

try:
    _try_run()
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
            _try_run()
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
    with open(runner_py, "w") as f:
        f.write(runner_code)

    # Shell runner (not used by CMD anymore; kept for compatibility)
    runner_sh = os.path.join(workspace, "gravix_runner.sh")
    with open(runner_sh, "w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("set -e\n")
        f.write('export BOT_TOKEN="${TELEGRAM_TOKEN}"\n')
        f.write("python gravix_runner.py\n")
    os.chmod(runner_sh, 0o755)

    # Write autodetected requirements file (preferred)
    req_auto_path = None
    if requirements:
        req_auto_path = os.path.join(workspace, "requirements.autodetected.txt")
        with open(req_auto_path, "w") as rf:
            rf.write("\n".join(requirements))
        # Also ensure a requirements.txt exists for user code
        req_txt_path = os.path.join(workspace, "requirements.txt")
        if not os.path.exists(req_txt_path):
            try:
                with open(req_txt_path, "w") as rtf:
                    rtf.write("\n".join(requirements))
            except Exception:
                pass

    # Decide run mode from settings
    try:
        settings = get_settings()
        run_mode = str(settings.get("run_mode", "runner")).lower()
    except Exception:
        run_mode = "runner"

    dockerfile = os.path.join(workspace, "Dockerfile")
    with open(dockerfile, "w") as f:
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
        f.write("ENV PYTHONUNBUFFERED=1\n")
        if run_mode == "direct":
            # Directly run user's entry, token is available via env (BOT_TOKEN/TOKEN/TELEGRAM_TOKEN)
            f.write(f'CMD ["python", "-u", "/app/{entry_file}"]\n')
        else:
            # Use the Python runner to ensure token injection works for simple scripts
            f.write('CMD ["python", "/app/gravix_runner.py"]\n')
    # Runner executes the detected entry file; token is passed via TELEGRAM_TOKEN env var
    entry_file = entry or "bot.py"

    # Python runner: injects token into globals so common patterns like BOT_TOKEN/TOKEN work
    runner_py = os.path.join(workspace, "gravix_runner.py")
    runner_code = f"""import os, runpy, sys, subprocess, threading, time, re

token = os.getenv('TELEGRAM_TOKEN') or os.getenv('BOT_TOKEN') or ''
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

# Run the user's entry file in this process
print('gravix_runner: entry={entry_file} token_len=%d' % (len(token)))
def _try_run():
    runpy.run_path('{entry_file}', init_globals=init_globals)

try:
    _try_run()
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
            _try_run()
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
    with open(runner_py, "w") as f:
        f.write(runner_code)

    # Shell runner (not used by CMD anymore; kept for compatibility)
    runner_sh = os.path.join(workspace, "gravix_runner.sh")
    with open(runner_sh, "w") as f:
        f.write("#!/usr/bin/env bash\\n")
        f.write("set -e\\n")
        f.write('export BOT_TOKEN="${TELEGRAM_TOKEN}"\\n')
        f.write("python gravix_runner.py\\n")
    os.chmod(runner_sh, 0o755)

    # Write autodetected requirements file (preferred)
    req_auto_path = None
    if requirements:
        req_auto_path = os.path.join(workspace, "requirements.autodetected.txt")
        with open(req_auto_path, "w") as rf:
            rf.write("\\n".join(requirements))
        # Also ensure a requirements.txt exists for user code
        req_txt_path = os.path.join(workspace, "requirements.txt")
        if not os.path.exists(req_txt_path):
            try:
                with open(req_txt_path, "w") as rtf:
                    rtf.write("\\n".join(requirements))
            except Exception:
                pass

    # Decide run mode from settings
    try:
        settings = get_settings()
        run_mode = str(settings.get("run_mode", "runner")).lower()
    except Exception:
        run_mode = "runner"

    dockerfile = os.path.join(workspace, "Dockerfile")
    with open(dockerfile, "w") as f:
        f.write("FROM python:3.11-slim\\n")
        f.write("WORKDIR /app\\n")
        f.write("COPY . /app\\n")
        # Basic system deps that frequently help builds (kept minimal)
        f.write("RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*\\n")
        f.write("RUN pip install --no-cache-dir --upgrade pip\\n")
        # Prefer installing autodetected requirements first (clean set)
        if req_auto_path:
            f.write("RUN pip install -r requirements.autodetected.txt\\n")
        # Then try user requirements if present
        f.write("RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi\\n")
        f.write("ENV PYTHONUNBUFFERED=1\\n")
        if run_mode == "direct":
            # Directly run user's entry, token is available via env (BOT_TOKEN/TOKEN/TELEGRAM_TOKEN)
            f.write(f'CMD ["python", "-u", "/app/{entry_file}"]\\n')
        else:
            # Use the Python runner to ensure token injection works for simple scripts
            f.write('CMD ["python", "/app/gravix_runner.py"]\\n')


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
    Replace previous multi-file workspace build with single-file, temp-dir based flow
    similar to the provided method: detect framework, guess minimal requirements,
    write bot.py and Dockerfile into a temp dir, build, and run.
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

    framework, token_var = detect_framework(code)
    reqs = guess_requirements(framework)

    temp_dir = None
    client = docker_from_env()
    try:
        temp_dir = tempfile.mkdtemp()
        # Write code and requirements to temp dir
        with open(os.path.join(temp_dir, "bot.py"), "w", encoding="utf-8") as f:
            f.write(code)
        with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(reqs) if reqs else "")

        # Base image selection based on framework
        base_img = AIOGRAM_V2_IMAGE if framework == "aiogram_v2" else DEFAULT_BASE_IMAGE
        dockerfile = (
            f"FROM {base_img}\n"
            "WORKDIR /app\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY bot.py .\n"
            f"ENV TOKEN={token}\n"
            f"ENV BOT_TOKEN={token}\n"
            f"ENV TELEGRAM_TOKEN={token}\n"
            f"ENV {token_var}={token}\n"
            'CMD ["python","-u","bot.py"]\n'
        )
        with open(os.path.join(temp_dir, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write(dockerfile)

        image_tag = f"hostbot_{user_id}_{bot_id}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")
        container_name = f"hostbot_{user_id}_{bot_id}_{int(time.time())}".lower().replace(" ", "_").replace("-", "_")

        # Build image
        log_event(f"Building image {image_tag} for {bot_id}")
        client.images.build(path=temp_dir, tag=image_tag, rm=True, timeout=BUILD_TIMEOUT_SECS)

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

        # Run container with simple resource limits (same-to-same style)
        container = client.containers.run(
            image_tag,
            name=container_name,
            detach=True,
            cpu_quota=DEFAULT_CPU_QUOTA,
            mem_limit=DEFAULT_MEM_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            network=network if network else None,
            restart_policy={"Name": "unless-stopped"},
        )

        runtime_id = container.id
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