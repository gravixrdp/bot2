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
