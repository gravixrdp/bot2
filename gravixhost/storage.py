import json
import os
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from .config import DB_PATH, DATA_DIR, FREE_PLAN_DURATION, RUNTIME_CPU_LIMIT, RUNTIME_MEM_LIMIT, RUNTIME_NETWORK


def _resolve_db_path() -> str:
    base_dir = DATA_DIR
    os.makedirs(base_dir, exist_ok=True)
    target = DB_PATH
    # Try to create file if missing and test writability
    try:
        if not os.path.exists(target):
            with open(target, "w") as f:
                json.dump({"users": {}, "bots": {}, "logs": [], "messages": [], "settings": {}}, f)
        else:
            with open(target, "a"):
                pass
        return target
    except Exception:
        # Fallback to XDG data home
        xdg = os.getenv("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share", "gravixhost")
        try:
            os.makedirs(xdg, exist_ok=True)
            fallback = os.path.join(xdg, "db.json")
            if not os.path.exists(fallback):
                with open(fallback, "w") as f:
                    json.dump({"users": {}, "bots": {}, "logs": [], "messages": [], "settings": {}}, f)
            return fallback
        except Exception:
            # Last resort: tmp
            tmp_dir = os.path.join(tempfile.gettempdir(), "gravixhost")
            os.makedirs(tmp_dir, exist_ok=True)
            return os.path.join(tmp_dir, "db.json")


_DB_PATH = _resolve_db_path()


def _ensure_dirs():
    os.makedirs(os.path.dirname(_DB_PATH) or DATA_DIR, exist_ok=True)
    if not os.path.exists(_DB_PATH):
        with open(_DB_PATH, "w") as f:
            json.dump({"users": {}, "bots": {}, "logs": [], "messages": [], "settings": {}}, f)


_ensure_dirs()


def _read_db() -> Dict[str, Any]:
    with open(_DB_PATH, "r") as f:
        db = json.load(f)
    db.setdefault("users", {})
    db.setdefault("bots", {})
    db.setdefault("logs", [])
    db.setdefault("messages", [])
    db.setdefault("settings", {})
    return db


def _write_db(db: Dict[str, Any]):
    # Atomic write to reduce permission/partial write issues
    dirpath = os.path.dirname(_DB_PATH) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirpath, prefix="db_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(db, f, indent=2)
        os.replace(tmp_path, _DB_PATH)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def log_event(event: str, scope: str = "user"):
    """
    Append a log entry.
    scope:
      - "admin": admin actions (not auto-cleared)
      - "user": user/system/app events (auto-cleared after 30 minutes)
    """
    db = _read_db()
    db.setdefault("logs", [])
    db["logs"].append({"time": datetime.utcnow().isoformat(), "event": event, "scope": scope})
    _write_db(db)


def log_event_admin(event: str):
    log_event(event, scope="admin")


def purge_old_logs(max_age_minutes: int = 30):
    """
    Remove logs older than max_age_minutes unless scope == 'admin'.
    Run frequently; it's idempotent and cheap.
    """
    db = _read_db()
    logs = db.get("logs", [])
    if not logs:
        return
    cutoff = datetime.utcnow() - timedelta(minutes=max_age_minutes)
    kept = []
    for entry in logs:
        try:
            t = datetime.fromisoformat(entry.get("time", ""))
        except Exception:
            t = None
        scope = entry.get("scope", "user")
        if scope == "admin":
            kept.append(entry)
        else:
            # keep if newer than cutoff
            if t and t >= cutoff:
                kept.append(entry)
    db["logs"] = kept
    _write_db(db)


def clear_admin_logs():
    """
    Remove all logs with scope == 'admin'.
    """
    db = _read_db()
    logs = db.get("logs", [])
    if not logs:
        return
    db["logs"] = [e for e in logs if e.get("scope", "user") != "admin"]
    _write_db(db)


def add_message(user_id: int, text: str):
    """
    Store a message from a user to the admin inbox.
    """
    db = _read_db()
    db.setdefault("messages", [])
    db["messages"].append(
        {
            "user_id": str(user_id),
            "text": text,
            "time": datetime.utcnow().isoformat(),
            "from_admin": False,
        }
    )
    _write_db(db)


def add_admin_reply(target_user_id: int, admin_id: int, text: str):
    """
    Store an admin reply to a user in the inbox log (for context/history).
    """
    db = _read_db()
    db.setdefault("messages", [])
    db["messages"].append(
        {
            "user_id": str(target_user_id),
            "admin_id": str(admin_id),
            "text": text,
            "time": datetime.utcnow().isoformat(),
            "from_admin": True,
        }
    )
    _write_db(db)


def get_messages(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Return the last N messages for the admin inbox.
    """
    db = _read_db()
    msgs = db.get("messages", [])
    return msgs[-limit:]


# Users

def get_user(user_id: int) -> Dict[str, Any]:
    db = _read_db()
    users = db["users"]
    user = users.get(str(user_id))
    if not user:
        user = {
            "id": user_id,
            "name": "",
            "is_premium": False,
            "premium_expiry": None,
        }
        users[str(user_id)] = user
        _write_db(db)
    return user


def update_user(user_id: int, **kwargs):
    db = _read_db()
    users = db["users"]
    user = users.get(str(user_id)) or get_user(user_id)
    user.update(kwargs)
    users[str(user_id)] = user
    _write_db(db)


def set_premium(user_id: int, days: int):
    user = get_user(user_id)
    now = datetime.utcnow()
    if user.get("premium_expiry"):
        base = datetime.fromisoformat(user["premium_expiry"])
        if base < now:
            base = now
    else:
        base = now
    expiry = base + timedelta(days=days)
    update_user(user_id, is_premium=True, premium_expiry=expiry.isoformat())
    log_event(f"Premium set for {user_id} until {expiry.isoformat()}")


def remove_premium(user_id: int):
    update_user(user_id, is_premium=False, premium_expiry=None)
    log_event(f"Premium removed for {user_id}")


def premium_expired(user_id: int) -> bool:
    user = get_user(user_id)
    expiry = user.get("premium_expiry")
    if not user.get("is_premium"):
        return True
    if not expiry:
        return True
    return datetime.utcnow() > datetime.fromisoformat(expiry)


# Bots

def add_bot(owner_id: int, name: str, token: str, path: str) -> Dict[str, Any]:
    db = _read_db()
    bots = db["bots"]
    bot_id = f"b{owner_id}-{int(datetime.utcnow().timestamp())}"
    bot = {
        "id": bot_id,
        "owner_id": owner_id,
        "name": name,
        "token": token,
        "path": path,
        "status": "stopped",  # running | stopped | error
        "runtime_id": None,
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "plan": "free",
    }
    bots[bot_id] = bot
    _write_db(db)
    log_event(f"Bot added {bot_id} for {owner_id}")
    return bot


def update_bot(bot_id: str, **kwargs):
    db = _read_db()
    bots = db["bots"]
    bot = bots.get(bot_id)
    if not bot:
        return
    bot.update(kwargs)
    bots[bot_id] = bot
    _write_db(db)


def get_bot(bot_id: str) -> Optional[Dict[str, Any]]:
    db = _read_db()
    return db["bots"].get(bot_id)


def delete_bot(bot_id: str):
    db = _read_db()
    if bot_id in db["bots"]:
        del db["bots"][bot_id]
        _write_db(db)
        log_event(f"Bot removed {bot_id}")


def get_user_bots(user_id: int) -> List[Dict[str, Any]]:
    db = _read_db()
    return [b for b in db["bots"].values() if b["owner_id"] == user_id]


def get_active_bots(user_id: int) -> List[Dict[str, Any]]:
    return [b for b in get_user_bots(user_id) if b["status"] == "running"]


def can_host_more(user_id: int) -> bool:
    user = get_user(user_id)
    if user.get("is_premium"):
        return True
    return len(get_active_bots(user_id)) == 0


def mark_started(bot_id: str, plan: str, runtime_id: str):
    update_bot(bot_id, status="running", started_at=datetime.utcnow().isoformat(), plan=plan, runtime_id=runtime_id)


def mark_stopped(bot_id: str):
    update_bot(bot_id, status="stopped", runtime_id=None)
    log_event(f"Bot stopped {bot_id}")


def has_free_time_expired(bot_id: str) -> bool:
    bot = get_bot(bot_id)
    if not bot or bot["plan"] != "free":
        return False
    started = bot.get("started_at")
    if not started:
        return False
    started_dt = datetime.fromisoformat(started)
    # Use settings override if present; default to FREE_PLAN_DURATION
    settings = get_settings()
    minutes = settings.get("free_duration_minutes")
    try:
        free_delta = timedelta(minutes=int(minutes)) if minutes is not None else FREE_PLAN_DURATION
    except Exception:
        free_delta = FREE_PLAN_DURATION
    return datetime.utcnow() > started_dt + free_delta


# Settings
def get_settings() -> Dict[str, Any]:
    """
    Return current runtime settings. Fallbacks to environment-config defaults.
    Stored keys:
      - free_duration_minutes: int (default 60)
      - restart_policy: "on" | "off" (default "on")
      - cpu_limit: str/float (default from env RUNTIME_CPU_LIMIT)
      - mem_limit: str (default from env RUNTIME_MEM_LIMIT)
      - network: str | None (default from env RUNTIME_NETWORK)
      - run_mode: "runner" | "direct" (default "runner")
    """
    db = _read_db()
    s = db.get("settings", {}) or {}
    # Defaults
    if "free_duration_minutes" not in s:
        s["free_duration_minutes"] = 60
    if "restart_policy" not in s:
        s["restart_policy"] = "on"
    if "cpu_limit" not in s:
        s["cpu_limit"] = RUNTIME_CPU_LIMIT
    if "mem_limit" not in s:
        s["mem_limit"] = RUNTIME_MEM_LIMIT
    if "network" not in s:
        s["network"] = RUNTIME_NETWORK
    if "run_mode" not in s:
        s["run_mode"] = "runner"
    db["settings"] = s
    _write_db(db)
    return s


def update_settings(**kwargs):
    db = _read_db()
    s = db.get("settings", {}) or {}
    s.update({k: v for k, v in kwargs.items() if v is not None})
    db["settings"] = s
    _write_db(db)