import asyncio
from datetime import timedelta
from typing import Callable

from ..storage import (
    get_bot,
    get_user_bots,
    has_free_time_expired,
    premium_expired,
    mark_stopped,
    update_user,
    get_user,
    purge_old_logs,
)
from .hoster import stop_runtime
from ..config import FREE_PLAN_DURATION


class Scheduler:
    def __init__(self, on_timeout_notify: Callable[[int, str], None]):
        # on_timeout_notify(user_id, bot_id)
        self.on_timeout_notify = on_timeout_notify
        self._task = None

    async def start(self):
        self._task = asyncio.create_task(self._loop())

    async def _loop(self):
        while True:
            try:
                # Periodic user-log cleanup (keeps admin logs)
                purge_old_logs(max_age_minutes=30)
                # Check free bots for timeout
                await self._check_free_timeouts()
                # Check premium expiry daily
                await self._check_premium_expiry()
            except Exception:
                # Silent protection; logs handled in storage layer
                pass
            await asyncio.sleep(30)  # frequent checks

    async def _check_free_timeouts(self):
        # For all users and bots
        for user_id_bots in self._all_user_ids():
            for bot in get_user_bots(user_id_bots):
                if bot["status"] == "running" and has_free_time_expired(bot["id"]):
                    rid = bot.get("runtime_id")
                    if rid:
                        stop_runtime(rid)
                    mark_stopped(bot["id"])
                    self.on_timeout_notify(bot["owner_id"], bot["id"])

    async def _check_premium_expiry(self):
        for user_id in self._all_user_ids():
            user = get_user(user_id)
            if user.get("is_premium") and premium_expired(user_id):
                # Downgrade and stop their bots
                update_user(user_id, is_premium=False, premium_expiry=None)
                for bot in get_user_bots(user_id):
                    if bot["status"] == "running":
                        rid = bot.get("runtime_id")
                        if rid:
                            stop_runtime(rid)
                        mark_stopped(bot["id"])

    def _all_user_ids(self):
        # Read from storage db
        from ..storage import _read_db
        db = _read_db()
        return [int(uid) for uid in db["users"].keys()]