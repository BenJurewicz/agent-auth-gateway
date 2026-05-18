#!/usr/bin/env python3
"""
Auth Proxy Server — Generalized credential gate with Telegram approval.

Sits in a Proxmox LXC container, holds all service credentials (SSH keys,
API tokens, etc.), and requires explicit Telegram approval before executing
any privileged operation.

Endpoints:
  POST /gate/{service}/{action}      — JSON response (for text-based operations)
  POST /gate/pull/{service}/{action} — Binary stream response (for bundle downloads)
  GET  /health                       — Health check

Services may skip Telegram approval for specific actions (e.g. read-only
lookups) by overriding ``requires_approval(action) -> bool``.

Extensible via service plugins in services/*.py.

Usage:
    python auth-proxy-server.py

Env overrides:
    AUTH_PROXY_TOKEN      API auth token (takes precedence over config.yaml)
    AUTH_PROXY_TELEGRAM   Telegram bot token (takes precedence over config.yaml)
"""

import asyncio
import json
import logging
import os
import secrets
import shutil
import sqlite3
import sys
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException, Header, Request, Response
from pydantic import BaseModel
import uvicorn

try:
    from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.error import BadRequest as TelegramBadRequest
    from telegram.ext import Application, CallbackQueryHandler, ContextTypes
    from telegram.constants import ParseMode as TGParseMode
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    class TelegramBadRequest(Exception):
        pass
    class TGParseMode:
        MARKDOWN = "Markdown"

from services import get_service, list_services

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("auth-proxy")

APP_VERSION = "1.4.0"

# ── Config Loading ───────────────────────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent.resolve() / "config.yaml"

DEFAULT_CONFIG = {
    "server": {"host": "0.0.0.0", "port": 8443},
    "api": {"auth_token": ""},
    "telegram": {"bot_token": "", "allowed_user_ids": []},
    "approval": {"mode": "telegram", "timeout": 300, "request_ttl": 14400, "running_timeout": 3600, "db_path": ""},
    "services": {},
}


def load_config() -> dict:
    defaults = {k: dict(v) for k, v in DEFAULT_CONFIG.items()}

    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}
        log.warning("No config.yaml found — using defaults + env vars")

    merged = {}
    for key in defaults:
        merged[key] = {**defaults[key], **(cfg.get(key) or {})}

    # Env overrides
    env_token = os.environ.get("AUTH_PROXY_TOKEN", "")
    if env_token:
        merged["api"]["auth_token"] = env_token

    env_bot = os.environ.get("AUTH_PROXY_TELEGRAM", "")
    if env_bot:
        merged["telegram"]["bot_token"] = env_bot

    if not merged["api"]["auth_token"]:
        log.error("No API auth token set! Set AUTH_PROXY_TOKEN env or add to config.yaml")

    return merged


config = load_config()

# ── Durable Request Store ───────────────────────────────────────────────────

TERMINAL_STATUSES = {"succeeded", "failed", "denied", "expired", "cancelled"}


def _now() -> float:
    return time.time()


def _approval_timeout() -> int:
    return int(config.get("approval", {}).get("timeout", 300))


def _request_ttl() -> int:
    return int(config.get("approval", {}).get("request_ttl", 14400))


def _running_timeout() -> int:
    return int(config.get("approval", {}).get("running_timeout", 3600))


def _db_path() -> Path:
    configured = config.get("approval", {}).get("db_path", "")
    if configured:
        return Path(os.path.expanduser(configured))
    return Path(__file__).parent.resolve() / "auth-proxy-requests.sqlite3"


def _artifact_dir() -> Path:
    path = Path(__file__).parent.resolve() / "request-artifacts"
    path.mkdir(parents=True, exist_ok=True)
    return path


class RequestStore:
    """SQLite-backed approval/execution queue.

    HTTP requests are short-lived. Approval requests are durable and can be
    approved hours later, then executed by the background worker.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._events: dict[str, asyncio.Event] = {}
        self._init_db()

    @contextmanager
    def _connect(self):
        con = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def _init_db(self) -> None:
        with self._lock, self._connect() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    action TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    result_json TEXT,
                    artifact_path TEXT,
                    approved_by TEXT,
                    approved_at REAL
                )
            """)
            con.execute("CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_requests_expires ON requests(expires_at)")

    def _row_to_dict(self, row: sqlite3.Row | None) -> Optional[dict]:
        if row is None:
            return None
        d = dict(row)
        d["data"] = json.loads(d.pop("data_json") or "{}")
        result_raw = d.pop("result_json", None)
        d["result"] = json.loads(result_raw) if result_raw else None
        d["expired"] = d["status"] not in TERMINAL_STATUSES and _now() > d["expires_at"]
        return d

    def create(self, service: str, action: str, data: dict, *, status: str = "pending") -> dict:
        req_id = secrets.token_urlsafe(16)
        now = _now()
        expires_at = now + _request_ttl()
        with self._lock, self._connect() as con:
            con.execute(
                """INSERT INTO requests
                   (id, service, action, data_json, status, created_at, updated_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (req_id, service, action, json.dumps(data), status, now, now, expires_at),
            )
        return self.get(req_id) or {"id": req_id, "service": service, "action": action, "status": status}

    def get(self, req_id: str) -> Optional[dict]:
        with self._lock, self._connect() as con:
            row = con.execute("SELECT * FROM requests WHERE id = ?", (req_id,)).fetchone()
        return self._row_to_dict(row)

    def list(self, status: str = "", limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 200))
        with self._lock, self._connect() as con:
            if status:
                rows = con.execute(
                    "SELECT * FROM requests WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM requests ORDER BY created_at DESC LIMIT ?", (limit,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_pending(self) -> int:
        with self._lock, self._connect() as con:
            row = con.execute(
                "SELECT COUNT(*) AS n FROM requests WHERE status IN ('pending', 'approved', 'running')"
            ).fetchone()
        return int(row["n"])

    def _notify(self, req_id: str) -> None:
        # Events are one-shot broadcasts. Remove after set so terminal/non-terminal
        # transitions do not leak memory and waiters create a fresh event if needed.
        ev = self._events.pop(req_id, None)
        if ev and not ev.is_set():
            ev.set()

    def event_for(self, req_id: str) -> asyncio.Event:
        ev = self._events.get(req_id)
        if ev is None:
            ev = asyncio.Event()
            self._events[req_id] = ev
        return ev

    def approve(self, req_id: str, approved_by: str = "") -> bool:
        now = _now()
        with self._lock, self._connect() as con:
            cur = con.execute(
                """UPDATE requests
                   SET status = 'approved', approved_by = ?, approved_at = ?, updated_at = ?
                   WHERE id = ? AND status = 'pending' AND expires_at > ?""",
                (approved_by, now, now, req_id, now),
            )
            ok = cur.rowcount == 1
        if ok:
            self._notify(req_id)
        return ok

    def deny(self, req_id: str, approved_by: str = "") -> bool:
        result = {"success": False, "output": "Request denied by user", "exit_code": -1, "approved": False}
        return self.finish(req_id, "denied", result, approved_by=approved_by)

    def cancel(self, req_id: str, reason: str = "Request cancelled") -> bool:
        result = {"success": False, "output": reason, "exit_code": -1, "approved": False}
        now = _now()
        with self._lock, self._connect() as con:
            cur = con.execute(
                """UPDATE requests SET status = 'cancelled', result_json = ?, updated_at = ?
                   WHERE id = ? AND status IN ('pending', 'approved', 'running')""",
                (json.dumps(result), now, req_id),
            )
            ok = cur.rowcount == 1
        if ok:
            self._notify(req_id)
        return ok

    def expire_stale(self) -> int:
        now = _now()
        expired_result = {"success": False, "output": "Approval expired", "exit_code": -1, "approved": False}
        failed_result = {"success": False, "output": "Running request timed out", "exit_code": -1, "approved": True}
        running_cutoff = now - _running_timeout()
        with self._lock, self._connect() as con:
            expired_rows = con.execute(
                "SELECT id FROM requests WHERE status IN ('pending', 'approved') AND expires_at <= ?",
                (now,),
            ).fetchall()
            running_rows = con.execute(
                "SELECT id FROM requests WHERE status = 'running' AND updated_at <= ?",
                (running_cutoff,),
            ).fetchall()
            con.execute(
                """UPDATE requests SET status = 'expired', result_json = ?, updated_at = ?
                   WHERE status IN ('pending', 'approved') AND expires_at <= ?""",
                (json.dumps(expired_result), now, now),
            )
            con.execute(
                """UPDATE requests SET status = 'failed', result_json = ?, updated_at = ?
                   WHERE status = 'running' AND updated_at <= ?""",
                (json.dumps(failed_result), now, running_cutoff),
            )
        rows = [*expired_rows, *running_rows]
        for r in rows:
            self._notify(r["id"])
        return len(rows)

    def claim_next_approved(self) -> Optional[dict]:
        now = _now()
        with self._lock, self._connect() as con:
            row = con.execute(
                """SELECT * FROM requests
                   WHERE status = 'approved' AND expires_at > ?
                   ORDER BY approved_at ASC, created_at ASC LIMIT 1""",
                (now,),
            ).fetchone()
            if not row:
                return None
            cur = con.execute(
                "UPDATE requests SET status = 'running', updated_at = ? WHERE id = ? AND status = 'approved'",
                (now, row["id"]),
            )
            if cur.rowcount != 1:
                return None
        self._notify(row["id"])
        return self.get(row["id"])

    def finish(self, req_id: str, status: str, result: dict, *, artifact_path: str = "", approved_by: str = "") -> bool:
        now = _now()
        with self._lock, self._connect() as con:
            cur = con.execute(
                """UPDATE requests
                   SET status = ?, result_json = ?, artifact_path = COALESCE(NULLIF(?, ''), artifact_path),
                       approved_by = COALESCE(NULLIF(?, ''), approved_by), updated_at = ?
                   WHERE id = ? AND status NOT IN ('succeeded', 'failed', 'denied', 'expired', 'cancelled')""",
                (status, json.dumps(result), artifact_path, approved_by, now, req_id),
            )
            ok = cur.rowcount == 1
        if ok:
            self._notify(req_id)
        return ok

    def clear_artifact(self, req_id: str) -> Optional[str]:
        now = _now()
        with self._lock, self._connect() as con:
            row = con.execute("SELECT artifact_path FROM requests WHERE id = ?", (req_id,)).fetchone()
            path = row["artifact_path"] if row else None
            if path:
                con.execute("UPDATE requests SET artifact_path = '', updated_at = ? WHERE id = ?", (now, req_id))
        return path

    def cleanup_artifacts(self, older_than: float) -> int:
        with self._lock, self._connect() as con:
            rows = con.execute(
                """SELECT id, artifact_path FROM requests
                   WHERE artifact_path IS NOT NULL AND artifact_path != '' AND updated_at <= ?""",
                (older_than,),
            ).fetchall()
            con.executemany(
                "UPDATE requests SET artifact_path = '', updated_at = ? WHERE id = ?",
                [(_now(), r["id"]) for r in rows],
            )
        removed = 0
        for r in rows:
            try:
                os.unlink(r["artifact_path"])
                removed += 1
            except FileNotFoundError:
                pass
            except OSError as e:
                log.warning("Artifact cleanup failed for %s: %s", r["artifact_path"], e)
        return removed

    async def wait_terminal(self, req_id: str, timeout: int) -> dict:
        deadline = _now() + timeout
        while True:
            req = self.get(req_id)
            if not req:
                return {"status": "missing", "result": {"success": False, "output": "Request not found", "exit_code": -1}}
            if req["status"] in TERMINAL_STATUSES:
                return req
            remaining = deadline - _now()
            if remaining <= 0:
                return req
            ev = self.event_for(req_id)
            try:
                await asyncio.wait_for(ev.wait(), timeout=min(remaining, 5))
            except asyncio.TimeoutError:
                pass


request_store = RequestStore(_db_path())


class ApprovalRequestView:
    """Small adapter used only for service approval_text rendering."""
    def __init__(self, row: dict) -> None:
        self.id = row["id"]
        self.service = row["service"]
        self.action = row["action"]
        self.data = row["data"]
        self.created_at = row["created_at"]

    @property
    def ttl(self) -> int:
        return max(0, int(self.created_at + _request_ttl() - _now()))


# ── Telegram ─────────────────────────────────────────────────────────────────

def _fmt_approval(req: ApprovalRequestView) -> str:
    svc = get_service(req.service)
    if svc:
        return svc.approval_text(req.action, req.data, req.id)
    lines = [
        "🔐 *Auth Proxy — Operation*",
        f"`{req.id[:16]}…`",
        "",
        f"🛠 *Service:* `{req.service}`",
        f"📋 *Action:* `{req.action}`",
        f"\n⏱ *Expires in {req.ttl}s*",
    ]
    return "\n".join(lines)


async def send_approval(row: dict) -> None:
    tg = config.get("telegram", {})
    token = tg.get("bot_token", "")
    allowed = tg.get("allowed_user_ids", [])

    bot = Bot(token=token)
    view = ApprovalRequestView(row)
    text = _fmt_approval(view)

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Approve", callback_data=f"ap:{view.id}"),
            InlineKeyboardButton("❌ Deny", callback_data=f"de:{view.id}"),
        ]
    ])

    sent = 0
    for uid in allowed:
        try:
            await bot.send_message(
                chat_id=uid, text=text, reply_markup=keyboard,
                parse_mode=TGParseMode.MARKDOWN,
            )
            sent += 1
        except Exception as e:
            log.error("Telegram send to %s failed: %s", uid, e)

    if sent == 0:
        raise RuntimeError(
            "Could not deliver Telegram approval message to any user. "
            "Check 'allowed_user_ids' and 'bot_token' in config."
        )
    log.info("Approval %s sent to %d user(s)", view.id[:16], sent)


async def _safe_edit(query, text: str, **kwargs) -> None:
    """Edit message text, silently ignoring duplicate edits."""
    try:
        await query.edit_message_text(text=text, **kwargs)
    except TelegramBadRequest:
        pass


async def handle_tg_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if not query.data:
        return

    try:
        action, req_id = query.data.split(":", 1)
    except ValueError:
        return

    user = update.effective_user
    uid = user.id if user else None
    allowed = config.get("telegram", {}).get("allowed_user_ids", [])

    if allowed and uid not in allowed:
        await _safe_edit(query, "⛔ You are not authorized to approve requests.")
        return

    req = request_store.get(req_id)
    if not req or req["status"] != "pending" or req.get("expired"):
        await _safe_edit(query, "⌛ This request has already been processed or expired.")
        return

    name = f"@{user.username}" if user and user.username else ((user.first_name if user else None) or "Unknown")

    if action == "ap":
        ok = request_store.approve(req_id, approved_by=str(uid or ""))
        if not ok:
            await _safe_edit(query, "⌛ This request has already been processed or expired.")
            return
        await _safe_edit(query,
            text=query.message.text + f"\n\n✅ *Approved by* {name}\n⏳ Queued for execution.",
            parse_mode=TGParseMode.MARKDOWN, reply_markup=None,
        )
        log.info("Request %s APPROVED by %s", req_id[:16], uid)
    else:
        ok = request_store.deny(req_id, approved_by=str(uid or ""))
        if not ok:
            await _safe_edit(query, "⌛ This request has already been processed or expired.")
            return
        await _safe_edit(query,
            text=query.message.text + f"\n\n❌ *Denied by* {name}",
            parse_mode=TGParseMode.MARKDOWN, reply_markup=None,
        )
        log.info("Request %s DENIED by %s", req_id[:16], uid)


async def telegram_bot_main() -> None:
    tg = config.get("telegram", {})
    token = tg.get("bot_token", "")

    if not token or token == "YOUR_BOT_TOKEN_HERE":
        log.info("Telegram bot not configured — approval mode will fall back")
        return

    if not TELEGRAM_AVAILABLE:
        log.error("python-telegram-bot not installed.")
        return

    app = Application.builder().token(token).build()
    app.add_handler(CallbackQueryHandler(handle_tg_callback))

    log.info("Starting Telegram bot polling...")
    await app.initialize()
    await app.start()
    await app.updater.start_polling()

    while True:
        await asyncio.sleep(3600)


# ── Console Approval ─────────────────────────────────────────────────────────

async def console_approval(row: dict) -> bool:
    print("\n" + "=" * 60, flush=True)
    print("🔐 AUTH PROXY — OPERATION REQUIRES APPROVAL".center(60))
    print("=" * 60, flush=True)
    text = _fmt_approval(ApprovalRequestView(row)).replace("*", "").replace("`", "")
    print(text)
    print("-" * 60, flush=True)
    print("Approve? [y/N]: ", end="", flush=True)
    answer = await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)
    return answer.strip().lower() in ("y", "yes", "approve")


# ── FastAPI ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("Auth Proxy starting — services: %s", ", ".join(list_services()))
    reap_task = asyncio.create_task(_reaper_loop())
    worker_task = asyncio.create_task(_worker_loop())
    tg_task = asyncio.create_task(telegram_bot_main())
    yield
    log.info("Auth Proxy shutting down")
    for task in (tg_task, worker_task, reap_task):
        task.cancel()
    for task in (tg_task, worker_task, reap_task):
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass


app = FastAPI(
    title="Auth Proxy",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if os.environ.get("AUTH_PROXY_DEBUG") else None,
    redoc_url=None,
)


# ── API Models ───────────────────────────────────────────────────────────────

class GateRequest(BaseModel):
    params: dict = {}       # Service-specific parameters
    details: str = ""       # Human-readable context for approval prompt
    async_request: bool = False  # Return after enqueue instead of waiting for execution


class GateResponse(BaseModel):
    success: bool
    output: str = ""
    exit_code: int = 0
    approved: bool = True
    request_id: str = ""
    service: str = ""
    action: str = ""
    status: str = ""


def _public_request(row: dict) -> dict:
    svc = get_service(row["service"])
    raw_data = dict(row.get("data") or {})
    data = svc.redact_request_data(row["action"], raw_data) if svc else raw_data
    return {
        "id": row["id"],
        "service": row["service"],
        "action": row["action"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "expires_at": row["expires_at"],
        "approved_by": row.get("approved_by"),
        "approved_at": row.get("approved_at"),
        "expired": row.get("expired", False),
        "data": data,
        "result": row.get("result"),
        "has_artifact": bool(row.get("artifact_path")),
    }


def _gate_response_payload(
    result: dict,
    *,
    approved: bool,
    request_id: str,
    service: str,
    action: str,
    status: str = "",
) -> dict:
    payload = dict(result)
    output = payload.get("output", "")
    if isinstance(output, str):
        output = output.strip()

    payload.update({
        "success": payload.get("success", False),
        "output": output,
        "exit_code": payload.get("exit_code", -1),
        "approved": approved,
        "request_id": request_id,
        "service": service,
        "action": action,
        "status": status or payload.get("status", ""),
    })
    return payload


def _queued_payload(row: dict) -> dict:
    return {
        "success": True,
        "output": f"Request queued: {row['id']}",
        "exit_code": 0,
        "approved": False,
        "request_id": row["id"],
        "service": row["service"],
        "action": row["action"],
        "status": row["status"],
        "expires_at": row["expires_at"],
    }


# ── Auth ─────────────────────────────────────────────────────────────────────

async def _check_auth(authorization: str | None = Header(None)) -> bool:
    if not authorization:
        return False
    expected = config.get("api", {}).get("auth_token", "")
    if not expected:
        return False
    if authorization.startswith("Bearer "):
        return secrets.compare_digest(authorization[7:], expected)
    return secrets.compare_digest(authorization, expected)


async def _require_auth(authorization: str | None = Header(None)) -> None:
    if not await _check_auth(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── Shared Gate Logic ────────────────────────────────────────────────────────

async def _submit_request(service: str, action: str, body: GateRequest, authorization: str | None) -> tuple:
    if not await _check_auth(authorization):
        return (None, None, HTTPException(status_code=401, detail="Unauthorized"))

    svc = get_service(service)
    if not svc:
        return (None, None, HTTPException(
            status_code=404, detail=f"Unknown service: '{service}'. Available: {', '.join(list_services())}"
        ))

    try:
        svc.validate(action, body.params)
    except ValueError as e:
        return (None, None, HTTPException(status_code=400, detail=str(e)))

    req_data = {**body.params, "details": body.details}
    needs_approval = svc.requires_approval(action)
    row = request_store.create(service, action, req_data, status="pending" if needs_approval else "approved")

    approval_mode = config.get("approval", {}).get("mode", "telegram")
    tg_configured = bool(
        config.get("telegram", {}).get("bot_token", "")
        and config["telegram"]["bot_token"] != "YOUR_BOT_TOKEN_HERE"
    )
    use_telegram = approval_mode == "telegram" and tg_configured

    if not needs_approval:
        log.info("Action %s/%s does not require approval — queued directly", service, action)
    elif use_telegram:
        try:
            await send_approval(row)
        except Exception as e:
            request_store.cancel(row["id"], reason=f"Failed to send Telegram approval: {e}")
            return (None, None, HTTPException(status_code=502, detail=f"Failed to send Telegram approval: {e}"))
    elif approval_mode == "auto":
        log.info("Auto-approval — approving without user interaction")
        request_store.approve(row["id"], approved_by="auto")
    elif approval_mode == "console":
        approved = await console_approval(row)
        if approved:
            request_store.approve(row["id"], approved_by="console")
        else:
            request_store.deny(row["id"], approved_by="console")
    else:
        request_store.cancel(row["id"], reason=f"Unknown approval mode: {approval_mode}")
        return (None, None, HTTPException(status_code=500, detail=f"Unknown approval mode: {approval_mode}"))

    return (svc, request_store.get(row["id"]), None)


async def _run_gate_flow(service: str, action: str, body: GateRequest, authorization: str | None) -> tuple:
    svc, row, err = await _submit_request(service, action, body, authorization)
    if err is not None:
        return (None, None, None, err)

    if body.async_request:
        return (svc, row, _queued_payload(row), None)

    final = await request_store.wait_terminal(row["id"], _approval_timeout())
    if final["status"] not in TERMINAL_STATUSES:
        return (None, None, None, {
            "success": False,
            "output": "Request is still pending/running; use request-status to check later",
            "exit_code": -1,
            "approved": False,
            "request_id": row["id"],
            "service": service,
            "action": action,
            "status": final["status"],
        })

    result = final.get("result") or {"success": False, "output": final["status"], "exit_code": -1}
    approved = final["status"] not in {"denied", "expired", "cancelled"}
    return (svc, final, result, None)


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/gate/{service}/{action}")
async def handle_gate(
    service: str,
    action: str,
    body: GateRequest,
    authorization: str | None = Header(None),
) -> dict:
    """Submit a service operation. Use ``async_request`` to enqueue only."""
    svc, req, exec_result, err = await _run_gate_flow(service, action, body, authorization)

    if err is not None:
        if isinstance(err, HTTPException):
            raise err
        return _gate_response_payload(
            err,
            approved=err.get("approved", False),
            request_id=err.get("request_id", ""),
            service=service,
            action=action,
            status=err.get("status", ""),
        )

    approved = req["status"] not in {"pending", "denied", "expired", "cancelled"}
    return _gate_response_payload(
        exec_result,
        approved=approved,
        request_id=req["id"],
        service=service,
        action=action,
        status=req["status"],
    )


@app.post("/gate/pull/{service}/{action}")
async def handle_gate_pull(
    service: str,
    action: str,
    body: GateRequest,
    authorization: str | None = Header(None),
) -> Response:
    """Binary-download variant of /gate/{service}/{action}.

    Async pull requests return JSON with a request id. Blocking pull requests
    stream the artifact once the background worker has produced it.
    """
    svc, req, exec_result, err = await _run_gate_flow(service, action, body, authorization)

    if err is not None:
        if isinstance(err, HTTPException):
            raise err
        return Response(
            content=json.dumps(err),
            media_type="application/json",
            status_code=202 if err.get("status") in {"pending", "approved", "running"} else 403,
        )

    if body.async_request:
        return Response(content=json.dumps(exec_result), media_type="application/json", status_code=202)

    response_result = dict(exec_result)
    artifact_path = req.get("artifact_path")
    binary_file = response_result.pop("_binary_file", None) or artifact_path
    if binary_file and exec_result.get("success"):
        try:
            with open(binary_file, "rb") as f:
                content = f.read()
            try:
                os.unlink(binary_file)
            except OSError:
                pass
            log.info("Streamed artifact %s (%d bytes) in /gate/pull response", binary_file, len(content))
            return Response(
                content=content,
                media_type="application/octet-stream",
                headers={
                    "Content-Disposition": "attachment; filename=repo.bundle",
                    "Content-Length": str(len(content)),
                    "X-Repo-Url": body.params.get("repo", ""),
                },
            )
        except Exception as e:
            log.error("Failed to read/stream artifact: %s", e)
            return Response(
                content=json.dumps({"success": False, "output": f"Failed to read artifact: {e}", "exit_code": -1}),
                media_type="application/json",
                status_code=500,
            )

    return Response(
        content=json.dumps(_gate_response_payload(
            response_result,
            approved=req["status"] not in {"pending", "denied", "expired", "cancelled"},
            request_id=req["id"],
            service=service,
            action=action,
            status=req["status"],
        )),
        media_type="application/json",
    )


@app.get("/requests")
async def list_requests(
    status: str = "",
    limit: int = 50,
    authorization: str | None = Header(None),
) -> dict:
    await _require_auth(authorization)
    rows = request_store.list(status=status, limit=limit)
    return {"success": True, "requests": [_public_request(r) for r in rows], "count": len(rows)}


@app.get("/requests/{request_id}")
async def request_status(request_id: str, authorization: str | None = Header(None)) -> dict:
    await _require_auth(authorization)
    row = request_store.get(request_id)
    if not row:
        raise HTTPException(status_code=404, detail="Request not found")
    return {"success": True, "request": _public_request(row)}


@app.get("/requests/{request_id}/artifact")
async def request_artifact(request_id: str, authorization: str | None = Header(None)) -> Response:
    await _require_auth(authorization)
    row = request_store.get(request_id)
    if not row:
        raise HTTPException(status_code=404, detail="Request not found")
    path = row.get("artifact_path")
    if not path:
        raise HTTPException(status_code=404, detail="Request has no artifact")
    try:
        with open(path, "rb") as f:
            content = f.read()
    except OSError as e:
        request_store.clear_artifact(request_id)
        raise HTTPException(status_code=404, detail=f"Artifact unavailable: {e}") from e
    cleared_path = request_store.clear_artifact(request_id)
    if cleared_path:
        try:
            os.unlink(cleared_path)
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning("Failed to remove downloaded artifact %s: %s", cleared_path, e)
    return Response(content=content, media_type="application/octet-stream")


@app.post("/requests/{request_id}/cancel")
async def cancel_request(request_id: str, authorization: str | None = Header(None)) -> dict:
    await _require_auth(authorization)
    ok = request_store.cancel(request_id)
    if not ok:
        raise HTTPException(status_code=409, detail="Request cannot be cancelled")
    return {"success": True, "request_id": request_id, "status": "cancelled"}


@app.post("/requests/expire-stale")
async def expire_stale_requests(authorization: str | None = Header(None)) -> dict:
    await _require_auth(authorization)
    n = request_store.expire_stale()
    return {"success": True, "expired": n}


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": APP_VERSION,
        "pending_requests": request_store.count_pending(),
        "request_ttl": _request_ttl(),
        "approval_timeout": _approval_timeout(),
        "running_timeout": _running_timeout(),
        "services": list_services(),
    }


# ── Worker/Reaper ────────────────────────────────────────────────────────────

def _execute_request_sync(row: dict) -> tuple[dict, str]:
    svc = get_service(row["service"])
    if not svc:
        return ({"success": False, "output": f"Unknown service: {row['service']}", "exit_code": -1}, "")
    try:
        result = svc.execute(row["action"], row["data"], config)
    except Exception as e:
        log.exception("Service execution error for %s", row["id"][:16])
        result = {"success": False, "output": f"Execution error: {e}", "exit_code": -1}

    artifact_path = ""
    source_artifact = result.pop("_binary_file", None)
    if source_artifact:
        dest = _artifact_dir() / f"{row['id']}.artifact"
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(source_artifact, dest)
            artifact_path = str(dest)
        except Exception as e:
            log.error("Failed to preserve artifact for %s: %s", row["id"][:16], e)
            result = {"success": False, "output": f"Failed to preserve artifact: {e}", "exit_code": -1}
    return result, artifact_path


async def _worker_loop() -> None:
    while True:
        try:
            row = request_store.claim_next_approved()
            if not row:
                await asyncio.sleep(1)
                continue
            log.info("Executing approved request %s %s/%s", row["id"][:16], row["service"], row["action"])
            result, artifact_path = await asyncio.to_thread(_execute_request_sync, row)
            status = "succeeded" if result.get("success") else "failed"
            request_store.finish(row["id"], status, result, artifact_path=artifact_path)
            log.info("Request %s finished: %s", row["id"][:16], status)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning("Worker error: %s", e)
            await asyncio.sleep(2)


async def _reaper_loop() -> None:
    while True:
        await asyncio.sleep(30)
        try:
            n = request_store.expire_stale()
            if n:
                log.info("Expired/failed %d stale request(s)", n)
            cleaned = request_store.cleanup_artifacts(_now() - _request_ttl())
            if cleaned:
                log.info("Cleaned %d stale artifact(s)", cleaned)
        except Exception as e:
            log.warning("Reaper error: %s", e)


# ── Entry Point ──────────────────────────────────────────────────────────────

def main() -> None:
    svr = config.get("server", {})
    host = svr.get("host", "0.0.0.0")
    port = int(svr.get("port", 8443))

    log.info("Listening on %s:%d", host, port)
    log.info("Registered services: %s", ", ".join(list_services()))

    if not config.get("api", {}).get("auth_token"):
        log.warning("⚠  No API auth token set! Set AUTH_PROXY_TOKEN env.")

    uvicorn.run(
        "auth-proxy-server:app",
        host=host, port=port,
        log_level="info", reload=False,
    )


if __name__ == "__main__":
    main()
