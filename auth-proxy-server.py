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
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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

# ── Config Loading ───────────────────────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent.resolve() / "config.yaml"

DEFAULT_CONFIG = {
    "server": {"host": "0.0.0.0", "port": 8443},
    "api": {"auth_token": ""},
    "telegram": {"bot_token": "", "allowed_user_ids": []},
    "approval": {"mode": "telegram", "timeout": 300},
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

# ── Request Store ────────────────────────────────────────────────────────────

class PendingRequest:
    """An operation awaiting user approval."""

    def __init__(self, service: str, action: str, data: dict) -> None:
        self.id = secrets.token_urlsafe(16)
        self.service = service
        self.action = action
        self.data = data
        self.created_at = time.time()
        self.event = asyncio.Event()
        self.result: Optional[dict] = None
        self.approved: Optional[bool] = None

    @property
    def ttl(self) -> int:
        return config.get("approval", {}).get("timeout", 300)

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > self.ttl

    def approve(self) -> None:
        self.approved = True
        self.event.set()

    def deny(self) -> None:
        self.approved = False
        self.result = {"success": False, "output": "Request denied by user", "exit_code": -1, "approved": False}
        self.event.set()

    def fail_timeout(self) -> None:
        self.approved = False
        self.result = {"success": False, "output": "Approval timed out", "exit_code": -1, "approved": False}
        self.event.set()


class RequestStore:
    """Async-safe store for pending approval requests."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._requests: dict[str, PendingRequest] = {}

    async def add(self, req: PendingRequest) -> None:
        async with self._lock:
            self._requests[req.id] = req

    async def get(self, rid: str) -> Optional[PendingRequest]:
        async with self._lock:
            return self._requests.get(rid)

    async def remove(self, rid: str) -> None:
        async with self._lock:
            self._requests.pop(rid, None)

    async def reap(self) -> int:
        async with self._lock:
            now = time.time()
            dead = [r for r in self._requests.values() if r.expired and not r.event.is_set()]
            for req in dead:
                req.fail_timeout()
                del self._requests[req.id]
        return len(dead)

    @property
    async def count(self) -> int:
        async with self._lock:
            return len(self._requests)


request_store = RequestStore()

# ── Telegram ─────────────────────────────────────────────────────────────────

def _fmt_approval(req: PendingRequest) -> str:
    svc = get_service(req.service)
    if svc:
        return svc.approval_text(req.action, req.data, req.id)
    # Fallback for unknown services
    lines = [
        "🔐 *Auth Proxy — Operation*",
        f"`{req.id[:16]}…`",
        "",
        f"🛠 *Service:* `{req.service}`",
        f"📋 *Action:* `{req.action}`",
        f"\n⏱ *Expires in {req.ttl}s*",
    ]
    return "\n".join(lines)


async def send_approval(req: PendingRequest) -> None:
    tg = config.get("telegram", {})
    token = tg.get("bot_token", "")
    allowed = tg.get("allowed_user_ids", [])

    bot = Bot(token=token)
    text = _fmt_approval(req)

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Approve", callback_data=f"ap:{req.id}"),
            InlineKeyboardButton("❌ Deny", callback_data=f"de:{req.id}"),
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
    log.info("Approval %s sent to %d user(s)", req.id[:16], sent)


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

    req = await request_store.get(req_id)
    if not req or req.event.is_set():
        await _safe_edit(query, "⌛ This request has already been processed or expired.")
        return

    name = f"@{user.username}" if user and user.username else (user.first_name or "Unknown")

    if action == "ap":
        req.approve()
        await _safe_edit(query,
            text=query.message.text + f"\n\n✅ *Approved by* {name}",
            parse_mode=TGParseMode.MARKDOWN, reply_markup=None,
        )
        log.info("Request %s APPROVED by %s", req_id[:16], uid)
    else:
        req.deny()
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

async def console_approval(req: PendingRequest) -> bool:
    print("\n" + "=" * 60, flush=True)
    print("🔐 AUTH PROXY — OPERATION REQUIRES APPROVAL".center(60))
    print("=" * 60, flush=True)
    text = _fmt_approval(req).replace("*", "").replace("`", "")
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
    tg_task = asyncio.create_task(telegram_bot_main())
    yield
    log.info("Auth Proxy shutting down")
    tg_task.cancel()
    reap_task.cancel()
    try:
        await tg_task
    except (asyncio.CancelledError, Exception):
        pass
    try:
        await reap_task
    except (asyncio.CancelledError, Exception):
        pass


app = FastAPI(
    title="Auth Proxy",
    version="1.1.0",
    lifespan=lifespan,
    docs_url="/docs" if os.environ.get("AUTH_PROXY_DEBUG") else None,
    redoc_url=None,
)


# ── API Models ───────────────────────────────────────────────────────────────

class GateRequest(BaseModel):
    params: dict = {}       # Service-specific parameters
    details: str = ""       # Human-readable context for approval prompt


class GateResponse(BaseModel):
    success: bool
    output: str = ""
    exit_code: int = 0
    approved: bool = True
    request_id: str = ""
    service: str = ""
    action: str = ""


# ── Auth ─────────────────────────────────────────────────────────────────────

async def _check_auth(authorization: str | None = Header(None)) -> bool:
    if not authorization:
        return False
    expected = config.get("api", {}).get("auth_token", "")
    if not expected:
        return False
    if authorization.startswith("Bearer "):
        return authorization[7:] == expected
    return authorization == expected


# ── Shared Gate Logic ────────────────────────────────────────────────────────

async def _run_gate_flow(
    service: str,
    action: str,
    body: GateRequest,
    authorization: str | None,
) -> tuple:
    """
    Validate auth, service, params, run approval, and execute.

    Returns (svc_class, pending_req, exec_result, None) on success, or
    (None, None, None, error_response) on failure (error_response is
    either an HTTPException or a dict for JSON/binary endpoints).
    """
    # Auth
    if not await _check_auth(authorization):
        return (None, None, None, HTTPException(status_code=401, detail="Unauthorized"))

    # Service lookup
    svc = get_service(service)
    if not svc:
        return (None, None, None, HTTPException(
            status_code=404, detail=f"Unknown service: '{service}'. Available: {', '.join(list_services())}"
        ))

    # Validation
    try:
        svc.validate(action, body.params)
    except ValueError as e:
        return (None, None, None, HTTPException(status_code=400, detail=str(e)))

    # Approval mode
    approval_mode = config.get("approval", {}).get("mode", "telegram")
    tg_configured = bool(
        config.get("telegram", {}).get("bot_token", "")
        and config["telegram"]["bot_token"] != "YOUR_BOT_TOKEN_HERE"
    )
    use_telegram = approval_mode == "telegram" and tg_configured

    # Create pending request
    req_data = {**body.params, "details": body.details}
    req = PendingRequest(service, action, req_data)
    await request_store.add(req)

    # ── Send approval ───────────────────────────────────────────────────
    if use_telegram:
        try:
            await send_approval(req)
        except Exception as e:
            await request_store.remove(req.id)
            err = HTTPException(status_code=502, detail=f"Failed to send Telegram approval: {e}")
            return (None, None, None, err)
    elif approval_mode == "auto":
        log.info("Auto-approval — approving without user interaction")
        req.approve()
    elif approval_mode == "console":
        approved = await console_approval(req)
        if approved:
            req.approve()
        else:
            req.deny()
    else:
        await request_store.remove(req.id)
        err = HTTPException(status_code=500, detail=f"Unknown approval mode: {approval_mode}")
        return (None, None, None, err)

    # ── Wait for result ─────────────────────────────────────────────────
    ttl = req.ttl
    try:
        await asyncio.wait_for(req.event.wait(), timeout=ttl)
    except asyncio.TimeoutError:
        req.fail_timeout()
        await request_store.remove(req.id)
        timeout_result = {
            "success": False, "output": "Approval timed out", "exit_code": -1,
            "approved": False, "request_id": req.id, "service": service, "action": action,
        }
        return (None, None, None, timeout_result)

    if not req.approved:
        result = req.result or {"success": False, "output": "Denied", "exit_code": -1}
        await request_store.remove(req.id)
        denied_result = {
            "success": result["success"],
            "output": result.get("output", ""),
            "exit_code": result.get("exit_code", -1),
            "approved": False,
            "request_id": req.id,
            "service": service,
            "action": action,
        }
        return (None, None, None, denied_result)

    # ── Execute ─────────────────────────────────────────────────────────
    try:
        exec_result = svc.execute(action, req_data, config)
    except Exception as e:
        log.error("Service execution error: %s", e)
        exec_result = {"success": False, "output": f"Execution error: {e}", "exit_code": -1}

    await request_store.remove(req.id)
    return (svc, req, exec_result, None)


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/gate/{service}/{action}")
async def handle_gate(
    service: str,
    action: str,
    body: GateRequest,
    authorization: str | None = Header(None),
) -> GateResponse:
    """Submit a service operation for approval and execution.

    The request goes through:
      1. Validation
      2. Telegram approval (the user taps ✅ or ❌)
      3. Execution on the proxy

    Returns the execution result as JSON.
    """
    svc, req, exec_result, err = await _run_gate_flow(service, action, body, authorization)

    if err is not None:
        if isinstance(err, HTTPException):
            raise err
        # err is a dict (timeout or denied result)
        return GateResponse(
            success=err.get("success", False),
            output=err.get("output", ""),
            exit_code=err.get("exit_code", -1),
            approved=err.get("approved", False),
            request_id=err.get("request_id", ""),
            service=service,
            action=action,
        )

    return GateResponse(
        success=exec_result.get("success", False),
        output=exec_result.get("output", "").strip(),
        exit_code=exec_result.get("exit_code", -1),
        approved=True,
        request_id=req.id,
        service=service,
        action=action,
    )


@app.post("/gate/pull/{service}/{action}")
async def handle_gate_pull(
    service: str,
    action: str,
    body: GateRequest,
    authorization: str | None = Header(None),
) -> Response:
    """Binary-download variant of /gate/{service}/{action}.

    Same auth, validation, and Telegram approval flow. After execution,
    if the service returns a file path via ``_binary_file``, the file is
    streamed as application/octet-stream. Otherwise a JSON GateResponse
    is returned.
    """
    svc, req, exec_result, err = await _run_gate_flow(service, action, body, authorization)

    # Handle errors
    if err is not None:
        if isinstance(err, HTTPException):
            raise err
        # err is a dict (timeout or denied result)
        return Response(
            content=json.dumps(err),
            media_type="application/json",
            status_code=403 if err.get("approved") is False else 408,
        )

    # Check for binary file in the result
    binary_file = exec_result.pop("_binary_file", None)
    if binary_file and exec_result.get("success"):
        try:
            with open(binary_file, "rb") as f:
                content = f.read()
            os.unlink(binary_file)
            log.info("Streamed bundle %s (%d bytes) in /gate/pull response", binary_file, len(content))
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
            log.error("Failed to read/stream bundle: %s", e)
            return Response(
                content=json.dumps({
                    "success": False, "output": f"Failed to read bundle: {e}", "exit_code": -1,
                }),
                media_type="application/json",
                status_code=500,
            )

    # Normal JSON response (no binary file)
    return Response(
        content=json.dumps({
            "success": exec_result.get("success", False),
            "output": exec_result.get("output", "").strip(),
            "exit_code": exec_result.get("exit_code", -1),
            "approved": True,
            "request_id": req.id,
            "service": service,
            "action": action,
        }),
        media_type="application/json",
    )


@app.get("/health")
async def health() -> dict:
    cnt = await request_store.count
    return {
        "status": "ok",
        "version": "1.1.0",
        "pending_requests": cnt,
        "services": list_services(),
    }


# ── Reaper ───────────────────────────────────────────────────────────────────

async def _reaper_loop() -> None:
    while True:
        await asyncio.sleep(30)
        try:
            n = await request_store.reap()
            if n:
                log.info("Reaped %d expired request(s)", n)
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
