#!/usr/bin/env python3
"""
Auth Proxy Client — Generic client for the Auth Proxy gate.

Holds no credentials. Sends operations to the proxy, which holds all
service keys and requires Telegram approval before execution.

Usage as CLI:
    python auth-proxy-client.py gate git push \\
        --param repo=git@github.com:user/repo.git \\
        --param workdir=/path \\
        --param branch=main \\
        --details "Auto-generated feature"

    python auth-proxy-client.py gate git clone \\
        --param repo=git@github.com:user/repo.git \\
        --param target-dir=/path

    python auth-proxy-client.py health

Usage as library:
    from auth_proxy_client import AuthProxyClient

    proxy = AuthProxyClient(proxy_url="http://auth-proxy.lxc:8443", auth_token="secret")

    # Git
    result = proxy.git_push(repo="git@github.com:user/repo.git", workdir="/path", branch="main")
    result = proxy.git_clone(repo="git@github.com:user/repo.git", target_dir="/path")
    result = proxy.git_fetch(repo="git@github.com:user/repo.git", workdir="/path")
    result = proxy.git_pull(repo="git@github.com:user/repo.git", workdir="/path")

    # Future: Google Calendar
    # result = proxy.calendar_create(...)
    # result = proxy.calendar_list(...)

    print(proxy.health())
"""

import argparse
import json
import os
import sys
from typing import Optional
from urllib import request as url_request
from urllib.error import URLError


class AuthProxyError(Exception):
    """Raised when the proxy returns an error."""


class AuthProxyClient:
    """Generic client for the Auth Proxy Server.

    Args:
        proxy_url: Base URL (e.g. http://auth-proxy.lxc:8443).
        auth_token: Shared API auth token.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        proxy_url: str = "http://localhost:8443",
        auth_token: str = "",
        timeout: int = 600,
    ) -> None:
        self.proxy_url = proxy_url.rstrip("/")
        self.auth_token = auth_token or os.environ.get("AUTH_PROXY_TOKEN", "")
        self.timeout = timeout

    def _gate(self, service: str, action: str, params: dict, details: str = "") -> dict:
        """Low-level: send a gated operation to the proxy."""
        url = f"{self.proxy_url}/gate/{service}/{action}"
        body = json.dumps({"params": params, "details": details}).encode("utf-8")

        req = url_request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.auth_token}",
            },
            method="POST",
        )

        try:
            resp = url_request.urlopen(req, timeout=self.timeout)
            return json.loads(resp.read().decode("utf-8"))
        except url_request.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8")
            except Exception:
                pass
            raise AuthProxyError(f"Proxy returned HTTP {e.code}: {e.reason}\n{detail}") from e
        except URLError as e:
            raise AuthProxyError(f"Cannot reach proxy at {url}: {e.reason}") from e

    # ── Git service ─────────────────────────────────────────────────────

    def git_push(
        self, repo: str, workdir: str, branch: str = "",
        refspec: str = "", details: str = "",
    ) -> dict:
        return self._gate("git", "push", {
            "repo": repo, "workdir": workdir, "branch": branch, "refspec": refspec,
        }, details)

    def git_clone(
        self, repo: str, target_dir: str = "",
        branch: str = "", details: str = "",
    ) -> dict:
        return self._gate("git", "clone", {
            "repo": repo, "target_dir": target_dir, "branch": branch,
        }, details)

    def git_fetch(
        self, repo: str, workdir: str, branch: str = "", details: str = "",
    ) -> dict:
        return self._gate("git", "fetch", {
            "repo": repo, "workdir": workdir, "branch": branch,
        }, details)

    def git_pull(
        self, repo: str, workdir: str, branch: str = "", details: str = "",
    ) -> dict:
        return self._gate("git", "pull", {
            "repo": repo, "workdir": workdir, "branch": branch,
        }, details)

    # ── Generic gate ────────────────────────────────────────────────────

    def gate(self, service: str, action: str, params: dict, details: str = "") -> dict:
        """Send an arbitrary gated operation. Use when no convenience method exists."""
        return self._gate(service, action, params, details)

    # ── Health ──────────────────────────────────────────────────────────

    def health(self) -> dict:
        try:
            resp = url_request.urlopen(f"{self.proxy_url}/health", timeout=10)
            return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"status": "error", "error": str(e)}


# ── CLI ──────────────────────────────────────────────────────────────────────

def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Auth Proxy Client — send gated operations through the approval proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--proxy-url",
        default=os.environ.get("AUTH_PROXY_URL", "http://localhost:8443"),
        help="Proxy URL (env: AUTH_PROXY_URL, default: http://localhost:8443)",
    )
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("AUTH_PROXY_TOKEN", ""),
        help="API auth token (env: AUTH_PROXY_TOKEN)",
    )
    parser.add_argument("--timeout", type=int, default=600, help="Request timeout (default: 600s)")

    sub = parser.add_subparsers(dest="command", required=True)

    # gate
    p_gate = sub.add_parser("gate", help="Submit a gated operation")
    p_gate.add_argument("service", help="Service name (e.g. git)")
    p_gate.add_argument("action", help="Action name (e.g. push, clone)")
    p_gate.add_argument("--param", "-p", action="append", default=[],
                        help="Key=value parameter (can be repeated)")
    p_gate.add_argument("--details", "-d", default="", help="Human-readable context")

    # health
    sub.add_parser("health", help="Check proxy health")

    args = parser.parse_args()

    client = AuthProxyClient(
        proxy_url=args.proxy_url,
        auth_token=args.auth_token,
        timeout=args.timeout,
    )

    if args.command == "gate":
        params = {}
        for p in args.param:
            if "=" not in p:
                print(f"ERROR: --param must be key=value, got: {p}", file=sys.stderr)
                sys.exit(1)
            key, val = p.split("=", 1)
            params[key] = val

        try:
            result = client.gate(args.service, args.action, params, args.details)
        except AuthProxyError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "health":
        result = client.health()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("status") == "ok" else 1)


if __name__ == "__main__":
    cli()
