"""
GitHub Service — Repository lookup, PR creation, repo creation.

Uses a GitHub Personal Access Token stored in proxy config
(services.github.token) to call the GitHub REST API.

Approval policy:
  - list-repos: auto-approved (read-only, no approval prompt)
  - create-repo: requires Telegram approval
  - create-pr: requires Telegram approval
"""

import json
import logging
import os
import time
from urllib import request as url_request
from urllib.error import HTTPError as URLHTTPError, URLError

from . import BaseService, service

log = logging.getLogger("auth-proxy.github")

API_BASE = "https://api.github.com"

# ── Helpers ──────────────────────────────────────────────────────────────────


def _token(config: dict) -> str:
    return config.get("services", {}).get("github", {}).get("token", "")


def _api_headers(config: dict) -> dict:
    token = _token(config)
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "auth-proxy/1.0",
    }


def _as_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y")
    return default


def _gh_api(method: str, path: str, headers: dict, body: dict | None = None, timeout: int = 30) -> dict:
    """Make a GitHub API request and return parsed JSON."""
    url = f"{API_BASE}{path}"
    data = json.dumps(body).encode("utf-8") if body else None

    req = url_request.Request(url, data=data, headers=headers, method=method)

    try:
        resp = url_request.urlopen(req, timeout=timeout)
        raw = resp.read().decode("utf-8")
        if raw.strip():
            return json.loads(raw)
        return {}
    except URLHTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")
        except Exception:
            pass
        raise RuntimeError(f"GitHub API error {e.code}: {e.reason}\n{detail}") from e
    except URLError as e:
        raise RuntimeError(f"GitHub API unreachable: {e.reason}") from e


# ── Service ──────────────────────────────────────────────────────────────────


@service("github")
class GitHubService(BaseService):

    valid_actions = {"list-repos", "create-repo", "create-pr"}

    # ── Validation ─────────────────────────────────────────────────────

    @classmethod
    def validate(cls, action: str, data: dict) -> None:
        if action not in cls.valid_actions:
            raise ValueError(
                f"Unsupported github action: '{action}'. "
                f"Use: {', '.join(cls.valid_actions)}"
            )

        if action == "create-repo":
            name = data.get("name", "").strip()
            if not name:
                raise ValueError("'name' is required for 'create-repo'")

        if action == "create-pr":
            if not data.get("owner", "").strip():
                raise ValueError("'owner' is required for 'create-pr'")
            if not data.get("repo", "").strip():
                raise ValueError("'repo' is required for 'create-pr'")
            if not data.get("title", "").strip():
                raise ValueError("'title' is required for 'create-pr'")
            if not data.get("head", "").strip():
                raise ValueError("'head' (source branch) is required for 'create-pr'")
            if not data.get("base", "").strip():
                raise ValueError("'base' (target branch) is required for 'create-pr'")

    # ── Auto-approval: list-repos is read-only ─────────────────────────

    @classmethod
    def requires_approval(cls, action: str) -> bool:
        return action != "list-repos"

    # ── Execute ────────────────────────────────────────────────────────

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        headers = _api_headers(config)
        token = _token(config)
        if not token:
            return {"success": False, "output": "GitHub token not configured (services.github.token)", "exit_code": -1}

        timeout = config.get("services", {}).get("github", {}).get("timeout", 30)

        if action == "list-repos":
            return cls._list_repos(headers, timeout, data)
        elif action == "create-repo":
            return cls._create_repo(data, headers, timeout)
        elif action == "create-pr":
            return cls._create_pr(data, headers, timeout)
        else:
            raise ValueError(f"Unsupported action: {action}")

    # ── list-repos ─────────────────────────────────────────────────────

    @classmethod
    def _list_repos(cls, headers: dict, timeout: int, data: dict) -> dict:
        """List repositories visible to the token. Optionally filter by name."""
        filter_name = data.get("filter", "").strip().lower()
        per_page = min(int(data.get("per_page", 100)), 100)
        page = int(data.get("page", 1))

        try:
            # Try authenticated user's repos
            result = _gh_api("GET", f"/user/repos?per_page={per_page}&page={page}&sort=updated&direction=desc",
                             headers, timeout=timeout)
        except RuntimeError as e:
            return {"success": False, "output": str(e), "exit_code": -1}

        if isinstance(result, list):
            repos = result
        elif isinstance(result, dict) and "message" in result:
            return {"success": False, "output": result["message"], "exit_code": -1}
        else:
            return {"success": False, "output": f"Unexpected response: {str(result)[:500]}", "exit_code": -1}

        # Format output
        lines = []
        for r in repos:
            rname = r.get("full_name", r.get("name", "?"))
            desc = r.get("description", "") or ""
            private = "🔒" if r.get("private") else "🌐"
            fork = " 🍴" if r.get("fork") else ""
            archived = " 🗄" if r.get("archived") else ""

            if filter_name and filter_name not in rname.lower():
                continue

            line = f"{private} {rname}{fork}{archived}"
            if desc:
                line += f"\n   {desc}"
            lines.append(line)

        if filter_name and not lines:
            lines.append(f"No repos found matching '{filter_name}'")

        output = "\n\n".join(lines) if lines else "No repositories found."

        # Also return structured data for programmatic use
        structured = []
        for r in repos:
            name = r.get("full_name", r.get("name", ""))
            if filter_name and filter_name not in name.lower():
                continue
            structured.append({
                "name": r.get("full_name", r.get("name", "")),
                "ssh_url": r.get("ssh_url", ""),
                "clone_url": r.get("clone_url", ""),
                "private": r.get("private", False),
                "description": r.get("description", ""),
                "html_url": r.get("html_url", ""),
                "default_branch": r.get("default_branch", ""),
                "fork": r.get("fork", False),
                "archived": r.get("archived", False),
                "language": r.get("language", ""),
                "updated_at": r.get("updated_at", ""),
            })

        return {
            "success": True,
            "output": output,
            "exit_code": 0,
            "repos": structured,
            "count": len(structured),
        }

    # ── create-repo ────────────────────────────────────────────────────

    @classmethod
    def _create_repo(cls, data: dict, headers: dict, timeout: int) -> dict:
        name = data.get("name", "").strip()
        private = _as_bool(data.get("private"), default=True)
        description = data.get("description", "").strip()
        auto_init = _as_bool(data.get("auto_init"), default=False)

        body = {
            "name": name,
            "private": private,
            "auto_init": auto_init,
        }
        if description:
            body["description"] = description

        try:
            result = _gh_api("POST", "/user/repos", headers, body, timeout)
        except RuntimeError as e:
            return {"success": False, "output": str(e), "exit_code": -1}

        if isinstance(result, dict) and result.get("id"):
            html_url = result.get("html_url", "")
            ssh_url = result.get("ssh_url", "")
            return {
                "success": True,
                "output": f"Repository created!\n   {html_url}\n   SSH: {ssh_url}",
                "exit_code": 0,
                "html_url": html_url,
                "ssh_url": ssh_url,
                "name": result.get("full_name", name),
            }
        elif isinstance(result, dict) and "message" in result:
            return {"success": False, "output": f"GitHub error: {result['message']}", "exit_code": -1}
        else:
            return {"success": False, "output": f"Unexpected response: {str(result)[:500]}", "exit_code": -1}

    # ── create-pr ──────────────────────────────────────────────────────

    @classmethod
    def _create_pr(cls, data: dict, headers: dict, timeout: int) -> dict:
        owner = data.get("owner", "").strip()
        repo = data.get("repo", "").strip()
        title = data.get("title", "").strip()
        head = data.get("head", "").strip()
        base = data.get("base", "").strip()
        body_text = data.get("body", "").strip()

        payload = {
            "title": title,
            "head": head,
            "base": base,
        }
        if body_text:
            payload["body"] = body_text

        try:
            result = _gh_api("POST", f"/repos/{owner}/{repo}/pulls", headers, payload, timeout)
        except RuntimeError as e:
            return {"success": False, "output": str(e), "exit_code": -1}

        if isinstance(result, dict) and result.get("number"):
            html_url = result.get("html_url", "")
            pr_number = result.get("number", "")
            return {
                "success": True,
                "output": f"PR #{pr_number} created!\n   {html_url}",
                "exit_code": 0,
                "pr_number": pr_number,
                "html_url": html_url,
                "title": title,
            }
        elif isinstance(result, dict) and "message" in result:
            return {"success": False, "output": f"GitHub error: {result['message']}", "exit_code": -1}
        else:
            return {"success": False, "output": f"Unexpected response: {str(result)[:500]}", "exit_code": -1}

    # ── Approval text ──────────────────────────────────────────────────

    @classmethod
    def approval_text(cls, action: str, data: dict, request_id: str) -> str:
        if action == "create-repo":
            lines = [
                "🔐 *Auth Proxy — Create GitHub Repository*",
                f"`{request_id[:16]}…`",
                "",
                f"📋 *Action:* `create-repo`",
                f"📦 *Name:* `{data.get('name', '?')}`",
                f"🔒 *Visibility:* {'Private' if _as_bool(data.get('private'), default=True) else 'Public'}",
            ]
            if data.get("description"):
                lines.append(f"📝 *Description:* {data['description']}")
            if data.get("details"):
                lines.append(f"\n📎 *Details:*\n{data['details']}")
            return "\n".join(lines)

        elif action == "create-pr":
            lines = [
                "🔐 *Auth Proxy — Create Pull Request*",
                f"`{request_id[:16]}…`",
                "",
                f"📋 *Action:* `create-pr`",
                f"📦 *Repo:* `{data.get('owner', '?')}/{data.get('repo', '?')}`",
                f"🌿 *Head:* `{data.get('head', '?')}` → `{data.get('base', '?')}`",
                f"📰 *Title:* {data.get('title', '?')}",
            ]
            if data.get("body"):
                body_preview = data["body"][:200]
                if len(data["body"]) > 200:
                    body_preview += "…"
                lines.append(f"📄 *Body:*\n{body_preview}")
            if data.get("details"):
                lines.append(f"\n📎 *Details:*\n{data['details']}")
            return "\n".join(lines)

        return "\n".join([
            "🔐 *Auth Proxy — GitHub Operation*",
            f"`{request_id[:16]}…`",
            "",
            f"📋 *Action:* `{action}`",
        ])
