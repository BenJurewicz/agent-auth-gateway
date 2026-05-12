"""
Git Service — GitHub operations via SSH key.

Holds the user's SSH private key on the proxy. Every git operation
(push, clone, fetch, pull) requires Telegram approval.
"""

import logging
import os
import subprocess

from . import BaseService, service

log = logging.getLogger("auth-proxy.git")

# Character blacklist for shell injection prevention
_FORBIDDEN = set(";&|$`(){}<>\n\r")


def _sanitize(val: str) -> str:
    """Strip forbidden chars from a git parameter."""
    if not isinstance(val, str):
        return ""
    if any(c in val for c in _FORBIDDEN):
        raise ValueError(f"Invalid characters in parameter")
    return val.strip()


def _ssh_env(config: dict) -> dict:
    """Build environment dict with GIT_SSH_COMMAND set."""
    key_path = os.path.expanduser(
        config.get("services", {})
        .get("git", {})
        .get("ssh_key_path", "~/.ssh/id_ed25519")
    )
    ssh_cmd = (
        f"ssh -i {key_path} "
        f"-o StrictHostKeyChecking=accept-new "
        f"-o PasswordAuthentication=no "
        f"-o IdentitiesOnly=yes"
    )
    env = os.environ.copy()
    env["GIT_SSH_COMMAND"] = ssh_cmd
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _timeout(config: dict) -> int:
    return config.get("services", {}).get("git", {}).get("timeout", 120)


@service("git")
class GitService(BaseService):

    valid_actions = {"push", "clone", "fetch", "pull"}

    @classmethod
    def validate(cls, action: str, data: dict) -> None:
        if action not in cls.valid_actions:
            raise ValueError(f"Unsupported git action: '{action}'. Use: {', '.join(cls.valid_actions)}")

        repo = _sanitize(data.get("repo", ""))
        if not repo:
            raise ValueError("'repo' is required")
        if not repo.startswith("git@") and not repo.startswith("ssh://"):
            raise ValueError("Only SSH git URLs are allowed (git@ or ssh://)")

        if action != "clone":
            workdir = _sanitize(data.get("workdir", ""))
            if not workdir:
                raise ValueError(f"'workdir' is required for '{action}'")
            if not os.path.isdir(workdir):
                raise ValueError(f"Workdir does not exist: {workdir}")

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        """Run a git command and return the result."""
        env = _ssh_env(config)
        timeout = _timeout(config)

        repo = _sanitize(data.get("repo", ""))
        branch = _sanitize(data.get("branch", ""))
        refspec = _sanitize(data.get("refspec", ""))

        if action == "clone":
            target_dir = _sanitize(data.get("target_dir", "") or data.get("target-dir", ""))
            cmd = f"git clone --progress {repo}"
            if branch:
                cmd += f" --branch {branch}"
            if target_dir:
                cmd += f" {target_dir}"
            workdir = "."  # git clone creates the target dir itself
        else:
            workdir = _sanitize(data.get("workdir", ""))
            if action == "push":
                cmd = "git push origin"
                if branch:
                    cmd += f" {branch}"
                if refspec:
                    cmd += f" {refspec}"
            elif action == "fetch":
                cmd = "git fetch origin"
                if branch:
                    cmd += f" {branch}"
            elif action == "pull":
                cmd = "git pull origin"
                if branch:
                    cmd += f" {branch}"
            else:
                raise ValueError(f"Unsupported git action: '{action}'")

        log.info("→ git %s  (workdir=%s)", action, workdir)

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=workdir,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            log.info("← exit=%d  stdout=%dB  stderr=%dB",
                     result.returncode, len(result.stdout or ""), len(result.stderr or ""))
            return {
                "success": result.returncode == 0,
                "output": (result.stdout or "") + "\n" + (result.stderr or ""),
                "exit_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            log.warning("Git command timed out after %ds", timeout)
            return {"success": False, "output": f"TIMEOUT after {timeout}s", "exit_code": -1}
        except Exception as e:
            log.error("Git execution error: %s", e)
            return {"success": False, "output": str(e), "exit_code": -1}

    @classmethod
    def approval_text(cls, action: str, data: dict, request_id: str) -> str:
        lines = [
            "🔐 *Auth Proxy — Git Operation*",
            f"`{request_id[:16]}…`",
            "",
            f"📋 *Action:* `{action}`",
            f"📦 *Repo:* `{data.get('repo')}`",
        ]
        if data.get("branch"):
            lines.append(f"🌿 *Branch:* `{data['branch']}`")
        if data.get("refspec"):
            lines.append(f"📎 *Refspec:* `{data['refspec']}`")
        if data.get("target_dir"):
            lines.append(f"📁 *Target:* `{data['target_dir']}`")
        if data.get("workdir"):
            lines.append(f"📁 *Workdir:* `{data['workdir']}`")
        if data.get("details"):
            lines.append(f"\n📝 *Details:*\n{data['details']}")

        ctx = cls.context(action, data)
        if ctx:
            lines.append(f"\n📊 *Context:*\n```\n{ctx}\n```")

        return "\n".join(lines)

    @classmethod
    def context(cls, action: str, data: dict) -> str:
        """Gather local git context for richer approval messages."""
        workdir = data.get("workdir", "")
        if not workdir or not os.path.isdir(workdir):
            return ""

        def _sh(cmd: str) -> str:
            try:
                r = subprocess.run(cmd, shell=True, cwd=workdir,
                                   capture_output=True, text=True, timeout=5)
                return r.stdout.strip() if r.returncode == 0 else ""
            except Exception:
                return ""

        parts = []
        branch = _sh("git rev-parse --abbrev-ref HEAD 2>/dev/null")
        if branch:
            parts.append(f"Branch: {branch}")
        url = _sh("git remote get-url origin 2>/dev/null")
        if url:
            parts.append(f"Remote: {url}")
        logs = _sh("git log --oneline -5 2>/dev/null")
        if logs:
            parts.append(f"Recent:\n{logs}")
        ahead = _sh("git log --oneline @{u}..HEAD 2>/dev/null")
        if ahead:
            parts.append(f"Ahead of remote:\n{ahead}")
        stats = _sh("git diff --stat 2>/dev/null | tail -1")
        if stats:
            parts.append(f"Uncommitted: {stats}")

        return "\n".join(parts)
