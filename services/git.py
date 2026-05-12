"""
Git Service — GitHub operations via SSH key.

Holds the user's SSH private key on the proxy. Every git operation
(push, clone, fetch, pull) requires Telegram approval.

Supports git bundle transport for proxying repo data to/from the client:
  - fetch-bundle: Clone/fetch repo to bare cache, create a .bundle file of
    branch contents that the client can download and git-clone/git-fetch from.
  - push-bundle: Accept a base64-encoded bundle from the client, apply it to
    the bare cache, and push to origin.
"""

import base64
import hashlib
import logging
import os
import secrets
import subprocess
import tempfile
import time

from . import BaseService, service

log = logging.getLogger("auth-proxy.git")

# Character blacklist for shell injection prevention
_FORBIDDEN = set(";&|$`(){}<>\n\r")

# Base cache directory for bare repos
CACHE_BASE = "/tmp/auth-gate-cache"


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


def _cache_dir_for(repo: str) -> str:
    """Deterministic bare-cache path for a repo URL."""
    h = hashlib.sha256(repo.encode()).hexdigest()[:16]
    return os.path.join(CACHE_BASE, h)


def _ensure_cache(repo: str, config: dict) -> str:
    """Ensure a bare clone exists in the cache, update it, return its path."""
    cache_dir = _cache_dir_for(repo)
    env = _ssh_env(config)
    timeout = _timeout(config)

    if os.path.isdir(cache_dir):
        # Update existing cache
        log.info("Updating cache %s …", cache_dir)
        try:
            subprocess.run(
                "git fetch origin",
                shell=True, cwd=cache_dir, env=env,
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("Cache fetch timed out — continuing with stale cache")
        except Exception as e:
            log.warning("Cache fetch error (continuing): %s", e)
    else:
        # Full bare clone
        os.makedirs(CACHE_BASE, exist_ok=True)
        log.info("Cloning bare cache %s …", cache_dir)
        try:
            subprocess.run(
                f"git clone --bare {repo} {cache_dir}",
                shell=True, env=env,
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Initial clone timed out after {timeout}s")

    return cache_dir


def _git_in_cache(cache_dir: str, *args: str, env: dict, timeout: int) -> subprocess.CompletedProcess:
    """Run a git command inside the bare cache directory."""
    cmd = "git " + " ".join(args)
    return subprocess.run(
        cmd, shell=True, cwd=cache_dir, env=env,
        capture_output=True, text=True, timeout=timeout,
    )


@service("git")
class GitService(BaseService):

    valid_actions = {"fetch-bundle", "push-bundle"}

    @classmethod
    def validate(cls, action: str, data: dict) -> None:
        if action not in cls.valid_actions:
            raise ValueError(
                f"Unsupported git action: '{action}'. "
                f"Use: {', '.join(cls.valid_actions)}"
            )

        repo = _sanitize(data.get("repo", ""))
        if not repo:
            raise ValueError("'repo' is required")
        if not repo.startswith("git@") and not repo.startswith("ssh://"):
            raise ValueError("Only SSH git URLs are allowed (git@ or ssh://)")

        if action == "fetch-bundle":
            branch = _sanitize(data.get("branch", ""))
            if not branch:
                raise ValueError("'branch' is required for 'fetch-bundle'")

        if action == "push-bundle":
            if not data.get("bundle_b64", ""):
                raise ValueError("'bundle_b64' is required for 'push-bundle'")

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        env = _ssh_env(config)
        timeout = _timeout(config)

        if action == "fetch-bundle":
            return cls._fetch_bundle(data, config, env, timeout)
        elif action == "push-bundle":
            return cls._push_bundle(data, config, env, timeout)
        else:
            raise ValueError(f"Unsupported git action: '{action}'")

    # ── Bundle: clone/fetch via bundle ─────────────────────────────────────

    @classmethod
    def _fetch_bundle(cls, data: dict, config: dict, env: dict, timeout: int) -> dict:
        """
        Create a git bundle that the client can use to clone or fetch.

        Maintains a bare cache of the repo on the gateway. On first call
        the cache is created via git clone --bare. Subsequent calls do a
        lightweight git fetch origin.

        The bundle contains only the delta from known_ref (if provided and
        valid), or a full snapshot if not.
        """
        repo = _sanitize(data.get("repo", ""))
        branch = _sanitize(data.get("branch", "main"))
        known_ref = _sanitize(data.get("known_ref", ""))

        # 1. Ensure the bare cache exists and is up to date
        try:
            cache_dir = _ensure_cache(repo, config)
        except Exception as e:
            return {"success": False, "output": f"Failed to prepare cache: {e}", "exit_code": -1}

        # 2. Determine what to put in the bundle
        ref_spec = f"origin/{branch}"
        bundle_ref = f"refs/heads/{branch}"

        use_delta = bool(known_ref)
        if use_delta:
            # Verify known_ref exists in the cache
            check = subprocess.run(
                ["git", "cat-file", "-e", known_ref],
                cwd=cache_dir, capture_output=True, timeout=10,
            )
            if check.returncode != 0:
                log.warning("known_ref %s not found in cache — falling back to full bundle", known_ref)
                use_delta = False

        # 3. Create the bundle
        bundle_id = secrets.token_hex(8)
        bundle_path = os.path.join(tempfile.gettempdir(), f"gate-bundle-{bundle_id}.bundle")

        try:
            if use_delta:
                cmd = f"git bundle create {bundle_path} {ref_spec} --not {known_ref}"
            else:
                cmd = f"git bundle create {bundle_path} --all"

            log.info("Creating bundle %s (delta=%s)", bundle_id, use_delta)
            result = subprocess.run(
                cmd, shell=True, cwd=cache_dir, env=env,
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                err = (result.stderr or "") + (result.stdout or "")
                return {"success": False, "output": f"Bundle creation failed: {err}", "exit_code": result.returncode}

            size = os.path.getsize(bundle_path)
            log.info("Bundle %s created: %d bytes", bundle_id, size)
        except Exception as e:
            return {"success": False, "output": f"Bundle creation error: {e}", "exit_code": -1}

        return {
            "success": True,
            "output": f"Bundle created: {size} bytes",
            "exit_code": 0,
            "_binary_file": bundle_path,
        }

    # ── Bundle: push via bundle ────────────────────────────────────────────

    @classmethod
    def _push_bundle(cls, data: dict, config: dict, env: dict, timeout: int) -> dict:
        """
        Accept a base64-encoded git bundle from the client, apply it to
        the bare cache, and push to origin.

        The client creates the bundle locally with:
            git bundle create changes.bundle HEAD --not refs/remotes/origin/<branch>
        """
        repo = _sanitize(data.get("repo", ""))
        branch = _sanitize(data.get("branch", "main"))
        b64 = data.get("bundle_b64", "")

        # 1. Decode bundle
        try:
            bundle_bytes = base64.b64decode(b64)
        except Exception as e:
            return {"success": False, "output": f"Failed to decode bundle: {e}", "exit_code": -1}

        bundle_path = os.path.join(
            tempfile.gettempdir(),
            f"gate-push-{secrets.token_hex(8)}.bundle",
        )
        try:
            with open(bundle_path, "wb") as f:
                f.write(bundle_bytes)
        except Exception as e:
            return {"success": False, "output": f"Failed to write bundle: {e}", "exit_code": -1}

        try:
            # 2. Ensure cache exists and is up to date
            cache_dir = _ensure_cache(repo, config)

            # 3. Fetch the bundle contents into the cache
            #    The bundle contains refs/heads/<branch> with the client's commits
            log.info("Applying push bundle for %s/%s", repo, branch)
            fetch_result = subprocess.run(
                f"git fetch {bundle_path} refs/heads/{branch}:refs/heads/{branch}",
                shell=True, cwd=cache_dir, env=env,
                capture_output=True, text=True, timeout=timeout,
            )
            if fetch_result.returncode != 0:
                err = (fetch_result.stderr or "") + (fetch_result.stdout or "")
                return {
                    "success": False,
                    "output": f"Failed to apply bundle to cache: {err}",
                    "exit_code": fetch_result.returncode,
                }

            # 4. Push to origin
            log.info("Pushing %s/%s to origin", repo, branch)
            push_result = subprocess.run(
                f"git push origin {branch}:{branch}",
                shell=True, cwd=cache_dir, env=env,
                capture_output=True, text=True, timeout=timeout,
            )
            output = (push_result.stdout or "") + (push_result.stderr or "")
            log.info("Push result: exit=%d", push_result.returncode)

            return {
                "success": push_result.returncode == 0,
                "output": output,
                "exit_code": push_result.returncode,
            }
        except Exception as e:
            return {"success": False, "output": str(e), "exit_code": -1}
        finally:
            # Clean up the received bundle
            try:
                os.unlink(bundle_path)
            except OSError:
                pass

    # ── Approval text ──────────────────────────────────────────────────────

    @classmethod
    def approval_text(cls, action: str, data: dict, request_id: str) -> str:
        if action == "fetch-bundle":
            lines = [
                "🔐 *Auth Proxy — Git Fetch Bundle*",
                f"`{request_id[:16]}…`",
                "",
                f"📋 *Action:* `{action}`",
                f"📦 *Repo:* `{data.get('repo')}`",
            ]
            if data.get("branch"):
                lines.append(f"🌿 *Branch:* `{data['branch']}`")
            if data.get("known_ref"):
                lines.append(f"🔖 *Known ref:* `{data['known_ref'][:12]}…`")
            if data.get("details"):
                lines.append(f"\n📝 *Details:*\n{data['details']}")
            return "\n".join(lines)

        elif action == "push-bundle":
            lines = [
                "🔐 *Auth Proxy — Git Push Bundle*",
                f"`{request_id[:16]}…`",
                "",
                f"📋 *Action:* `push changes`",
                f"📦 *Repo:* `{data.get('repo')}`",
            ]
            if data.get("branch"):
                lines.append(f"🌿 *Branch:* `{data['branch']}`")
            if data.get("details"):
                lines.append(f"\n📝 *Details:*\n{data['details']}")
            return "\n".join(lines)

        # Fallback for legacy actions
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
        return "\n".join(lines)
