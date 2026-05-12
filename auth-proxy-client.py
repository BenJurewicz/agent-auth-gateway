#!/usr/bin/env python3
"""
Auth Proxy Client — Generic client for the Auth Proxy gate.

Holds no credentials. Sends operations to the proxy, which holds all
service keys and requires Telegram approval before execution.

Usage as CLI:
    # Legacy: operations execute on the proxy
    python auth-proxy-client.py gate git push --param repo=... --param workdir=... --details "..."
    python auth-proxy-client.py gate git clone --param repo=... --param target-dir=...

    # Bundle transport: clone/fetch repos to the client machine
    python auth-proxy-client.py pull git fetch-bundle \\
        --param repo=git@github.com:user/repo.git \\
        --param target-dir=/home/agent/projects/repo \\
        --param branch=main \\
        --details "Clone my repo"

    python auth-proxy-client.py gate git push-bundle \\
        --param repo=git@github.com:user/repo.git \\
        --param workdir=/home/agent/projects/repo \\
        --param branch=main \\
        --details "Pushing my changes"

    python auth-proxy-client.py health

Usage as library:
    from auth_proxy_client import AuthProxyClient

    proxy = AuthProxyClient(proxy_url="http://auth-proxy.lxc:8443", auth_token="secret")

    # Bundle transport (clone/fetch to this machine)
    proxy.git_fetch_bundle(repo="git@github.com:user/repo.git", target_dir="/path",
                           branch="main")

    # Bundle transport (push from this machine through gateway)
    proxy.git_push_bundle(repo="git@github.com:user/repo.git", workdir="/path",
                          branch="main", details="My update")

    # Legacy proxy-executed ops
    result = proxy.git_push(repo="git@github.com:user/repo.git", workdir="/path", branch="main")
    result = proxy.git_clone(repo="git@github.com:user/repo.git", target_dir="/path")

    print(proxy.health())
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
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
                    Used as a hard timeout for the entire request across approval + execution.
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
        """Low-level: send a gated operation to the proxy (JSON endpoint)."""
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

    def _gate_pull(self, service: str, action: str, params: dict, details: str = "") -> bytes:
        """Low-level: send a gated operation to the binary-download endpoint.

        Returns the raw bytes of the response body.
        """
        url = f"{self.proxy_url}/gate/pull/{service}/{action}"
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
            return resp.read()
        except url_request.HTTPError as e:
            # Try to parse JSON error body
            detail = ""
            try:
                detail = e.read().decode("utf-8")
            except Exception:
                pass
            raise AuthProxyError(f"Proxy returned HTTP {e.code}: {e.reason}\n{detail}") from e
        except URLError as e:
            raise AuthProxyError(f"Cannot reach proxy at {url}: {e.reason}") from e

    # ── Git service: Bundle transport (clone/fetch to this machine) ──────

    def git_fetch_bundle(
        self,
        repo: str,
        target_dir: str,
        branch: str = "main",
        known_ref: str = "",
        details: str = "",
    ) -> dict:
        """Clone or fetch a repo through the gateway via bundle transport.

        If *target_dir* does not exist, a full clone is performed.
        If *target_dir* exists and is a git repo, the bundle is applied
        as an incremental fetch.

        Args:
            repo: SSH git URL (e.g. git@github.com:user/repo.git).
            target_dir: Local directory to clone/fetch into.
            branch: Branch to track (default: main).
            known_ref: Commit SHA that the client already has (empty = full clone).
                       Automatically detected if target_dir exists.
            details: Human-readable context for the approval prompt.

        Returns:
            Dict with keys: success, output, exit_code, target_dir
        """
        # Auto-detect known_ref from existing repo
        if not known_ref and os.path.isdir(os.path.join(target_dir, ".git")):
            try:
                result = subprocess.run(
                    ["git", "rev-parse", f"refs/remotes/origin/{branch}"],
                    cwd=target_dir, capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    known_ref = result.stdout.strip()
            except Exception:
                pass

        if not known_ref and os.path.isdir(os.path.join(target_dir, ".git")):
            try:
                result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=target_dir, capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    known_ref = result.stdout.strip()
            except Exception:
                pass

        params = {
            "repo": repo,
            "branch": branch,
        }
        if known_ref:
            params["known_ref"] = known_ref

        is_initial = not os.path.isdir(os.path.join(target_dir, ".git"))

        # Download the bundle
        try:
            bundle_bytes = self._gate_pull("git", "fetch-bundle", params, details)
        except AuthProxyError as e:
            return {"success": False, "output": str(e), "exit_code": -1, "target_dir": target_dir}

        if len(bundle_bytes) == 0:
            return {"success": False, "output": "Empty bundle received from gateway", "exit_code": -1, "target_dir": target_dir}

        # Save bundle to temp file
        fd, bundle_path = tempfile.mkstemp(suffix=".bundle", prefix="claw-bundle-")
        os.close(fd)
        try:
            with open(bundle_path, "wb") as f:
                f.write(bundle_bytes)

            if is_initial:
                # First time: git clone from bundle
                os.makedirs(os.path.dirname(target_dir), exist_ok=True)

                clone_result = subprocess.run(
                    ["git", "clone", bundle_path, target_dir],
                    capture_output=True, text=True, timeout=self.timeout,
                )
                if clone_result.returncode != 0:
                    return {
                        "success": False,
                        "output": f"git clone from bundle failed:\n{clone_result.stderr}",
                        "exit_code": clone_result.returncode,
                        "target_dir": target_dir,
                    }

                # Save the bundle's tip SHA before removing the bundle remote
                bundle_tip = subprocess.run(
                    ["git", "rev-parse", f"refs/remotes/origin/{branch}"],
                    cwd=target_dir, capture_output=True, text=True, timeout=10,
                )
                tip_sha = bundle_tip.stdout.strip() if bundle_tip.returncode == 0 else ""

                # Remove the bundle-based origin entirely, add the real GitHub URL
                subprocess.run(
                    ["git", "remote", "remove", "origin"],
                    cwd=target_dir, capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["git", "remote", "add", "origin", repo],
                    cwd=target_dir, capture_output=True, timeout=10,
                )

                # Restore the tracking ref under the new origin
                if tip_sha:
                    subprocess.run(
                        ["git", "update-ref", f"refs/remotes/origin/{branch}", tip_sha],
                        cwd=target_dir, capture_output=True, timeout=10,
                    )

                return {
                    "success": True,
                    "output": f"Cloned into {target_dir} ({len(bundle_bytes)} bytes via bundle)",
                    "exit_code": 0,
                    "target_dir": target_dir,
                }
            else:
                # Incremental: git fetch from bundle
                fetch_result = subprocess.run(
                    ["git", "fetch", bundle_path, f"refs/heads/{branch}:refs/remotes/origin/{branch}"],
                    cwd=target_dir, capture_output=True, text=True, timeout=self.timeout,
                )
                if fetch_result.returncode != 0:
                    return {
                        "success": False,
                        "output": f"git fetch from bundle failed:\n{fetch_result.stderr}",
                        "exit_code": fetch_result.returncode,
                        "target_dir": target_dir,
                    }

                # Merge the fetched branch
                merge_result = subprocess.run(
                    ["git", "merge", f"origin/{branch}"],
                    cwd=target_dir, capture_output=True, text=True, timeout=self.timeout,
                )
                output = (fetch_result.stdout or "") + "\n" + (merge_result.stdout or "")
                if merge_result.stderr:
                    output += "\n" + merge_result.stderr

                return {
                    "success": True,
                    "output": output.strip(),
                    "exit_code": 0,
                    "target_dir": target_dir,
                }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": f"Local git operation timed out", "exit_code": -1, "target_dir": target_dir}
        except Exception as e:
            return {"success": False, "output": str(e), "exit_code": -1, "target_dir": target_dir}
        finally:
            try:
                os.unlink(bundle_path)
            except OSError:
                pass

    # ── Git service: Bundle transport (push from this machine) ───────────

    def git_push_bundle(
        self,
        repo: str,
        workdir: str,
        branch: str = "main",
        details: str = "",
    ) -> dict:
        """Push local commits through the gateway via bundle transport.

        Creates a git bundle of new commits (HEAD --not origin/<branch>)
        and sends it to the gateway, which applies it and pushes to origin.

        Args:
            repo: SSH git URL (e.g. git@github.com:user/repo.git).
            workdir: Local repo directory containing the new commits.
            branch: Branch to push (default: main).
            details: Human-readable context for the approval prompt.

        Returns:
            Dict with keys: success, output, exit_code
        """
        if not os.path.isdir(workdir):
            return {"success": False, "output": f"Workdir does not exist: {workdir}", "exit_code": -1}
        if not os.path.isdir(os.path.join(workdir, ".git")):
            return {"success": False, "output": f"Not a git repo: {workdir}", "exit_code": -1}

        # Determine base ref for the bundle (commits not yet in origin/<branch>)
        # Try multiple possible remote tracking refs (origin, bundle-origin, then local branch)
        candidate_refs = [
            f"refs/remotes/origin/{branch}",
            f"refs/remotes/bundle-origin/{branch}",
            f"refs/heads/{branch}",
        ]
        base_ref = None
        try:
            for ref in candidate_refs:
                check = subprocess.run(
                    ["git", "rev-parse", "--verify", "-q", ref],
                    cwd=workdir, capture_output=True, timeout=10,
                )
                if check.returncode == 0:
                    base_ref = ref
                    break
        except Exception as e:
            return {"success": False, "output": f"Failed to check base ref: {e}", "exit_code": -1}

        if not base_ref:
            return {"success": False, "output": f"Branch '{branch}' not found locally (tried origin, bundle-origin, and local)", "exit_code": -1}

        # Create bundle
        fd, bundle_path = tempfile.mkstemp(suffix=".bundle", prefix="claw-push-")
        os.close(fd)
        try:
            # Create an incremental bundle: only new commits since origin/<branch>
            bundle_cmd = [
                "git", "bundle", "create", bundle_path,
                f"refs/heads/{branch}", f"^{base_ref}",
            ]
            create_result = subprocess.run(
                bundle_cmd, cwd=workdir,
                capture_output=True, text=True, timeout=120,
            )
            if create_result.returncode != 0:
                return {
                    "success": False,
                    "output": f"Failed to create push bundle:\n{create_result.stderr}",
                    "exit_code": create_result.returncode,
                }

            # Check if there's anything to push
            if os.path.getsize(bundle_path) == 0:
                return {"success": False, "output": "Nothing to push (no new commits)", "exit_code": 0}

            # Read and base64 encode
            with open(bundle_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "git bundle create timed out", "exit_code": -1}
        except Exception as e:
            return {"success": False, "output": str(e), "exit_code": -1}
        finally:
            try:
                os.unlink(bundle_path)
            except OSError:
                pass

        # Send to gateway
        return self._gate("git", "push-bundle", {
            "repo": repo,
            "branch": branch,
            "bundle_b64": b64,
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

    # ── gate (generic / JSON endpoint) ──────────────────────────────────
    p_gate = sub.add_parser("gate", help="Submit a gated operation (JSON response)")
    p_gate.add_argument("service", help="Service name (e.g. git)")
    p_gate.add_argument("action", help="Action name (e.g. push, clone)")
    p_gate.add_argument("--param", "-p", action="append", default=[],
                        help="Key=value parameter (can be repeated)")
    p_gate.add_argument("--details", "-d", default="", help="Human-readable context")

    # ── pull (binary download endpoint) ─────────────────────────────────
    p_pull = sub.add_parser("pull", help="Download a bundle via the binary endpoint")
    p_pull.add_argument("service", help="Service name (e.g. git)")
    p_pull.add_argument("action", help="Action name (e.g. fetch-bundle)")
    p_pull.add_argument("--param", "-p", action="append", default=[],
                        help="Key=value parameter (can be repeated)")
    p_pull.add_argument("--details", "-d", default="", help="Human-readable context")
    p_pull.add_argument("--output", "-o", default="",
                        help="Path to save the downloaded bundle (default: stdout)")

    # ── fetch-bundle (convenience) ──────────────────────────────────────
    p_fetch = sub.add_parser("fetch-bundle",
                             help="Clone/fetch a repo to a local directory via bundle")
    p_fetch.add_argument("--repo", required=True, help="SSH git URL")
    p_fetch.add_argument("--target-dir", required=True, help="Local target directory")
    p_fetch.add_argument("--branch", default="main", help="Branch (default: main)")
    p_fetch.add_argument("--details", "-d", default="", help="Human-readable context")
    p_fetch.add_argument("--timeout", type=int, default=0,
                         help="Override request timeout in seconds")

    # ── push-bundle (convenience) ───────────────────────────────────────
    p_push = sub.add_parser("push-bundle",
                            help="Push local commits through the gateway via bundle")
    p_push.add_argument("--repo", required=True, help="SSH git URL")
    p_push.add_argument("--workdir", required=True, help="Local repo directory")
    p_push.add_argument("--branch", default="main", help="Branch (default: main)")
    p_push.add_argument("--details", "-d", default="", help="Human-readable context")
    p_push.add_argument("--timeout", type=int, default=0,
                        help="Override request timeout in seconds")

    # ── health ──────────────────────────────────────────────────────────
    sub.add_parser("health", help="Check proxy health")

    args = parser.parse_args()

    timeout = args.timeout if hasattr(args, "timeout") and args.timeout else None
    client = AuthProxyClient(
        proxy_url=args.proxy_url,
        auth_token=args.auth_token,
        timeout=timeout or 600,
    )

    # ── gate ────────────────────────────────────────────────────────────
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

    # ── pull (low-level binary download) ────────────────────────────────
    elif args.command == "pull":
        params = {}
        for p in args.param:
            if "=" not in p:
                print(f"ERROR: --param must be key=value, got: {p}", file=sys.stderr)
                sys.exit(1)
            key, val = p.split("=", 1)
            params[key] = val

        try:
            data = client._gate_pull(args.service, args.action, params, args.details)
        except AuthProxyError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        if args.output:
            with open(args.output, "wb") as f:
                f.write(data)
            print(f"Downloaded {len(data)} bytes to {args.output}")
        else:
            sys.stdout.buffer.write(data)

        sys.exit(0)

    # ── fetch-bundle ────────────────────────────────────────────────────
    elif args.command == "fetch-bundle":
        client.timeout = timeout or 600
        result = client.git_fetch_bundle(
            repo=args.repo,
            target_dir=args.target_dir,
            branch=args.branch,
            details=args.details,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result.get("success") else 1)

    # ── push-bundle ─────────────────────────────────────────────────────
    elif args.command == "push-bundle":
        client.timeout = timeout or 600
        result = client.git_push_bundle(
            repo=args.repo,
            workdir=args.workdir,
            branch=args.branch,
            details=args.details,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result.get("success") else 1)

    # ── health ──────────────────────────────────────────────────────────
    elif args.command == "health":
        result = client.health()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("status") == "ok" else 1)


if __name__ == "__main__":
    cli()
