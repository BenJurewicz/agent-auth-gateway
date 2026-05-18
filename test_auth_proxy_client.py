#!/usr/bin/env python3

import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path

import services.git as git_service


CLIENT_PATH = Path(__file__).with_name("auth-proxy-client.py")
SPEC = importlib.util.spec_from_file_location("auth_proxy_client", CLIENT_PATH)
auth_proxy_client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth_proxy_client)
AuthProxyClient = auth_proxy_client.AuthProxyClient

# The server module is tested for queue internals without requiring FastAPI
# or python-telegram-bot in the local unit-test environment.
if "fastapi" not in sys.modules:
    fake_fastapi = types.ModuleType("fastapi")

    class FakeHTTPException(Exception):
        def __init__(self, status_code=500, detail=""):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class FakeResponse:
        def __init__(self, content=b"", media_type="", status_code=200, headers=None):
            self.content = content
            self.media_type = media_type
            self.status_code = status_code
            self.headers = headers or {}

    class FakeFastAPI:
        def __init__(self, *args, **kwargs):
            pass
        def post(self, *args, **kwargs):
            return lambda fn: fn
        def get(self, *args, **kwargs):
            return lambda fn: fn

    fake_fastapi.FastAPI = FakeFastAPI
    fake_fastapi.HTTPException = FakeHTTPException
    fake_fastapi.Header = lambda default=None: default
    fake_fastapi.Request = object
    fake_fastapi.Response = FakeResponse
    sys.modules["fastapi"] = fake_fastapi

if "uvicorn" not in sys.modules:
    fake_uvicorn = types.ModuleType("uvicorn")
    fake_uvicorn.run = lambda *args, **kwargs: None
    sys.modules["uvicorn"] = fake_uvicorn

try:
    import pydantic  # noqa: F401
except Exception:
    fake_pydantic = types.ModuleType("pydantic")
    class FakeBaseModel:
        pass
    fake_pydantic.BaseModel = FakeBaseModel
    sys.modules["pydantic"] = fake_pydantic

SERVER_PATH = Path(__file__).with_name("auth-proxy-server.py")
SERVER_SPEC = importlib.util.spec_from_file_location("auth_proxy_server", SERVER_PATH)
auth_proxy_server = importlib.util.module_from_spec(SERVER_SPEC)
SERVER_SPEC.loader.exec_module(auth_proxy_server)


def run_git(args, cwd, **kwargs):
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        **kwargs,
    )
    return result.stdout.strip()


class CapturingClient(AuthProxyClient):
    def _gate(self, service, action, params, details="", async_request=False):
        bundle = base64.b64decode(params["bundle_b64"])
        with tempfile.NamedTemporaryFile(suffix=".bundle") as tmp:
            tmp.write(bundle)
            tmp.flush()
            refs = run_git(["bundle", "list-heads", tmp.name], cwd=".")
        return {
            "success": True,
            "output": refs,
            "exit_code": 0,
            "service": service,
            "action": action,
            "branch": params["branch"],
        }


class BundleServingClient(AuthProxyClient):
    def __init__(self, bundle_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bundle_path = Path(bundle_path)

    def _gate_pull(self, service, action, params, details=""):
        return self.bundle_path.read_bytes()


class ClientQueueTests(unittest.TestCase):
    def test_gate_sends_async_request_flag(self):
        captured = {}

        class FakeResponse:
            def read(self):
                return b'{"success": true, "request_id": "req123", "status": "pending"}'

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["timeout"] = timeout
            captured["body"] = json.loads(req.data.decode("utf-8"))
            captured["auth"] = req.headers.get("Authorization")
            return FakeResponse()

        with mock.patch.object(auth_proxy_client.url_request, "urlopen", side_effect=fake_urlopen):
            result = AuthProxyClient("http://proxy", "secret", timeout=7).gate(
                "github", "create-pr", {"repo": "r"}, "details", async_request=True,
            )

        self.assertTrue(result["success"])
        self.assertEqual(captured["url"], "http://proxy/gate/github/create-pr")
        self.assertEqual(captured["timeout"], 7)
        self.assertEqual(captured["auth"], "Bearer secret")
        self.assertTrue(captured["body"]["async_request"])
        self.assertEqual(captured["body"]["details"], "details")


class GitPushBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.origin = self.root / "origin.git"
        self.seed = self.root / "seed"
        self.workdir = self.root / "workdir"

        run_git(["init", "--bare", str(self.origin)], cwd=self.root)
        run_git(["init", "-b", "main", str(self.seed)], cwd=self.root)
        run_git(["config", "user.email", "test@example.com"], cwd=self.seed)
        run_git(["config", "user.name", "Test User"], cwd=self.seed)
        (self.seed / "README.md").write_text("initial\n")
        run_git(["add", "README.md"], cwd=self.seed)
        run_git(["commit", "-m", "Initial commit"], cwd=self.seed)
        run_git(["remote", "add", "origin", str(self.origin)], cwd=self.seed)
        run_git(["push", "-u", "origin", "main"], cwd=self.seed)
        run_git(["symbolic-ref", "HEAD", "refs/heads/main"], cwd=self.origin)

        run_git(["clone", str(self.origin), str(self.workdir)], cwd=self.root)
        run_git(["config", "user.email", "test@example.com"], cwd=self.workdir)
        run_git(["config", "user.name", "Test User"], cwd=self.workdir)

    def tearDown(self):
        self.tmp.cleanup()

    def commit_file(self, filename, content, message):
        path = self.workdir / filename
        path.write_text(content)
        run_git(["add", filename], cwd=self.workdir)
        run_git(["commit", "-m", message], cwd=self.workdir)

    def create_origin_bundle(self):
        bundle_path = self.root / "origin.bundle"
        run_git(["bundle", "create", str(bundle_path), "--all"], cwd=self.origin)
        return bundle_path

    def test_new_branch_uses_main_ancestor_as_base(self):
        run_git(["checkout", "-b", "feature/new-branch"], cwd=self.workdir)
        self.commit_file("feature.txt", "new branch\n", "Add feature")

        client = CapturingClient()
        base_ref, error = client._git_push_base_ref(str(self.workdir), "feature/new-branch")
        expected_base = run_git(
            ["merge-base", "refs/heads/feature/new-branch", "refs/remotes/origin/main"],
            cwd=self.workdir,
        )

        self.assertIsNone(error)
        self.assertEqual(base_ref, expected_base)

        result = client.git_push_bundle(
            repo=str(self.origin),
            workdir=str(self.workdir),
            branch="feature/new-branch",
        )

        self.assertTrue(result["success"], result["output"])
        self.assertIn("refs/heads/feature/new-branch", result["output"])

    def test_existing_remote_branch_keeps_same_name_tracking_ref(self):
        run_git(["checkout", "-b", "feature/existing"], cwd=self.workdir)
        self.commit_file("existing.txt", "remote branch\n", "Add existing branch")
        run_git(["push", "-u", "origin", "feature/existing"], cwd=self.workdir)
        self.commit_file("existing.txt", "local update\n", "Update existing branch")

        client = CapturingClient()
        base_ref, error = client._git_push_base_ref(str(self.workdir), "feature/existing")

        self.assertIsNone(error)
        self.assertEqual(base_ref, "refs/remotes/origin/feature/existing")

    def test_fetch_bundle_initial_clone_allows_relative_target_dir(self):
        bundle_path = self.create_origin_bundle()
        old_cwd = os.getcwd()
        os.chdir(self.root)
        try:
            result = BundleServingClient(bundle_path).git_fetch_bundle(
                repo=str(self.origin),
                target_dir="relative-clone",
                branch="main",
            )
        finally:
            os.chdir(old_cwd)

        self.assertTrue(result["success"], result["output"])
        self.assertTrue((self.root / "relative-clone" / ".git").is_dir())

    def test_fetch_bundle_reports_merge_conflict_as_failure(self):
        (self.seed / "README.md").write_text("remote update\n")
        run_git(["add", "README.md"], cwd=self.seed)
        run_git(["commit", "-m", "Remote update"], cwd=self.seed)
        run_git(["push", "origin", "main"], cwd=self.seed)

        self.commit_file("README.md", "local update\n", "Local update")
        bundle_path = self.create_origin_bundle()

        result = BundleServingClient(bundle_path).git_fetch_bundle(
            repo=str(self.origin),
            target_dir=str(self.workdir),
            branch="main",
        )

        self.assertFalse(result["success"])
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIn("git merge failed", result["output"])


class RequestQueueTests(unittest.TestCase):
    def test_durable_store_approve_claim_finish(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = auth_proxy_server.RequestStore(Path(tmp) / "requests.sqlite3")
            row = store.create("git", "clear-cache", {"details": "test"})

            self.assertEqual(row["status"], "pending")
            self.assertTrue(store.approve(row["id"], approved_by="tester"))

            claimed = store.claim_next_approved()
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed["status"], "running")

            result = {"success": True, "output": "done", "exit_code": 0}
            self.assertTrue(store.finish(row["id"], "succeeded", result))

            final = store.get(row["id"])
            self.assertEqual(final["status"], "succeeded")
            self.assertEqual(final["result"], result)

    def test_cancelled_request_is_not_overwritten_by_late_worker_finish(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = auth_proxy_server.RequestStore(Path(tmp) / "requests.sqlite3")
            row = store.create("git", "clear-cache", {"details": "test"}, status="approved")
            claimed = store.claim_next_approved()
            self.assertEqual(claimed["status"], "running")

            self.assertTrue(store.cancel(row["id"]))
            late_result = {"success": True, "output": "late success", "exit_code": 0}
            self.assertFalse(store.finish(row["id"], "succeeded", late_result))

            final = store.get(row["id"])
            self.assertEqual(final["status"], "cancelled")
            self.assertFalse(final["result"]["success"])

    def test_durable_store_expires_stale_pending_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "requests.sqlite3"
            store = auth_proxy_server.RequestStore(db)
            row = store.create("git", "clear-cache", {"details": "test"})
            with store._connect() as con:
                con.execute("UPDATE requests SET expires_at = ? WHERE id = ?", (0, row["id"]))

            self.assertEqual(store.expire_stale(), 1)
            expired = store.get(row["id"])
            self.assertEqual(expired["status"], "expired")
            self.assertFalse(expired["result"]["success"])

    def test_execute_request_preserves_binary_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "source.bundle"
            artifact.write_bytes(b"bundle-data")
            row = {
                "id": "reqtestartifact",
                "service": "git",
                "action": "clear-cache",
                "data": {},
            }
            with mock.patch.object(git_service.GitService, "execute", return_value={
                "success": True,
                "output": "ok",
                "exit_code": 0,
                "_binary_file": str(artifact),
            }), mock.patch.object(auth_proxy_server, "_artifact_dir", return_value=Path(tmp) / "artifacts"):
                result, artifact_path = auth_proxy_server._execute_request_sync(row)

            self.assertTrue(result["success"])
            self.assertTrue(Path(artifact_path).is_file())
            self.assertEqual(Path(artifact_path).read_bytes(), b"bundle-data")
            self.assertFalse(artifact.exists())

    def test_public_request_redacts_push_bundle_payload(self):
        public = auth_proxy_server._public_request({
            "id": "req",
            "service": "git",
            "action": "push-bundle",
            "status": "pending",
            "created_at": 1,
            "updated_at": 1,
            "expires_at": 2,
            "approved_by": None,
            "approved_at": None,
            "expired": False,
            "data": {"bundle_b64": "abc123", "branch": "main"},
            "result": None,
            "artifact_path": "",
        })

        self.assertEqual(public["data"]["bundle_b64"], "<redacted 6 chars>")
        self.assertEqual(public["data"]["branch"], "main")


class GitServiceTests(unittest.TestCase):
    def test_clear_cache_allows_no_repo_and_removes_cache_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            repo_cache = cache / "repo.git"
            repo_cache.mkdir(parents=True)
            (repo_cache / "HEAD").write_text("ref: refs/heads/main\n")
            (cache / "leftover.bundle").write_text("temporary bundle\n")

            with mock.patch.object(git_service, "CACHE_BASE", str(cache)):
                git_service.GitService.validate("clear-cache", {})
                result = git_service.GitService.execute("clear-cache", {}, {})

            self.assertTrue(result["success"], result["output"])
            self.assertEqual(result["removed"], 2)
            self.assertTrue(cache.is_dir())
            self.assertEqual(list(cache.iterdir()), [])

    def test_validate_rejects_invalid_branch_and_known_ref(self):
        with self.assertRaises(ValueError):
            git_service.GitService.validate("fetch-bundle", {
                "repo": "git@github.com:user/repo.git",
                "branch": "bad branch",
            })

        with self.assertRaises(ValueError):
            git_service.GitService.validate("fetch-bundle", {
                "repo": "git@github.com:user/repo.git",
                "branch": "main",
                "known_ref": "--not-a-commit",
            })

    def test_ensure_cache_uses_argv_and_reports_clone_failure(self):
        config = {"services": {"git": {"timeout": 10, "ssh_key_path": "~/.ssh/id_ed25519"}}}
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(git_service, "CACHE_BASE", tmp):
                completed = subprocess.CompletedProcess(
                    args=["git"], returncode=128, stdout="", stderr="permission denied",
                )
                with mock.patch.object(git_service.subprocess, "run", return_value=completed) as run:
                    with self.assertRaisesRegex(RuntimeError, "Initial clone failed"):
                        git_service._ensure_cache("git@github.com:user/repo.git", config)

                args, kwargs = run.call_args
                self.assertEqual(args[0][:3], ["git", "clone", "--bare"])
                self.assertNotIn("shell", kwargs)

    def test_git_approval_text_escapes_markdown_details(self):
        text = git_service.GitService.approval_text("push-bundle", {
            "repo": "git@github.com:user/repo.git",
            "branch": "main",
            "details": "Fix *bold* `code` [link]",
        }, "abcdefghijklmnopqrstuvwxyz")

        self.assertIn(r"Fix \*bold\* \`code\` \[link\]", text)
        self.assertNotIn("Fix *bold* `code` [link]", text)


if __name__ == "__main__":
    unittest.main()
