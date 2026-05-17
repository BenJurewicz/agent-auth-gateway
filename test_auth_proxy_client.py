#!/usr/bin/env python3

import base64
import importlib.util
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import services.git as git_service


CLIENT_PATH = Path(__file__).with_name("auth-proxy-client.py")
SPEC = importlib.util.spec_from_file_location("auth_proxy_client", CLIENT_PATH)
auth_proxy_client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth_proxy_client)
AuthProxyClient = auth_proxy_client.AuthProxyClient


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
    def _gate(self, service, action, params, details=""):
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
