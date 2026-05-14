#!/usr/bin/env python3

import base64
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
