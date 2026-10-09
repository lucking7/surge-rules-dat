import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/publish.sh"


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.source, self.remote, self.dist = root / "source", root / "remote.git", root / "dist"
        self.scratch = root / "scratch"
        self.source.mkdir()
        self.dist.mkdir()
        self.scratch.mkdir()
        self.git("init", "--bare", str(self.remote))
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.com")
        (self.source / "source.txt").write_text("source branch must remain unchanged\n")
        self.git("add", ".")
        self.git("commit", "-m", "Initial source")
        self.source_head = self.git("rev-parse", "HEAD")
        self.git("remote", "add", "origin", str(self.remote))
        (self.dist / "manifest.json").write_text(json.dumps({"upstream": {"sha": "a" * 40}}))
        (self.dist / "old.list").write_text("DOMAIN,old.example\n")

    def command(self, *args, check=True, env=None):
        return subprocess.run(args, cwd=self.source, check=check, text=True, capture_output=True, env=env)

    def git(self, *args):
        return self.command("git", *args).stdout.strip()

    def publish(self, check=True):
        env = {**os.environ, "TMPDIR": str(self.scratch)}
        return self.command("bash", str(SCRIPT), str(self.dist), check=check, env=env)

    def local_branches(self):
        return self.git("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/")

    def assert_cleaned_up(self, branches, status=""):
        self.assertEqual(self.git("rev-parse", "HEAD"), self.source_head)
        self.assertEqual(self.git("status", "--porcelain"), status)
        self.assertEqual(self.local_branches(), branches)
        worktrees = self.git("worktree", "list", "--porcelain").splitlines()
        self.assertEqual([line for line in worktrees if line.startswith("worktree ")],
                         [f"worktree {self.source.resolve()}"])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_initial_update_deletion_and_noop_preserve_history(self):
        branches = self.local_branches()
        self.publish()
        first = self.git("--git-dir", str(self.remote), "rev-parse", "release")
        self.assert_cleaned_up(branches)
        self.publish()
        self.assertEqual(first, self.git("--git-dir", str(self.remote), "rev-parse", "release"))
        self.assert_cleaned_up(branches)
        (self.dist / "old.list").unlink()
        (self.dist / "new.list").write_text("DOMAIN,new.example\n")
        self.publish()
        second = self.git("--git-dir", str(self.remote), "rev-parse", "release")
        self.assertNotEqual(first, second)
        self.assertEqual(first, self.git("--git-dir", str(self.remote), "rev-parse", "release^"))
        self.assertEqual(self.git("--git-dir", str(self.remote), "ls-tree", "--name-only", "release"),
                         "manifest.json\nnew.list")
        self.assert_cleaned_up(branches)

    def test_failed_first_push_can_retry_and_cleans_up(self):
        branches = self.local_branches()
        (self.source / "source.txt").write_text("staged concurrent change\n")
        self.git("add", "source.txt")
        (self.source / "untracked.txt").write_text("untracked concurrent work\n")
        status = self.git("status", "--porcelain")
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        result = self.publish(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pre-receive hook declined", result.stderr)
        self.assertEqual(self.git("ls-remote", "--heads", "origin", "refs/heads/release"), "")
        self.assert_cleaned_up(branches, status)
        hook.unlink()
        self.publish()
        self.assertEqual(self.git("--git-dir", str(self.remote), "ls-tree", "--name-only", "release"),
                         "manifest.json\nold.list")
        self.assert_cleaned_up(branches, status)

    def test_initial_publication_preserves_existing_local_release_branch(self):
        self.git("branch", "release")
        branches = self.local_branches()
        self.publish()
        remote_head = self.git("--git-dir", str(self.remote), "rev-parse", "release")
        self.assertNotEqual(remote_head, self.source_head)
        self.assertEqual(self.git("rev-parse", "release"), self.source_head)
        self.assert_cleaned_up(branches)

    def test_failed_update_push_can_retry_without_changing_source_or_history(self):
        branches = self.local_branches()
        self.publish()
        first = self.git("--git-dir", str(self.remote), "rev-parse", "release")
        (self.source / "source.txt").write_text("staged concurrent change\n")
        self.git("add", "source.txt")
        (self.source / "source.txt").write_text("unstaged concurrent change\n")
        (self.source / "untracked.txt").write_text("untracked concurrent work\n")
        status = self.git("status", "--porcelain")
        source_bytes = (self.source / "source.txt").read_bytes()
        index_content = self.git("show", ":source.txt")
        (self.dist / "old.list").unlink()
        (self.dist / "new.list").write_text("DOMAIN,new.example\n")
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        result = self.publish(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pre-receive hook declined", result.stderr)
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "release"), first)
        self.assert_cleaned_up(branches, status)
        self.assertEqual((self.source / "source.txt").read_bytes(), source_bytes)
        self.assertEqual(self.git("show", ":source.txt"), index_content)
        self.assertEqual((self.source / "untracked.txt").read_text(), "untracked concurrent work\n")
        hook.unlink()
        self.publish()
        self.assertEqual(self.git("--git-dir", str(self.remote), "rev-parse", "release^"), first)
        self.assertEqual(self.git("--git-dir", str(self.remote), "ls-tree", "--name-only", "release"),
                         "manifest.json\nnew.list")
        self.assert_cleaned_up(branches, status)
        self.assertEqual((self.source / "source.txt").read_bytes(), source_bytes)
        self.assertEqual(self.git("show", ":source.txt"), index_content)
        self.assertEqual((self.source / "untracked.txt").read_text(), "untracked concurrent work\n")


if __name__ == "__main__":
    unittest.main()
