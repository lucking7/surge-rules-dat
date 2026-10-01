import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/publish.sh"


class PublicationTests(unittest.TestCase):
    def test_initial_update_deletion_and_noop_preserve_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, remote, dist = root / "source", root / "remote.git", root / "dist"
            source.mkdir()
            dist.mkdir()

            def run(*args, cwd=source):
                return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()

            run("git", "init", "--bare", str(remote))
            run("git", "init", "-b", "main")
            run("git", "config", "user.name", "Test")
            run("git", "config", "user.email", "test@example.com")
            (source / "source.txt").write_text("source branch must remain unchanged\n")
            run("git", "add", ".")
            run("git", "commit", "-m", "Initial source")
            source_head = run("git", "rev-parse", "HEAD")
            run("git", "remote", "add", "origin", str(remote))
            (dist / "manifest.json").write_text(json.dumps({"upstream": {"sha": "a" * 40}}))
            (dist / "old.list").write_text("DOMAIN,old.example\n")
            run("bash", str(SCRIPT), str(dist))
            first = run("git", "--git-dir", str(remote), "rev-parse", "release")
            run("bash", str(SCRIPT), str(dist))
            self.assertEqual(first, run("git", "--git-dir", str(remote), "rev-parse", "release"))
            (dist / "old.list").unlink()
            (dist / "new.list").write_text("DOMAIN,new.example\n")
            run("bash", str(SCRIPT), str(dist))
            second = run("git", "--git-dir", str(remote), "rev-parse", "release")
            self.assertNotEqual(first, second)
            self.assertEqual(first, run("git", "--git-dir", str(remote), "rev-parse", "release^"))
            self.assertEqual(run("git", "--git-dir", str(remote), "ls-tree", "--name-only", "release"),
                             "manifest.json\nnew.list")
            self.assertEqual(source_head, run("git", "rev-parse", "HEAD"))
            self.assertEqual(run("git", "status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
