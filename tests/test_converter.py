import contextlib
import io
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from convert import convert_archive, convert_rules, read_rules
from catalog import catalog
from validate import validate, validate_rule


def rule_set(**rule):
    return {"version": 2, "rules": [rule]}


class RuleConversionTests(unittest.TestCase):
    def test_scalar_values_and_exact_domain_semantics(self):
        rules, unsupported, counts = convert_rules(rule_set(
            domain="example.com", domain_suffix=["example.org"], domain_keyword="sentry"))
        self.assertEqual(rules, ["DOMAIN,example.com", "DOMAIN-KEYWORD,sentry", "DOMAIN-SUFFIX,example.org"])
        self.assertFalse(unsupported)
        self.assertEqual(sum(counts.values()), 3)

    def test_ipv4_ipv6_and_duplicates(self):
        rules, _, counts = convert_rules(rule_set(ip_cidr=["192.0.2.0/24", "2001:db8::/32", "192.0.2.0/24"]))
        self.assertEqual(rules, ["IP-CIDR,192.0.2.0/24,no-resolve", "IP-CIDR6,2001:db8::/32,no-resolve"])
        self.assertEqual(counts["ip_cidr"], 3)

    def test_regex_preserved_without_approximation(self):
        expression = r"^chatgpt-\S+-\d+\.example\.com$"
        rules, unsupported, counts = convert_rules(rule_set(domain_regex=expression))
        self.assertEqual(rules, [])
        self.assertEqual(unsupported[0]["value"], expression)
        self.assertEqual(counts["domain_regex"], 1)

    def test_deduplication_preserves_source_and_regex_multiplicity(self):
        expression = r"^x\d+$"
        rules, unsupported, counts = convert_rules({"version": 2, "rules": [
            {"domain": ["same.example", "same.example"], "domain_regex": [expression, expression]},
            {"domain": "same.example", "ip_cidr": ["2001:0db8::/32", "2001:db8::/32"]}]})
        self.assertEqual(rules, ["DOMAIN,same.example", "IP-CIDR6,2001:db8::/32,no-resolve"])
        self.assertEqual(dict(counts), {"domain": 3, "domain_regex": 2, "ip_cidr": 2})
        self.assertEqual(unsupported, [{"field": "domain_regex", "value": expression,
                                      "reason": "Surge RULE-SET does not support DOMAIN-REGEX"}] * 2)

    def test_domain_and_destination_ip_conditions_preserve_or(self):
        rules, unsupported, _ = convert_rules(rule_set(domain="example.com", ip_cidr="192.0.2.0/24"))
        self.assertEqual(rules, ["DOMAIN,example.com", "IP-CIDR,192.0.2.0/24,no-resolve"])
        self.assertFalse(unsupported)

    def test_each_rule_requires_a_nonempty_match_condition(self):
        empty_rules = [{field: []} for field in
                       ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr")]
        empty_rules.append({"domain": [], "ip_cidr": []})
        for empty in empty_rules:
            for source_rules in ([empty], [empty, {"domain": "example.com"}],
                                 [{"domain": "example.com"}, empty]):
                with self.subTest(rules=source_rules), self.assertRaisesRegex(ValueError, "match condition"):
                    convert_rules({"version": 2, "rules": source_rules})

    def test_empty_fields_with_nonempty_match_conditions_are_allowed(self):
        rules, unsupported, counts = convert_rules(rule_set(domain=[], ip_cidr="192.0.2.0/24"))
        self.assertEqual(rules, ["IP-CIDR,192.0.2.0/24,no-resolve"])
        self.assertFalse(unsupported)
        self.assertEqual(dict(counts), {"ip_cidr": 1})
        rules, unsupported, counts = convert_rules(rule_set(domain=[], domain_regex=r"^x\d+$"))
        self.assertEqual(rules, [])
        self.assertEqual(unsupported[0]["value"], r"^x\d+$")
        self.assertEqual(dict(counts), {"domain_regex": 1})

    def test_future_incompatible_rules_fail_closed(self):
        cases = [rule_set(type="logical", rules=[]), rule_set(invert=True, domain="example.com"),
                 rule_set(domain_suffix=".example.com"), rule_set(domain="a,b"),
                 rule_set(domain=[42]), rule_set(ip_cidr="192.0.2.1/24"),
                 rule_set(ip_cidr="192.0.2.1"), {"version": 99, "rules": [{"domain": "a"}]}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                convert_rules(case)

    def test_output_validation_rejects_policy_and_wrong_ip_family(self):
        for line in ["DOMAIN,example.com,DIRECT", "IP-CIDR,2001:db8::/32,no-resolve", "DOMAIN-REGEX,^x$"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                validate_rule(line)


class SnapshotFixture:
    SHA = "a" * 40

    def make_archive(self, path, omit_srs=False, extra=None):
        fixtures = {"geo/geosite/example.json": rule_set(domain="example.com", domain_regex=r"^x\d+$"),
                    "geo-lite/geoip/cn.json": rule_set(ip_cidr="192.0.2.0/24"),
                    "asn/AS13335.json": rule_set(ip_cidr="2001:db8::/32")}
        if extra:
            fixtures.update(extra)
        with tarfile.open(path, "w:gz") as archive:
            for name, data in fixtures.items():
                raw = json.dumps(data).encode()
                member = tarfile.TarInfo("snapshot/" + name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
                if not omit_srs:
                    raw = b"placeholder srs"
                    member = tarfile.TarInfo("snapshot/" + name.removesuffix(".json") + ".srs")
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))


class SnapshotTests(SnapshotFixture, unittest.TestCase):
    def test_full_coverage_accounting_and_determinism(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz")
            first = convert_archive(root / "source.tar.gz", root / "first", self.SHA)
            second = convert_archive(root / "source.tar.gz", root / "second", self.SHA)
            self.assertEqual(first, second)
            self.assertEqual(first["summary"]["rule_sets"], 3)
            self.assertEqual(first["summary"]["unsupported_rules"], 1)
            self.assertEqual(first["summary"]["source_rules"], 4)
            validate(root / "first")
            for file in (root / "first").rglob("*"):
                if file.is_file():
                    self.assertEqual(file.read_bytes(), (root / "second" / file.relative_to(root / "first")).read_bytes())

    def test_incomplete_or_unsafe_archive_rejected(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "missing.tar.gz", omit_srs=True)
            with self.assertRaisesRegex(ValueError, "coverage mismatch"):
                convert_archive(root / "missing.tar.gz", root / "missing", self.SHA)
            self.make_archive(root / "unsafe.tar.gz", extra={"../outside.json": rule_set(domain="x")})
            with self.assertRaisesRegex(ValueError, "unsafe"):
                convert_archive(root / "unsafe.tar.gz", root / "unsafe", self.SHA)

    def test_duplicate_json_and_srs_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz")
            with tarfile.open(root / "source.tar.gz", "r:gz") as archive:
                entries = [(member.name, archive.extractfile(member).read()) for member in archive]
            for suffix in (".json", ".srs"):
                duplicate = next(entry for entry in entries if entry[0].endswith(suffix))
                path = root / (suffix[1:] + ".tar.gz")
                with tarfile.open(path, "w:gz") as archive:
                    for name, raw in entries + [duplicate]:
                        member = tarfile.TarInfo(name)
                        member.size = len(raw)
                        archive.addfile(member, io.BytesIO(raw))
                output = root / suffix[1:]
                with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, "duplicate source path"):
                    convert_archive(path, output, self.SHA)
                self.assertFalse((output / "manifest.json").exists())

    def test_archive_member_order_does_not_change_rule_outputs(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "first.tar.gz")
            with tarfile.open(root / "first.tar.gz", "r:gz") as archive:
                entries = [(member.name, archive.extractfile(member).read()) for member in archive]
            with tarfile.open(root / "reordered.tar.gz", "w:gz") as archive:
                for name, raw in reversed(entries):
                    member = tarfile.TarInfo(name)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
            first = convert_archive(root / "first.tar.gz", root / "first", self.SHA)
            reordered = convert_archive(root / "reordered.tar.gz", root / "reordered", self.SHA)
            self.assertNotEqual(first["upstream"]["archive_sha256"], reordered["upstream"]["archive_sha256"])
            del first["upstream"]["archive_sha256"], reordered["upstream"]["archive_sha256"]
            self.assertEqual(first, reordered)
            for file in (root / "first").rglob("*"):
                if file.is_file() and file.name != "manifest.json":
                    self.assertEqual(file.read_bytes(), (root / "reordered" / file.relative_to(root / "first")).read_bytes())

    def test_tampering_detected(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz")
            convert_archive(root / "source.tar.gz", root / "output", self.SHA)
            (root / "output/asn/AS13335.list").write_text("DOMAIN,attacker.example\n")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                validate(root / "output")

    def test_cli_rejects_conditionless_rule_without_publishing_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_archive(root / "source.tar.gz", extra={"geo/geosite/mixed.json": {
                "version": 2, "rules": [{"domain": []}, {"domain": ["example.com"]}]}})
            output = root / "output"
            script = Path(__file__).resolve().parents[1] / "scripts/convert.py"
            result = subprocess.run([sys.executable, str(script), "--archive", str(root / "source.tar.gz"),
                                     "--sha", self.SHA, "--output", str(output)],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("match condition", result.stderr)
            self.assertFalse((output / "manifest.json").exists())
            self.assertFalse((output / "unsupported.json").exists())


class GeoLiteMergeTests(SnapshotFixture, unittest.TestCase):
    def test_matching_categories_single_sides_and_regex_provenance(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz", extra={
                "geo-lite/geosite/cn.json": rule_set(domain_suffix="example.cn", domain_regex=r"^x\d+\.cn$"),
                "geo-lite/geosite/openai.json": rule_set(domain="chat.example.com"),
                "geo-lite/geoip/jp.json": rule_set(ip_cidr="2001:db8::/32")})
            manifest = convert_archive(root / "source.tar.gz", root / "output", self.SHA)
            merged = {record["path"]: record for record in manifest["merged_files"]}
            self.assertEqual(set(merged), {"geo-lite/cn.list", "geo-lite/jp.list", "geo-lite/openai.list"})
            self.assertEqual(read_rules(root / "output/geo-lite/cn.list"),
                             ["DOMAIN-SUFFIX,example.cn", "IP-CIDR,192.0.2.0/24,no-resolve"])
            self.assertEqual(merged["geo-lite/cn.list"]["sources"],
                             ["geo-lite/geoip/cn.list", "geo-lite/geosite/cn.list"])
            self.assertEqual(merged["geo-lite/cn.list"]["status"], "partial")
            self.assertEqual(merged["geo-lite/cn.list"]["unsupported"], 1)
            self.assertEqual(read_rules(root / "output/geo-lite/openai.list"), ["DOMAIN,chat.example.com"])
            self.assertEqual(read_rules(root / "output/geo-lite/jp.list"), ["IP-CIDR6,2001:db8::/32,no-resolve"])
            # Derived rules never count twice as upstream rules or regex records.
            self.assertEqual(manifest["summary"]["rule_sets"], 6)
            self.assertEqual(manifest["summary"]["source_rules"], 8)
            self.assertEqual(manifest["summary"]["unsupported_rules"], 2)
            self.assertEqual(manifest["summary"]["merged_rule_sets"], 3)
            validate(root / "output")

    def test_duplicate_union_and_unsupported_only(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz", extra={
                "geo-lite/geosite/cn.json": rule_set(ip_cidr="192.0.2.0/24"),
                "geo-lite/geosite/regex.json": rule_set(domain_regex=r"^x\d+$")})
            manifest = convert_archive(root / "source.tar.gz", root / "output", self.SHA)
            merged = {record["path"]: record for record in manifest["merged_files"]}
            self.assertEqual(merged["geo-lite/cn.list"]["rules"], 1)
            self.assertEqual(merged["geo-lite/cn.list"]["deduplicated"], 1)
            self.assertEqual(merged["geo-lite/regex.list"]["status"], "unsupported_only")
            self.assertEqual(read_rules(root / "output/geo-lite/regex.list"), [])
            validate(root / "output")

    def test_widened_merged_match_rejected_even_with_updated_checksum(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz")
            manifest = convert_archive(root / "source.tar.gz", root / "output", self.SHA)
            target = root / "output/geo-lite/cn.list"
            content = b"DOMAIN,unrelated.example\nIP-CIDR,192.0.2.0/24,no-resolve\n"
            target.write_bytes(content)
            manifest["merged_files"][0]["sha256"] = hashlib.sha256(content).hexdigest()
            manifest["merged_files"][0]["rules"] = 2
            (root / "output/manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "source union"):
                validate(root / "output")

    def test_removed_source_changes_the_next_snapshot(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "first.tar.gz", extra={
                "geo-lite/geosite/cn.json": rule_set(domain_suffix="example.cn"),
                "geo-lite/geosite/removed.json": rule_set(domain="removed.example")})
            first = convert_archive(root / "first.tar.gz", root / "first", self.SHA)
            self.make_archive(root / "next.tar.gz")
            next_snapshot = convert_archive(root / "next.tar.gz", root / "next", self.SHA)
            self.assertIn("DOMAIN-SUFFIX,example.cn", read_rules(root / "first/geo-lite/cn.list"))
            self.assertNotIn("DOMAIN-SUFFIX,example.cn", read_rules(root / "next/geo-lite/cn.list"))
            self.assertTrue((root / "first/geo-lite/removed.list").exists())
            self.assertFalse((root / "next/geo-lite/removed.list").exists())
            self.assertEqual(len(first["merged_files"]), 2)
            self.assertEqual(len(next_snapshot["merged_files"]), 1)


class CatalogTests(SnapshotFixture, unittest.TestCase):
    def test_fork_guide_catalog_and_licenses_are_rendered_from_the_snapshot(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz", extra={
                "geo-lite/geosite/cn.json": rule_set(domain_suffix="example.cn")})
            output = root / "output"
            convert_archive(root / "source.tar.gz", output, self.SHA)
            catalog(output, "example/fork")
            guide = (output / "README.md").read_text()
            self.assertNotIn("{{REPOSITORY}}", guide)
            self.assertIn("https://github.com/example/fork/tree/main", guide)
            self.assertIn("RULE-SET,https://raw.githubusercontent.com/example/fork/release/geo-lite/cn.list,DIRECT", guide)
            self.assertIn("### 精简分类只用一条 URL", guide)
            self.assertIn("## 格式与边界", guide)
            rows = (output / "CATALOG.md").read_text()
            self.assertIn("[geo-lite/cn.list](https://raw.githubusercontent.com/example/fork/release/geo-lite/cn.list)", rows)
            self.assertIn("[geo-lite/geoip/cn.list]", rows)
            self.assertIn("[geo-lite/geosite/cn.list]", rows)
            self.assertNotIn("[asn/AS13335.list]", rows)
            repository = Path(__file__).resolve().parents[1]
            for name in ("LICENSE", "NOTICE.md"):
                self.assertEqual((output / name).read_bytes(), (repository / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
