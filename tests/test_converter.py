import contextlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from convert import convert_archive, convert_rules
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

    def test_domain_and_destination_ip_conditions_preserve_or(self):
        rules, unsupported, _ = convert_rules(rule_set(domain="example.com", ip_cidr="192.0.2.0/24"))
        self.assertEqual(rules, ["DOMAIN,example.com", "IP-CIDR,192.0.2.0/24,no-resolve"])
        self.assertFalse(unsupported)

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


class SnapshotTests(unittest.TestCase):
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

    def test_tampering_detected(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            self.make_archive(root / "source.tar.gz")
            convert_archive(root / "source.tar.gz", root / "output", self.SHA)
            (root / "output/asn/AS13335.list").write_text("DOMAIN,attacker.example\n")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                validate(root / "output")


if __name__ == "__main__":
    unittest.main()
