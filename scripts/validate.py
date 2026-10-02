#!/usr/bin/env python3
"""Validate coverage, checksums and every emitted Surge rule."""

import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile

from convert import domain_token, geo_lite_groups, read_rules


def validate_rule(line):
    parts = line.split(",")
    if parts[0] in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD") and len(parts) == 2:
        domain_token(parts[1])
    elif parts[0] in ("IP-CIDR", "IP-CIDR6") and len(parts) == 3 and parts[2] == "no-resolve":
        network = ipaddress.ip_network(parts[1], strict=True)
        if (network.version == 4) != (parts[0] == "IP-CIDR"):
            raise ValueError(f"IP family mismatch: {line}")
    else:
        raise ValueError(f"invalid Surge rule: {line}")


def native_check(rules, cli):
    # --check does not load RULE-SET resources. Inline every unique rule instead.
    ordered = sorted(rules)
    chunk_size = 20000
    with tempfile.TemporaryDirectory(prefix="surge-rules-check-") as temp:
        profile = Path(temp) / "validation.conf"
        for start in range(0, len(ordered), chunk_size):
            lines = []
            for rule in ordered[start:start + chunk_size]:
                if rule.endswith(",no-resolve"):
                    lines.append(rule.removesuffix(",no-resolve") + ",DIRECT,no-resolve")
                else:
                    lines.append(rule + ",DIRECT")
            profile.write_text("[General]\nloglevel = notify\n[Rule]\n" +
                               "\n".join(lines) + "\nFINAL,DIRECT\n", encoding="utf-8")
            result = subprocess.run([str(cli), "--check", str(profile)],
                                    text=True, capture_output=True, timeout=120)
            if result.returncode or result.stdout.strip() != "OK":
                raise ValueError("Surge native validation failed: " + result.stdout + result.stderr)
    return len(ordered)


def validate(output, cli=None):
    output = Path(output)
    manifest = json.loads((output / "manifest.json").read_text())
    unsupported = json.loads((output / "unsupported.json").read_text())
    reported = Counter(record["source"] for record in unsupported["rules"])
    if unsupported["upstream_sha"] != manifest["upstream"]["sha"]:
        raise ValueError("unsupported report belongs to a different snapshot")
    expected = set()
    unique_rules = set()
    emitted, lost, deduplicated, source_total = 0, 0, 0, 0
    for record in manifest["files"]:
        path = record["path"]
        if path in expected:
            raise ValueError("duplicate manifest path")
        expected.add(path)
        content = (output / path).read_bytes()
        if hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise ValueError(f"checksum mismatch: {path}")
        rules = read_rules(output / path)
        if len(rules) != record["rules"] or rules != sorted(set(rules)):
            raise ValueError(f"count/order mismatch: {path}")
        if reported[record["source"]] != record["unsupported"]:
            raise ValueError(f"unsupported count mismatch: {path}")
        if record["input_rules"] != record["rules"] + record["unsupported"] + record["deduplicated"]:
            raise ValueError(f"input accounting mismatch: {path}")
        for rule in rules:
            validate_rule(rule)
        if cli:
            unique_rules.update(rules)
        emitted += len(rules)
        lost += record["unsupported"]
        deduplicated += record["deduplicated"]
        source_total += record["input_rules"]
    if len(expected) != manifest["summary"]["rule_sets"]:
        raise ValueError("manifest does not cover all rule files")
    if emitted != manifest["summary"]["emitted_rules"] or lost != manifest["summary"]["unsupported_rules"]:
        raise ValueError("summary count mismatch")
    if deduplicated != manifest["summary"]["deduplicated_rules"] or source_total != manifest["summary"]["source_rules"]:
        raise ValueError("source accounting mismatch")
    merged_files = manifest.get("merged_files", [])
    merged_total = 0
    groups = geo_lite_groups(manifest["files"])
    expected_merged = {"geo-lite/" + name for name in groups}
    if {record["path"] for record in merged_files} != expected_merged:
        raise ValueError("merged manifest does not cover all geo-lite categories")
    for record in merged_files:
        path = record["path"]
        if path in expected:
            raise ValueError("duplicate merged manifest path")
        expected.add(path)
        sources = groups[Path(path).name]
        if record["sources"] != [source["path"] for source in sources]:
            raise ValueError(f"merged sources mismatch: {path}")
        content = (output / path).read_bytes()
        if hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise ValueError(f"checksum mismatch: {path}")
        rules = read_rules(output / path)
        union = sorted({rule for source in sources for rule in read_rules(output / source["path"])})
        unsupported_count = sum(source["unsupported"] for source in sources)
        status = "complete" if not unsupported_count else "partial" if union else "unsupported_only"
        if rules != union or record["rules"] != len(union) or len(union) > 1_000_000:
            raise ValueError(f"merged rules differ from source union: {path}")
        if record["unsupported"] != unsupported_count or record["status"] != status:
            raise ValueError(f"merged status mismatch: {path}")
        if record["deduplicated"] != sum(source["rules"] for source in sources) - len(union):
            raise ValueError(f"merged deduplication mismatch: {path}")
        for rule in rules:
            validate_rule(rule)
        if cli:
            unique_rules.update(rules)
        merged_total += len(rules)
    if len(merged_files) != manifest["summary"].get("merged_rule_sets", 0) or merged_total != manifest["summary"].get("merged_rules", 0):
        raise ValueError("merged summary count mismatch")
    actual = {str(p.relative_to(output)) for p in output.rglob("*.list")}
    if actual != expected:
        raise ValueError("manifest does not cover all rule files")
    native = native_check(unique_rules, cli) if cli else None
    print(json.dumps({"validated_files": len(expected), "validated_rules": emitted,
                      "validated_merged_rules": merged_total, "unsupported_records": lost,
                      "surge_native_unique_rules": native}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--surge-cli", type=Path)
    args = parser.parse_args()
    validate(args.output, args.surge_cli)
