#!/usr/bin/env python3
"""Convert a pinned meta-rules-dat sing snapshot into Surge RULE-SET files."""

import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request

UPSTREAM = "MetaCubeX/meta-rules-dat"
BRANCH = "sing"
FIELDS = {"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"}
ROOTS = {"geo", "geo-lite", "asn"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def values(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ValueError("rule values must be a string or an array of strings")


def domain_token(value):
    if not value or any(c.isspace() or c in ",#*?" for c in value):
        raise ValueError(f"invalid domain token: {value!r}")
    return value


def convert_rules(data):
    if not isinstance(data, dict) or set(data) != {"version", "rules"}:
        raise ValueError("unexpected rule-set schema")
    if type(data["version"]) is not int or data["version"] not in (1, 2, 3):
        raise ValueError("unsupported rule-set version")
    if not isinstance(data["rules"], list) or not data["rules"]:
        raise ValueError("empty or invalid rule-set")
    converted = []
    unsupported = []
    counts = Counter()
    for rule in data["rules"]:
        if not isinstance(rule, dict) or not rule or set(rule) - FIELDS:
            raise ValueError(f"unsupported rule fields: {rule!r}")
        # sing-box combines an IP condition with a domain condition using AND.
        # A flat Surge list uses OR, so reject such a future schema change.
        if "ip_cidr" in rule and any(k in rule for k in FIELDS - {"ip_cidr"}):
            raise ValueError("mixed IP/domain conditions cannot be flattened")
        for key in sorted(rule):
            for value in values(rule[key]):
                if not value or any(c in value for c in "\r\n\x00"):
                    raise ValueError("empty or multiline rule value")
                counts[key] += 1
                if key == "domain_regex":
                    unsupported.append({"field": key, "value": value,
                                        "reason": "Surge RULE-SET does not support DOMAIN-REGEX"})
                elif key == "ip_cidr":
                    if "/" not in value:
                        raise ValueError(f"IP prefix is missing: {value!r}")
                    network = ipaddress.ip_network(value, strict=True)
                    kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
                    converted.append(f"{kind},{network},no-resolve")
                elif key == "domain_suffix":
                    domain_token(value)
                    if value.startswith("."):
                        raise ValueError("subdomain-only suffix requires a different Surge rule")
                    converted.append("DOMAIN-SUFFIX," + value)
                elif key == "domain":
                    converted.append("DOMAIN," + domain_token(value))
                elif key == "domain_keyword":
                    converted.append("DOMAIN-KEYWORD," + domain_token(value))
    return sorted(set(converted)), unsupported, counts


def source_path(member_name):
    path = PurePosixPath(member_name)
    if len(path.parts) < 3 or any(p in ("..", ".") for p in path.parts):
        raise ValueError(f"unsafe archive path: {member_name}")
    relative = PurePosixPath(*path.parts[1:])
    if relative.parts[0] not in ROOTS:
        raise ValueError(f"unexpected upstream directory: {relative}")
    return str(relative)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def convert_archive(archive, output, sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("upstream SHA must be a full commit hash")
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be empty; use a fresh build directory")
    output.mkdir(parents=True, exist_ok=True)
    files = []
    json_paths, srs_paths = set(), set()
    unsupported_records = []
    field_counts = Counter()
    groups = Counter()
    input_total = 0
    output_total = 0
    duplicate_total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if not member.isfile() or not member.name.endswith((".json", ".srs")):
                continue
            path = source_path(member.name)
            if path.endswith(".srs"):
                if path in srs_paths:
                    raise ValueError(f"duplicate source path: {path}")
                srs_paths.add(path)
                continue
            if path in json_paths:
                raise ValueError(f"duplicate source path: {path}")
            json_paths.add(path)
            raw = tar.extractfile(member).read()
            rules, unsupported, counts = convert_rules(json.loads(raw))
            target = str(PurePosixPath(path).with_suffix(".list"))
            groups[str(PurePosixPath(path).parent)] += 1
            field_counts.update(counts)
            input_count = sum(counts.values())
            input_total += input_count
            output_total += len(rules)
            duplicates = input_count - len(unsupported) - len(rules)
            duplicate_total += duplicates
            status = "complete" if not unsupported else "partial" if rules else "unsupported_only"
            source_url = f"https://raw.githubusercontent.com/{UPSTREAM}/{BRANCH}/{path}"
            header = ["# Generated Surge RULE-SET. No policy is embedded.",
                      f"# Source: {source_url}",
                      f"# Status: {status}; emitted: {len(rules)}; unsupported: {len(unsupported)}"]
            if unsupported:
                header.append("# DOMAIN-REGEX entries are preserved in unsupported.json, not approximated.")
            content = ("\n".join(header + rules) + "\n").encode()
            dest = output / target
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
            files.append({"path": target, "source": path, "source_sha256": digest(raw),
                          "sha256": digest(content), "input_rules": input_count,
                          "rules": len(rules), "unsupported": len(unsupported),
                          "deduplicated": duplicates, "status": status})
            for item in unsupported:
                unsupported_records.append({"source": path, **item})
    if not json_paths or {p.removesuffix(".json") for p in json_paths} != {
            p.removesuffix(".srs") for p in srs_paths}:
        raise ValueError("JSON/SRS coverage mismatch; refuse to publish an incomplete snapshot")
    if {PurePosixPath(p).parts[0] for p in json_paths} != ROOTS:
        raise ValueError("snapshot must include geo, geo-lite, and asn")
    files.sort(key=lambda record: record["path"])
    unsupported_records.sort(key=lambda record: (record["source"], record["value"]))
    manifest = {"format_version": 1, "upstream": {"repository": UPSTREAM, "branch": BRANCH,
                "sha": sha, "archive_sha256": digest(Path(archive).read_bytes())},
                "converter_sha256": digest(Path(__file__).read_bytes()),
                "summary": {"rule_sets": len(files), "source_rules": input_total,
                            "emitted_rules": output_total, "unsupported_rules": len(unsupported_records),
                            "deduplicated_rules": duplicate_total,
                            "statuses": dict(sorted(Counter(f["status"] for f in files).items())),
                            "groups": dict(sorted(groups.items())),
                            "fields": dict(sorted(field_counts.items()))}, "files": files}
    write_json(output / "manifest.json", manifest)
    write_json(output / "unsupported.json", {"upstream_sha": sha, "rules": unsupported_records})
    summary = manifest["summary"]
    print(json.dumps({"upstream_sha": sha, **summary}, ensure_ascii=False, indent=2))
    return manifest


def latest_sha():
    result = subprocess.run(["git", "ls-remote", "--heads",
                             f"https://github.com/{UPSTREAM}.git", BRANCH],
                            check=True, capture_output=True, text=True)
    rows = result.stdout.splitlines()
    if len(rows) != 1:
        raise ValueError("cannot resolve the upstream sing branch")
    return rows[0].split()[0]


def download(sha, target):
    request = urllib.request.Request(f"https://codeload.github.com/{UPSTREAM}/tar.gz/{sha}",
                                     headers={"User-Agent": "surge-rules-dat"})
    with urllib.request.urlopen(request, timeout=120) as response, Path(target).open("wb") as dest:
        while chunk := response.read(1024 * 1024):
            dest.write(chunk)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--archive", type=Path, help="use an existing pinned upstream archive")
    parser.add_argument("--sha", help="pinned sing commit (required with --archive)")
    args = parser.parse_args()
    if args.archive and not args.sha:
        parser.error("--archive requires --sha")
    sha = args.sha or latest_sha()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        parser.error("invalid commit SHA")
    if args.archive:
        convert_archive(args.archive, args.output, sha)
    else:
        with tempfile.TemporaryDirectory(prefix="meta-rules-dat-") as temp:
            archive = Path(temp) / "snapshot.tar.gz"
            download(sha, archive)
            convert_archive(archive, args.output, sha)


if __name__ == "__main__":
    main()
