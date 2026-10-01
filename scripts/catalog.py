#!/usr/bin/env python3
"""Render the usage guide and the non-ASN rule catalog for the release branch."""

import argparse
import json
from pathlib import Path
from urllib.parse import quote


def catalog(output, repository):
    output = Path(output)
    manifest = json.loads((output / "manifest.json").read_text())
    summary = manifest["summary"]
    sha = manifest["upstream"]["sha"]
    base = f"https://raw.githubusercontent.com/{repository}/release/"
    guide = (Path(__file__).resolve().parents[1] / "docs/usage.md").read_text()
    guide = guide.replace("{{REPOSITORY}}", repository)
    status = (f"\n## 当前快照\n\n上游 commit：[`{sha[:12]}`]"
              f"(https://github.com/MetaCubeX/meta-rules-dat/commit/{sha})。\n\n"
              f"共 {summary['rule_sets']:,} 个规则集，输出 {summary['emitted_rules']:,} 条规则，"
              f"另有 {summary['unsupported_rules']:,} 条正则记录无法用于 Surge RULE-SET。\n\n"
              "[分类目录](CATALOG.md)、[完整清单与校验值](manifest.json)、"
              "[无法转换的原始规则](unsupported.json)。\n")
    (output / "README.md").write_text(guide + status)
    rows = ["# 分类目录", "", "ASN 分类见 manifest.json，路径为 `asn/AS编号.list`。", "",
            "`partial` 表示包含无法转换的正则；`unsupported_only` 表示没有可供 RULE-SET 使用的规则。", "",
            "| 分类 | 输出规则数 | 正则数 | 状态 |", "| --- | ---: | ---: | --- |"]
    for record in manifest["files"]:
        if record["path"].startswith("asn/"):
            continue
        path = record["path"]
        rows.append(f"| [{path}]({base}{quote(path, safe='/')}) | {record['rules']} | "
                    f"{record['unsupported']} | {record['status']} |")
    (output / "CATALOG.md").write_text("\n".join(rows) + "\n")
    root = Path(__file__).resolve().parents[1]
    for name in ("LICENSE", "NOTICE.md"):
        (output / name).write_bytes((root / name).read_bytes())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repository", default="lucking7/surge-rules-dat")
    args = parser.parse_args()
    catalog(args.output, args.repository)
