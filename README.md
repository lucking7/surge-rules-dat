# surge-rules-dat

将 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 `sing` 分支同步为 Surge `RULE-SET`，覆盖全部 `geo`、`geo-lite` 和 `asn` 分类。

**[使用说明与最新产物](https://github.com/lucking7/surge-rules-dat/tree/release)** · **[完整分类目录](https://github.com/lucking7/surge-rules-dat/blob/release/CATALOG.md)** · **[同步状态](https://github.com/lucking7/surge-rules-dat/actions/workflows/sync.yml)**

Surge 无法表达的 `domain_regex` 不会静默丢弃或扩大匹配范围。原始记录和受影响分类发布在 `unsupported.json`；详见 [格式边界](docs/usage.md#格式与边界)。因此“覆盖全部分类”不等于“全部规则都能无损转换”。

## 自动更新

每 6 小时由 GitHub Actions 同步，上游快照固定到一个 commit。通过测试、覆盖检查和全部输出规则校验后，发布到 `release` 分支。失败不会覆盖已有产物，不需要额外 Secrets。手动运行 **Actions → Sync Surge rules → Run workflow** 可立即同步。

## 本地构建

需要 Python 3.12+、Git 和 rsync，无 Python 第三方依赖：

```sh
python3 -m unittest discover -s tests -v
python3 scripts/convert.py --output dist
python3 scripts/validate.py dist
python3 scripts/catalog.py dist --repository lucking7/surge-rules-dat
```

`dist` 必须是空目录，重新构建时使用新的输出目录。用已有归档复现：

```sh
python3 scripts/convert.py --archive snapshot.tar.gz --sha <完整上游commit> --output dist
```

在安装 Surge 的 macOS 上，还可对所有唯一输出规则进行原生语法校验：

```sh
python3 scripts/validate.py dist --surge-cli /Applications/Surge.app/Contents/Applications/surge-cli
```

此检查将规则分批写入独立临时 profile 并执行 `--check`，不会切换或修改活动配置。它证明规则语法可接受，不证明真实网络分流效果。CI 在 Linux 上执行 Python 校验，不运行 Surge。

## 设计

- 读取上游 `sing` 分支公开的 JSON 源格式，避免解码二进制 `.srs`。
- 检查 JSON 与 SRS 分类一一对应，拒绝缺失目录、未知字段、异常 CIDR 和重复归档路径，并检查 Surge 单集合 100 万条规则的上限。
- 一一保留分类路径；规则排序去重；IPv4 和 IPv6 分别输出正确类型。
- 来源、校验值、规则数量及正则缺口保存在 `manifest.json` 和 `unsupported.json`。
- [上游转换器](https://github.com/MetaCubeX/meta-rules-converter)说明数据生成过程。[Surge RULE-SET 文档](https://manual.nssurge.com/rules/ruleset.html)说明目标格式。

## 许可

GPL-3.0，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE.md)。
