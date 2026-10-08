# Surge rules dat

从 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 `sing` 分支自动生成 Surge `RULE-SET`。

保留所有 `geo`、`geo-lite`、`asn` 分类和属性分类（例如 `steam@cn`）。每个上游 JSON 对应一个同路径的 `.list`。源代码在 [`main` 分支](https://github.com/lucking7/surge-rules-dat/tree/main)，生成文件在 [`release` 分支](https://github.com/lucking7/surge-rules-dat/tree/release)。

## 使用

在 Surge 配置的 `[Rule]` 中引用所需分类，策略名使用你配置中实际存在的名称：

```ini
[Rule]
RULE-SET,https://raw.githubusercontent.com/lucking7/surge-rules-dat/release/geo/geosite/openai.list,PROXY,update-interval=86400
RULE-SET,https://raw.githubusercontent.com/lucking7/surge-rules-dat/release/geo/geosite/youtube.list,PROXY,update-interval=86400
RULE-SET,https://raw.githubusercontent.com/lucking7/surge-rules-dat/release/geo/geosite/cn.list,DIRECT,update-interval=86400
RULE-SET,https://raw.githubusercontent.com/lucking7/surge-rules-dat/release/geo/geoip/cn.list,DIRECT,no-resolve,update-interval=86400
FINAL,PROXY
```

规则按配置顺序匹配。示例中的 `PROXY` 需要替换为你的代理策略或策略组；仓库不提供代理节点或完整配置。按需引用分类即可，无需同时加载所有 ASN 文件。

路径：

- `geo/geosite/<分类>.list`：域名、域名后缀和关键词。
- `geo/geoip/<分类>.list`：IPv4/IPv6 CIDR。
- `geo-lite/geosite/<分类>.list`、`geo-lite/geoip/<分类>.list`：上游精简集合。
- `geo-lite/<分类>.list`：同名精简域名与 IP 集合的合并入口。
- `asn/AS<编号>.list`：ASN 对应的 IPv4/IPv6 CIDR，例如 `asn/AS13335.list`。

### 精简分类只用一条 URL

同一分类的域名和 IP 需要走同一策略时，使用 `geo-lite/<分类>.list`。例如国内分流只需：

```ini
RULE-SET,https://raw.githubusercontent.com/lucking7/surge-rules-dat/release/geo-lite/cn.list,DIRECT,update-interval=86400
```

这个文件是 `geo-lite/geosite/cn.list` 与 `geo-lite/geoip/cn.list` 的并集，按行排序去重，IP 规则保留 `no-resolve`。所有精简分类都有统一入口，例如 `geo-lite/apple.list`、`geo-lite/netflix.list`、`geo-lite/openai.list`。分类只有域名或只有 IP 时，入口包含现有的一边，不额外补充其他来源。

原来的分离 URL 继续提供。若域名和 IP 要走不同策略，请分别引用原文件；合并文件中的任一域名或 IP 命中，都会使用这一条 `RULE-SET` 指定的策略。正则缺口会从来源分类传递到合并入口。

## 格式与边界

| sing-box 字段 | Surge 输出 |
| --- | --- |
| `domain` | `DOMAIN` |
| `domain_suffix` | `DOMAIN-SUFFIX` |
| `domain_keyword` | `DOMAIN-KEYWORD` |
| `ip_cidr` IPv4 | `IP-CIDR,...,no-resolve` |
| `ip_cidr` IPv6 | `IP-CIDR6,...,no-resolve` |
| `domain_regex` | 无法用于 Surge RULE-SET，原值保留在 `unsupported.json` |

每条源规则必须至少包含一个非空匹配值。所有字段都为空数组的规则对象会使构建失败；同一规则中其他字段有匹配值时，允许空数组字段。

Surge 不支持 `DOMAIN-REGEX`。此仓库不把正则改成更宽泛的后缀或通配符。含正则的分类标记为 `partial`，纯正则分类标记为 `unsupported_only`，后者的 `.list` 只有注释，不能提供有效匹配。分类目录、清单和每个文件头都会明确标注。

IP 规则设置 `no-resolve`，避免仅为了匹配 IP 规则而对域名进行 DNS 查询。它匹配已经知道的目标 IP；DNS 解析与代理连接策略由使用者的 Surge 配置决定。

## 同步

GitHub Actions 每 6 小时检查并重新生成，也支持手动运行；GitHub 调度可能延迟。每次固定一个上游 commit，再下载该 commit 的完整快照，避免混合不同时间的数据。校验通过后才发布到 `release`；失败保留上一次成功版本，Actions 会显示失败。若首次运行失败，`release` 尚不存在。

生成结果完全替换本仓库的产物，因此上游删除的分类也会删除，合并入口随来源重新生成。发布保留 Git 历史，不 force push。相同输入与转换器生成相同文件，不产生空提交。`manifest.json` 保存来源 commit、源文件和产物 SHA-256、规则数量及转换状态，`merged_files` 单独记录合并文件及其来源，避免重复计算上游规则。

更新源代码后会自动触发同步，手动触发入口是仓库的 **Actions → Sync Surge rules → Run workflow**。长期无人维护的仓库可能被 GitHub 暂停定时 workflow，可在 Actions 页面恢复。

## 来源

规则来源为 MetaCubeX 及其整合的上游项目，详见 [MetaCubeX README](https://github.com/MetaCubeX/meta-rules-dat#readme)。项目携带上游 GPL-3.0 LICENSE 和 NOTICE；原始规则及各上游的版权声明和适用条款保留归原作者。

## 当前快照

上游 commit：[`af31d411549a`](https://github.com/MetaCubeX/meta-rules-dat/commit/af31d411549a7c5f50c960d1e2d78639c0842903)。

共 84,303 个规则集，输出 2,399,616 条规则，另有 403 条正则记录无法用于 Surge RULE-SET。

额外提供 27 个 `geo-lite/<分类>.list` 合并入口。合并入口是已有规则的并集，不重复计入上游规则统计。

[分类目录](CATALOG.md)、[完整清单与校验值](manifest.json)、[无法转换的原始规则](unsupported.json)。
