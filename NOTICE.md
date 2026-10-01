# Provenance and notices

This project converts the published `sing` branch of:

- https://github.com/MetaCubeX/meta-rules-dat
- Upstream conversion implementation: https://github.com/MetaCubeX/meta-rules-converter

The upstream rule repository distributes a GNU GPL version 3 license, reproduced in LICENSE. Rule data remains attributed to MetaCubeX and its upstream contributors. See the upstream README for its full source and acknowledgments list. Conversion does not transfer ownership of the original data or replace source-specific notices and terms.

The Python converter and synchronization workflow are provided under GPL-3.0. The rule files are mechanically converted from the upstream JSON source; no proxy policy is assigned. Regex rules unsupported by Surge RULE-SET are preserved in a separate report.

Every generated snapshot records the immutable upstream commit and input/output SHA-256 values in manifest.json. Source JSON files can be obtained from that commit. Conversion source is available in this repository's main branch.
