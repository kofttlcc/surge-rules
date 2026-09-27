#!/usr/bin/env python3
"""Build validated, reproducible Shadowrocket rules from surge-rules/release.

Uses only the Python standard library. Input is a checkout of the upstream
release branch, not the source branch or files downloaded from arbitrary URLs.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import NamedTuple


UPSTREAM_REPOSITORY = "Loyalsoldier/surge-rules"
DEFAULT_REPOSITORY = "kofttlcc/surge-rules"
RULE_NAMES = (
    "private", "reject", "icloud", "apple", "google", "proxy", "direct",
    "gfw", "greatfire", "tld-not-cn", "telegramcidr", "cncidr",
)
CIDR_NAMES = frozenset({"telegramcidr", "cncidr"})
LAN_NETWORKS = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)


class ValidationError(ValueError):
    """An input cannot safely be published as a Shadowrocket rule set."""


class ConvertedRules(NamedTuple):
    content: bytes
    input_rule_count: int
    output_rule_count: int


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_name(value: str) -> str:
    """Validate a DNS name, including IDNA and underscore service labels.

    A leading dot is handled only by the custom-domain parser. Wildcards,
    URLs, ports, IP addresses, empty labels and whitespace are not domains.
    """
    if not value or value != value.strip() or any(c.isspace() for c in value):
        raise ValidationError("empty domain or whitespace in domain")
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError("invalid IDNA domain") from exc
    if len(normalized) > 253:
        raise ValidationError("domain exceeds 253 characters")
    labels = normalized.split(".")
    for label in labels:
        if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label):
            raise ValidationError(f"invalid DNS label: {label!r}")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise ValidationError("IP address supplied as a domain")
    return normalized


def active_lines(data: bytes, source_name: str):
    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{source_name}: input is not UTF-8") from exc
    for number, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "<" in line or ">" in line or "\x00" in line:
            raise ValidationError(f"{source_name}:{number}: HTML or invalid control data")
        yield number, line


def convert_rules(data: bytes, name: str, *, custom: bool = False) -> ConvertedRules:
    """Validate one list, normalize syntax, and deduplicate in source order.

    China CIDRs deliberately omit no-resolve: domain traffic that has not
    matched a domain list must still be eligible for China-IP direct routing.
    Telegram CIDRs use no-resolve to avoid an unnecessary DNS lookup there.
    """
    output: list[str] = []
    seen: set[str] = set()
    input_count = 0
    for number, line in active_lines(data, name):
        input_count += 1
        try:
            if custom:
                suffix = line.startswith(".")
                value = domain_name(line[1:] if suffix else line)
                result = f"{'DOMAIN-SUFFIX' if suffix else 'DOMAIN'},{value}"
            else:
                fields = [field.strip() for field in line.split(",")]
                rule_type = fields[0]
                if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
                    if name in CIDR_NAMES:
                        raise ValidationError("domain entry in a CIDR-only list")
                    if len(fields) != 2:
                        raise ValidationError("domain rules require exactly two fields")
                    result = f"{rule_type},{domain_name(fields[1])}"
                elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
                    if name not in CIDR_NAMES:
                        raise ValidationError("CIDR entry in a domain-only list")
                    if len(fields) not in {2, 3} or (
                        len(fields) == 3 and fields[2] != "no-resolve"
                    ):
                        raise ValidationError("CIDR rules accept only an optional no-resolve flag")
                    if "/" not in fields[1]:
                        raise ValidationError("CIDR prefix length is required")
                    try:
                        network = ipaddress.ip_network(fields[1], strict=True)
                    except ValueError as exc:
                        raise ValidationError(f"invalid CIDR: {fields[1]!r}") from exc
                    if rule_type == "IP-CIDR6" and network.version != 6:
                        raise ValidationError("IP-CIDR6 requires an IPv6 network")
                    flag = "" if name == "cncidr" else ",no-resolve"
                    result = f"IP-CIDR,{network}{flag}"
                else:
                    raise ValidationError(f"unsupported rule type: {rule_type!r}")
        except ValidationError as exc:
            raise ValidationError(f"{name}:{number}: {exc}") from exc
        if result not in seen:
            seen.add(result)
            output.append(result)
    if not output:
        raise ValidationError(f"{name}: required rule list is empty")
    return ConvertedRules(("\n".join(output) + "\n").encode(), input_count, len(output))


def configuration(repository: str, *, lite: bool) -> bytes:
    base = f"https://raw.githubusercontent.com/{repository}/shadowrocket-release/rules"
    lines = [
        "# Shadowrocket for iOS — generated configuration",
        "# PROXY uses your existing selected node; this file contains no node credentials.",
        "# Use configuration routing mode. Unknown destinations default to PROXY.",
        "# Lite omits the reject list." if lite else "# Full includes the upstream reject list.",
        "", "[General]", "dns-server = system", "ipv6 = true",
        "prefer-ipv6 = false", "private-ip-answer = true", "", "[Rule]",
        "# Custom direct exceptions take precedence over every remote list.",
        f"RULE-SET,{base}/custom-direct.list,DIRECT",
        "# Local IP destinations are direct; no-resolve avoids triggering DNS here.",
    ]
    lines.extend(f"IP-CIDR,{network},DIRECT,no-resolve" for network in LAN_NETWORKS)
    lines.append(f"RULE-SET,{base}/private.list,DIRECT")
    if not lite:
        lines.append(f"RULE-SET,{base}/reject.list,REJECT")
    lines.extend([
        f"RULE-SET,{base}/icloud.list,DIRECT",
        f"RULE-SET,{base}/apple.list,DIRECT",
        f"RULE-SET,{base}/proxy.list,PROXY",
        f"RULE-SET,{base}/direct.list,DIRECT",
        f"RULE-SET,{base}/telegramcidr.list,PROXY",
        "# China CIDRs allow DNS resolution for domains not covered above.",
        f"RULE-SET,{base}/cncidr.list,DIRECT",
        "FINAL,PROXY", "",
    ])
    return "\n".join(lines).encode("utf-8")


def release_readme(repository: str, upstream_sha: str) -> bytes:
    base = f"https://raw.githubusercontent.com/{repository}/shadowrocket-release"
    text = f"""# Shadowrocket iOS 規則發佈

由 [{UPSTREAM_REPOSITORY}](https://github.com/{UPSTREAM_REPOSITORY}) 的 release
提交 [`{upstream_sha}`](https://github.com/{UPSTREAM_REPOSITORY}/commit/{upstream_sha}) 轉換。
這個分支是自動生成的產物；請在主分支修改轉換程式或 `coustom-direct`。

## 匯入

先在 Shadowrocket 新增或保留可用節點。在「配置」中以 URL 新增配置，下載後啟用，
再將全局路由設為「配置」，並選擇可用節點。

- [完整配置（含廣告／追蹤攔截）]({base}/shadowrocket.conf)
- [精簡配置（不載入 reject 規則）]({base}/shadowrocket-lite.conf)

配置使用 Shadowrocket 內建的 `PROXY` 策略，指向目前選擇的代理節點，
不包含節點、訂閱、密碼或解密設定。

## 預設路由

依次為：自訂直連、區域網路、private、reject（完整版本）、iCloud、Apple、
proxy、direct、Telegram IP、中國 IP，最後未匹配流量走代理。
自訂清單中裸域名為精確匹配，前導 `.` 為域名及其子域名匹配。

IPv6 CIDR 轉為 Shadowrocket 的 `IP-CIDR` 語法。區域網路與 Telegram CIDR
使用 `no-resolve`；中國 CIDR 不加此標記，讓未命中域名清單的請求仍可透過
DNS 解析後的中國 IP 直連。`ipv6 = true` 保留 IPv6 路由。

`google`、`gfw`、`greatfire`、`tld-not-cn` 清單亦提供下載，預設配置未啟用。
所有遠端規則 URL 均指向本倉庫的 `shadowrocket-release` 分支。

`metadata.json` 記錄上游提交、每份輸入／輸出的規則數與 SHA-256，
可核對發佈來源。轉換遇到遺漏、空清單或不支援格式時會停止。
上游授權條款見 [LICENSE](LICENSE)。
"""
    return text.encode("utf-8")


def build(
    source_dir: Path,
    output_dir: Path,
    upstream_sha: str,
    repository: str = DEFAULT_REPOSITORY,
    custom_direct: Path = Path("coustom-direct"),
) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", upstream_sha):
        raise ValidationError("--upstream-sha must be a full 40-character Git SHA")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ValidationError("--repository must be owner/repository")
    upstream_sha = upstream_sha.lower()
    if source_dir.resolve() == output_dir.resolve():
        raise ValidationError("source and output directories must differ")
    artifacts: dict[str, bytes] = {}
    records: dict[str, dict] = {}
    inputs = [(name, source_dir / "ruleset" / f"{name}.txt", False) for name in RULE_NAMES]
    inputs.append(("custom-direct", custom_direct, True))
    for name, path, custom in inputs:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValidationError(f"cannot read required input {path}: {exc}") from exc
        converted = convert_rules(data, name, custom=custom)
        relative = f"rules/{name}.list"
        artifacts[relative] = converted.content
        records[relative] = {
            "input": path.name if custom else f"ruleset/{name}.txt",
            "input_sha256": sha256(data),
            "output_sha256": sha256(converted.content),
            "input_rule_count": converted.input_rule_count,
            "output_rule_count": converted.output_rule_count,
            "duplicates_removed": converted.input_rule_count - converted.output_rule_count,
        }
    license_path = source_dir / "LICENSE"
    if not license_path.is_file():
        license_path = Path(__file__).resolve().parents[1] / "LICENSE"
    try:
        license_bytes = license_path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"cannot read upstream LICENSE: {exc}") from exc
    if not license_bytes.strip():
        raise ValidationError("LICENSE is empty")
    artifacts["LICENSE"] = license_bytes
    artifacts["shadowrocket.conf"] = configuration(repository, lite=False)
    artifacts["shadowrocket-lite.conf"] = configuration(repository, lite=True)
    artifacts["README.md"] = release_readme(repository, upstream_sha)
    metadata = {
        "schema_version": 1,
        "upstream": {"repository": UPSTREAM_REPOSITORY, "branch": "release", "sha": upstream_sha},
        "repository": repository,
        "release_branch": "shadowrocket-release",
        "rules": records,
        "artifacts": {
            name: {"sha256": sha256(content), "bytes": len(content)}
            for name, content in sorted(artifacts.items()) if name not in records
        },
    }
    artifacts["metadata.json"] = (json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    # Validate and render every input before writing any release artifact.
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative, content in artifacts.items():
        target = output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--upstream-sha", required=True)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--custom-direct", type=Path, default=Path("coustom-direct"))
    args = parser.parse_args(argv)
    try:
        metadata = build(args.source_dir, args.output_dir, args.upstream_sha, args.repository, args.custom_direct)
    except (ValidationError, OSError) as exc:
        print(f"Shadowrocket build failed: {exc}", file=sys.stderr)
        return 1
    count = sum(record["output_rule_count"] for record in metadata["rules"].values())
    print(f"Built {len(metadata['rules'])} rule lists ({count:,} rules) in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
