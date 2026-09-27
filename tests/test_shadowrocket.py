"""Regression checks for data integrity and the generated routing policy."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_shadowrocket.py"
SPEC = importlib.util.spec_from_file_location("build_shadowrocket", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class RuleValidationTests(unittest.TestCase):
    def test_domain_identity_order_deduplication_and_idna(self):
        data = b"# header\nDOMAIN,Example.com\nDOMAIN-SUFFIX,example.com\nDOMAIN,example.com\n"
        result = builder.convert_rules(data, "proxy")
        self.assertEqual(result.content, b"DOMAIN,example.com\nDOMAIN-SUFFIX,example.com\n")
        self.assertEqual((result.input_rule_count, result.output_rule_count), (3, 2))
        self.assertEqual(builder.domain_name("例子.測試"), "xn--fsqu00a.xn--g6w251d")

    def test_custom_exact_and_suffix_are_distinct(self):
        result = builder.convert_rules(b"time.apple.com\n.time.apple.com\n.gdmf.apple.com\n", "custom-direct", custom=True)
        self.assertEqual(result.content, b"DOMAIN,time.apple.com\nDOMAIN-SUFFIX,time.apple.com\nDOMAIN-SUFFIX,gdmf.apple.com\n")

    def test_ipv6_conversion_and_china_dns_fallback(self):
        raw = b"IP-CIDR,1.0.0.0/24,no-resolve\nIP-CIDR6,2400:3200::/32,no-resolve\n"
        self.assertEqual(builder.convert_rules(raw, "cncidr").content,
                         b"IP-CIDR,1.0.0.0/24\nIP-CIDR,2400:3200::/32\n")
        self.assertEqual(builder.convert_rules(raw, "telegramcidr").content,
                         b"IP-CIDR,1.0.0.0/24,no-resolve\nIP-CIDR,2400:3200::/32,no-resolve\n")

    def test_cidr_normalization_deduplicates_equivalent_ipv6(self):
        raw = b"IP-CIDR6,2400:0320::/32\nIP-CIDR,2400:320:0:0::/32,no-resolve\n"
        result = builder.convert_rules(raw, "telegramcidr")
        self.assertEqual(result.content, b"IP-CIDR,2400:320::/32,no-resolve\n")
        self.assertEqual(result.output_rule_count, 1)

    def test_rejects_invalid_data_instead_of_silently_skipping(self):
        cases = [
            (b"", "proxy"), (b"# only comments\n", "proxy"),
            (b"<!DOCTYPE html>\n<html>502</html>", "proxy"),
            (b"DOMAIN-SUFFIX,valid.com\nURL-REGEX,.*", "proxy"),
            (b"DOMAIN-SUFFIX,example.com,PROXY", "proxy"),
            (b"DOMAIN-SUFFIX,.example.com", "proxy"),
            (b"DOMAIN,https://example.com", "proxy"),
            (b"DOMAIN,example.com/path", "proxy"),
            (b"DOMAIN,*.example.com", "proxy"),
            (b"DOMAIN,example..com", "proxy"),
            (b"DOMAIN,-example.com", "proxy"),
            (b"DOMAIN,127.0.0.1", "proxy"),
            (b"DOMAIN,ex ample.com", "proxy"),
            (b"DOMAIN,example.com\x00", "proxy"),
            (b"\xff", "proxy"),
            (b"IP-CIDR,10.0.0.1/8", "cncidr"),
            (b"IP-CIDR,10.0.0.0/33", "cncidr"),
            (b"IP-CIDR,10.0.0.1", "cncidr"),
            (b"IP-CIDR6,10.0.0.0/8", "cncidr"),
            (b"IP-CIDR,10.0.0.0/8,DIRECT", "cncidr"),
            (b"IP-CIDR,10.0.0.0/8,no-resolve,extra", "cncidr"),
            (b"DOMAIN,example.com", "cncidr"),
            (b"IP-CIDR,10.0.0.0/8", "proxy"),
        ]
        for data, name in cases:
            with self.subTest(data=data, name=name):
                with self.assertRaises(builder.ValidationError):
                    builder.convert_rules(data, name)


class BuildTests(unittest.TestCase):
    SHA = "0123456789abcdef0123456789abcdef01234567"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.output = self.root / "output"
        (self.source / "ruleset").mkdir(parents=True)
        for name in builder.RULE_NAMES:
            content = "IP-CIDR,1.0.0.0/24\nIP-CIDR6,2400::/12\n" if name in builder.CIDR_NAMES else "DOMAIN-SUFFIX,example.com\n"
            (self.source / "ruleset" / f"{name}.txt").write_text(content)
        (self.source / "LICENSE").write_text("Fixture upstream license\n")
        self.custom = self.root / "coustom-direct"
        self.custom.write_text(".time.apple.com\n.gdmf.apple.com\n")

    def build(self, output=None):
        return builder.build(self.source, output or self.output, self.SHA, "owner/repo", self.custom)

    def test_reproducible_outputs_and_source_hashes(self):
        metadata = self.build()
        second = self.root / "second"
        self.build(second)
        files = sorted(path.relative_to(self.output) for path in self.output.rglob("*") if path.is_file())
        self.assertEqual(len(files), len(builder.RULE_NAMES) + 6)
        for relative in files:
            self.assertEqual((self.output / relative).read_bytes(), (second / relative).read_bytes())
        self.assertEqual(json.loads((self.output / "metadata.json").read_text()), metadata)
        for relative, record in metadata["rules"].items():
            source = self.custom if relative.endswith("custom-direct.list") else self.source / record["input"]
            self.assertEqual(record["input_sha256"], builder.sha256(source.read_bytes()))
            self.assertEqual(record["output_sha256"], builder.sha256((self.output / relative).read_bytes()))
        self.assertEqual((self.output / "LICENSE").read_bytes(), (self.source / "LICENSE").read_bytes())
        self.assertEqual(metadata["upstream"]["sha"], self.SHA)

    def test_missing_or_late_invalid_input_leaves_output_unwritten(self):
        (self.source / "ruleset" / "cncidr.txt").write_text("<html>upstream error</html>")
        with self.assertRaises(builder.ValidationError):
            self.build()
        self.assertFalse(self.output.exists())
        (self.source / "ruleset" / "cncidr.txt").unlink()
        with self.assertRaises(builder.ValidationError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_rejects_partial_sha_and_repository_url_injection(self):
        for sha, repository in [("0123456", "owner/repo"), (self.SHA, "owner/repo\nFINAL,DIRECT")]:
            with self.subTest(sha=sha, repository=repository):
                with self.assertRaises(builder.ValidationError):
                    builder.build(self.source, self.output, sha, repository, self.custom)
        self.assertFalse(self.output.exists())

    def test_config_routing_precedence_and_lite_difference(self):
        self.build()
        full = (self.output / "shadowrocket.conf").read_text()
        lite = (self.output / "shadowrocket-lite.conf").read_text()
        full_rules = full.split("[Rule]\n", 1)[1].splitlines()
        full_rules = [line for line in full_rules if line and not line.startswith("#")]
        lite_rules = lite.split("[Rule]\n", 1)[1].splitlines()
        lite_rules = [line for line in lite_rules if line and not line.startswith("#")]
        self.assertEqual(lite_rules, [line for line in full_rules if "/reject.list," not in line])
        self.assertTrue(full_rules[0].endswith("/custom-direct.list,DIRECT"))
        self.assertEqual(full_rules[-1], "FINAL,PROXY")
        rulesets = [line.split("/")[-1] for line in full_rules if line.startswith("RULE-SET,")]
        self.assertEqual(rulesets, [
            "custom-direct.list,DIRECT", "private.list,DIRECT", "reject.list,REJECT",
            "icloud.list,DIRECT", "apple.list,DIRECT", "proxy.list,PROXY",
            "direct.list,DIRECT", "telegramcidr.list,PROXY", "cncidr.list,DIRECT",
        ])
        self.assertIn("IP-CIDR,fc00::/7,DIRECT,no-resolve", full_rules)
        self.assertIn("https://raw.githubusercontent.com/owner/repo/shadowrocket-release/rules/", full)
        for unsupported in ["[Proxy]", "[Proxy Group]", "PROCESS-NAME", "force-remote-dns", "dns-failed", "google.list", "IP-CIDR6", "bypass-system"]:
            self.assertNotIn(unsupported, full)


if __name__ == "__main__":
    unittest.main()
