import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import sshd_checker as sc

GOOD = """
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
AllowGroups ssh-users
X11Forwarding no
"""


def rules(text):
    settings, _ = sc.parse_config(text)
    return {f["rule"] for f in sc.check_config(settings)}


class ParseTests(unittest.TestCase):
    def test_comments_and_blank_lines(self):
        settings, _ = sc.parse_config("# note\n\nPort 22\n")
        self.assertEqual(settings, {"port": "22"})

    def test_keys_are_case_insensitive(self):
        settings, _ = sc.parse_config("permitrootlogin NO\n")
        self.assertEqual(settings["permitrootlogin"], "NO")

    def test_equals_sign_form(self):
        settings, _ = sc.parse_config("PermitRootLogin=yes\nPort = 2222\n")
        self.assertEqual(settings["permitrootlogin"], "yes")
        self.assertEqual(settings["port"], "2222")

    def test_first_value_wins(self):
        settings, _ = sc.parse_config("PermitRootLogin no\nPermitRootLogin yes\n")
        self.assertEqual(settings["permitrootlogin"], "no")

    def test_match_block_is_ignored(self):
        settings, has_match = sc.parse_config("PermitRootLogin no\nMatch User bob\n  PermitRootLogin yes\n")
        self.assertTrue(has_match)
        self.assertEqual(settings["permitrootlogin"], "no")

    def test_quoted_value(self):
        settings, _ = sc.parse_config('AllowUsers "alice"\n')
        self.assertEqual(settings["allowusers"], "alice")

    def test_key_without_value(self):
        settings, _ = sc.parse_config("Compression\n")
        self.assertEqual(settings["compression"], "")


class RuleTests(unittest.TestCase):
    def test_good_config_is_clean(self):
        self.assertEqual(rules(GOOD), set())

    def test_root_login(self):
        self.assertIn("root-login", rules("PermitRootLogin yes"))
        self.assertNotIn("root-login", rules("PermitRootLogin prohibit-password"))
        self.assertNotIn("root-login", rules("PermitRootLogin no"))
        self.assertNotIn("root-login", rules(""))

    def test_empty_passwords(self):
        self.assertIn("empty-passwords", rules("PermitEmptyPasswords yes"))
        self.assertNotIn("empty-passwords", rules("PermitEmptyPasswords no"))

    def test_protocol_1(self):
        self.assertIn("protocol-1", rules("Protocol 2,1"))
        self.assertIn("protocol-1", rules("Protocol 1"))
        self.assertNotIn("protocol-1", rules("Protocol 2"))

    def test_password_auth_explicit_and_default(self):
        self.assertIn("password-auth", rules("PasswordAuthentication yes"))
        self.assertIn("password-auth", rules("Port 22"))
        self.assertNotIn("password-auth", rules("PasswordAuthentication no"))

    def test_password_auth_message_mentions_default(self):
        settings, _ = sc.parse_config("Port 22")
        found = [f for f in sc.check_config(settings) if f["rule"] == "password-auth"]
        self.assertIn("default", found[0]["message"])

    def test_pubkey_disabled(self):
        self.assertIn("pubkey-disabled", rules("PubkeyAuthentication no"))

    def test_max_auth_tries_edge(self):
        self.assertNotIn("max-auth-tries", rules("MaxAuthTries 6"))
        self.assertIn("max-auth-tries", rules("MaxAuthTries 7"))
        self.assertNotIn("max-auth-tries", rules("MaxAuthTries lots"))

    def test_yes_means_risky_switches(self):
        for key, rule in (("HostbasedAuthentication", "hostbased-auth"),
                          ("PermitUserEnvironment", "user-environment"),
                          ("GatewayPorts", "gateway-ports")):
            self.assertIn(rule, rules("%s yes" % key))
            self.assertNotIn(rule, rules("%s no" % key))

    def test_no_means_risky_switches(self):
        self.assertIn("rhosts", rules("IgnoreRhosts no"))
        self.assertIn("strict-modes", rules("StrictModes no"))
        self.assertNotIn("strict-modes", rules("StrictModes yes"))

    def test_weak_ciphers(self):
        self.assertIn("weak-ciphers", rules("Ciphers aes128-cbc,aes256-ctr"))
        self.assertIn("weak-ciphers", rules("Ciphers 3des-cbc"))
        self.assertNotIn("weak-ciphers", rules("Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"))

    def test_cipher_prefix_characters(self):
        self.assertIn("weak-ciphers", rules("Ciphers +aes128-cbc"))

    def test_weak_macs(self):
        self.assertIn("weak-macs", rules("MACs hmac-md5,hmac-sha2-256"))
        self.assertIn("weak-macs", rules("MACs hmac-sha1-96"))
        self.assertNotIn("weak-macs", rules("MACs hmac-sha2-512-etm@openssh.com"))

    def test_x11(self):
        self.assertIn("x11-forwarding", rules("X11Forwarding yes"))
        self.assertNotIn("x11-forwarding", rules("X11Forwarding no"))

    def test_login_grace(self):
        self.assertIn("login-grace", rules("LoginGraceTime 2m"))
        self.assertIn("login-grace", rules("LoginGraceTime 120"))
        self.assertIn("login-grace", rules("LoginGraceTime 0"))
        self.assertNotIn("login-grace", rules("LoginGraceTime 60"))
        self.assertNotIn("login-grace", rules("LoginGraceTime 30s"))
        self.assertNotIn("login-grace", rules("LoginGraceTime soon"))

    def test_idle_timeout(self):
        self.assertIn("no-idle-timeout", rules("Port 22"))
        self.assertIn("no-idle-timeout", rules("ClientAliveInterval 0"))
        self.assertNotIn("no-idle-timeout", rules("ClientAliveInterval 300"))

    def test_allowlist(self):
        self.assertIn("no-allowlist", rules("Port 22"))
        self.assertNotIn("no-allowlist", rules("AllowUsers alice"))
        self.assertNotIn("no-allowlist", rules("AllowGroups ops"))

    def test_seconds_helper(self):
        self.assertEqual(sc._seconds("90"), 90)
        self.assertEqual(sc._seconds("2m"), 120)
        self.assertEqual(sc._seconds("1h"), 3600)
        self.assertIsNone(sc._seconds("abc"))


class OutputTests(unittest.TestCase):
    def test_sorted_high_first(self):
        settings, _ = sc.parse_config("PermitRootLogin yes\nX11Forwarding yes\n")
        order = [sc.SEVERITIES[f["severity"]] for f in sc.check_config(settings)]
        self.assertEqual(order, sorted(order, reverse=True))

    def test_filter(self):
        settings, _ = sc.parse_config("PermitRootLogin yes\n")
        high = sc.filter_findings(sc.check_config(settings), "high")
        self.assertTrue(all(f["severity"] == "high" for f in high))

    def test_text_and_json(self):
        settings, _ = sc.parse_config("PermitRootLogin yes\n")
        results = [("a.conf", sc.check_config(settings))]
        self.assertIn("root-login", sc.format_text(results))
        self.assertEqual(json.loads(sc.format_json(results))[0]["config"], "a.conf")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, text, mode="w"):
        path = os.path.join(self.dir.name, name)
        with open(path, mode) as handle:
            handle.write(text)
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = sc.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        code, out, _ = self.run_cli(self.write("a.conf", GOOD))
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_high_exit_1(self):
        self.assertEqual(self.run_cli(self.write("a.conf", "PermitRootLogin yes\n"))[0], 1)

    def test_fail_on(self):
        path = self.write("a.conf", GOOD.replace("X11Forwarding no", "X11Forwarding yes"))
        self.assertEqual(self.run_cli(path)[0], 0)
        self.assertEqual(self.run_cli(path, "--fail-on", "low")[0], 1)

    def test_min_severity(self):
        path = self.write("a.conf", GOOD.replace("X11Forwarding no", "X11Forwarding yes"))
        _, out, _ = self.run_cli(path, "--min-severity", "medium")
        self.assertNotIn("x11-forwarding", out)

    def test_json(self):
        path = self.write("a.conf", "PermitRootLogin yes\n")
        _, out, _ = self.run_cli(path, "--format", "json")
        self.assertEqual(json.loads(out)[0]["findings"][0]["rule"], "root-login")

    def test_first_value_wins_in_cli(self):
        path = self.write("a.conf", GOOD + "PermitRootLogin yes\n")
        self.assertEqual(self.run_cli(path)[0], 0)

    def test_missing_file(self):
        code, _, err = self.run_cli(os.path.join(self.dir.name, "none.conf"))
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_binary_file(self):
        code, _, err = self.run_cli(self.write("bin.conf", b"\xff\xfe\x00\x80", mode="wb"))
        self.assertEqual(code, 2)
        self.assertIn("not a text file", err)

    def test_match_note(self):
        path = self.write("a.conf", GOOD + "Match User bob\n  PermitRootLogin yes\n")
        code, _, err = self.run_cli(path)
        self.assertEqual(code, 0)
        self.assertIn("Match", err)

    def test_empty_file_still_checks_defaults(self):
        code, out, _ = self.run_cli(self.write("empty.conf", ""))
        self.assertIn("password-auth", out)
        self.assertEqual(code, 0)


class SampleTests(unittest.TestCase):
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_configs")

    def findings(self, name):
        settings, _ = sc.load_config(os.path.join(self.base, name))
        return sc.check_config(settings)

    def test_risky(self):
        found = self.findings("01_risky_server.conf")
        self.assertEqual(len(found), 12)
        self.assertEqual(sum(f["severity"] == "high" for f in found), 3)

    def test_default_style(self):
        self.assertEqual(len(self.findings("02_default_style.conf")), 4)

    def test_hardened(self):
        self.assertEqual(self.findings("03_hardened.conf"), [])


if __name__ == "__main__":
    unittest.main()
