import json
import unittest
from pathlib import Path

from guard_preview import recovery_decision, render_rules


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


class RulesTest(unittest.TestCase):
    def test_default_drop_and_scoped_exception(self):
        text = render_rules("utun4", "en0", ["192.0.2.10"])
        self.assertEqual(text.splitlines(), [
            "pass quick on lo0 all no state",
            "pass quick on utun4 all no state",
            "pass out quick on en0 inet proto tcp from any to 192.0.2.10 port 443 flags any no state",
            "pass in quick on en0 inet proto tcp from 192.0.2.10 port 443 to any flags any no state",
            "block drop quick all",
        ])

    def test_rejects_interface_injection_and_nonfixture_peers(self):
        for args in (
            ("utun4\npass all", "en0", ["192.0.2.10"]),
            ("utun4", "en0 quick", ["192.0.2.10"]),
            ("utun4", "en0", ["10.0.0.1"]),
            ("utun4", "en0", ["192.0.2.10", "192.0.2.10"]),
            ("utun4", "en0", []),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                render_rules(*args)


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.case = json.loads((EXAMPLES / "recovery.json").read_text(encoding="utf-8"))

    def test_owned_rules_still_require_ownership_check(self):
        self.assertEqual(recovery_decision(**self.case), {
            "decision": "check_ownership_before_recovery",
            "restore_main": True,
            "clear_session_anchor": True,
        })

    def test_holds_when_task_exit_is_unconfirmed(self):
        self.case["tasks_exited"] = "yes"
        self.assertEqual(recovery_decision(**self.case)["reason"], "task_exit_unconfirmed")

    def test_holds_on_rule_drift(self):
        for field in ("main", "session_anchor", "nat", "system_anchors"):
            with self.subTest(field=field):
                old = self.case["current"][field]
                self.case["current"][field] += "\nother change"
                self.assertEqual(recovery_decision(**self.case)["reason"], "rules_changed_outside_session")
                self.case["current"][field] = old

    def test_resumes_partial_restore(self):
        self.case["current"]["main"] = self.case["baseline"]["main"]
        result = recovery_decision(**self.case)
        self.assertFalse(result["restore_main"])
        self.assertTrue(result["clear_session_anchor"])

    def test_preserves_quoted_whitespace(self):
        self.case["current"]["system_anchors"] = 'anchor "system/ example" all'
        self.assertEqual(recovery_decision(**self.case)["reason"], "rules_changed_outside_session")
