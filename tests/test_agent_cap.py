from __future__ import annotations
import math
import unittest
from dataclasses import replace
from src.agent_cap import AgentCapRuntime, CapMint, CapVerdict


class CapTests(unittest.TestCase):
    def setUp(self):
        self.mint = CapMint(b"edge-secret")
        self.rt = AgentCapRuntime(self.mint)
        self.tok = self.mint.mint("req1", {"kv:read", "fetch:get"}, not_after=1000.0)

    def test_allow_listed(self):
        verdict, reason = self.rt.invoke(self.tok, "kv:read", now=900.0)
        self.assertEqual(verdict, CapVerdict.ALLOW)
        self.assertIsNone(reason)

    def test_refuse_unlisted(self):
        verdict, reason = self.rt.invoke(self.tok, "kv:write", now=900.0)
        self.assertEqual(verdict, CapVerdict.REFUSE)
        self.assertEqual(reason, "CAPABILITY_NOT_GRANTED")

    def test_escalate_forbidden(self):
        with self.assertRaises(RuntimeError):
            self.rt.escalate(self.tok, "kv:write")

    def test_subcap_can_only_attenuate_capability_and_time(self):
        root = self.mint.mint(
            "root", {"kv:read", "fetch:get"}, not_after=1000.0, not_before=100.0
        )
        child, receipt = self.mint.issue_subcap(
            root, "child", {"kv:read"}, not_after=800.0, not_before=200.0
        )
        self.assertTrue(self.mint.verify(child))
        self.assertTrue(self.mint.verify_delegation(root, child))
        self.assertEqual(child.parent_fingerprint, root.fingerprint())
        self.assertEqual(child.delegation_depth, 1)
        self.assertEqual(receipt.removed_capabilities, ("fetch:get",))
        self.assertEqual(receipt.parent_fingerprint, root.fingerprint())
        self.assertEqual(receipt.child_fingerprint, child.fingerprint())
        self.assertEqual(len(receipt.fingerprint), 64)
        self.assertEqual(root.capabilities, frozenset({"kv:read", "fetch:get"}))

    def test_subcap_cannot_add_capability_or_expand_time(self):
        root = self.mint.mint(
            "root", {"kv:read"}, not_after=1000.0, not_before=100.0
        )
        with self.assertRaisesRegex(PermissionError, "CAPABILITY_ESCALATION"):
            self.mint.issue_subcap(root, "child-a", {"kv:read", "kv:write"}, 800.0)
        with self.assertRaisesRegex(PermissionError, "TIME_ESCALATION"):
            self.mint.issue_subcap(root, "child-b", {"kv:read"}, 1001.0)
        with self.assertRaisesRegex(PermissionError, "TIME_ESCALATION"):
            self.mint.issue_subcap(root, "child-c", {"kv:read"}, 800.0, 99.0)
        with self.assertRaisesRegex(ValueError, "CHILD_REQUEST_ID_MUST_DIFFER"):
            self.mint.issue_subcap(root, "root", {"kv:read"}, 800.0)

    def test_multihop_provenance_is_parent_specific(self):
        root = self.mint.mint("root", {"kv:read", "fetch:get"}, 1000.0, 100.0)
        child, _ = self.mint.issue_subcap(root, "child", {"kv:read"}, 800.0, 200.0)
        grandchild, _ = self.mint.issue_subcap(child, "grandchild", {"kv:read"}, 700.0, 300.0)
        self.assertEqual(grandchild.parent_fingerprint, child.fingerprint())
        self.assertEqual(grandchild.delegation_depth, 2)
        self.assertTrue(self.mint.verify_delegation(child, grandchild))
        self.assertFalse(self.mint.verify_delegation(root, grandchild))

    def test_tampered_child_fails_verification(self):
        root = self.mint.mint("root", {"kv:read", "fetch:get"}, 1000.0)
        child, _ = self.mint.issue_subcap(root, "child", {"kv:read"}, 800.0)
        tampered = replace(child, capabilities=frozenset({"kv:read", "fetch:get"}))
        self.assertFalse(self.mint.verify(tampered))
        self.assertFalse(self.mint.verify_delegation(root, tampered))

    def test_structural_framing_removes_pipe_delimiter_collision(self):
        left = self.mint.mint("req", {"a|b", "c"}, 1000.0)
        right = self.mint.mint("req", {"a", "b|c"}, 1000.0)
        self.assertNotEqual(left.mac, right.mac)
        self.assertNotEqual(left.fingerprint(), right.fingerprint())

    def test_time_precision_is_cross_runtime_canonical(self):
        with self.assertRaisesRegex(ValueError, "not_after_precision"):
            self.mint.mint("req", {"kv:read"}, 1.0000004)
        with self.assertRaises(ValueError):
            self.mint.mint("req", {"kv:read"}, math.nan)

    def test_cross_runtime_fixed_vector(self):
        root = self.mint.mint(
            "req-root", {"kv:read", "fetch:get"}, not_after=1000.0, not_before=100.0
        )
        self.assertEqual(root.mac, "a56ac6b6edea0411ed64c319c62ce30d0180b770d8753b6ea111c4d93b42a09c")
        self.assertEqual(root.fingerprint(), "cf8ecf84b94045d72ced2471abcd76f22a52025e5014673a34e000b8269e49eb")
        child, receipt = self.mint.issue_subcap(
            root, "req-child", {"kv:read"}, not_after=800.0, not_before=200.0
        )
        self.assertEqual(child.mac, "52ecf7bd9562fcf4a0569b7880f0a6c5aa7c87ae077f9f26e7c44c28bc04fc43")
        self.assertEqual(child.fingerprint(), "db45b340f54c52132d25234fcb7bb88baaf69369d88601c5ce98a3aeff813784")
        self.assertEqual(receipt.fingerprint, "cb602f1db81add14536dc4e615f1a54f5bdbf20714ee333c7e81ed06b93a9395")


if __name__ == "__main__":
    unittest.main()
