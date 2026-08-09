
from __future__ import annotations
import unittest
from src.agent_cap import AgentCapRuntime, CapMint, CapVerdict

class CapTests(unittest.TestCase):
    def setUp(self):
        self.mint = CapMint(b"edge-secret")
        self.rt = AgentCapRuntime(self.mint)
        self.tok = self.mint.mint("req1", {"kv:read", "fetch:get"}, not_after=1000.0)

    def test_allow_listed(self):
        v, r = self.rt.invoke(self.tok, "kv:read", now=900.0)
        self.assertEqual(v, CapVerdict.ALLOW)

    def test_refuse_unlisted(self):
        v, r = self.rt.invoke(self.tok, "kv:write", now=900.0)
        self.assertEqual(r, "CAPABILITY_NOT_GRANTED")

    def test_escalate_forbidden(self):
        with self.assertRaises(RuntimeError):
            self.rt.escalate(self.tok, "kv:write")

if __name__ == "__main__":
    unittest.main()
