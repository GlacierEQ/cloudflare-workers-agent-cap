from __future__ import annotations
import unittest
from src.agent_cap import AgentCapRuntime, CapMint, CapToken, CapVerdict

class Adv(unittest.TestCase):
    def test_bad_mac_refuses(self):
        mint = CapMint(b"s")
        tok = mint.mint("r", {"a"}, not_after=1e12)
        bad = CapToken(tok.request_id, tok.capabilities, tok.not_after, "0"*64)
        v, reason = AgentCapRuntime(mint).invoke(bad, "a", now=1.0)
        self.assertEqual(v, CapVerdict.REFUSE)
        self.assertEqual(reason, "BAD_MAC")
    def test_expired_refuses(self):
        mint = CapMint(b"s")
        tok = mint.mint("r", {"a"}, not_after=10.0)
        v, reason = AgentCapRuntime(mint).invoke(tok, "a", now=99.0)
        self.assertEqual(v, CapVerdict.REFUSE)
        self.assertEqual(reason, "EXPIRED")
    def test_escalate_forbidden(self):
        mint = CapMint(b"s")
        tok = mint.mint("r", {"a"}, not_after=1e12)
        with self.assertRaises(RuntimeError):
            AgentCapRuntime(mint).escalate(tok, "admin")

if __name__ == "__main__":
    unittest.main()
