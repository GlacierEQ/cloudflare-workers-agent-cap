import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))
TARGET = json.loads((ROOT / "machine" / "target-contract.json").read_text(encoding="utf-8"))
RECEIPT_PATH = ROOT / "machine" / "evolution-receipts" / "2026-08-11-attenuating-subcap-delegation.json"
RECEIPT = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))


class EvolutionContractTests(unittest.TestCase):
    def test_consumed_cursor_is_exact_proof_bound(self):
        self.assertEqual(RECEIPT["result"], "PASS")
        self.assertEqual(RECEIPT["candidate_source_sha"], "d710370ecb7d03bd94cc08f4500d8e3ed92902ba")
        self.assertEqual(RECEIPT["workflow_run"], 31464021756)
        event = STATE["evolution_history"][-1]
        self.assertEqual(event["consumed_cursor"], RECEIPT["consumed_cursor"])
        self.assertEqual(event["receipt"], str(RECEIPT_PATH.relative_to(ROOT)))

    def test_next_cursor_is_consistent(self):
        expected = "next:externally_rooted_issuer_identity_revocation_and_durable_distributed_replay_state"
        self.assertEqual(STATE["evolution_cursor"], expected)
        self.assertEqual(TARGET["next_evolution"], expected)
        self.assertEqual(RECEIPT["next_cursor"], expected)
        self.assertIn("Root issuer identity outside", POSITION["next_evolution"])
        self.assertIn("distributed worker processes", POSITION["next_evolution"])

    def test_claim_ceiling_and_authority_boundaries_do_not_inflate(self):
        self.assertEqual(STATE["claim_ceiling"], "PROMOTED")
        boundary = " ".join(TARGET["nonclaims"]).lower()
        self.assertIn("no cloudflare affiliation", boundary)
        self.assertIn("no revocation ledger", boundary)
        self.assertIn("no durable distributed replay state", boundary)

    def test_fixed_vectors_are_machine_bound(self):
        vectors = RECEIPT["fixed_vectors"]
        self.assertEqual(vectors["root_fingerprint"], "cf8ecf84b94045d72ced2471abcd76f22a52025e5014673a34e000b8269e49eb")
        self.assertEqual(vectors["delegation_receipt_fingerprint"], "cb602f1db81add14536dc4e615f1a54f5bdbf20714ee333c7e81ed06b93a9395")


if __name__ == "__main__":
    unittest.main()
