#!/usr/bin/env python3
"""Cold-start: AgentCapRuntime refuse unlisted capability."""
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_cap import AgentCapRuntime, CapMint, CapVerdict

def main() -> int:
    mint = CapMint(b"operate-secret")
    tok = mint.mint("req-1", {"read"}, not_after=1e12)
    rt = AgentCapRuntime(mint)
    v, reason = rt.invoke(tok, "write", now=1e9)
    out = {
        "verdict": v.value,
        "reason": reason,
        "expected_verdict": CapVerdict.REFUSE.value,
        "expected_reason": "CAPABILITY_NOT_GRANTED",
        "token_fp": tok.fingerprint(),
        "ok": v is CapVerdict.REFUSE and reason == "CAPABILITY_NOT_GRANTED",
    }
    print(json.dumps(out, sort_keys=True))
    return 0 if out["ok"] else 1
if __name__ == "__main__":
    raise SystemExit(main())
