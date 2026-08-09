import { mint, invoke, escalate } from "./agent_cap.mjs";
import assert from "node:assert/strict";
const tok = mint("edge-secret", "req1", ["kv:read", "fetch:get"], 1000);
assert.equal(invoke("edge-secret", tok, "kv:read", 900).status, "ALLOW");
assert.equal(invoke("edge-secret", tok, "kv:write", 900).reason, "CAPABILITY_NOT_GRANTED");
assert.throws(() => escalate(), /ESCALATION_FORBIDDEN/);
console.log("ok");
