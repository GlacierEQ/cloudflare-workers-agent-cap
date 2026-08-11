import assert from "node:assert/strict";
import {
  delegationReceipt,
  escalate,
  fingerprint,
  invoke,
  issueSubcap,
  mint,
  verify,
  verifyDelegation,
} from "./agent_cap.mjs";

const secret = "edge-secret";
const tok = mint(secret, "req1", ["kv:read", "fetch:get"], 1000);
assert.equal(invoke(secret, tok, "kv:read", 900).status, "ALLOW");
assert.equal(invoke(secret, tok, "kv:write", 900).reason, "CAPABILITY_NOT_GRANTED");
assert.throws(() => escalate(), /ESCALATION_FORBIDDEN/);

const root = mint(secret, "root", ["kv:read", "fetch:get"], 1000, { notBefore: 100 });
const { child, receipt } = issueSubcap(secret, root, "child", ["kv:read"], 800, { notBefore: 200 });
assert.equal(verify(secret, child), true);
assert.equal(verifyDelegation(secret, root, child), true);
assert.equal(child.parentFingerprint, fingerprint(root));
assert.equal(child.delegationDepth, 1);
assert.deepEqual(receipt.removedCapabilities, ["fetch:get"]);
assert.equal(receipt.parentFingerprint, fingerprint(root));
assert.equal(receipt.childFingerprint, fingerprint(child));
assert.equal(receipt.fingerprint.length, 64);
assert.deepEqual(root.capabilities, ["fetch:get", "kv:read"]);

assert.throws(() => issueSubcap(secret, root, "plus", ["kv:read", "kv:write"], 800), /CAPABILITY_ESCALATION/);
assert.throws(() => issueSubcap(secret, root, "late", ["kv:read"], 1001), /TIME_ESCALATION/);
assert.throws(() => issueSubcap(secret, root, "early", ["kv:read"], 800, { notBefore: 99 }), /TIME_ESCALATION/);
assert.throws(() => issueSubcap(secret, root, "root", ["kv:read"], 800), /CHILD_REQUEST_ID_MUST_DIFFER/);

const grandchild = issueSubcap(secret, child, "grandchild", ["kv:read"], 700, { notBefore: 300 }).child;
assert.equal(grandchild.parentFingerprint, fingerprint(child));
assert.equal(grandchild.delegationDepth, 2);
assert.equal(verifyDelegation(secret, child, grandchild), true);
assert.equal(verifyDelegation(secret, root, grandchild), false);

const tampered = { ...child, capabilities: Object.freeze(["fetch:get", "kv:read"]) };
assert.equal(verify(secret, tampered), false);
assert.equal(verifyDelegation(secret, root, tampered), false);

const left = mint(secret, "req", ["a|b", "c"], 1000);
const right = mint(secret, "req", ["a", "b|c"], 1000);
assert.notEqual(left.mac, right.mac);
assert.notEqual(fingerprint(left), fingerprint(right));

assert.throws(() => mint(secret, "precision", ["kv:read"], 1.0000004), /not_after_precision/);
assert.throws(() => mint(secret, "nan", ["kv:read"], Number.NaN), /not_after/);

const vectorRoot = mint(secret, "req-root", ["kv:read", "fetch:get"], 1000, { notBefore: 100 });
assert.equal(vectorRoot.mac, "a56ac6b6edea0411ed64c319c62ce30d0180b770d8753b6ea111c4d93b42a09c");
assert.equal(fingerprint(vectorRoot), "cf8ecf84b94045d72ced2471abcd76f22a52025e5014673a34e000b8269e49eb");
const vectorDelegation = issueSubcap(secret, vectorRoot, "req-child", ["kv:read"], 800, { notBefore: 200 });
assert.equal(vectorDelegation.child.mac, "52ecf7bd9562fcf4a0569b7880f0a6c5aa7c87ae077f9f26e7c44c28bc04fc43");
assert.equal(fingerprint(vectorDelegation.child), "db45b340f54c52132d25234fcb7bb88baaf69369d88601c5ce98a3aeff813784");
assert.equal(vectorDelegation.receipt.fingerprint, "cb602f1db81add14536dc4e615f1a54f5bdbf20714ee333c7e81ed06b93a9395");
assert.equal(delegationReceipt(secret, vectorRoot, vectorDelegation.child).fingerprint, vectorDelegation.receipt.fingerprint);

console.log("ok");
