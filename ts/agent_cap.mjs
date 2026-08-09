import crypto from "node:crypto";
export function mint(secret, requestId, capabilities, notAfter) {
  const caps = [...capabilities].sort();
  const raw = `${requestId}|${caps.join("|")}|${notAfter}`;
  const mac = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  return { requestId, capabilities: caps, notAfter, mac };
}
export function invoke(secret, token, capability, now) {
  const raw = `${token.requestId}|${token.capabilities.join("|")}|${token.notAfter}`;
  const mac = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  if (mac !== token.mac) return { status: "REFUSE", reason: "BAD_MAC" };
  if (now > token.notAfter) return { status: "REFUSE", reason: "EXPIRED" };
  if (!token.capabilities.includes(capability)) return { status: "REFUSE", reason: "CAPABILITY_NOT_GRANTED" };
  return { status: "ALLOW", reason: null };
}
export function escalate() { throw new Error("ESCALATION_FORBIDDEN"); }
