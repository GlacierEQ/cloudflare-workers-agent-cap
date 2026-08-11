import crypto from "node:crypto";

export const TOKEN_VERSION = 2;
const TIME_SCALE = 1_000_000;

function token(name, value) {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(name);
  return value;
}

function finite(name, value) {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new TypeError(name);
  return value;
}

function timeUs(name, value) {
  const normalized = finite(name, value);
  if (normalized < 0) throw new TypeError(name);
  const micros = Math.round(normalized * TIME_SCALE);
  if (!Number.isSafeInteger(micros) || Math.abs(micros / TIME_SCALE - normalized) > 1e-9) throw new TypeError(`${name}_precision`);
  return micros;
}

function caps(values) {
  const unique = [...new Set([...values])].sort();
  if (!unique.length) throw new TypeError("capabilities");
  for (const cap of unique) token("capability", cap);
  return unique;
}

function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError("non_finite_json");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonical);
  if (typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key]);
    return out;
  }
  throw new TypeError("unsupported_json");
}

export function canonicalJson(value) { return JSON.stringify(canonical(value)); }
export function digest(value) { return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex"); }

function unsignedBody({ requestId, capabilities, notBefore, notAfter, issuerId, parentFingerprint, delegationDepth, version }) {
  return {
    version,
    request_id: requestId,
    capabilities: [...capabilities].sort(),
    not_before_us: timeUs("not_before", notBefore),
    not_after_us: timeUs("not_after", notAfter),
    issuer_id: issuerId,
    parent_fingerprint: parentFingerprint,
    delegation_depth: delegationDepth,
  };
}

function mac(secret, body) {
  if (typeof secret !== "string" || !secret.length) throw new TypeError("secret");
  return crypto.createHmac("sha256", secret).update(canonicalJson(body), "utf8").digest("hex");
}

function build(secret, requestId, capabilities, notAfter, { notBefore = 0, issuerId = "local-authority", parentFingerprint = "", delegationDepth = 0 } = {}) {
  const rid = token("request_id", requestId);
  const normalizedCaps = caps(capabilities);
  const nb = finite("not_before", notBefore);
  const na = finite("not_after", notAfter);
  timeUs("not_before", nb); timeUs("not_after", na);
  token("issuer_id", issuerId);
  if (na <= nb) throw new TypeError("validity_window");
  if (!Number.isInteger(delegationDepth) || delegationDepth < 0) throw new TypeError("delegation_depth");
  if (parentFingerprint && !/^[0-9a-f]{64}$/.test(parentFingerprint)) throw new TypeError("parent_fingerprint");
  if (!parentFingerprint && delegationDepth !== 0) throw new TypeError("delegation_without_parent");
  const body = unsignedBody({ requestId: rid, capabilities: normalizedCaps, notBefore: nb, notAfter: na, issuerId, parentFingerprint, delegationDepth, version: TOKEN_VERSION });
  return Object.freeze({ requestId: rid, capabilities: Object.freeze(normalizedCaps), notBefore: nb, notAfter: na, issuerId, parentFingerprint, delegationDepth, version: TOKEN_VERSION, mac: mac(secret, body) });
}

export function mint(secret, requestId, capabilities, notAfter, options = {}) { return build(secret, requestId, capabilities, notAfter, options); }
export function fingerprint(tokenValue) { return digest({ ...unsignedBody(tokenValue), mac: tokenValue.mac }); }

export function verify(secret, tokenValue, issuerId = "local-authority") {
  try {
    if (!tokenValue || tokenValue.version !== TOKEN_VERSION || tokenValue.issuerId !== issuerId) return false;
    if (!Array.isArray(tokenValue.capabilities) || !tokenValue.capabilities.length) return false;
    const normalizedCaps = caps(tokenValue.capabilities);
    if (canonicalJson(normalizedCaps) !== canonicalJson(tokenValue.capabilities)) return false;
    const body = unsignedBody({ ...tokenValue, capabilities: normalizedCaps });
    const expected = mac(secret, body);
    if (typeof tokenValue.mac !== "string" || !/^[0-9a-f]{64}$/.test(tokenValue.mac)) return false;
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(tokenValue.mac, "hex"));
  } catch { return false; }
}

export function issueSubcap(secret, parent, childRequestId, capabilities, notAfter, options = {}) {
  const issuerId = options.issuerId ?? parent?.issuerId ?? "local-authority";
  if (!verify(secret, parent, issuerId)) throw new Error("PARENT_TOKEN_INVALID");
  const rid = token("request_id", childRequestId);
  if (rid === parent.requestId) throw new Error("CHILD_REQUEST_ID_MUST_DIFFER");
  const childCaps = caps(capabilities);
  if (!childCaps.every(capability => parent.capabilities.includes(capability))) throw new Error("CAPABILITY_ESCALATION");
  const childNotBefore = options.notBefore ?? parent.notBefore;
  timeUs("not_before", childNotBefore); timeUs("not_after", notAfter);
  if (childNotBefore < parent.notBefore || notAfter > parent.notAfter || notAfter <= childNotBefore) throw new Error("TIME_ESCALATION");
  const child = build(secret, rid, childCaps, notAfter, { notBefore: childNotBefore, issuerId, parentFingerprint: fingerprint(parent), delegationDepth: parent.delegationDepth + 1 });
  return { child, receipt: delegationReceipt(secret, parent, child) };
}

export function verifyDelegation(secret, parent, child) {
  const issuerId = parent?.issuerId ?? "local-authority";
  if (!verify(secret, parent, issuerId) || !verify(secret, child, issuerId)) return false;
  return child.parentFingerprint === fingerprint(parent)
    && child.issuerId === parent.issuerId
    && child.delegationDepth === parent.delegationDepth + 1
    && child.capabilities.every(capability => parent.capabilities.includes(capability))
    && child.notBefore >= parent.notBefore
    && child.notAfter <= parent.notAfter;
}

export function delegationReceipt(secret, parent, child) {
  if (!verifyDelegation(secret, parent, child)) throw new Error("DELEGATION_INVALID");
  const removedCapabilities = parent.capabilities.filter(capability => !child.capabilities.includes(capability)).sort();
  const body = {
    parent_fingerprint: fingerprint(parent), child_fingerprint: fingerprint(child), issuer_id: child.issuerId,
    child_request_id: child.requestId, removed_capabilities: removedCapabilities,
    parent_not_before_us: timeUs("parent_not_before", parent.notBefore), child_not_before_us: timeUs("child_not_before", child.notBefore),
    parent_not_after_us: timeUs("parent_not_after", parent.notAfter), child_not_after_us: timeUs("child_not_after", child.notAfter),
    parent_depth: parent.delegationDepth, child_depth: child.delegationDepth,
  };
  return Object.freeze({ parentFingerprint: body.parent_fingerprint, childFingerprint: body.child_fingerprint, issuerId: child.issuerId, childRequestId: child.requestId, removedCapabilities: Object.freeze(removedCapabilities), parentNotBefore: parent.notBefore, childNotBefore: child.notBefore, parentNotAfter: parent.notAfter, childNotAfter: child.notAfter, parentDepth: parent.delegationDepth, childDepth: child.delegationDepth, fingerprint: digest(body) });
}

export function invoke(secret, tokenValue, capability, now) {
  if (!verify(secret, tokenValue, tokenValue?.issuerId ?? "local-authority")) return { status: "REFUSE", reason: "BAD_MAC" };
  if (typeof capability !== "string" || capability.trim() === "" || typeof now !== "number" || !Number.isFinite(now)) return { status: "REFUSE", reason: "INVALID_INVOCATION" };
  if (now < tokenValue.notBefore) return { status: "REFUSE", reason: "NOT_YET_VALID" };
  if (now > tokenValue.notAfter) return { status: "REFUSE", reason: "EXPIRED" };
  if (!tokenValue.capabilities.includes(capability)) return { status: "REFUSE", reason: "CAPABILITY_NOT_GRANTED" };
  return { status: "ALLOW", reason: null };
}

export function escalate() { throw new Error("ESCALATION_FORBIDDEN: use issueSubcap with a verified parent"); }
