# ISSUE CONTRACT

## Pain
Edge agents need to hand off bounded authority without accumulating privileges, ambiguously signing capability sets, or losing provenance across worker hops.

## Success
- Root CAP tokens enumerate exact capabilities and validity.
- Signed structure is unambiguous and interoperable across Python and Node.
- Subcaps bind a verified parent and can only reduce capability/time authority.
- Parent authority is never mutated in place.
- Delegation receipts bind parent, child, removed authority, validity narrowing, and depth.
- Invocation fails closed outside the granted set or validity window.

## Boundaries
- HMAC issuer identity is repository-local shared-secret authority, not externally rooted Cloudflare identity.
- No revocation ledger or durable distributed replay state yet.
- No Cloudflare affiliation, adoption, or production Workers authorization claim.
