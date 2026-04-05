# Planned Changes to the Signature-Key Spec

## Context

The AAuth Headers spec (`draft-hardt-aauth-headers`) is being split. Signature-related content moves into the Signature-Key spec (`draft-hardt-httpbis-signature-key`); protocol-level content (AAuth-Requirement) has been absorbed into the AAuth Protocol spec. After these changes, the AAuth Headers spec can be retired.

The Signature-Key spec gains two things:

1. **Signature-Requirement header** (new) — challenge header for requesting signatures
2. **Signature-Error header** (moved from AAuth Headers, renamed from AAuth-Error)

The **HTTP Message Signatures profile** (algorithms, covered components, signing/verification requirements) stays in the AAuth Protocol spec — it represents AAuth's opinion about how to use signatures, not a general Signature-Key concern. Another protocol using Signature-Key could profile differently.

## 1. Signature-Requirement Header (NEW)

A response header that tells an agent what level of signing is required.

### Header Structure

Dictionary (RFC 8941, Section 3.2) with the following members:

- `requirement` (REQUIRED): Token — the requirement level
- `algorithms` (OPTIONAL): Inner List of String — accepted signing algorithms

### Requirement Levels

| Level | Meaning |
|-------|---------|
| `pseudonym` | Signed request proving key possession (hwk or jkt-jwt scheme) |
| `identity` | Verified agent identity (jwks_uri or jwt scheme) |

### Response Status Codes

The `Signature-Requirement` header MAY be sent with the following status codes:

| Status | Meaning | Legacy client behavior | Signature-aware client behavior |
|--------|---------|----------------------|-------------------------------|
| `401` | Authentication required | Falls back to WWW-Authenticate | Signs request at required level |
| `402` | Payment + authentication required | Processes payment mechanism | Signs request AND processes payment |
| `429` | Rate limited | Respects Retry-After, slows down | Signs request, gets higher per-key rate limit |

The `429` case is particularly important for incremental adoption: a server can add `Signature-Requirement` to its existing 429 responses with zero risk. Legacy clients ignore the unknown header and respect `Retry-After`. Signature-aware clients sign with a pseudonymous key, giving the server a stable key thumbprint for per-client rate limiting — and the client gets a higher rate limit in return.

### Examples

```http
HTTP/1.1 401 Unauthorized
Signature-Requirement: requirement=pseudonym
```

```http
HTTP/1.1 401 Unauthorized
Signature-Requirement: requirement=identity, algorithms=("EdDSA" "ES256")
```

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Signature-Requirement: requirement=pseudonym
```

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Signature-Requirement: requirement=pseudonym
```

### Pseudonym Required

Server requires a signed request using a pseudonymous Signature-Key scheme (hwk or jkt-jwt). The server can track the agent by JWK Thumbprint (RFC 7638) without knowing its identity.

Include the flow diagram and use cases from the former AAuth Headers spec:
- Rate limiting anonymous requests
- Tracking repeat visitors by key thumbprint
- Spam prevention without requiring verified identity
- Hardware-backed pseudonymous identity

### Identity Required

Server requires verified agent identity using an identity Signature-Key scheme (jwks_uri or jwt).

Include the flow diagram and use cases from the former AAuth Headers spec:
- API access policies based on known agents
- Webhook signature verification
- Allowlisting trusted agents for elevated rate limits

### Incremental Adoption

`Signature-Requirement` is designed for zero-coordination deployment. The header is unknown to legacy clients and ignored per HTTP semantics — servers can add it to existing responses without breaking anything.

**Stage 1 — Rate limiting (429):** A server adds `Signature-Requirement: requirement=pseudonym` to its 429 responses. Legacy clients slow down as before. Signature-aware clients sign requests and get higher per-key rate limits. The server gains per-client rate limiting without requiring registration or API keys.

**Stage 2 — Authentication (401):** The server starts requiring signatures on some paths, returning 401 with `Signature-Requirement`. It can include `WWW-Authenticate` alongside for legacy clients that have other auth mechanisms. Signature-aware clients sign; legacy clients fall back to bearer tokens or other schemes.

**Stage 3 — Identity (401):** The server upgrades from `pseudonym` to `identity` on sensitive paths, requiring verifiable agent identity via `jwks_uri` or `jwt` schemes. The server can now make identity-based policy decisions without pre-registration.

Each stage is independently deployable. A server can use stage 1 on all endpoints while using stage 3 on admin endpoints. No bilateral agreements or client coordination required.

### Coexistence with WWW-Authenticate

`Signature-Requirement` and `WWW-Authenticate` are independent headers; a response MAY include both. A client that understands Signature-Key processes `Signature-Requirement`; a legacy client processes `WWW-Authenticate`.

### IANA Registration

Register `Signature-Requirement` in the HTTP Field Name Registry, and establish a Signature Requirement Level Registry with `pseudonym` and `identity` as initial entries.

## 2. Signature-Error Header (RENAMED + MOVED)

Renamed from `AAuth-Error`. All content moves from the AAuth Headers spec with only the name change.

### Header Structure

Dictionary (RFC 8941, Section 3.2) with required `error` member plus additional members per error code.

### Error Codes (unchanged)

| Code | Meaning |
|------|---------|
| `invalid_request` | Missing required info unrelated to signature |
| `invalid_input` | Missing required covered components |
| `invalid_signature` | Signature missing, malformed, or verification failed |
| `unsupported_algorithm` | Signing algorithm not supported |
| `invalid_key` | Key cannot be parsed or doesn't meet trust requirements |
| `unknown_key` | Key not found at jwks_uri |
| `invalid_jwt` | JWT malformed or signature verification failed |
| `expired_jwt` | JWT expired |

### IANA Registration

Register `Signature-Error` in the HTTP Field Name Registry, and establish a Signature Error Code Registry with the 8 initial codes.

## 3. Privacy and Security Considerations (MOVED)

Move from the AAuth Headers spec — only the items that are about signatures/keys (not the profile):

- **Key Thumbprint Tracking** — agents MUST use distinct keys per server
- **Agent Identity Disclosure** — jwks_uri/jwt schemes reveal agent's HTTPS URL
- **JWKS Fetch Side Channel** — server fetching JWKS reveals verification activity

Note: The Signature-Key spec already has Security and Privacy sections. Merge these into the existing sections rather than duplicating.

## 4. Changes to Existing Signature-Key Spec Sections

- **IANA Considerations**: Add HTTP Field Name registrations for `Signature-Requirement` and `Signature-Error`, plus two new registries (Signature Requirement Level Registry, Signature Error Code Registry)
- **Document History**: Record these additions in the next version entry

## 5. What Stays in AAuth Protocol Spec

The following content from AAuth Headers moves to the AAuth Protocol spec (not Signature-Key):

- **HTTP Message Signatures profile** — algorithms (EdDSA/Ed25519 MUST, ECDSA/P-256 SHOULD), covered components (@method, @authority, @path, signature-key; optional content-digest), signature parameters (created timestamp), six-step verification procedure
- **Replay Protection** — 60-second created timestamp window, cache (thumbprint, created) pairs
- **JWKS Caching** — recommended TTLs, HTTP cache header support
- **HTTP Message Signature Security** — request integrity, replay protection, key binding guarantees

These are AAuth's opinions about how to use signatures, not general Signature-Key concerns.

## 6. Retirement of AAuth Headers Spec

After these changes, `draft-hardt-aauth-headers` has no remaining content — everything has been absorbed into either the Signature-Key spec or the AAuth Protocol spec. It can be retired.

## Source Material

All content comes from `draft-hardt-aauth-headers.md` in the AAuth repo:
- Signature-Requirement: derived from lines 73-181 (AAuth-Requirement pseudonym/identity sections)
- Signature-Error: lines 308-398 (AAuth-Error section, renamed)
- HTTP Message Signatures profile: lines 255-307 (→ AAuth Protocol)
- Privacy considerations: lines 400-413 (split between Signature-Key and AAuth Protocol)
- Security considerations: lines 414-435 (→ AAuth Protocol)
