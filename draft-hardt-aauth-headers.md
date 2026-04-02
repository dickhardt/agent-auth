%%%
title = "HTTP AAuth Headers"
abbrev = "AAuth-Headers"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["agent", "authentication", "http", "signatures"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-aauth-headers-latest"
stream = "IETF"

date = 2026-03-19T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

%%%

<reference anchor="x402" target="https://docs.x402.org">
  <front>
    <title>x402: HTTP 402 Payment Protocol</title>
    <author>
      <organization>x402 Foundation</organization>
    </author>
    <date year="2025"/>
  </front>
</reference>

.# Abstract

This document defines two HTTP response headers — AAuth-Requirement and AAuth-Error — and profiles HTTP Message Signatures ([@!RFC9421]) for request authentication, with keying material conveyed via the Signature-Key header ([@!I-D.hardt-httpbis-signature-key]). A server uses AAuth-Requirement to require pseudonymous or verified agent identity, to request user interaction, or to signal that approval is pending. AAuth-Error conveys structured error information. Both headers use extensible registries for their values.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*


This document is part of the AAuth specification family. Source for this draft and an issue tracker can be found at https://github.com/dickhardt/AAuth.


{mainmatter}

# Introduction

Modern distributed systems need a standard way for servers to communicate requirements to agents and for agents to present cryptographic identity. The existing HTTP `WWW-Authenticate` header ([@!RFC9110], Section 11.6.1) is limited to a fixed set of authentication schemes, cannot express progressive requirements, and cannot appear in `202 Accepted` responses. The AAuth-Requirement header provides an extensible mechanism for progressive requirements — from pseudonymous access and verified identity to user interaction and deferred approval.

This specification defines:

- The `AAuth-Requirement` HTTP response header with an extensible requirement level registry
- Four requirement levels: `pseudonym`, `identity`, `interaction`, and `approval`
- A profile of HTTP Message Signatures ([@!RFC9421]) for request authentication, specifying required covered components, signature parameters, and keying material via the `Signature-Key` header ([@!I-D.hardt-httpbis-signature-key])
- The `AAuth-Error` HTTP response header with an extensible error code registry

# Conventions and Definitions

{::boilerplate bcp14-tagged}

All HTTP requests and responses in AAuth MUST use HTTPS (HTTP over TLS ([@!RFC8446])). Any reference to "HTTP" in this document implies HTTPS unless explicitly noted otherwise.

# Terminology

- **Agent**: An HTTP client ([@!RFC9110], Section 3.5) that signs its requests. In AAuth, agents have cryptographic identity.
- **Server**: An HTTP origin server ([@!RFC9110], Section 3.6) that communicates requirements via the `AAuth-Requirement` header.

# AAuth-Requirement HTTP Response Header

Servers use the `AAuth-Requirement` response header to indicate requirements to agents. The header MAY be sent with `401 Unauthorized` or `202 Accepted` responses. A `401` response indicates that authentication or authorization is required. A `202` response indicates that the request is pending and additional action is required — either user interaction (`requirement=interaction`) or third-party approval (`requirement=approval`).

`AAuth-Requirement` and `WWW-Authenticate` are independent header fields; a response MAY include both. A client that understands AAuth processes `AAuth-Requirement`; a legacy client processes `WWW-Authenticate`. Neither header's presence invalidates the other.

The header MAY also be sent with `402 Payment Required` when a server requires both authentication and payment. The `AAuth-Requirement` conveys the authentication requirement; the payment requirement is conveyed by a separate mechanism such as x402 [@x402] or the Micropayment Protocol (MPP) ([@I-D.ryan-httpauth-payment]).

## Header Structure

The `AAuth-Requirement` header field is a Dictionary ([@!RFC8941], Section 3.2). It MUST contain the following member:

- `requirement`: A Token ([@!RFC8941], Section 3.3.4) indicating the requirement level.

Additional members are defined per requirement level by the specification that registers the level. Recipients MUST ignore unknown members.

Example:

```http
AAuth-Requirement: requirement=pseudonym
```

## Requirement Levels

The `requirement` value is an extension point. This document defines four levels:

| Level | Status Code | Meaning |
|-------|-------------|---------|
| `pseudonym` | `401` | Signed request proving key possession |
| `identity` | `401` | Verified agent identity |
| `interaction` | `202` | User action required at an interaction endpoint |
| `approval` | `202` | Approval pending, poll for result |

The AAuth Protocol specification (draft-hardt-aauth-protocol) registers additional levels (e.g., `auth-token`).

## Pseudonym Required

When a server requires a signed request:

```http
HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=pseudonym
```

The agent retries with an HTTP Message Signature using a pseudonymous Signature-Key scheme ({{keying-material}}). The server can track the agent by JWK Thumbprint ([@!RFC7638]) without knowing its identity.

~~~ ascii-art
Agent                                          Server
  |                                               |
  |  unsigned request                             |
  |---------------------------------------------->|
  |                                               |
  |  401 Unauthorized                             |
  |  AAuth-Requirement: requirement=pseudonym           |
  |<----------------------------------------------|
  |                                               |
  |  HTTPSig request                              |
  |  (pseudonymous key)                           |
  |---------------------------------------------->|
  |                                               |  verify signature,
  |                                               |  track by key
  |                                               |  thumbprint
  |                                               |
  |  200 OK                                       |
  |<----------------------------------------------|
  |                                               |
~~~

If the agent already knows the server requires pseudonymous access (from a previous interaction or metadata), it MAY sign the initial request directly without waiting for a `401` challenge.

**Use cases:** Rate limiting anonymous requests, tracking repeat visitors by key thumbprint, spam prevention without requiring verified identity, hardware-backed pseudonymous identity.

## Identity Required

When a server requires verified agent identity:

```http
HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=identity
```

The agent retries with a signed request using an identity Signature-Key scheme ({{keying-material}}).

~~~ ascii-art
Agent                                          Server
  |                                               |
  |  HTTPSig request                              |
  |---------------------------------------------->|
  |                                               |
  |  401 Unauthorized                             |
  |  AAuth-Requirement: requirement=identity            |
  |<----------------------------------------------|
  |                                               |
  |  HTTPSig request                              |
  |  (verifiable identity)                        |
  |---------------------------------------------->|
  |                                               |  verify agent
  |                                               |  identity,
  |                                               |  apply policy
  |                                               |
  |  200 OK                                       |
  |<----------------------------------------------|
  |                                               |
~~~

If the agent already knows the server requires agent identity, it MAY present its identity on the initial request without waiting for a `401` challenge.

**Use cases:** API access policies based on known agents, webhook signature verification, allowlisting trusted agents for elevated rate limits.

## Interaction Required

When a server requires user action — such as authentication, consent, payment approval, or any decision requiring a human in the loop — it returns a `202 Accepted` response:

```http
HTTP/1.1 202 Accepted
AAuth-Requirement: requirement=interaction; url="https://example.com/interact";
    code="A1B2-C3D4"
Location: /pending/f7a3b9c
Retry-After: 0
```

The `AAuth-Requirement` header MUST include the following parameters:

- `url` (String): The interaction URL where the user completes the required action. MUST use the `https` scheme and MUST NOT contain query or fragment components.
- `code` (String): An interaction code that links the agent's pending request to the user's session at the interaction URL.

The response MUST also include:

- `Location`: A URL the agent polls (with GET) for a terminal response.
- `Retry-After`: Recommended polling interval in seconds.

The agent constructs a user-facing URL by appending the code as a query parameter: `{url}?code={code}`. The agent then directs the user to this URL using one of:

- **Browser redirect**: The agent opens the URL in the user's browser.
- **Display code**: The agent displays the `url` and `code` for the user to enter manually. The agent MAY also render the constructed URL as a QR code for the user to scan with their phone.

After directing the user, the agent polls the `Location` URL with GET requests, respecting the `Retry-After` interval. A `202` response means the request is still pending. A non-`202` response is terminal — `200` indicates success, `403` indicates denial, and `408` indicates timeout.

~~~ ascii-art
Agent                        User                         Server
  |                            |                             |
  |  202 Accepted                                            |
  |  AAuth-Requirement:                                        |
  |    requirement=interaction;                                  |
  |    url="..."; code="..."                                 |
  |  Location: /pending/...                                  |
  |<---------------------------------------------------------|
  |                            |                             |
  |  open {url}?code={code}    |                             |
  |  (or display code / QR)    |                             |
  |--------------------------->|                             |
  |                            |                             |
  |                            |  {url}?code={code}          |
  |                            |---------------------------->|
  |                            |                             |
  |                            |  user completes action      |
  |                            |<----------------------------|
  |                            |                             |
  |  GET /pending/...                                        |
  |--------------------------------------------------------->|
  |                            |                             |
  |  200 OK                                                  |
  |<---------------------------------------------------------|
~~~

**Use cases:** User login, consent, payment confirmation, document review, CAPTCHA, any workflow requiring human action.

## Approval Pending

When a server is obtaining approval from another party without requiring the agent to direct a user — for example, via push notification, email, or administrator review:

```http
HTTP/1.1 202 Accepted
AAuth-Requirement: requirement=approval
Location: /pending/f7a3b9c
Retry-After: 30
```

The response MUST include `Location` and `Retry-After`. The agent polls the `Location` URL with GET requests until a terminal response is received. No user action is required at the agent side. The same terminal response codes apply as for `interaction`.

**Use cases:** Administrator approval, resource owner consent, compliance review, direct user authorization via established communication channel.

# HTTP Message Signatures Profile

This section profiles HTTP Message Signatures ([@!RFC9421]) for use with AAuth. Signing requirements (what the agent does) and verification requirements (what the server does) are specified separately.

## Signature Algorithms

Agents and resources MUST support EdDSA using Ed25519 ([@!RFC8032]). Agents and resources SHOULD support ECDSA using P-256 with deterministic signatures ([@!RFC6979]). The `alg` parameter in the JWK ([@!RFC7517]) key representation identifies the algorithm. See the IANA JSON Web Signature and Encryption Algorithms registry ([@RFC7518], Section 7.1) for the full list of algorithm identifiers.

## Keying Material {#keying-material}

The signing key is conveyed in the `Signature-Key` header ([@!I-D.hardt-httpbis-signature-key]). The Signature-Key scheme determines how the server obtains the public key:

- For `pseudonym`: the agent uses `scheme=hwk` (inline public key) or `scheme=jkt-jwt` (delegation from a hardware-backed key).
- For `identity`: the agent uses `scheme=jwks_uri` (JWKS endpoint) or `scheme=jwt` (JWT with public key in `cnf` claim).

See the Signature-Key specification ([@!I-D.hardt-httpbis-signature-key]) for scheme definitions, key discovery, and verification procedures.

## Signing (Agent)

The agent creates an HTTP Message Signature ([@!RFC9421]) on each request, including the following headers:

- `Signature-Key`: Public key or key reference for signature verification
- `Signature-Input`: Signature metadata including covered components
- `Signature`: The HTTP message signature

### Covered Components {#covered-components}

The signature MUST cover the following derived components and header fields:

- `@method`: The HTTP request method ([@!RFC9421], Section 2.2.1)
- `@authority`: The target host ([@!RFC9421], Section 2.2.3)
- `@path`: The request path ([@!RFC9421], Section 2.2.6)
- `signature-key`: The Signature-Key header value

Servers MAY require additional covered components (e.g., `content-digest` ([@RFC9530]) for request body integrity). The agent learns about additional requirements from server metadata or from an `invalid_input` error response that includes `required_input` ({{error-codes}}).

### Signature Parameters

The `Signature-Input` header ([@!RFC9421], Section 4.1) MUST include the following parameters:

- `created`: Signature creation timestamp as an Integer (Unix time). The agent MUST set this to the current time.

## Verification (Server) {#verification-resource}

When a server receives a signed request, it MUST perform the following steps. Any failure MUST result in a `401` response with the appropriate `AAuth-Error` header ({{error-codes}}).

1. Extract the `Signature`, `Signature-Input`, and `Signature-Key` headers. If any are missing, return `invalid_request`.
2. Verify that the `Signature-Input` covers the required components defined in {{covered-components}}. If the server requires additional components, verify those are covered as well. If not, return `invalid_input` with `required_input`.
3. Verify the `created` parameter is present and within 60 seconds of the server's current time. Reject with `invalid_signature` if outside this window. Servers and agents SHOULD synchronize their clocks using NTP ([@RFC5905]).
4. Determine the signature algorithm from the `alg` parameter in the key. If the algorithm is not supported, return `unsupported_algorithm`.
5. Obtain the public key from the `Signature-Key` header according to the scheme, as specified in ([@!I-D.hardt-httpbis-signature-key]). Return `invalid_key` if the key cannot be parsed, `unknown_key` if the key is not found at the `jwks_uri`, `invalid_jwt` if a JWT scheme fails verification, or `expired_jwt` if the JWT has expired.
6. Verify the HTTP Message Signature ([@!RFC9421]) using the obtained public key and determined algorithm. Return `invalid_signature` if verification fails.

# AAuth-Error HTTP Response Header

When a server rejects a request that includes AAuth signature headers (`Signature`, `Signature-Input`, and `Signature-Key`), the `401` response MUST include the `AAuth-Error` header.

## Header Structure

The `AAuth-Error` header field is a Dictionary ([@!RFC8941], Section 3.2). It MUST contain the following member:

- `error`: A Token ([@!RFC8941], Section 3.3.4) indicating the error code.

Additional members are defined per error code. Recipients MUST ignore unknown members.

```http
AAuth-Error: error=unsupported_algorithm,
    supported_algorithms=("EdDSA" "ES256")
```

The response body is OPTIONAL and MAY contain a human-readable description in any content type. The agent MUST NOT depend on the response body for error handling — all machine-readable error information is in the header.

## Error Codes {#error-codes}

### invalid_request

The request is malformed or missing required information unrelated to signature verification — such as missing query parameters or an unsupported content type.

```http
AAuth-Error: error=invalid_request
```

### invalid_input

The Signature-Input is missing required covered components. The response SHOULD include a `required_input` member listing the components the server requires (see {{covered-components}} for the base set):

```http
AAuth-Error: error=invalid_input,
    required_input=("@method" "@authority" "@path"
    "signature-key" "content-digest")
```

### invalid_signature

The HTTP Message Signature is missing, malformed, or cryptographic verification failed. This includes missing `Signature`, `Signature-Input`, or `Signature-Key` headers, an expired `created` timestamp, or a signature that does not verify.

```http
AAuth-Error: error=invalid_signature
```

### unsupported_algorithm

The signing algorithm used by the agent is not supported by the server. The response MUST include a `supported_algorithms` member:

```http
AAuth-Error: error=unsupported_algorithm,
    supported_algorithms=("EdDSA" "ES256")
```

### invalid_key

The public key in `Signature-Key` could not be parsed, is expired, or does not meet the server's trust requirements.

```http
AAuth-Error: error=invalid_key
```

### unknown_key

The public key from `Signature-Key` does not match any key at the agent's `jwks_uri` (applicable when the agent uses `scheme=jwks_uri` for verified identity; see {{keying-material}}). The server SHOULD re-fetch the JWKS once before returning this error, to handle key rotation.

```http
AAuth-Error: error=unknown_key
```

### invalid_jwt

The JWT in the `Signature-Key` header (when using `scheme=jwt` or `scheme=jkt-jwt`) is malformed or its signature verification failed.

```http
AAuth-Error: error=invalid_jwt
```

### expired_jwt

The JWT in the `Signature-Key` header (when using `scheme=jwt` or `scheme=jkt-jwt`) has expired (`exp` claim is in the past).

```http
AAuth-Error: error=expired_jwt
```

## Access Denied

When the server successfully verifies the agent's signature and identity but denies access based on policy (e.g., the agent is not authorized for this resource), the server returns `403 Forbidden`. This is not an AAuth error — the authentication succeeded but authorization was denied. The response MUST NOT include an `AAuth-Requirement` or `AAuth-Error` header.

# Privacy Considerations

## Key Thumbprint Tracking

When an agent uses `scheme=hwk` (pseudonymous access), the server can track the agent across requests by JWK Thumbprint ([@!RFC7638]). If the agent uses the same key across multiple servers, those servers could correlate the agent's activity. Agents MUST use distinct keys for distinct servers to prevent cross-server correlation of pseudonymous identity.

## Agent Identity Disclosure

When an agent presents its identity via `scheme=jwks_uri` or `scheme=jwt`, the server learns the agent's HTTPS URL. This reveals which software is making the request. Servers SHOULD NOT disclose agent identity information to third parties without the agent operator's consent.

## JWKS Fetch Side Channel

When a server fetches an agent's JWKS from `jwks_uri` to verify a signature, the fetch itself reveals to the agent's JWKS host that someone is verifying signatures for that agent.

# Security Considerations

## HTTP Message Signature Security

HTTP Message Signatures provide:

1. **Request Integrity**: The signature covers HTTP method, target URI, and headers
2. **Replay Protection**: The `created` timestamp limits signature validity
3. **Key Binding**: Signatures are bound to specific keys via `Signature-Key`

## Replay Protection {#replay-protection}

The 60-second validity window on the `created` timestamp (see {{verification-resource}}) limits the useful lifetime of a captured signature. The 60-second value balances clock-skew tolerance (NTP-synchronized hosts typically drift less than 10 seconds) against replay exposure — a shorter window would reject legitimate requests from hosts with modest clock drift, while a longer window would widen the replay attack surface.

Within that window, resources MUST maintain a cache of recently seen (key thumbprint, `created`) pairs and reject duplicate combinations. Without this cache, an attacker who captures a signed request can replay it within the validity window.

## JWKS Caching

Resources that fetch JWKS documents for signature verification SHOULD cache the results with a TTL appropriate to their risk tolerance (recommended: 5 minutes for auth servers, 60 minutes for resources). JWKS endpoints SHOULD support standard HTTP caching headers (`Cache-Control`, `Expires`) per ([@RFC9111]).

When signature verification fails due to an unknown key, the server SHOULD re-fetch the JWKS once before returning an `unknown_key` error, to handle key rotation.

# IANA Considerations

## HTTP Header Field Registration

This specification registers the following entry in the "Hypertext Transfer Protocol (HTTP) Field Name Registry" ([@!RFC9110], Section 16.3.1):

- Header Field Name: `AAuth-Requirement`
- Status: permanent
- Structured Type: Dictionary
- Reference: This document

- Header Field Name: `AAuth-Error`
- Status: permanent
- Structured Type: Dictionary
- Reference: This document

## AAuth Requirement Level Registry

This specification establishes the AAuth Requirement Level Registry. The initial contents are:

| Value | Reference |
|-------|-----------|
| `pseudonym` | This document |
| `identity` | This document |
| `interaction` | This document |
| `approval` | This document |

New values may be registered following the Specification Required policy ([@!RFC8126]).

## AAuth Error Code Registry

This specification establishes the AAuth Error Code Registry. The initial contents are:

| Value | Reference |
|-------|-----------|
| `invalid_request` | This document |
| `invalid_input` | This document |
| `invalid_signature` | This document |
| `unsupported_algorithm` | This document |
| `invalid_key` | This document |
| `unknown_key` | This document |
| `invalid_jwt` | This document |
| `expired_jwt` | This document |

New values may be registered following the Specification Required policy ([@!RFC8126]).

# Design Rationale

## Why Not Extend WWW-Authenticate?

`WWW-Authenticate` ([@!RFC9110], Section 11.6.1) tells the client which authentication scheme to use. Its challenge model is "present credentials" — it cannot express progressive requirements, authorization, or deferred approval, and it cannot appear in a `202 Accepted` response.

AAuth-Requirement coexists with `WWW-Authenticate`. A `401` response MAY include both headers, and the client uses whichever it understands:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
AAuth-Requirement: requirement=identity
```

A `402` response MAY include `WWW-Authenticate` for payment (e.g., the Payment scheme defined by the Micropayment Protocol ([@!I-D.ryan-httpauth-payment])) alongside `AAuth-Requirement` for authentication or authorization:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
AAuth-Requirement: requirement=pseudonym
```

# Implementation Status

*Note: This section is to be removed before publishing as an RFC.*

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in [@RFC7942]. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.

The following implementations are known at the time of writing:

- **@aauth npm packages** (https://www.npmjs.com/org/aauth): JavaScript/TypeScript libraries implementing HTTP Message Signatures and AAuth-Requirement processing for agents and servers.

- **aauth-implementation** (https://github.com/christian-posta/aauth-implementation): Python library implementing HTTP Message Signatures (RFC 9421), AAuth request signing/verification, and Signature-Key header support. Author: Christian Posta.

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-aauth-headers-00
  - Initial submission, renamed from draft-hardt-aauth-header
  - Added AAuth-Error header with extensible error code registry
  - Added `interaction` and `approval` requirement levels
  - Added `url` parameter to interaction for self-contained challenge
  - Renamed terminology from "resource" to "server"

# Acknowledgments

TBD

{backmatter}
