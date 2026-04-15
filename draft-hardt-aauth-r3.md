%%%
title = "AAuth Rich Resource Requests (R3)"
abbrev = "AAuth-R3"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["agent", "authorization", "http", "resource"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-aauth-r3-latest"
stream = "IETF"

date = 2026-03-24T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

%%%

<reference anchor="I-D.hardt-aauth-protocol" target="https://github.com/dickhardt/AAuth">
  <front>
    <title>AAuth Protocol</title>
    <author initials="D." surname="Hardt" fullname="Dick Hardt">
      <organization>Hellō</organization>
    </author>
    <date year="2026"/>
  </front>
</reference>


.# Abstract

This document defines AAuth Rich Resource Requests (R3), an extension to the AAuth Protocol ([@!I-D.hardt-aauth-protocol]) that enables structured, vocabulary-based authorization for resource access. Resources publish R3 documents (content-addressed authorization definitions) and advertise vocabularies describing their operations. Agents request access using those vocabularies. Auth tokens carry granted operations in the same vocabulary format, enabling resources to enforce authorization directly from the token. R3 provides human-displayable context for consent decisions and content-addressed audit provenance via the `r3_s256` hash in auth tokens.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

This document is part of the AAuth specification family. Source for this draft and an issue tracker can be found at https://github.com/dickhardt/AAuth.

{mainmatter}

# Introduction

**Status: Exploratory Draft**

The AAuth Protocol ([@!I-D.hardt-aauth-protocol]) defines resource tokens as the mechanism by which resources declare what authorization is needed to access them, and scope strings as the primary way to express what operations are available. Scopes are sufficient for simple, well-known access patterns but are limited in three respects:

1. **Human comprehension.** Scope strings like `calendar:write` are not self-describing to users or auth agents making approval decisions.

2. **Machine precision.** Scopes do not express which specific operations are being authorized or distinguish operations that need per-call approval.

3. **Audit completeness.** Scopes do not identify which specific version of an authorization definition was in effect at the time of approval.

R3 addresses these by introducing:

- **Vocabularies** that describe a resource's operations in terms the agent already understands (MCP tools, OpenAPI operations, gRPC methods, etc.)
- **R3 documents**: structured, content-addressed authorization definitions published by the resource and fetched by the AS
- **Vocabulary-based grants** in auth tokens, so resources can enforce authorization directly from claims they understand

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

- **Vocabulary**: A defined scheme for expressing resource operations. Each vocabulary corresponds to an API description format (MCP, OpenAPI, gRPC, GraphQL, AsyncAPI, WSDL, OData). Resources advertise which vocabularies they support; agents use them to request access.
- **R3 Document**: A JSON document published by a resource, describing the operations it provides and the consequences of granting access. Identified by the SHA-256 hash of its content. Fetched by both the MM (for user consent using `display` fields) and the AS (for policy evaluation using `operations`); not accessible to agents.
- **R3 URI (`r3_uri`)**: A URI identifying an R3 document. Included in a resource token.
- **R3 Hash (`r3_s256`)**: A SHA-256 hash of the R3 document, base64url-encoded without padding. Included alongside `r3_uri` in the resource token and the auth token.

# Vocabularies

Resources advertise their supported vocabularies in well-known metadata. Each vocabulary maps to an API description format that agents already know how to discover and parse.

## Resource Metadata Extensions

R3 extends the `/.well-known/aauth-resource.json` document defined in AAuth Protocol ([@!I-D.hardt-aauth-protocol]):

```json
{
  "resource": "https://calendar.example.com",
  "r3_vocabularies": {
    "urn:aauth:vocabulary:mcp": "https://calendar.example.com/mcp",
    "urn:aauth:vocabulary:openapi": "https://calendar.example.com/openapi.json"
  }
}
```

**`r3_vocabularies`** (OPTIONAL). A JSON object mapping vocabulary URIs to their discovery endpoints. Keys MUST be vocabulary URIs from the `urn:aauth:vocabulary:` namespace for standard vocabularies defined in this document, or third-party URI namespaces for proprietary vocabularies. Values are vocabulary-specific discovery endpoints (the MCP server URL, the OpenAPI spec URL, the gRPC reflection endpoint, etc.). A resource MAY advertise multiple vocabularies simultaneously.

## Standard Vocabularies

This document defines seven standard vocabularies. Third parties MAY define additional vocabularies using their own URI namespaces. Each vocabulary defines: the vocabulary URI, the structure of operation requests, how the resource maps operations to R3 documents, and the discovery endpoint.

Standard vocabularies use the `urn:aauth:vocabulary:` namespace.

### MCP Vocabulary (`urn:aauth:vocabulary:mcp`) {#mcp-vocabulary}

For resources that expose an MCP server. The discovery endpoint is the MCP server URL. Agents discover available tool names via MCP tool discovery.

Each operation entry contains:

- **`tool`** (REQUIRED). The MCP tool name as advertised by the MCP server's tool discovery.

```json
{
  "vocabulary": "urn:aauth:vocabulary:mcp",
  "operations": [
    { "tool": "create_calendar_event" },
    { "tool": "modify_calendar_event" }
  ]
}
```

### OpenAPI Vocabulary (`urn:aauth:vocabulary:openapi`) {#openapi-vocabulary}

For resources that expose an OpenAPI-described HTTP API. The discovery endpoint is the OpenAPI specification URL. Agents discover available operations by fetching and parsing the spec.

Each operation entry contains:

- **`operationId`** (REQUIRED). The `operationId` as defined in the OpenAPI specification.

```json
{
  "vocabulary": "urn:aauth:vocabulary:openapi",
  "operations": [
    { "operationId": "createEvent" },
    { "operationId": "updateEvent" }
  ]
}
```

### gRPC Vocabulary (`urn:aauth:vocabulary:grpc`) {#grpc-vocabulary}

For resources that expose a gRPC server. The discovery endpoint is the gRPC server reflection endpoint (supporting `grpc.reflection.v1.ServerReflection`) or a hosted `.proto` file URL.

Each operation entry contains:

- **`method`** (REQUIRED). The fully qualified gRPC method name in the form `package.ServiceName/MethodName`.

```json
{
  "vocabulary": "urn:aauth:vocabulary:grpc",
  "operations": [
    { "method": "calendar.CalendarService/CreateEvent" },
    { "method": "calendar.CalendarService/UpdateEvent" }
  ]
}
```

### GraphQL Vocabulary (`urn:aauth:vocabulary:graphql`) {#graphql-vocabulary}

For resources that expose a GraphQL API. The discovery endpoint is the GraphQL endpoint. Agents discover available operations via GraphQL introspection (`__schema` query).

Each operation entry contains:

- **`operation`** (REQUIRED). The GraphQL operation name. MUST be a named query, mutation, or subscription.
- **`type`** (REQUIRED). One of `query`, `mutation`, or `subscription`.

```json
{
  "vocabulary": "urn:aauth:vocabulary:graphql",
  "operations": [
    { "operation": "CreateCalendarEvent", "type": "mutation" },
    { "operation": "GetCalendarEvents", "type": "query" }
  ]
}
```

### AsyncAPI Vocabulary (`urn:aauth:vocabulary:asyncapi`) {#asyncapi-vocabulary}

For resources that expose an event-driven interface described by AsyncAPI. The discovery endpoint is the AsyncAPI specification URL.

Each operation entry contains:

- **`operationId`** (REQUIRED). The `operationId` as defined in the AsyncAPI specification.
- **`action`** (REQUIRED). One of `send` or `receive`.

```json
{
  "vocabulary": "urn:aauth:vocabulary:asyncapi",
  "operations": [
    { "operationId": "publishCalendarUpdate", "action": "send" },
    { "operationId": "receiveCalendarEvent", "action": "receive" }
  ]
}
```

### WSDL Vocabulary (`urn:aauth:vocabulary:wsdl`) {#wsdl-vocabulary}

For resources that expose a SOAP/WSDL-described web service. The discovery endpoint is the WSDL document URL.

Each operation entry contains:

- **`operation`** (REQUIRED). The operation name as defined in the WSDL `portType` or `binding`.
- **`service`** (OPTIONAL). The WSDL service name, for disambiguation when multiple services expose the same operation name.

```json
{
  "vocabulary": "urn:aauth:vocabulary:wsdl",
  "operations": [
    { "operation": "CreateCalendarEvent", "service": "CalendarService" }
  ]
}
```

### OData Vocabulary (`urn:aauth:vocabulary:odata`) {#odata-vocabulary}

For resources that expose an OData service. The discovery endpoint is the OData service root URL. Agents discover entity sets, functions, and actions via the `$metadata` document.

Each operation entry contains:

- **`operation`** (REQUIRED). An entity set name, a bound function (`EntitySet/FunctionName`), or a bound action (`EntitySet/ActionName`).
- **`methods`** (OPTIONAL). An array of HTTP methods for entity set CRUD (e.g., `["GET", "POST"]`). Omitted for bound functions and actions.

```json
{
  "vocabulary": "urn:aauth:vocabulary:odata",
  "operations": [
    { "operation": "Events", "methods": ["GET", "POST", "PATCH"] },
    { "operation": "Events/SendCancellation" }
  ]
}
```

# Authorization Endpoint Extensions {#authorization-endpoint-extensions}

R3 extends the authorization endpoint defined in AAuth Protocol ([@!I-D.hardt-aauth-protocol]) with an `r3_operations` request parameter. When an agent wants to declare intended operations using a resource's vocabulary, it includes `r3_operations` in the authorization endpoint request body.

## Request

The agent sends `r3_operations` in the authorization endpoint request:

```http
POST /authorize HTTP/1.1
Host: calendar.example.com
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1741824000
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "r3_operations": {
    "vocabulary": "urn:aauth:vocabulary:openapi",
    "operations": [
      { "operationId": "createEvent" },
      { "operationId": "updateEvent" }
    ]
  }
}
```

**`r3_operations`** (OPTIONAL). An object containing:

- **`vocabulary`** (REQUIRED). A URI identifying the vocabulary. MUST be supported by the resource as advertised in `r3_vocabularies`.
- **`operations`** (REQUIRED). An array of operation requests. Structure is vocabulary-specific; see {{mcp-vocabulary}} through {{odata-vocabulary}}.

When `r3_operations` is present, the resource maps the declared operations to an appropriate R3 document and includes `r3_uri` and `r3_s256` in the resource token. When `r3_operations` is absent, the resource MAY still include R3 claims in the resource token based on its own policy.

## Response

The resource returns a resource token as defined in AAuth Protocol ([@!I-D.hardt-aauth-protocol]), extended with R3 claims:

```json
{
  "resource_token": "eyJhbGciOiJFUzI1NiJ9..."
}
```

The resource token contains `r3_uri` and `r3_s256` identifying the R3 document that covers the requested operations. The resource's internal mapping from operations to R3 documents is opaque to the agent.

# R3 Document

An R3 document is a JSON object published by the resource at a URI. It describes the authorization semantics for a class of access: what operations are covered (in vocabulary format), what the access means in human terms, and what consequences it carries.

The document MUST be served over HTTPS. The resource MUST require a valid HTTP Message Signature on requests to R3 document URIs, and MUST reject requests that are not signed by the resource's AS. Agents cannot fetch R3 documents.

```json
{
  "type": "urn:example:calendar:write",
  "version": "2",
  "vocabulary": "urn:aauth:vocabulary:mcp",
  "operations": [
    { "tool": "create_calendar_event" },
    { "tool": "modify_calendar_event" }
  ],
  "display": {
    "summary": "Create and modify events on your work calendar",
    "implications": "Meetings can be scheduled or rescheduled. Existing events can be modified.",
    "data_accessed": "Event titles, times, attendees, and descriptions in the work calendar",
    "irreversible": "Sent meeting invitations cannot be unsent"
  }
}
```

## Fields

**`type`** (REQUIRED). A URI identifying the class of authorization. SHOULD be a namespaced URI under the resource's authority.

**`version`** (RECOMMENDED). A string identifying the version of this authorization type definition. The combination of URI + SHA-256 hash provides content-addressing independent of this field; `version` is for human readability.

**`vocabulary`** (REQUIRED). The vocabulary URI identifying how operations are expressed. MUST match one of the vocabularies the resource advertises in `r3_vocabularies`.

**`operations`** (REQUIRED). An array of operations covered by this R3 document, using the vocabulary-specific structure defined in {{mcp-vocabulary}} through {{odata-vocabulary}}. This is the same format used in the agent's `r3_operations` request and in the auth token's `r3_granted` and `r3_conditional` claims.

**`display`** (RECOMMENDED). Human-readable descriptions of the consequences of granting this access. The resource describes what *it* does, not what the agent intends:

- `summary` (REQUIRED if `display` present). A short plain-language description suitable for a consent UI or auth agent.
- `implications` (OPTIONAL). Side effects of granting this access: emails sent, records modified, costs incurred.
- `data_accessed` (OPTIONAL). What data becomes visible to the caller.
- `irreversible` (OPTIONAL). Plain-language description of actions that cannot be undone.

## Content Addressing

The R3 hash (`r3_s256`) is computed as the SHA-256 hash of the canonical JSON serialization ([@!RFC8785]) of the R3 document, base64url-encoded without padding.

The `r3_s256` hash is the document's identity, not the URI. The AS caches documents by hash. If a resource updates the document at the same URI, existing auth tokens still reference the previous hash (which the AS has cached). New resource tokens reference the new hash. This enables:

- **Infinite caching by the AS.** A document that verifies against its hash need never be re-fetched.
- **Permanent audit records.** An auth token carrying `r3_s256` identifies the exact authorization semantics that were approved, regardless of subsequent changes at the same URI.

## Resource Token Extensions

R3 extends the resource token defined in AAuth Protocol ([@!I-D.hardt-aauth-protocol]) (a JWT with `typ: resource+jwt`) with two additional payload claims. When a resource includes R3 information, it MUST include both.

Base claims (from AAuth Protocol):
- `iss`: Resource URL
- `dwk`: `aauth-resource.json`
- `aud`: Auth server URL
- `jti`: Unique token identifier
- `agent`: Agent identifier
- `agent_jkt`: JWK Thumbprint of the agent's signing key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp
- `scope`: Requested scopes (optional)

R3 extension claims:
- **`r3_uri`** (REQUIRED for R3): The URI where the AS can fetch the R3 document. The AS authenticates itself using an HTTP Message Signature.
- **`r3_s256`** (REQUIRED for R3): The SHA-256 hash of the R3 document at `r3_uri`, base64url-encoded without padding.

```json
{
  "typ": "resource+jwt",
  "alg": "ES256",
  "kid": "resource-key-1"
}
```

```json
{
  "iss": "https://calendar.example.com",
  "dwk": "aauth-resource.json",
  "aud": "https://as.example.com",
  "jti": "rt-8f3a2b",
  "agent": "assistant@agent.example",
  "agent_jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "r3_uri": "https://calendar.example.com/r3/a1b2c3d4",
  "r3_s256": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd",
  "iat": 1741824000,
  "exp": 1741824300
}
```

Resource tokens MAY include both `scope` (as defined in AAuth Protocol ([@!I-D.hardt-aauth-protocol])) and R3 claims. When both are present, the AS MUST enforce both independently.

# R3 Processing

Both the MM and the AS fetch R3 documents, but for different purposes:

- **The MM** fetches R3 to present the `display` section to the user during consent — summary, implications, data accessed, irreversibility. The MM uses this information to determine whether the request fits the mission scope and to obtain informed user consent.
- **The AS** fetches R3 to evaluate `operations` for policy decisions and to populate `r3_granted` and `r3_conditional` in the auth token.

Both independently verify `r3_s256` against the fetched document. Because R3 documents are content-addressed, both can cache aggressively by hash.

## AS Processing

When the AS receives a resource token containing `r3_uri` and `r3_s256`, it MUST:

1. Validate the resource token signature per AAuth Protocol ([@!I-D.hardt-aauth-protocol]).
2. Fetch the R3 document at `r3_uri`. The AS MAY use a cached copy if the cache entry was stored with the same `r3_s256` value.
3. Compute the SHA-256 hash of the fetched document using canonical JSON serialization ([@!RFC8785]) and compare it to `r3_s256`. If the hashes do not match, the AS MUST reject the resource token.
4. Record `r3_uri` and `r3_s256` in its audit log alongside the token issuance event, the agent identifier, and the timestamp.
5. Use the `operations` section for policy evaluation.
6. Include `r3_uri`, `r3_s256`, `r3_granted`, and (if applicable) `r3_conditional` in the issued auth token.

## Caching

Because R3 documents are content-addressed, the AS MAY cache them by `r3_s256` to avoid redundant fetches. When serving a cached entry, the AS MUST verify that the stored document produces the expected hash. The AS is not required to retain R3 documents beyond their immediate use in token issuance — the AS's audit log records `r3_uri` and `r3_s256`, which is sufficient for later verification by re-fetching.


# Auth Token Extensions

R3 extends the auth token defined in AAuth Protocol ([@!I-D.hardt-aauth-protocol]) (a JWT with `typ: auth+jwt`) with claims for audit provenance and vocabulary-based grants. The resource can enforce authorization directly from these claims.

Base claims (from AAuth Protocol):
- `iss`: Auth server URL
- `dwk`: `aauth-issuer.json`
- `aud`: Resource URL
- `jti`: Unique token identifier
- `agent`: Agent identifier
- `cnf`: Confirmation claim with `jwk` containing the agent's public key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp
- `sub`: User identifier (conditional)
- `scope`: Authorized scopes (conditional)

R3 extension claims:
- **`r3_uri`** (REQUIRED for R3): The URI of the R3 document that was in effect at approval time.
- **`r3_s256`** (REQUIRED for R3): The SHA-256 hash of that R3 document.
- **`r3_granted`** (REQUIRED for R3): Operations the AS fully authorized. The resource serves these immediately.
- **`r3_conditional`** (OPTIONAL): Operations authorized in principle but requiring per-call approval based on the specific parameters the agent provides.

```json
{
  "typ": "auth+jwt",
  "alg": "ES256",
  "kid": "as-key-1"
}
```

```json
{
  "iss": "https://as.example.com",
  "dwk": "aauth-issuer.json",
  "aud": "https://calendar.example.com",
  "jti": "at-9d4c1e",
  "agent": "assistant@agent.example",
  "sub": "user:alice@example.com",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "NzbLsXh8uDCcd..." } },
  "r3_uri": "https://calendar.example.com/r3/a1b2c3d4",
  "r3_s256": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd",
  "r3_granted": {
    "vocabulary": "urn:aauth:vocabulary:mcp",
    "operations": [
      { "tool": "list_calendar_events" },
      { "tool": "modify_calendar_event" }
    ]
  },
  "r3_conditional": {
    "vocabulary": "urn:aauth:vocabulary:mcp",
    "operations": [
      { "tool": "create_calendar_event" }
    ]
  },
  "iat": 1741824000,
  "exp": 1741824900
}
```

**`r3_uri`** and **`r3_s256`** provide audit provenance: a permanent, verifiable record of which R3 document was in effect at approval time. The AS can verify the R3 document by fetching `r3_uri` and checking `r3_s256`.

**`r3_granted`** and **`r3_conditional`** use the same vocabulary-specific operation format as the R3 document's `operations` field and the agent's `r3_operations` request:

- **`vocabulary`** (REQUIRED). The vocabulary URI.
- **`operations`** (REQUIRED). An array of operations using the vocabulary-specific structure. The AS MAY narrow the grant to fewer operations than defined in the R3 document.

The distinction: `r3_granted` operations are fully authorized and the resource serves them. `r3_conditional` operations require the resource to challenge when the agent actually calls, including the specific parameters from the agent's API request in the resource token. The AS then evaluates those concrete parameters before issuing a per-call auth token.

## Resource Enforcement

The resource matches each incoming API call against the auth token claims:

1. **Match in `r3_granted`**: serve the request.
2. **Match in `r3_conditional`**: return `AAuth-Requirement` with a resource token containing the actual parameters the agent provided. The AS evaluates the specific call.
3. **No match**: reject the request.

No token introspection or R3 document fetch is needed at enforcement time. The resource uses the vocabulary it already understands.

When `r3_operations` was not used (the agent received the resource token via a 401 rather than the authorization endpoint), the AS populates `r3_granted` and `r3_conditional` based on the operations defined in the R3 document and its own policy. The AS decides which operations to grant outright and which to make conditional.

# Security Considerations

## R3 Document Access Restriction

The AS MUST authenticate itself when fetching `r3_uri` using an HTTP Message Signature as defined in the AAuth Protocol ([@!I-D.hardt-aauth-protocol]). The resource MUST reject requests not signed by its AS.

This prevents agents from fetching R3 documents by following the `r3_uri` they carry in the resource token. Since a resource has exactly one AS, the resource only needs to recognize signatures from that AS. The agent opacity property (agents carry the hash of a document they cannot read) depends on this restriction.

## R3 Endpoint Access Control

The agent opacity property — agents carry the hash of a document they cannot read — depends entirely on the resource correctly restricting access to R3 document endpoints. If the resource fails to require a valid HTTP Message Signature from its AS on R3 document requests, or accepts signatures from keys other than its AS's, agents can fetch and read R3 documents, breaking the opacity guarantee. Implementations MUST treat R3 endpoint access control as a critical security requirement and SHOULD verify this restriction during deployment testing.

## Hash Verification

The AS MUST verify `r3_s256` against the fetched document before using it. Failure to verify allows a resource to serve different content than what was hashed in the resource token.

## Audit Log Integrity

The AS MUST write audit log entries atomically with token issuance. An auth token issued without a corresponding audit log entry creates an undetectable gap in the observability record. Implementations SHOULD use transactional writes or equivalent mechanisms.

## Operation Validation

For all vocabularies, the resource MUST validate declared operations against its authoritative definition (MCP tool list, OpenAPI spec, `.proto` file, GraphQL schema, AsyncAPI spec, WSDL document, or OData `$metadata`) before issuing a resource token.

## Grant Enforcement

Resources MUST enforce `r3_granted` and `r3_conditional` claims in auth tokens. Operations in `r3_granted` define fully authorized access. Operations in `r3_conditional` MUST trigger an `AAuth-Requirement` before being served. The resource MUST reject API calls that do not match an operation in either claim.

# IANA Considerations

## JWT Claims Registration

This document requests registration of the following JWT claims in the IANA JSON Web Token Claims registry:

| Claim | Description | Reference |
|-------|-------------|-----------|
| `r3_uri` | R3 document URI | This document |
| `r3_s256` | R3 document SHA-256 hash | This document |
| `r3_granted` | Fully authorized operations in vocabulary format | This document |
| `r3_conditional` | Conditionally authorized operations requiring per-call approval | This document |

## R3 Vocabulary Registry

This specification establishes the AAuth R3 Vocabulary Registry. The initial contents are:

| Vocabulary URI | Interface Type | Reference |
|----------------|---------------|-----------|
| `urn:aauth:vocabulary:mcp` | MCP server | This document |
| `urn:aauth:vocabulary:openapi` | HTTP/REST | This document |
| `urn:aauth:vocabulary:grpc` | gRPC | This document |
| `urn:aauth:vocabulary:graphql` | GraphQL | This document |
| `urn:aauth:vocabulary:asyncapi` | Event-driven | This document |
| `urn:aauth:vocabulary:wsdl` | SOAP/WSDL | This document |
| `urn:aauth:vocabulary:odata` | OData | This document |

New values may be registered following the Specification Required policy ([@!RFC8126]).

# Implementation Status

*Note: This section is to be removed before publishing as an RFC.*

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in [@RFC7942]. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.

There are currently no known implementations.

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-aauth-r3-00
  - Initial submission

# Acknowledgments

The author would like to thank reviewers for their feedback.

{backmatter}

# Design Rationale

## Why Not RAR

OAuth 2.0 Rich Authorization Requests ([@RFC9396]) defines `authorization_details` as a structured extension to authorization requests. RAR is a natural reference point for this work. R3 deliberately does not use or profile RAR for the following reasons:

**Directionality.** RAR is client-declared: the agent constructs `authorization_details` and sends it to the AS. The agent defines what it wants. R3 is resource-declared: the resource defines what access it provides and signs that definition. The agent cannot modify or reframe it. This is the opposite directionality, and the security properties depend on it.

**Agent opacity.** In R3, the R3 document is fetched by the AS directly from the resource, restricted to AS-only access. The agent carries a hash of a document it cannot read. RAR has no equivalent because the client constructs the authorization details and necessarily knows their content.

**Content addressing.** R3 uses a content-addressed URI plus SHA-256 hash to pin the exact authorization semantics in effect at approval time. An auth token carrying `r3_uri` and `r3_s256` is a permanent, verifiable record. RAR carries no equivalent versioning or integrity guarantee.

**Audit trail.** The AS records `r3_uri` in its audit log, creating a durable reference to the exact R3 document version. This is not possible with RAR's inline `authorization_details` structure.

RAR and R3 are complementary. RAR remains appropriate for client-declared authorization detail. R3 addresses the resource-declared case that RAR was not designed for.

# Vocabulary Summary

| Vocabulary URI | Interface Type | Operation Identifier | Discovery Mechanism |
|----------------|---------------|---------------------|---------------------|
| `urn:aauth:vocabulary:mcp` | MCP server | Tool name | MCP tool discovery |
| `urn:aauth:vocabulary:openapi` | HTTP/REST | `operationId` | OpenAPI spec URL |
| `urn:aauth:vocabulary:grpc` | gRPC | `package.Service/Method` | Server reflection or `.proto` URL |
| `urn:aauth:vocabulary:graphql` | GraphQL | Operation name | GraphQL introspection |
| `urn:aauth:vocabulary:asyncapi` | Event-driven | `operationId` | AsyncAPI spec URL |
| `urn:aauth:vocabulary:wsdl` | SOAP/WSDL | Operation name | WSDL document URL |
| `urn:aauth:vocabulary:odata` | OData | Entity set or bound operation | `$metadata` URL |

# Comparison with RAR

| Property | RAR ([@RFC9396]) | R3 |
|----------|---------------|----|
| Who declares | Client (agent) | Resource |
| Direction | Client -> AS | Resource -> AS (via agent carrier) |
| Agent visibility | Agent constructs the detail | Agent carries opaque token |
| Versioning | None | Content-addressed URI + hash |
| Audit trail | Inline in request | `r3_uri` recorded by AS |
| Human display | Not specified | `display` section in R3 document |
| Irreversibility signal | Not specified | `display.irreversible` field |
