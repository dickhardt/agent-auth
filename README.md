# Agent Auth (AAuth)

**Author:**
Dick Hardt
Email: dick.hardt@hello.coop

**Date:** November 21, 2025

---

## TL;DR

AAuth is an agent aware auth protocol for modern distributed systems:
- **Progressive authentication** - from abuse prevention to full authorization
- **Agent identity** - verify applications alongside users
- **Unified protocol** - authentication and authorization in one flow
- **Dynamic ecosystems** - no pre-registration required
- **Proof-of-possession** - every request is signed, removing shared secrets
- **Multi-hop access** - resources calling resources with token exchange or downstream user interaction

---

## Preamble

**Agent Auth (AAuth)** is an exploratory specification examining what new capabilities and features may be useful to address use cases that are not well-served by existing protocols like OAuth 2.0, OpenID Connect (OIDC), and SAML. While these protocols excel in their designed use cases, the internet has evolved in ways that create gaps AAuth aims to fill.

The document explores use cases requiring capabilities beyond OAuth 2.0 and OIDC's design:
- **From bearer tokens to proof-of-possession**: Every request is cryptographically signed, eliminating token exfiltration as an attack vector
- **From pre-registered client IDs to HTTPS-based agent identities**: Enabling dynamic ecosystems without registration bottlenecks
- **From long-lived shared secrets to ephemeral keys**: Supporting distributed application instances with rapid revocation
- **From separate authentication and authorization protocols to unified auth**: Single flow provides both identity and delegated access
- **From user-only authorization to agent-aware access control**: Resources can enforce policies based on verified agent identity
- **From coarse scopes to rich authorization context**: Enabling meaningful user consent and least-privilege access
- **From single-hop to multi-hop access**: Resources often need to access downstream resources to fulfill requests. Token exchange enables access through multiple hops while maintaining proof-of-possession and user context, with interaction requests bubbling up as needed

AAuth builds on proven patterns from OAuth 2.1 (authorization code flow, refresh tokens, metadata discovery) and OIDC (identity claims, user authentication) while introducing capabilities for modern agent-based architectures.

**This is an exploration and explainer, not a ready-to-adopt draft.** Coding agents were used to create the boilerplate normative text and examples. There may be mistakes. The objective is to paint a picture of how modern authorization could work and spark discussion about addressing the gap between OAuth 2.0's assumptions and today's security and architectural realities.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Protocol Overview](#3-protocol-overview)
4. [Agent-Auth Response Header](#4-agent-auth-response-header)
5. [Agent Tokens](#5-agent-tokens)
6. [Auth Tokens](#6-auth-tokens)
7. [Metadata Documents](#7-metadata-documents)
8. [Protocol Details](#8-protocol-details)
9. [HTTP Message Signing Profile](#9-http-message-signing-profile)
10. [Error Responses](#10-error-responses)
11. [Security Model](#11-security-model)
12. [IANA Considerations](#12-iana-considerations)

**Appendixes:**
- [Appendix A: Relationship to OAuth 2.1 and OIDC](#appendix-a-relationship-to-oauth-21-and-oidc)
- [Appendix B: Long Tail Agent Servers](#appendix-b-long-tail-agent-servers)
- [Appendix C: Agent Token Acquisition Patterns](#appendix-c-agent-token-acquisition-patterns)
- [Appendix D: Relationship to Web-Bot-Auth](#appendix-d-relationship-to-web-bot-auth)
- [Appendix E: Redirect Headers for Enhanced Security](#appendix-e-redirect-headers-for-enhanced-security)

---

## 1. Introduction

OAuth 2.0 was created to replace the anti-pattern of users providing their passwords to applications to scrape their data from web sites. Users could then authorize an application to scoped access of their data without sharing their passwords. The internet has evolved significantly since the release of OAuth 2.0.

- **Security requirements have changed.**

  Exfiltration of bearer tokens has become a common attack vector. While proof-of-possession with digital signatures is now practical and widely supported, bearer tokens and shared secrets are still used in most deployments.

- **Applications are distributed and more diverse.**

  When OAuth 2.0 was created, the client was typically a server. Today it may also be one of many widely distributed instances of a desktop, mobile, or command line application where managing a single long lived shared secret or private key is impractical.

- **Agents have loosened the client-server model.**

  Tightly bound, pre-registered client and server relationships are giving way to more open and dynamic ecosystems. In environments like the **Model Context Protocol (MCP)**, a client may interact with *any* server, not just those it was pre-registered with.

- **Enterprise systems span multiple trust domains.**

  Organizations deploy hundreds of applications across vendors, each requiring access to resources in different security contexts. Role-based authorization is often insufficient. Fine-grained, dynamic access control requires verifying both the calling application and user's identity.

- **OAuth scopes have become insufficient for modern authorization.**

  Traditional OAuth scopes like read or write provide only coarse-grained labels that fail to convey what data will be accessed, under what conditions, for what purpose, or for how long. This opacity prevents meaningful user consent and makes it impossible to enforce least privilege.

- **Resources have varying auth requirements.**

  Resources need different levels of protection for different operations. Public endpoints rely on IP addresses for rate limiting and abuse prevention. Application identity is verified through IP whitelisting, mTLS, or long-lived credentials. Authorization uses API keys, manually provisioned tokens, or OAuth flows—serving both user-delegated access and machine-to-machine patterns. These varying requirements have led to fragmented solutions: IP filtering for abuse, mTLS or credentials for application identity, OAuth or tokens for authorization.

- **Resources often act as agents to access downstream resources.**

  Modern architectures frequently require resources to call other resources to fulfill requests. An API gateway aggregates data from backend services, a data platform queries multiple data sources, or a coordination service orchestrates between systems. When a resource needs downstream access, it must acquire authorization—sometimes autonomously based on its identity, sometimes requiring user interaction despite having no direct user interface. These delegation chains create challenges around maintaining user context, preserving authorization chains, and managing keys across organizational boundaries.

- **Applications require both authentication and authorization.**

  OAuth 2.0 provides authorization (delegated access). OpenID Connect provides authentication (user identity via SSO, alongside SAML). Both protocols excel in their designed use cases: OAuth 2.0 for user-delegated API access; OIDC for browser-based SSO to web applications. However, applications often need both authentication and authorization in contexts where the separation creates friction. 

AAuth addresses these evolved requirements by redefining the relationships between three web participants:

- **Agents:** the applications and autonomous processes
- **Resources:** the protected APIs and data endpoints agents need to access
- **Auth Servers:** the systems that authenticate users and issue authorization

AAuth's protocol features directly address each trend:

- **HTTP Message Signing (HTTPSig)** replaces bearer tokens and shared secrets. Every request an agent makes is cryptographically signed with an ephemeral key it controls, eliminating token exfiltration as an attack vector and providing verifiable proof-of-possession and message integrity when calling both an auth server and a protected resource

- **HTTPS-based agent identity and delegation** addresses distributed applications. Agents are identified by HTTPS URLs rather than pre-registered client IDs and redirect URIs. An agent identity can be used directly by an agent server (publishing metadata and keys), or delegated to agent delegates through short-lived agent tokens that bind ephemeral signing keys to the agent's identity, enabling rapid key rotation without managing long-lived shared secrets.

- **Discoverable metadata** enables dynamic agent ecosystems. Each participant publishes a metadata document describing their capabilities and endpoints. Resources declare their trusted auth servers, auth servers advertise their features, and agents present their identity and policies. This allows any agent to interact with any resource or auth server without pre-established relationships if desired.

- **Verifiable application and user identity** supports multi-domain trust. Auth tokens can contain both the agent's cryptographically verified identity and user identity claims from the auth server, enabling fine-grained access control decisions based on who is requesting access and on whose behalf.

- **Extensible authorization context** goes beyond simple scopes. Resources can provide detailed authorization requests conveying what data will be accessed, under what conditions, for what purpose, and for how long. This enables meaningful user consent, fine-grained policy enforcement, and least privilege access control.

- **Progressive auth levels** allow resources to dynamically request the specific level of protection they need using the `Agent-Auth` header. A resource can challenge for signature-based proof-of-possession, verified agent identity, or authorization from the auth server—unifying IP-based abuse prevention, mTLS application identity, and OAuth authorization into a single protocol that scales with request sensitivity.

- **Unified authentication and authorization** eliminates the OAuth/OIDC split. AAuth uses "auth" to represent both authentication and authorization in a single protocol. Auth tokens can contain both identity claims and authorization scopes, giving resources everything they need for access control decisions. This eliminates confusion about when to use OAuth vs. OIDC and prevents common mistakes like misusing ID tokens for API access.


## 2. Terminology

### 2.1 New Definitions

- **agent**: An autonomous process or application identified by an HTTPS URL (the `agent` claim). An agent may act directly as an **agent server** or as an **agent delegate** using delegated authority from an agent server.

> **agent** was chosen rather than reusing **client** as they have different features and capabilities.

- **agent server**: An agent acting with its authoritative identity, using its published JWKS to sign requests directly. The agent server publishes metadata and keys at `https://agent.example/.well-known/agent-server` and may issue **agent tokens** to delegate its identity to agent delegates. For simplified key management for the long tail of agent servers see [Appendix B](#appendix-b-long-tail-agent-servers).

- **agent delegate**: An agent acting under delegated authority from an agent server. An agent delegate proves its identity by presenting an **agent token** (JWT) that binds its signing key to the agent server's identity. Agent delegates include server workloads (e.g., SPIFFE workloads), application installations (mobile, desktop, CLI), and device-specific deployments. 

- **agent token**: A proof-of-possession JWT issued by an agent server to an agent delegate, binding the delegate's signing key and granting it authority to act on behalf of the agent server. Presented to a resource or auth server to prove agent identity. The JWT header includes `"typ": "agent+jwt"` (media type: `application/agent+jwt`).

- **auth server**: The system that authenticates the user, evaluates authorization requests, and issues **auth tokens** binding the agent's key to the granted permissions.

- **auth token**: A proof-of-possession JWT issued by the auth server to an agent, enabling access to a resource. May contain identity claims, scopes, or both. The JWT header includes `"typ": "auth+jwt"` (media type: `application/auth+jwt`).

> **auth** was chosen over **access**, **authorization** or **authentication** to indicate a new token that can represent both authn and authz.

- **request token**: An opaque string issued by the auth server representing a pending authorization request. The agent uses this token at the `agent_authorization_endpoint` to initiate user consent. Similar to `request_uri` in PAR (RFC 9126) but represented as an opaque token value rather than a URI.

- **resource**: A protected HTTPS endpoint that enforces authorization and publishes metadata describing its trusted auth server and signing requirements. Multiple API endpoints may share a single resource identifier for authorization purposes.

> **resource** was chosen rather than reusing **resource server** as they have different features.

### 2.2 Existing Definitions

The following terms are defined in existing specifications and reused in AAuth:

- **refresh token**: A credential used to obtain new access tokens without user interaction. (OAuth 2.0 [RFC 6749] Section 1.5)

- **user**: A human or organization (resource owner) whose identity and consent are represented by the auth server. (OAuth 2.0 [RFC 6749] Section 1.1)

## 3. Protocol Overview

AAuth supports progressive authentication levels—pseudonymous, identified, and authorized—allowing resources to request the appropriate level of protection for each operation using the Agent-Auth response header ([Section 4](#4-agent-auth-response-header)). The protocol involves three participants: agents (applications and autonomous processes), resources (protected APIs), and auth servers (systems that issue authorization). Agents prove their identity using HTTP Message Signatures ([Section 9](#9-http-message-signing-profile)) with agent tokens ([Section 5](#5-agent-tokens)) or auth tokens ([Section 6](#6-auth-tokens)). This section illustrates how these participants interact through common use cases.

Resources use the Agent-Auth response header to dynamically challenge agents for appropriate authentication ([§4](#4-agent-auth-response-header)). However, agents that already know the required scope or request_uri can request authorization directly from the auth server without first calling the resource. The use cases below illustrate the dynamic challenge pattern; direct authorization requests follow the same flow starting from the auth server interaction.

### 3.1 Authentication Upgrade

A web crawler accesses public content without authentication. When rate limits are exceeded, the resource challenges for pseudonymous authentication ([Section 4](#4-agent-auth-response-header)) to grant higher limits using HTTP Message Signatures ([Section 9](#9-http-message-signing-profile)).

```mermaid
sequenceDiagram
    participant Agent as agent
    participant Resource as resource

    Agent->>Resource: unsigned request
    Resource->>Agent: 200 OK

    Note over Agent,Resource: ... more requests ...

    Agent->>Resource: unsigned request
    Resource->>Agent: 429 with Agent-Auth challenge

    Agent->>Resource: HTTPSig request (sig=hwk)
    Resource->>Agent: 200 OK (higher rate limit)
```

### 3.2 Agent Identity

A search engine crawler proves its identity using published JWKS ([Section 7.1](#71-agent-metadata)) to receive allowlisting and preferential rate limits.

```mermaid
sequenceDiagram
    participant Agent as agent server
    participant Resource as resource

    Agent->>Resource: HTTPSig request (sig=jwks)
    Resource->>Agent: fetch JWKS
    Agent->>Resource: JWKS
    Resource->>Resource: verify signature and identity
    Resource->>Agent: 200 OK
```

### 3.3 Delegated Agent

A mobile app with millions of installations uses agent delegation ([Section 5](#5-agent-tokens)) so each installation has unique identity without shared secrets.

```mermaid
sequenceDiagram
    participant Delegate as agent delegate
    participant Server as agent server
    participant Resource as resource

    Delegate->>Server: request agent token
    Server->>Delegate: agent token

    Delegate->>Resource: HTTPSig request (sig=jwt with agent-token)
    Resource->>Server: fetch JWKS
    Server->>Resource: JWKS
    Resource->>Resource: verify agent token and signature
    Resource->>Delegate: 200 OK
```

### 3.4 Autonomous Access

A data sync service copies customer records between CRM and billing systems hourly, authorized based on the service's identity (may request authorization directly if scope or request_uri is pre-configured). The auth server ([Section 8.3](#83-agent-auth-request)) issues an auth token ([Section 6](#6-auth-tokens)) without user interaction.

```mermaid
sequenceDiagram
    participant Agent as agent
    participant Resource as resource
    participant Auth as auth server

    Agent->>Resource: HTTPSig request (sig=jwks)
    Resource->>Agent: 401 with Agent-Auth challenge

    Agent->>Auth: HTTPSig request with resource, scope
    Auth->>Auth: evaluate policy
    Auth->>Agent: auth_token + refresh_token

    Agent->>Resource: HTTPSig request (sig=jwt with auth-token)
    Resource->>Resource: verify auth token
    Resource->>Agent: 200 OK
```

### 3.5 User Delegated Access

An AI assistant accesses a user's calendar data with their explicit consent through an interactive authorization flow ([Section 8.5](#85-user-consent-flow)). The auth token ([Section 6](#6-auth-tokens)) includes both user identity and authorization claims.

```mermaid
sequenceDiagram
    participant User as user
    participant Agent as agent
    participant Resource as resource
    participant Auth as auth server

    Agent->>Resource: HTTPSig request (sig=jwks)
    Resource->>Agent: 401 with Agent-Auth challenge

    Agent->>Auth: HTTPSig request with resource, scope
    Auth->>Agent: request_token

    Agent->>User: redirect to auth server
    User->>Auth: authenticate and consent
    Auth->>Agent: authorization_code (via redirect)

    Agent->>Auth: HTTPSig request with authorization_code
    Auth->>Agent: auth_token + refresh_token

    Agent->>Resource: HTTPSig request (sig=jwt with auth-token)
    Resource->>Agent: 200 OK
```

### 3.6 Auth Refresh

An agent maintains long-lived access by refreshing expired auth tokens ([Section 8.7](#87-auth-token-refresh)) using refresh tokens bound to its identity.

```mermaid
sequenceDiagram
    participant Agent as agent
    participant Auth as auth server
    participant Resource as resource

    Note over Agent: auth_token expired

    Agent->>Auth: HTTPSig request with refresh_token
    Auth->>Auth: verify agent identity and token binding
    Auth->>Agent: new auth_token

    Agent->>Resource: HTTPSig request (sig=jwt with auth-token)
    Resource->>Agent: 200 OK
```

### 3.7 User Interaction Request

A resource requires user interaction (login, SSO, OAuth flow, or consent for downstream access). The resource cannot interact with the user directly, so it returns a user interaction URL to the agent, the agent redirects the user to the resource's interaction endpoint (with `return_url`), the resource facilitates authentication/consent via the auth server, stores the result, redirects the user back to the agent, and the agent retries the original request ([Section 8.6](#86-resource-initiated-user-interaction)).

```mermaid
sequenceDiagram
    participant User as user
    participant Agent as agent
    participant Resource as resource
    participant Auth as auth server

    Agent->>Resource: HTTPSig request (sig=jwt with auth-token)
    Resource->>Agent: 401 Agent-Auth: user_interaction="https://resource.example/auth?session=xyz"

    Agent->>User: redirect to user_interaction URL (with return_url)
    User->>Resource: GET /auth?session=xyz&return_url=...

    Resource->>User: redirect to auth server
    User->>Auth: authenticate and consent
    Auth->>Resource: authorization code

    Resource->>Auth: exchange code for token
    Auth->>Resource: auth_token
    Note over Resource: Store auth_token keyed by session

    Resource->>User: redirect back to agent return_url

    Agent->>Resource: HTTPSig request (retry with session)
    Resource->>Agent: 200 OK
```

### 3.8 Token Exchange

A resource needs to access a downstream resource to fulfill a request. Resource 1 discovers it needs authorization for Resource 2, returns an auth_request with an `exchange` object, Agent 1 gets a new auth token with the `exchange` claim, and Resource 1 exchanges it for an auth token from Auth Server 2 ([Section 8.7](#87-token-exchange-and-chaining)).

```mermaid
sequenceDiagram
    participant Agent1 as agent 1
    participant Auth1 as auth server 1
    participant Resource1 as resource 1 / agent 2
    participant Auth2 as auth server 2
    participant Resource2 as resource 2

    Agent1->>Resource1: HTTPSig request
    Resource1->>Resource2: HTTPSig request (attempt)
    Resource2->>Resource1: 401 Agent-Auth: auth-token required

    Resource1->>Agent1: 401 Agent-Auth: auth_request="https://r1.example/req/xyz"
    Note over Resource1,Agent1: auth_request contains exchange property

    Agent1->>Auth1: Request auth token with exchange
    Auth1->>Agent1: auth_token (with exchange claim)

    Agent1->>Resource1: HTTPSig request (sig=jwt with auth-token)
    Note over Resource1: Extract auth-token from sig=jwt

    Resource1->>Auth2: request_type=exchange&exchange_token=...
    Auth2->>Auth2: Validate exchange authorization
    Auth2->>Resource1: auth_token (bound to Resource 1's key)

    Resource1->>Resource2: HTTPSig request (sig=jwt with new auth-token)
    Resource2->>Resource1: 200 OK

    Resource1->>Agent1: 200 OK (aggregated response)
```

## 4. Agent-Auth Response Header

Resources use the `Agent-Auth` response header (using HTTP structured fields per RFC 8941) to indicate authentication and authorization requirements.

### 4.1. Signature Required

Requires HTTP Message Signing with any authentication level (see Section 3.1).

```
Agent-Auth: httpsig
```

**Agent response:** Include `Signature-Key` header with any scheme (sig=hwk, sig=jwks, sig=x509, or sig=jwt).

### 4.2. Identity Required

Requires agent identity verification (see Section 3.1 for authentication levels).

```
Agent-Auth: httpsig; identity=?1
```

**Agent response:** Use `sig=jwks` or `sig=x509` (agent server) or `sig=jwt` with agent token (agent delegate).

### 4.3. Authorization Required

Requires authorization from an auth server (see Section 3.1 for authentication levels). Includes the resource identifier and access requirements.

**With scope:**
```
Agent-Auth: httpsig; auth-token; resource="https://resource.example"; scope="data.read data.write"
```

**With rich authorization request:**
```
Agent-Auth: httpsig; auth-token; resource="https://resource.example"; request_uri="https://resource.example/authz/req/3f5a"
```

**Agent response:** Obtain auth token from the specified resource's auth server, then retry request with `sig=jwt` and the auth token.

### 4.4. Status Codes and Progressive Rate Limiting

While `Agent-Auth` is typically used with **401 Unauthorized**, resources **MAY** use it with other status codes to enable progressive rate limiting and abuse mitigation based on authentication level.

**401 Unauthorized** - Authentication required

Used when the current authentication level is insufficient:

```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; identity=?1
```

**429 Too Many Requests** - Rate limit exceeded

Used when the agent has exceeded rate limits for their current authentication level, but a higher authentication level would have higher limits:

```http
HTTP/1.1 429 Too Many Requests
Agent-Auth: httpsig; identity=?1
Retry-After: 60
```

**Example progressive rate limiting:**
- Pseudonymous (sig=hwk): 10 requests/minute
- Identified (sig=jwks, sig=x509, or sig=jwt with agent-token): 100 requests/minute
- Authorized (sig=jwt with auth-token): 1000 requests/minute

**403 Forbidden** - Access denied for current authentication level

Used when the agent is blocked or access is denied at the current authentication level, but a higher level might be accepted:

```http
HTTP/1.1 403 Forbidden
Agent-Auth: httpsig; auth-token; resource="https://resource.example"; scope="data.read"
```

This allows resources to block abusive pseudonymous traffic while still accepting identified or authorized requests from the same origin.

### 4.5. Parameters

- `httpsig`: Authentication scheme (REQUIRED for all responses)
- `identity`: Boolean parameter (?1 = true) indicating agent identity is required
- `auth-token`: Bare token indicating authorization is required
- `resource`: String parameter with the resource identifier for authorization
- `scope`: String parameter with space-separated scopes
- `request_uri`: String parameter with URL to fetch rich authorization requirements

### 4.6. Compatibility with WWW-Authenticate

Resources **MAY** include both `Agent-Auth` and `WWW-Authenticate` headers to support multiple authentication protocols:

```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; auth-token; resource="https://resource.example"; scope="data.read"
WWW-Authenticate: Bearer realm="resource.example", scope="data.read"
```

## 5. Agent Tokens

Agent tokens enable agent delegates to prove delegated identity from an agent server. This section describes the token format, claims, and acquisition process.

### 5.1. Purpose

Agent tokens serve two primary purposes:

1. **Identity delegation**: Bind an agent delegate's signing key to the agent server's authoritative identity
2. **Key rotation**: Enable key rotation without affecting refresh tokens or user sessions

An agent server and agent delegate share the same agent identifier (the `agent` claim) from the perspective of resources and auth servers. The difference is in how they prove that identity:
- Agent server: Uses published JWKS directly (no agent token)
- Agent delegate: Presents an agent token signed by the agent server

When the delegate rotates its key (whether due to restart or policy), it obtains a new agent token with the same `sub` (agent delegate identifier), allowing refresh tokens to remain valid.

### 5.2. Token Format

Agent tokens **MUST** be signed JWTs using the JWS Compact Serialization format.

The JOSE header **MUST** include:
- `typ` (REQUIRED): **MUST** be `"agent+jwt"` (media type: `application/agent+jwt`)
- `alg` (REQUIRED): Signature algorithm from the agent server's JWKS
- `kid` (REQUIRED): Key ID identifying the signing key in the agent server's JWKS

### 5.3. Required Claims

- `iss` (REQUIRED): The agent server's HTTPS URL (also the agent identifier)
- `sub` (REQUIRED): Agent delegate identifier. Identifies the delegated workload or installation, not the specific instance. Examples:
  - Server workload: `spiffe://trust-domain/service/api`
  - Mobile app installation: `app-installation-uuid-xyz`
  - Desktop app installation: `desktop-app-install-abc`
  - This identifier persists across restarts and key rotations
- `exp` (REQUIRED): Expiration timestamp (Unix time)
- `cnf` (REQUIRED): Confirmation object containing:
  - `jwk` (REQUIRED): JSON Web Key - the agent delegate's public signing key

### 5.4. Optional Claims

- `aud` (OPTIONAL): Intended audience(s) - restricts which resources or auth servers can accept this agent token. May be a string (single audience) or an array of strings (multiple audiences)
- Additional claims: Agent servers **MAY** include custom claims for delegation policies (future work)

### 5.5. Example Agent Token

**JOSE Header:**
```json
{
  "typ": "agent+jwt",
  "alg": "EdDSA",
  "kid": "agent-server-key-1"
}
```

**Payload:**
```json
{
  "iss": "https://agent.example",
  "sub": "spiffe://example.com/workload/api-service",
  "exp": 1730218200,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  }
}
```

### 5.6. Token Acquisition

Agent delegates obtain agent tokens from their agent server. The specifics of this interaction are **out of scope** for this specification and may vary based on deployment needs. For common patterns and examples, see [Appendix C: Agent Token Acquisition Patterns](#appendix-c-agent-token-acquisition-patterns).

**Key management options:**

Agent delegates **SHOULD** rotate keys frequently. Two common approaches:

- **Ephemeral keys** (recommended for simplicity): Generate fresh key pair at startup, keep in memory only. When delegate restarts, generate new key and request new agent token with same `sub`. Eliminates need for secure key storage.

- **Persisted keys**: Store key securely, rotate based on policy (time-based, event-based, etc.). Request new agent token after rotation with same `sub`.

In both cases, the new agent token uses the same `sub` (agent delegate identifier), allowing refresh tokens to remain valid across key rotations.

**Security considerations:**

- Agent servers **SHOULD** issue short-lived tokens to enable frequent key rotation
- Agent servers **SHOULD** track issued tokens by `sub` for delegation management
- Agent servers **MAY** require additional authentication or authorization before issuing tokens
- Agent delegates **SHOULD** request new agent tokens before expiration to maintain service continuity
- Agent delegates using persisted keys **MUST** store private keys securely

### 5.7. Validation by Resources and Auth Servers

When an agent presents `Signature-Key: sig=jwt; jwt="<agent-token>"`, the recipient **MUST** validate:

1. Parse the JWT and extract the JOSE header
2. Verify `typ` is `"agent+jwt"`
3. Extract `kid` from the JOSE header
4. Extract `iss` (agent) from the payload
5. Fetch the agent server's JWKS (from metadata at `iss`)
6. Match the signing key by `kid`
7. Verify the JWT signature using the matched public key
8. Verify the `exp` claim (current time **MUST** be less than expiration)
9. Verify the `sub` claim is present (agent delegate identifier)
10. If `aud` claim is present, verify the recipient's identifier is included in the audience
11. Extract the public key from `cnf.jwk`
12. Verify that the HTTPSig request signature was created with the key from `cnf.jwk`

## 6. Auth Tokens

Auth tokens are proof-of-possession JWTs issued by auth servers that authorize agents to access specific resources. This section describes the token format and claims.

### 6.1. Purpose

Auth tokens bind together:
- **Agent identity**: Which agent is authorized (via `agent`)
- **Agent key**: The agent's signing key (via `cnf.jwk`)
- **Resource**: What the agent can access (via `aud`)
- **Authorization**: What the agent can do (via `scope` or other claims)
- **User identity**: Optionally, on whose behalf (via `sub` and identity claims)

### 6.2. Token Format

Auth tokens **MUST** be signed JWTs using the JWS Compact Serialization format.

The JOSE header **MUST** include:
- `typ` (REQUIRED): **MUST** be `"auth+jwt"` (media type: `application/auth+jwt`)
- `alg` (REQUIRED): Signature algorithm from the auth server's JWKS
- `kid` (REQUIRED): Key ID identifying the signing key in the auth server's JWKS

### 6.3. Required Claims

- `iss` (REQUIRED): The auth server's HTTPS URL
- `agent` (REQUIRED): The agent's HTTPS URL (from agent identity)
- `aud` (REQUIRED): The resource identifier this token authorizes access to
- `exp` (REQUIRED): Expiration time (Unix timestamp)
- `cnf` (REQUIRED): Confirmation claim object containing:
  - `jwk` (REQUIRED): JSON Web Key - the agent's public signing key (copied from agent token or agent JWKS)

### 6.4. Optional Claims

- `agent_delegate` (OPTIONAL): Agent delegate identifier - present when the agent uses delegation (copied from agent token's `sub`)
- `scope` (OPTIONAL): Space-separated authorized scopes (excludes identity scopes like `openid`, `profile`, `email` which control token claims rather than resource access)
- **User identity claims** (when `openid` scope was requested):
  - `sub` (REQUIRED if openid scope granted): User identifier
  - `name` (OPTIONAL): User's full name
  - `email` (OPTIONAL): User's email address
  - `email_verified` (OPTIONAL): Email verification status (boolean)
  - Additional standard claims per OpenID Connect Core 1.0 Section 5.1

### 6.5. Example Auth Token (User Authorization)

**JOSE Header:**
```json
{
  "typ": "auth+jwt",
  "alg": "EdDSA",
  "kid": "auth-server-key-1"
}
```

**Payload:**
```json
{
  "iss": "https://auth.example",
  "agent": "https://agent.example",
  "agent_delegate": "mobile-app-install-xyz",
  "aud": "https://resource.example",
  "exp": 1730221200,
  "scope": "data.read data.write",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  },
  "sub": "user-12345",
  "name": "Alice Smith",
  "email": "alice@example.com",
  "email_verified": true
}
```

### 6.6. Example Auth Token (Autonomous Agent)

**Payload:**
```json
{
  "iss": "https://auth.example",
  "agent": "https://agent.example",
  "agent_delegate": "spiffe://example.com/workload/api-service",
  "aud": "https://resource.example",
  "exp": 1730221200,
  "scope": "data.read",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  }
}
```

### 6.7. Validation by Resources

When an agent presents `Signature-Key: sig=jwt; jwt="<auth-token>"`, the resource **MUST** validate:

1. Parse the JWT and extract the JOSE header
2. Verify `typ` is `"auth+jwt"`
3. Extract `kid` from the JOSE header
4. Extract `iss` from the payload
5. Fetch the auth server's JWKS (from metadata)
6. Match the signing key by `kid`
7. Verify the JWT signature using the matched public key
8. Verify the `exp` claim (current time **MUST** be less than expiration)
9. Verify the `iss` matches the trusted auth server
10. Verify the `aud` matches the resource identifier being accessed
11. Verify the `agent` claim is present
12. Extract the public key from `cnf.jwk`
13. Verify that the HTTPSig request signature was created with the key from `cnf.jwk`
14. Verify the `scope` claim (if present) authorizes the requested operation
15. Optionally enforce policies based on `agent`, `agent_delegate`, or `sub` (user)

## 7. Metadata Documents

Metadata documents enable dynamic discovery of endpoints, capabilities, and keys. This section describes the metadata published by each participant type.

### 7.1. Agent Metadata

Agent servers **MUST** publish metadata at `/.well-known/agent-server`.

**Required fields:**

- `agent` (string): The agent's HTTPS URL
- `jwks_uri` (string): URL to the agent's JSON Web Key Set

**Required fields if agent requests user authorization:**

- `redirect_uris` (array of strings): Valid redirect URIs for authorization callbacks
- `name` (string): Human-readable agent name
- `logo_uri` (string): URL to agent logo
- `policy_uri` (string): URL to privacy policy
- `tos_uri` (string): URL to terms of service
- `homepage` (string): Agent homepage URL

**Example:**
```json
{
  "agent": "https://agent.example",
  "jwks_uri": "https://agent.example/jwks.json",
  "redirect_uris": [
    "https://agent.example/callback",
    "https://agent.example/aauth/callback"
  ],
  "name": "Example Agent",
  "logo_uri": "https://agent.example/logo.png",
  "policy_uri": "https://agent.example/privacy",
  "tos_uri": "https://agent.example/tos",
  "homepage": "https://agent.example"
}
```

### 7.2. Auth Server Metadata

Auth servers **MUST** publish metadata at `/.well-known/auth-server`.

**Required fields:**

- `issuer` (string): The auth server's HTTPS URL
- `jwks_uri` (string): URL to the auth server's JSON Web Key Set
- `agent_token_endpoint` (string): Endpoint for auth requests, code exchange, token exchange, and refresh
- `agent_auth_endpoint` (string): Endpoint for user authentication and consent flow
- `agent_signing_algs_supported` (array): Supported HTTPSig algorithms
- `request_types_supported` (array): Supported request_type values (e.g., `["auth", "code", "exchange", "refresh"]`)

**Optional fields:**

- `scopes_supported` (array): Supported scopes

**Example:**
```json
{
  "issuer": "https://auth.example",
  "jwks_uri": "https://auth.example/jwks.json",
  "agent_token_endpoint": "https://auth.example/agent/token",
  "agent_auth_endpoint": "https://auth.example/agent/auth",
  "agent_signing_algs_supported": [
    "ed25519",
    "rsa-pss-sha256"
  ],
  "request_types_supported": [
    "auth",
    "code",
    "exchange",
    "refresh"
  ],
  "scopes_supported": [
    "profile",
    "email",
    "data.read",
    "data.write"
  ]
}
```

### 7.3. Resource Metadata

Resources **MAY** publish metadata describing their authorization requirements. The resource identifier used in `aud` claims and Agent-Auth headers is **REQUIRED**, but publishing metadata at a discoverable location is optional.

**Recommended fields (if published):**

- `resource` (string): The resource identifier (used as `aud` in auth tokens)
- `auth_server` (string): The trusted auth server's HTTPS URL
- `scopes_supported` (array): Available scopes
- `scope_descriptions` (object): Human-readable descriptions of scopes
- `agent_signing_algs_supported` (array): Accepted HTTPSig algorithms

**Example:**
```json
{
  "resource": "https://resource.example",
  "auth_server": "https://auth.example",
  "scopes_supported": [
    "data.read",
    "data.write"
  ],
  "scope_descriptions": {
    "data.read": "Read your data records",
    "data.write": "Create and modify your data records"
  },
  "agent_signing_algs_supported": [
    "eddsa-ed25519",
    "rsa-pss-sha256"
  ]
}
```

## 8. Protocol Details

This section describes each step in the protocol flow in detail.

### 8.1. Resource Request

The agent makes a signed request to the resource including the `Signature-Key` header.

**Example pseudonymous request:**
```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; x="JrQLj5P..."
```

**Example identified request (agent delegate):**
```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt; jwt="eyJhbGc..."
```

**Example authorized request:**
```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt; jwt="eyJhbGc..."
```

### 8.2. Agent-Auth Challenge

If the resource requires a higher authentication level than provided, it responds with a 401 status and an `Agent-Auth` header.

**Example: Signature required**
```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig
```

**Example: Identity required**
```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; identity=?1
```

**Example: Authorization required**
```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; auth-token; resource="https://resource.example"; scope="data.read data.write"
```

**Example: Authorization with rich context**
```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; auth-token; resource="https://resource.example"; request_uri="https://resource.example/authz/req/3f5a"
```

### 8.3. Agent Auth Request

The agent makes a signed request to the auth server's `agent_token_endpoint` with `request_type=auth`.

**Request parameters:**

- `request_type` (REQUIRED): Must be `auth`
- `resource` (REQUIRED): The resource identifier
- `redirect_uri` (REQUIRED): The callback URI for authorization code
- `scope` (OPTIONAL): Requested scopes
- `state` (RECOMMENDED): Opaque value for CSRF protection

**Example request:**
```http
POST /agent/token HTTP/1.1
Host: auth.example
Content-Type: application/x-www-form-urlencoded
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig=("@method" "@target-uri" "content-type" "content-digest" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt; jwt="eyJhbGc..."

request_type=auth&resource=https://resource.example&redirect_uri=https://agent.example/callback&scope=data.read+data.write&state=af0ifjsldkj
```

### 8.4. Auth Response

The auth server validates the request and responds based on policy.

**Direct grant response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "auth_token": "eyJhbGc...",
  "expires_in": 3600,
  "refresh_token": "eyJhbGc..."
}
```

**User consent required response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "request_token": "eyJhbGciOiJub25lIn0.eyJleHAiOjE3MzAyMTgyMDB9.",
  "expires_in": 600
}
```

The `request_token` is an opaque value representing the pending auth request. The agent uses this at the `agent_auth_endpoint` to redirect the user for authentication and consent.

### 8.5. User Consent Flow

If `request_token` was provided, the agent directs the user to the `agent_auth_endpoint`:

```
https://auth.example/agent/auth?request_token=eyJhbGciOiJub25lIn0.eyJleHAiOjE3MzAyMTgyMDB9.
```

## 8.6. Resource-Initiated User Interaction

When a resource requires user interaction (login, SSO, OAuth flow, or consent for downstream access), the resource returns a `user_interaction` parameter directing the agent to facilitate the interaction.

**Agent-Auth response:**
```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; user_interaction="https://resource-r.example/auth-flow?session=xyz789&request=abc"; resource="https://resource-r2.example"; auth_server="https://auth2.example"
```

**Parameters:**
- `user_interaction` (string): URL at the resource where the agent should direct the user
- `resource`: The downstream resource identifier
- `auth_server`: The authorization server for the downstream resource

**Flow:**

1. **Agent receives challenge**: The agent extracts the `user_interaction` URL from the Agent-Auth header

2. **Agent redirects user**: The agent redirects the user to the `user_interaction` URL, appending a `return_url` parameter:
   ```http
   HTTP/1.1 303 See Other
   Location: https://resource-r.example/auth-flow?session=xyz789&request=abc&return_url=https://agent-a.example/callback
   ```

3. **Resource interacts with user**: The resource hosts the interaction endpoint and:
   - Validates the request context (session parameter)
   - Redirects the user to the auth server with the resource's identity
   - Receives authorization from the auth server
   - Stores the authorization result keyed by the session

4. **User returns to agent**: The resource redirects the user back to the `return_url` provided by the agent

5. **Agent retries request**: The agent makes the original request again with the same session context. The resource now has authorization and can process the request.

**Security considerations:**
- Resources MUST validate that `return_url` uses HTTPS unless in development environments
- Agents MUST NOT include sensitive data in the `return_url` query parameters
- Resources MUST expire session state after reasonable timeout and failed attempts

## 8.7. Token Exchange and Chaining

Token exchange enables authorization chains where one resource acts as an agent to access downstream resources. When a resource needs to call another resource to fulfill a request, it exchanges the auth token it received for a new auth token bound to its own key.

### 8.7.1. Exchange Claim

Auth tokens MAY include an `exchange` claim indicating the token holder is authorized to exchange the token for downstream access.

**Example auth token with exchange:**
```json
{
  "iss": "https://auth.example",
  "agent": "https://agent-a.example",
  "aud": "https://resource-r.example",
  "sub": "user-12345",
  "scope": "data.read data.write",
  "exchange": {
    "resource": "https://resource-r2.example",
    "auth_server": "https://auth2.example",
    "scope": "data.read"
  },
  "cnf": {
    "jwk": { /* Agent A's public key */ }
  }
}
```

**Exchange parameters:**
- `resource` (REQUIRED): The downstream resource identifier
- `auth_server` (REQUIRED): The authorization server for the downstream resource
- `scope` (REQUIRED if no auth_request): Space-separated scopes for downstream access
- `auth_request` (OPTIONAL): URL to fetch full authorization request details

If `auth_request` is present, it is authoritative for downstream authorization details including scope and potential nested exchange claims.

### 8.7.2. Exchange Flow

**Step 1: Resource requests token exchange**

Resource R makes an HTTPSig-authenticated request to the downstream auth server's `agent_token_endpoint`:

```http
POST /agent/token
Host: auth2.example
Signature-Key: sig=jwks; id="https://resource-r.example"; kid="key-1"
Content-Type: application/x-www-form-urlencoded

request_type=exchange&exchange_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF1dGgrand0Ii...
```

**Parameters:**
- `request_type` (REQUIRED): Must be `"exchange"` to indicate token exchange
- `exchange_token` (REQUIRED): The auth token (with `exchange` claim) received from the upstream agent

The resource's identity is authenticated via HTTP Message Signatures. The `exchange_token` contains the `exchange` claim authorizing this exchange.

**Step 2: Auth server validates and issues new token**

The downstream auth server:

1. Validates the HTTPSig request signature (authenticates Resource R)
2. Parses and validates the `exchange_token`:
   - Verifies JWT signature from the issuing auth server
   - Validates expiration, audience, and claims
   - Extracts the `exchange` claim
3. Validates the exchange is authorized:
   - `exchange.resource` matches a resource this auth server governs
   - `exchange.auth_server` matches this auth server's identifier
   - The presenter (Resource R from HTTPSig) matches `exchange_token.aud`
4. Determines if the issuing auth server is trusted (federation policy)
5. Issues a new auth token bound to Resource R's key

**Example issued token:**
```json
{
  "iss": "https://auth2.example",
  "agent": "https://resource-r.example",
  "aud": "https://resource-r2.example",
  "sub": "user-12345",
  "scope": "data.read",
  "act": {
    "agent": "https://agent-a.example"
  },
  "cnf": {
    "jwk": { /* Resource R's public key */ }
  }
}
```

**Key properties:**
- `agent`: Resource R (the exchange requester)
- `aud`: The downstream resource from `exchange.resource`
- `sub`: Preserved from original token (maintains user context)
- `act`: Contains the previous agent in the chain
- `cnf.jwk`: Resource R's key (extracted from HTTPSig or agent token)

### 8.7.3. Nested Exchange Chains

Auth tokens issued during exchange MAY themselves contain an `exchange` claim, enabling multi-level chains. Each token in the chain is bound to the current agent's key and preserves the authorization chain via nested `act` claims.

**Example three-level chain:**

Token 1 (Agent A → Resource R):
```json
{
  "agent": "https://agent-a.example",
  "aud": "https://resource-r.example",
  "exchange": {
    "resource": "https://resource-r2.example",
    "auth_server": "https://auth2.example",
    "scope": "data.read"
  }
}
```

Token 2 (Resource R → Resource R2):
```json
{
  "agent": "https://resource-r.example",
  "aud": "https://resource-r2.example",
  "act": {
    "agent": "https://agent-a.example"
  },
  "exchange": {
    "resource": "https://resource-r3.example",
    "auth_server": "https://auth3.example",
    "scope": "data.read"
  }
}
```

Token 3 (Resource R2 → Resource R3):
```json
{
  "agent": "https://resource-r2.example",
  "aud": "https://resource-r3.example",
  "act": {
    "agent": "https://resource-r.example",
    "act": {
      "agent": "https://agent-a.example"
    }
  }
}
```

**Privacy property:** Each party only sees one hop ahead. Resource R knows it will access R2, but does not know that R2 will access R3 unless R2's token is disclosed.

### 8.7.4. Cross-Auth-Server Exchange

When the downstream resource uses a different authorization server than the original request, the exchange crosses auth server boundaries. The downstream auth server MUST decide whether to trust tokens from the upstream auth server through pre-configured trust, federation protocols, or dynamic validation.

The downstream auth server MUST NOT require user interaction during exchange, as user consent was obtained by the original auth server. The `sub` claim MUST be preserved across auth server boundaries to maintain user identity context through the chain.

### 8.7.5. Authorization Request with Exchange

When initiating authorization that includes exchange, the authorization request object includes the `exchange` property:

```json
{
  "resource": "https://resource-r.example",
  "scope": "data.read data.write",
  "exchange": {
    "resource": "https://resource-r2.example",
    "auth_server": "https://auth2.example",
    "auth_request": "https://auth2.example/req/abc456"
  }
}
```

When user authorization is required, the auth server MUST present the complete exchange chain to the user. The auth server recursively fetches `auth_request` URLs to build the full chain for consent display.

**Example consent display:**
```
Agent A requests access to:
├─ Resource R (data.read data.write)
│  └─ which will access Resource R2 (data.read)
│     └─ which will access Resource R3 (data.read)
```

User consent applies to the entire chain. Subsequent exchanges occur without additional user interaction.

### 8.7.6. Multiple Downstream Resources

If a resource needs to access multiple downstream resources, it MUST perform separate exchanges for each. Auth tokens contain at most one `exchange` claim.

### 8.7.7. Refresh Tokens with Exchange

When an auth server issues a token via exchange, it MAY also issue a refresh token bound to the resource's identity. This enables the resource to maintain long-lived access to the downstream resource independently of the original agent's session.

### 8.8. Auth Token Request

The agent exchanges the authorization code for an auth token by making a signed request to the `agent_token_endpoint` with `request_type=code`.

**Request parameters:**

- `request_type` (REQUIRED): Must be `code`
- `code` (REQUIRED): The authorization code

**Example request:**
```http
POST /agent/token HTTP/1.1
Host: auth.example
Content-Type: application/x-www-form-urlencoded
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig=("@method" "@target-uri" "content-type" "content-digest" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt; jwt="eyJhbGc..."

request_type=code&code=AUTH_CODE_123
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "auth_token": "eyJhbGc...",
  "expires_in": 3600,
  "refresh_token": "eyJhbGc..."
}
```

### 8.9. Auth Token Refresh

When the auth token expires, the agent requests a new token using the refresh token by making a signed request to the `agent_token_endpoint` with `request_type=refresh`.

**Request parameters:**

- `request_type` (REQUIRED): Must be `refresh`
- `refresh_token` (REQUIRED): The refresh token

**Example request:**
```http
POST /agent/token HTTP/1.1
Host: auth.example
Content-Type: application/x-www-form-urlencoded
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig=("@method" "@target-uri" "content-type" "content-digest" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt; jwt="eyJhbGc..."

request_type=refresh&refresh_token=eyJhbGc...
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "auth_token": "eyJhbGc...",
  "expires_in": 3600
}
```

> **Note:** A new `refresh_token` is not included because the existing refresh token remains valid. In AAuth, every refresh request is cryptographically signed and the refresh token is bound to the agent's instance identifier, eliminating the security rationale for rotation.

### 8.10. Authorized Resource Access

The agent makes a signed request to the resource with the auth token.

```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt; jwt="eyJhbGc..."
```

The resource validates the auth token and signature, then returns the requested data if authorized.

### 8.11. Future Request Types

The following `request_type` values are reserved for future work and are not defined in this version of the specification:

**Device Authorization Flow:**
- `request_type=device_auth` - Initiate device authorization flow
  - May return `auth_token` (direct grant) or `device_code` + `user_code` + `verification_uri` (user interaction needed)
- `request_type=device_code` - Poll or exchange device_code for auth_token

**CIBA (Client Initiated Backchannel Authentication):**
- `request_type=backchannel_auth` - Initiate backchannel authentication
  - May return `auth_token` (direct grant) or `auth_req_id` (authentication in progress)
- `request_type=backchannel_poll` - Poll with auth_req_id for auth_token

**Token Exchange:**
- `request_type=token_exchange` - Exchange one credential type for another
  - Parameters and semantics to be defined

Auth servers **MAY** advertise supported request types in metadata using the `request_types_supported` field.

## 9. HTTP Message Signing Profile

AAuth uses HTTP Message Signing (HTTPSig) as defined in RFC 9421. This section provides a profile for AAuth implementations.

### 9.1. Signature-Key Header

The `Signature-Key` header provides the keying material required to verify the HTTP signature. It uses the format defined in the [Signature-Key specification](https://github.com/dickhardt/signature-key).

**Supported schemes:**

- `sig=hwk` - Header Web Key (pseudonymous, no identity)
- `sig=jwks` - Identified signer (explicit identity with id + optional metadata)
- `sig=x509` - X.509 certificate chain (explicit identity via PKI)
- `sig=jwt` - JWT containing confirmation key (explicit identity, agent-token or auth-token)

The signature label in `Signature-Key` **MUST** match the label used in `Signature-Input` and `Signature`.

### 9.2. Signature Algorithm Requirements

Implementations **MUST** support:
- `ed25519` (EdDSA using Curve25519)

Implementations **MAY** support additional algorithms from the HTTP Signature Algorithms Registry established by RFC 9421.

### 9.3. Covered Components

Signatures **MUST** cover the following HTTP message components:

**For all requests:**
- `@method`: The HTTP method
- `@target-uri`: The full request URI

**For requests with a body:**
- `content-type`: The Content-Type header
- `content-digest`: The Content-Digest header (per RFC 9530)

**For requests with Signature-Key header:**
- `signature-key`: The Signature-Key header value

### 9.4. Signature Parameters

The `Signature-Input` header **MUST** include:
- `created`: Signature creation timestamp

The `created` timestamp **MUST NOT** be more than 60 seconds in the past or future to prevent replay attacks.

### 9.5. Example Signatures

**Pseudonymous request (sig=hwk):**
```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri");created=1730217600
Signature: sig=:MEQCIAZg1fF0...:
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; x="JrQLj5P..."
```

**Identified request (sig=jwks):**
```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri" "signature-key");created=1730217600
Signature: sig=:MEQCIAZg1fF0...:
Signature-Key: sig=jwks; id="https://agent.example"; kid="key-1"
```

**Identified request (sig=jwt with agent-token):**
```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri" "signature-key");created=1730217600
Signature: sig=:MEQCIAZg1fF0...:
Signature-Key: sig=jwt; jwt="eyJhbGciOiJFUzI1NiIsInR5cCI6ImFnZW50LXRva2VuIiwia2lkIjoia2V5LTEifQ..."
```

**Authorized request (sig=jwt with auth-token):**
```http
GET /api/data HTTP/1.1
Host: resource.example
Signature-Input: sig=("@method" "@target-uri" "signature-key");created=1730217600
Signature: sig=:MEQCIAZg1fF0...:
Signature-Key: sig=jwt; jwt="eyJhbGciOiJFUzI1NiIsInR5cCI6ImF1dGgtdG9rZW4iLCJraWQiOiJrZXktMSJ9..."
```

**POST request with body:**
```http
POST /agent/authorize HTTP/1.1
Host: auth.example
Content-Type: application/x-www-form-urlencoded
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig=("@method" "@target-uri" "content-type" "content-digest" "signature-key");created=1730217600
Signature: sig=:MEQCIAZg1fF0...:
Signature-Key: sig=jwt; jwt="eyJhbGc..."

resource=https://resource.example&scope=data.read
```

### 9.6. Key Discovery and Verification

This section describes how to obtain the public key for verifying HTTP Message Signatures based on the `Signature-Key` header scheme.

**For sig=hwk (Pseudonymous):**
1. Extract key parameters directly from the Signature-Key header
2. Reconstruct the public key
3. Verify the HTTPSig signature

**For sig=jwks (Identified Signer):**
1. Extract `id`, optional `well-known`, and `kid` from Signature-Key header
2. If `well-known` is present:
   - Fetch metadata from `{id}/.well-known/{well-known}`
   - Extract `jwks_uri` from metadata
   - Fetch JWKS from `jwks_uri`
3. If `well-known` is absent:
   - Fetch `{id}` directly as JWKS
4. Match the key by `kid`
5. Verify the HTTPSig signature using the matched public key

**For sig=x509 (X.509 Certificate Chain):**
1. Extract `x5u` (certificate URL) and `x5t` (certificate thumbprint) from Signature-Key header
2. Check cache for certificate with matching `x5t` thumbprint
3. If cached certificate found and still valid, skip to step 6
4. Fetch the PEM file from the `x5u` URL
5. Parse and validate the X.509 certificate chain:
   - Verify chain of trust to a trusted root CA
   - Check certificate validity (not expired, not revoked via CRL/OCSP)
   - Validate certificate policies and constraints
   - Verify `x5t` matches BASE64URL(SHA256(DER_bytes_of_leaf_certificate))
6. Extract the public key from the end-entity certificate
7. Verify the HTTPSig signature using the extracted public key
8. Cache the certificate indexed by `x5t` for future requests

**For sig=jwt (Agent Token or Auth Token):**
1. Extract the JWT from the Signature-Key header
2. Parse the JWT and determine token type from `typ` in JOSE header
3. Validate the JWT:
   - If `typ` is `"agent+jwt"`: Follow validation steps in Section 5.7
   - If `typ` is `"auth+jwt"`: Follow validation steps in Section 6.7
4. Extract the public key from the JWT's `cnf.jwk` claim
5. Verify the HTTPSig signature using the extracted public key

### 9.7. Replay Prevention

While HTTPSig signatures include timestamps, applications **SHOULD** implement additional replay prevention:
- Track recently seen `created` timestamps per agent
- Reject requests with duplicate `created` values within the validity window
- Use nonces for high-value operations

## 10. Error Responses

AAuth reuses the OAuth 2.0 error response format and error codes (RFC 6749 Section 5.2) where applicable.

### 10.1. Error Response Format

Error responses **MUST** be returned with an appropriate HTTP status code (typically 400 or 401) and a JSON body:

- `error` (REQUIRED): A single ASCII error code
- `error_description` (OPTIONAL): Human-readable additional information
- `error_uri` (OPTIONAL): A URI with more information about the error

**Example:**
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_request",
  "error_description": "Missing required parameter: redirect_uri"
}
```

### 10.2. OAuth 2.0 Error Codes

- `invalid_request` - Malformed or missing required parameters
- `invalid_token` - Agent token or auth token is invalid or expired
- `invalid_grant` - Authorization code or refresh token is invalid, expired, or revoked
- `unauthorized_client` - Agent is not authorized for the requested access
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Requested scope is invalid, unknown, or malformed

### 10.3. AAuth-Specific Error Codes

- `invalid_signature` - HTTPSig signature validation failed
- `invalid_agent_token` - Agent token validation failed
- `key_mismatch` - Key in token's `cnf.jwk` doesn't match HTTPSig signing key
- `request_expired` - Request timestamp outside acceptable time window
- `invalid_redirect_uri` - Redirect URI doesn't match agent metadata

**Example:**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "invalid_signature",
  "error_description": "The HTTPSig signature could not be verified using the provided public key"
}
```

## 11. Security Model

- All participants use **HTTP Message Signing** for message integrity and replay protection
- **Agent tokens** and **auth tokens** are both **proof-of-possession** tokens
- Tokens are reusable for their valid lifetime; replay prevention is achieved through per-request signatures
- Agent server and auth server key rotation is achieved by updating the JWKS at each origin's `jwks_uri`
- Agent delegates rotate their keys frequently (ephemeral keys at restart or persisted keys per policy) by obtaining new agent tokens
- Refresh tokens are bound to:
  - **Agent server**: agent identifier (`agent` claim) only
  - **Agent delegate**: agent identifier (`agent` claim) + `sub` (agent delegate identifier)
- Refresh tokens do not require rotation due to proof-of-possession binding and per-request signatures

---

## 12. IANA Considerations

This specification registers the following identifiers in their respective IANA registries.

### 12.1. Well-Known URI Registrations

**Registry:** Well-Known URIs (RFC 8615)

**URI suffix:** `agent-server`
- **Change controller:** IETF
- **Specification document:** This specification, Section 7.1
- **Related information:** Metadata document for AAuth agent servers

**URI suffix:** `auth-server`
- **Change controller:** IETF
- **Specification document:** This specification, Section 7.2
- **Related information:** Metadata document for AAuth authorization servers

### 12.2. Media Type Registrations

**Registry:** Media Types

**Type name:** `application`
- **Subtype name:** `agent+jwt`
- **Required parameters:** None
- **Optional parameters:** None
- **Encoding considerations:** Binary (JWT, base64url-encoded)
- **Security considerations:** See Section 11 of this specification
- **Interoperability considerations:** None
- **Published specification:** This specification, Section 5.2
- **Applications that use this media type:** AAuth agent delegates
- **Additional information:** JWT type value for agent tokens
- **Person & email address to contact for further information:** Dick Hardt, dick.hardt@hello.coop
- **Intended usage:** COMMON
- **Restrictions on usage:** None
- **Change controller:** IETF

**Type name:** `application`
- **Subtype name:** `auth+jwt`
- **Required parameters:** None
- **Optional parameters:** None
- **Encoding considerations:** Binary (JWT, base64url-encoded)
- **Security considerations:** See Section 11 of this specification
- **Interoperability considerations:** None
- **Published specification:** This specification, Section 6.2
- **Applications that use this media type:** AAuth auth servers and resource servers
- **Additional information:** JWT type value for auth tokens
- **Person & email address to contact for further information:** Dick Hardt, dick.hardt@hello.coop
- **Intended usage:** COMMON
- **Restrictions on usage:** None
- **Change controller:** IETF

### 12.3. HTTP Header Field Registrations

**Registry:** HTTP Field Names (RFC 9110)

**Field name:** `Agent-Auth`
- **Status:** permanent
- **Specification document:** This specification, Section 4
- **Comments:** Response header indicating AAuth authentication and authorization requirements

### 12.4. JSON Web Token Type Values

**Registry:** JSON Web Token (JWT) Type Values

**Type value:** `agent+jwt`
- **Abbreviation for MIME Type:** `application/agent+jwt`
- **Change controller:** IETF
- **Specification document:** This specification, Section 5.2

**Type value:** `auth+jwt`
- **Abbreviation for MIME Type:** `application/auth+jwt`
- **Change controller:** IETF
- **Specification document:** This specification, Section 6.2

### 12.5. JSON Web Token Claims Registrations

**Registry:** JSON Web Token Claims (RFC 7519)

**Claim name:** `agent`
- **Claim description:** Agent identifier (HTTPS URL)
- **Change controller:** IETF
- **Specification document:** This specification, Section 6.3

### 12.6. AAuth Parameters Registry

**Registry:** AAuth Parameters (new registry)

This specification establishes a new IANA registry for AAuth protocol parameters used in requests and responses.

**Registration procedure:** Specification Required

**Parameters registered by this specification:**

**Parameter name:** `request_type`
- **Parameter usage location:** token request
- **Change controller:** IETF
- **Specification document:** This specification, Section 8.3
- **Description:** Type of request (auth, code, refresh, device_auth, backchannel_auth, etc.)

**Parameter name:** `request_token`
- **Parameter usage location:** authorization request
- **Change controller:** IETF
- **Specification document:** This specification, Section 8.4
- **Description:** Opaque token representing a pending authorization request

**Parameter name:** `auth_token`
- **Parameter usage location:** token response
- **Change controller:** IETF
- **Specification document:** This specification, Section 8.4
- **Description:** AAuth authorization token (JWT)

### 12.7. Error Codes

AAuth-specific error codes are defined in Section 10.3. These error codes extend the OAuth 2.0 error response framework for AAuth-specific validation failures including signature validation, agent token validation, and key binding verification.

The registration of these error codes in an appropriate IANA registry is **to be determined** based on whether AAuth establishes its own error registry or extends an existing OAuth error registry.

---

## Appendix A: Relationship to OAuth 2.1 and OIDC

### A.1. AAuth Design Philosophy

AAuth intentionally blends **OAuth 2.1** (authorization/delegated access) and **OpenID Connect** (authentication/identity) into a unified protocol for both authentication and authorization. This is why AAuth uses the term **"auth"** throughout:

- **`auth_token`** - Contains both authorization (scopes, audience) AND authentication (user identity claims)
- **`Agent-Auth` header** - Indicates need for additional auth (could be authentication, authorization, or both)
- **`request_type=auth`** - Generic request that may result in authentication-only, authorization-only, or both
- **`agent_auth_endpoint`** - User-facing endpoint for authentication and/or consent

The auth server determines what type of auth is needed based on policy, resource requirements, and user context. Resources receive a single token containing everything they need for access control decisions.

### A.2. Adding AAuth Support to Existing Servers

OAuth 2.1 and OpenID Connect servers can be **extended** to support AAuth while continuing to serve existing OAuth 2.1/OIDC clients. This is an addition, not a migration - both protocols can coexist.

**Core additions required:**

1. New endpoints for agent-centric flows
2. HTTP Message Signing validation
3. Agent identity verification
4. Token format extensions

### A.3. Why Not Extend OAuth 2.0?

AAuth explores what a protocol designed specifically for agent-centric scenarios could look like, rather than extending OAuth 2.0. This is a deliberate choice, not a criticism of OAuth's success in its designed use cases.

#### FAPI 2.0: A Successful OAuth Profile

FAPI 2.0 (Financial-grade API) demonstrates OAuth can be successfully profiled for high-security scenarios. FAPI 2.0:
- Builds on OAuth 2.1 base
- Mandates DPoP or mTLS for sender-constrained tokens
- Requires PAR (Pushed Authorization Requests)
- Requires PKCE with S256
- Eliminates optionality: confidential clients only, specific algorithms, limited flows
- Achieves formal security analysis under defined attacker model

**FAPI 2.0 succeeds because it:**
- Profiles OAuth without fundamentally changing it
- Reduces optionality through mandates
- Maintains OAuth compatibility
- Addresses well-defined high-security use case (financial APIs)

#### Why AAuth Takes a Different Approach

AAuth could theoretically be positioned as an OAuth profile, but that would inherit challenges that motivated exploring a fresh approach:

**1. Why HTTP Message Signatures Instead of DPoP or mTLS?**

OAuth 2.0 offers two main approaches for proof-of-possession:

**DPoP (Demonstrating Proof of Possession, RFC 9449):**
- **What it does:** Binds access tokens to a client's public key
- **How it works:** Creates a JWT proof containing HTTP method, URL, timestamp, and access token hash
- **Limitation:** Only proves token possession, does NOT sign the actual HTTP message
- **Does NOT provide:** Message integrity, tampering detection, or protection for non-token requests
- **Focus:** Token binding

**mTLS (Mutual TLS, RFC 8705):**
- **What it does:** Client authentication using TLS certificates
- **How it works:** Binds client certificate to TLS connection
- **Limitation:** Connection-based protection, not message-based
- **Does NOT provide:** Protection against message tampering after TLS termination
- **Challenges:** Complex certificate management, difficult with load balancers/proxies/CDNs
- **Focus:** Transport security

**HTTP Message Signatures (RFC 9421) in AAuth:**
- **What it does:** Signs individual HTTP message components
- **How it works:** Signs @method, @target-uri, headers, content-digest
- **Provides:** Full message integrity - detects any tampering
- **Works for:** ANY request, including those without tokens (pseudonymous, identified)
- **Survives:** Proxies, load balancers, CDNs (after TLS termination)
- **Supports:** Ephemeral keys (no certificate infrastructure needed)
- **Focus:** Message authentication and integrity

**Key differences:**

| Feature | DPoP | mTLS | HTTPSig (AAuth) |
|---------|------|------|-----------------|
| **Protects** | Token binding | TLS connection | Individual messages |
| **Message integrity** | No | No | Yes |
| **Non-token requests** | No | Auth only | Yes |
| **Survives proxies** | Yes | No | Yes |
| **Detects tampering** | No | In transit | Yes |
| **Certificate management** | Not needed | Required | Not needed |
| **Ephemeral keys** | Yes | No | Yes |

**Why AAuth chose HTTPSig:**
- **Message integrity:** Detects tampering of request components
- **Works everywhere:** Pseudonymous requests, identified requests, authorized requests
- **Modern infrastructure:** Works with load balancers, proxies, CDNs
- **Simpler key management:** Ephemeral keys, no certificate infrastructure
- **Stronger binding:** Authorization code bound to signing key (no PKCE needed)

DPoP and mTLS are excellent solutions for their designed purposes (token binding and transport security), but don't provide the message-level integrity and flexibility AAuth's agent scenarios require.

**2. Framework Cruft and Sharp Edges**

OAuth 2.0 has evolved over 13+ years with numerous extensions addressing different concerns. This creates:
- Legacy patterns kept for backward compatibility
- Security pitfalls from earlier design choices
- Sharp edges where extensions interact unexpectedly
- Complexity from maintaining compatibility with older deployments

Example: OAuth still supports bearer tokens (insecure) alongside DPoP and mTLS. FAPI 2.0 must explicitly forbid weak options that exist in the OAuth framework.

**3. Optionality Makes Conformance Hard**

OAuth 2.0 is explicitly a framework, not a protocol. "OAuth 2.0 compliant" is nearly meaningless because implementations choose different subsets:

Current optionality:
- Client authentication: None OR client_secret OR private_key_jwt OR mTLS
- Token binding: None OR DPoP OR mTLS
- Authorization request: Direct OR PAR
- Token type: Bearer OR DPoP-bound OR mTLS-bound
- Flows: Authorization Code OR Client Credentials OR Device OR CIBA
- Refresh rotation: Yes OR No

**Result:**
- Every deployment configures differently
- Interoperability requires negotiation
- Conformance testing tests "which options do you support?" not "are you compliant?"
- Security depends on configuration choices

**AAuth's approach:**
- Prescriptive protocol, not framework
- HTTPSig: REQUIRED (not optional)
- Specific token format: REQUIRED
- Specific endpoints: REQUIRED
- Clear profiles: Agent Server, Auth Server, Resource Server
- Conformance: binary (compliant or not)

**4. Model Mismatches for Agent Scenarios**

Some AAuth capabilities don't map cleanly to OAuth's client-centric model:

**Progressive authentication:**
- OAuth: Binary (token or no token)
- AAuth: Pseudonymous → Identified → Authorized
- OAuth extension attempt: Would need new token types, new challenge mechanisms - fundamental additions

**Agent delegation:**
- OAuth: client_id is static per client
- AAuth: agent (server) + sub (per delegate instance) with key rotation
- OAuth extension attempt: Doesn't fit client credentials model

**Unified auth:**
- OAuth/OIDC: Separate access tokens and ID tokens
- AAuth: Single auth token with both identity and authorization
- OAuth extension attempt: Would fundamentally change OAuth/OIDC separation

#### OAuth Community Also Sees Value in HTTPS-Based Identity

The OAuth community recognizes similar needs. The draft specification [Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) proposes:
- HTTPS URLs as client identifiers (like AAuth's agent)
- Fetching client metadata from that URL
- Avoiding pre-registration overhead

This shows the OAuth ecosystem is evolving toward concepts AAuth explores. The difference is AAuth asks: "What if we designed for this from the start rather than extending?"

#### Main Advantages of AAuth's Approach

**Not an exhaustive list, but key differentiators:**

1. **Message integrity**: HTTPSig provides tampering detection that DPoP and mTLS don't
2. **No optionality**: Clear requirements, guaranteed interoperability
3. **No legacy cruft**: Designed for modern security, no backward compatibility constraints
4. **Progressive authentication**: Three levels (pseudonymous, identified, authorized)
5. **Agent-centric model**: HTTPS identity, delegation with persistent sub across key rotation
6. **Unified auth**: Single token, single protocol for authentication and authorization
7. **Simpler security**: No PKCE needed (HTTPSig binds authorization codes to keys)
8. **Conformance**: Binary compliance with clear test suites per profile

#### Relationship to OAuth

AAuth is **not** positioned as:
- A replacement for OAuth/OIDC
- Backward compatible with OAuth
- An OAuth profile

AAuth **is** positioned as:
- Exploration of agent-centric protocol design
- Addressing use cases not well-served by OAuth's client-centric model
- Learning from OAuth's patterns (authorization code flow, refresh tokens, metadata)
- Potentially informing future OAuth evolution

Some AAuth concepts might eventually be backported to OAuth as extensions. Others represent fundamental design choices that don't fit OAuth's architecture. AAuth explores both.

### A.4. OAuth 2.1 and OIDC Foundation

AAuth builds upon OAuth 2.1 and OpenID Connect, reusing many core mechanisms while introducing fundamental changes to address modern security requirements and autonomous agent scenarios.

**Retained from OAuth 2.1:**

- Authorization code flow with user consent
- Client credentials flow concepts (adapted for autonomous agents)
- Refresh token mechanism
- Redirect-based user authentication
- Scopes and authorization details
- State parameter for CSRF protection
- TLS/HTTPS requirements
- Authorization server metadata (RFC 8414)
- Standard error response format

### A.5. Key Differences from OAuth 2.1

| **Aspect** | **OAuth 2.1** | **AAuth 1.0** |
|------------|---------------|---------------|
| **Access Control** | User identity and scopes | Agent identity, user identity, scopes, and agent-specific policies |
| **Token Format** | Opaque or JWT (RFC 9068) | Signed JWT with `cnf.jwk`, `agent`, and `typ` |
| **Token Security** | Bearer tokens (with optional DPoP) | Proof-of-possession only via HTTPSig |
| **Client/Agent Identity** | Pre-registered `client_id` | HTTPS URL with self-published metadata |
| **Client/Agent Registration** | Required | Optional; self-identification via HTTPS |
| **Authentication** | Client credentials, mTLS, or none | HTTPSig on every request |
| **Request Integrity** | Optional (DPoP or mTLS) | Mandatory via HTTPSig |
| **Key Management** | Long-lived credentials | Frequent key rotation per agent delegate (ephemeral or persisted) |
| **Delegate Management** | Single `client_id` | Unique `sub` (agent delegate identifier) in agent token |
| **Refresh Token Security** | Rotation required for public clients | No rotation needed (proof-of-possession) |
| **Progressive Authentication** | Not defined | Three levels: pseudonymous, identified, authorized |
| **Discovery** | Optional (RFC 8414) | Expected for dynamic ecosystems |

### A.6. Access Control Based on Agent Identity

AAuth enables resources to make access control decisions based on the verified identity of the calling agent (the `agent` claim), in addition to traditional user identity and scope-based authorization.

**Current Capabilities:**

- **Agent allowlisting/denylisting**: Permit only specific agents to access resources
- **Agent-specific rate limiting**: Different limits per agent based on trust level
- **Agent-specific scope interpretation**: Same scope grants different access per agent
- **Combined agent + user authorization**: Require both specific user AND specific agent

**Example authorization decision:**
```
IF auth_token.agent == "https://trusted-agent.example"
   AND auth_token.scope contains "data.write"
   AND auth_token.sub == valid_user_id
THEN allow access to sensitive resource
```

**Future Capabilities:**

Future versions may support **agent delegation policies** where agent servers include claims in agent tokens that constrain what agent delegates can do:

- Purpose limitation (e.g., healthcare data only for appointment scheduling)
- Time restrictions (e.g., business hours only)
- Data minimization (e.g., maximum data volume or specific fields)
- Contextual constraints (e.g., require specific user interaction patterns)

### A.7. Implementation Guide for OAuth 2.1/OIDC Servers

An existing OAuth 2.1 or OpenID Connect server can add AAuth support by implementing the following:

**New endpoints:**
- `agent_token_endpoint` - Receive auth requests (request_type=auth), perform token exchange (request_type=code), and handle refresh (request_type=refresh)
- `agent_auth_endpoint` - User authentication and consent flow (interactive, user-facing)

**HTTP Message Signing support:**
- RFC 9421 implementation
- Signature verification using keys from `Signature-Key` header
- Support for `sig=hwk`, `sig=jwks`, `sig=x509`, and `sig=jwt` schemes

**Agent token validation:**
- Fetch and validate agent metadata
- Verify agent token JWT signatures
- Validate agent identity binding

**Token issuance changes:**
- Include `agent` claim in auth tokens
- Include `cnf.jwk` for proof-of-possession
- Add `typ` header to distinguish token types
- Bind refresh tokens to agent identifier (`agent` claim) + `sub` (agent delegate identifier)

**Policy engine updates:**
- Evaluate agent identity in authorization decisions
- Support autonomous vs. user consent logic
- Implement agent-specific authorization rules

### A.8. Integration with OAuth/OIDC Protected Resources

AAuth resources can use the user interaction flow to access OAuth or OIDC protected resources, enabling seamless integration between AAuth-aware systems and traditional OAuth/OIDC ecosystems.

**Scenario:** An AAuth agent requests data from an AAuth resource, which needs to fetch data from a downstream OAuth-protected API (e.g., a third-party service requiring OAuth access tokens).

```mermaid
sequenceDiagram
    participant User as user
    participant Agent as AAuth agent
    participant Resource as AAuth resource<br/>(OAuth client)
    participant OAuth as OAuth/OIDC<br/>auth server
    participant API as OAuth-protected<br/>API

    Agent->>Resource: HTTPSig request (sig=jwks)
    Resource->>API: attempt to access (no token)
    API->>Resource: 401 WWW-Authenticate: Bearer

    Resource->>Agent: 401 Agent-Auth: user_interaction="https://resource.example/oauth-flow?session=xyz"

    Agent->>User: redirect to user_interaction URL (with return_url)
    User->>Resource: GET /oauth-flow?session=xyz&return_url=...

    Resource->>User: redirect to OAuth authorization endpoint
    User->>OAuth: authenticate and consent
    OAuth->>Resource: authorization code (via redirect)

    Resource->>OAuth: exchange code for access_token
    OAuth->>Resource: access_token + refresh_token
    Note over Resource: Store OAuth tokens keyed by session

    Resource->>User: redirect back to agent return_url

    Agent->>Resource: HTTPSig request (retry with session context)
    Resource->>API: request with OAuth access_token
    API->>Resource: 200 OK (data)
    Resource->>Agent: 200 OK (aggregated response)
```

**Complete flow:**

1. **AAuth agent requests resource**: Agent makes HTTPSig-authenticated request to AAuth resource (using `sig=jwks`, `sig=x509`, or `sig=jwt`)

2. **Resource attempts downstream access**: AAuth resource tries to access OAuth-protected API without a token and receives `401 WWW-Authenticate: Bearer`

3. **Resource initiates user interaction**: AAuth resource determines it needs user authorization for the OAuth API and returns a `user_interaction` URL:
   ```http
   HTTP/1.1 401 Unauthorized
   Agent-Auth: httpsig; user_interaction="https://resource.example/oauth-flow?session=xyz789"
   ```

4. **Agent redirects user**: Agent redirects user to the `user_interaction` URL, appending the agent's `return_url`:
   ```http
   HTTP/1.1 303 See Other
   Location: https://resource.example/oauth-flow?session=xyz789&return_url=https://agent.example/callback
   ```

5. **Resource acts as OAuth client**: AAuth resource (acting as OAuth client) redirects user to OAuth/OIDC authorization server with its registered `client_id`, `redirect_uri`, `scope`, and `state`

6. **User authenticates and consents**: User authenticates to the OAuth/OIDC authorization server and grants consent for the requested scopes

7. **OAuth returns authorization code**: OAuth/OIDC authorization server redirects back to AAuth resource with authorization code and state

8. **Resource exchanges code for tokens**: AAuth resource exchanges authorization code for OAuth access token and refresh token using the OAuth token endpoint

9. **Resource stores OAuth tokens**: AAuth resource stores the OAuth access token and refresh token, keyed by the session identifier from step 3

10. **User returns to agent**: AAuth resource redirects user back to agent's `return_url` from step 4

11. **Agent retries request**: Agent makes the original HTTPSig request again. The agent MAY include the session context (e.g., session cookie or header) to correlate with the stored OAuth tokens

12. **Resource uses OAuth token**: AAuth resource retrieves the stored OAuth access token using the session context, calls the OAuth-protected API with the access token, and returns aggregated response to agent

**Benefits:**

- **Transparent integration**: AAuth agents don't need to know downstream resources use OAuth/OIDC
- **Familiar consent flows**: Users authorize access through existing OAuth/OIDC consent screens
- **Independent token management**: AAuth resource manages OAuth tokens independently from AAuth tokens
- **Long-lived access**: AAuth resource can use OAuth refresh tokens to maintain access without repeated user interaction
- **Protocol bridging**: Enables AAuth adoption without requiring all services to implement AAuth

**Implementation considerations:**

- **OAuth client registration**: The AAuth resource must be registered as an OAuth client with the OAuth/OIDC authorization server, obtaining a `client_id` and `client_secret` (for confidential clients)

- **Session correlation**: The AAuth resource MUST securely correlate the agent's retry request with the stored OAuth tokens. Common approaches:
  - Session cookies (if the agent is a browser)
  - Session identifiers in request headers
  - Session tokens bound to the agent's identity

- **Token storage**: The AAuth resource SHOULD store OAuth tokens securely and associate them with:
  - The session identifier
  - The agent identity (from the original HTTPSig request)
  - The user identity (from the OAuth `id_token` or `sub` claim)
  - Expiration timestamps for cleanup

- **Refresh token usage**: The AAuth resource SHOULD use OAuth refresh tokens to maintain long-lived access:
  - Refresh the OAuth access token when expired
  - Avoid repeated user interaction for subsequent requests
  - Handle refresh token rotation per OAuth server policy

- **Scope management**: The AAuth resource determines which OAuth scopes to request based on:
  - The downstream API requirements
  - The agent's authorization (from AAuth auth token, if present)
  - Resource-specific policies

- **Error handling**: If OAuth authorization fails, the AAuth resource SHOULD return an appropriate Agent-Auth challenge to the agent with error details

- **Security**: The `user_interaction` URL SHOULD include a session-specific parameter that:
  - Prevents session fixation attacks
  - Expires after reasonable timeout
  - Is single-use (consumed after successful flow completion)

**OIDC integration notes:**

When integrating with OpenID Connect (OIDC) providers, the AAuth resource:

- Requests the `openid` scope (and optionally `profile`, `email`, etc.)
- Receives an `id_token` in addition to the `access_token`
- Can validate the `id_token` to obtain verified user identity claims
- May use the `id_token` for additional authorization decisions
- Should validate `id_token` signatures and claims per OIDC specification

**Example use cases:**

1. **Third-party integrations**: AAuth resource integrating with services like Google APIs, Microsoft Graph, or GitHub that require OAuth
2. **Legacy API access**: AAuth resource accessing internal APIs that haven't yet migrated to AAuth but use OAuth 2.0
3. **Multi-protocol environments**: Organizations transitioning to AAuth while maintaining OAuth-protected services
4. **Federated access**: AAuth resources accessing resources in partner organizations using OAuth federation

This integration demonstrates AAuth's interoperability with existing OAuth/OIDC ecosystems, enabling incremental adoption without requiring wholesale protocol replacement.

---

## Appendix C: Agent Token Acquisition Patterns

### C.1. Overview

This appendix describes common patterns for how agent delegates obtain agent tokens from their agent server. The agent token binds the delegate's signing key to the agent server's identity, enabling the delegate to act on behalf of the agent.

The specific mechanism for agent token acquisition is **out of scope** for this specification, but understanding common patterns helps illustrate how AAuth works in practice across different deployment scenarios.

**Common elements across all patterns:**

1. **Key generation**: Agent delegate generates or uses an existing key pair
2. **Authentication**: Agent delegate proves its identity or authorization to the agent server
3. **Token issuance**: Agent server issues an agent token containing:
   - `iss`: Agent server's HTTPS URL (the agent identifier)
   - `sub`: Agent delegate identifier (persists across restarts and key rotations)
   - `cnf.jwk`: Agent delegate's public key
   - `exp`: Short expiration (minutes to hours for frequent rotation)
4. **Key rotation**: When the delegate rotates keys (restart or policy), it requests a new token with the same `sub`

### C.2. Server Workloads

Server workloads include containerized services, microservices, serverless functions, and any backend process running in a datacenter or cloud environment. These workloads need to prove their identity when calling other services or APIs.

**SPIFFE-based workload identity:**

SPIFFE (Secure Production Identity Framework for Everyone) provides workload identity using X.509 SVIDs (SPIFFE Verifiable Identity Documents). In AAuth:

1. **Workload bootstrap**: The workload obtains its SPIFFE ID and X.509 SVID from the SPIFFE Workload API (typically via a local agent)
2. **Key generation**: The workload generates an ephemeral key pair for HTTP Message Signing
3. **Agent token request**: The workload presents its SPIFFE SVID to the agent server (mTLS authentication)
4. **Agent server validates**:
   - Verifies the SPIFFE SVID against the trust domain
   - Extracts the SPIFFE ID (e.g., `spiffe://example.com/workload/api-service`)
5. **Token issuance**: Agent server issues agent token with:
   - `sub`: The SPIFFE ID
   - `cnf.jwk`: The workload's ephemeral public key
   - `exp`: Short-lived (e.g., 1 hour)
6. **Key rotation**: When the workload restarts, it generates a new ephemeral key and obtains a new agent token with the same SPIFFE ID (`sub`)

**WIMSE-based workload identity:**

WIMSE (Workload Identity in Multi-System Environments) extends workload identity concepts with policy-driven delegation. In AAuth:

1. **Policy configuration**: The agent server defines delegation policies for workloads (e.g., "workload X can act as agent Y for purpose Z")
2. **Workload authentication**: The workload authenticates to the agent server using platform credentials (e.g., cloud provider instance identity, Kubernetes service account tokens)
3. **Policy evaluation**: The agent server evaluates whether this workload is authorized to receive an agent token based on:
   - Workload identity claims
   - Requested delegation scope
   - Context (time, environment, resource targets)
4. **Token issuance**: Agent server issues agent token with:
   - `sub`: Workload identifier (may be platform-specific)
   - `cnf.jwk`: Workload's public key (ephemeral or persisted)
   - `scope`: Pre-authorized scopes based on delegation policy
   - `exp`: Policy-determined lifetime
5. **Ongoing policy enforcement**: The agent server may issue short-lived tokens to enable frequent policy reevaluation

**Key benefits for workloads:**

- **No shared secrets**: Ephemeral keys eliminate the need to distribute and rotate long-lived credentials
- **Platform integration**: Leverage existing workload identity infrastructure (SPIFFE, Kubernetes, cloud IAM)
- **Policy-driven**: Agent server controls which workloads can act as delegates and with what constraints
- **Rapid revocation**: Short-lived tokens enable quick response to security events

### C.3. Mobile Applications

Mobile applications (iOS and Android) need to prove that they are legitimate installations of the app when calling APIs. Each installation should have a unique identity that persists across app restarts.

**iOS App Attest:**

iOS provides App Attest, allowing apps to generate cryptographic attestations proving they are genuine Apple-approved installations.

1. **Installation identity**: When the app first launches, it:
   - Generates a unique installation identifier (UUID stored in keychain)
   - Generates an attestation key pair using App Attest
   - Obtains an attestation from Apple proving the app's authenticity
2. **Agent server registration**: The app sends to the agent server:
   - Installation identifier (`sub`)
   - App Attest attestation
   - Public key for HTTP Message Signing (stored in iOS keychain)
3. **Agent server validates**:
   - Verifies the App Attest attestation with Apple's servers
   - Confirms the app bundle ID matches expectations
   - Stores the installation identifier
4. **Token issuance**: Agent server issues agent token with:
   - `sub`: Installation identifier (e.g., `ios-installation-abc123`)
   - `cnf.jwk`: The app's signing public key
   - `exp`: Hours to days (based on app usage patterns)
5. **Key rotation**: The app can rotate its signing key while keeping the same installation identifier, obtaining a new agent token with the same `sub`

**Android Play Integrity:**

Android provides Play Integrity API (successor to SafetyNet), allowing apps to prove they are legitimate Google Play installations.

1. **Installation identity**: When the app first launches, it:
   - Generates a unique installation identifier (stored securely in Android keystore)
   - Generates a key pair in Android keystore
2. **Agent server registration**: The app:
   - Calls Play Integrity API to get an integrity token
   - Sends the integrity token, installation identifier, and public key to the agent server
3. **Agent server validates**:
   - Verifies the Play Integrity token with Google's servers
   - Confirms the app package name and signing certificate
   - Stores the installation identifier
4. **Token issuance**: Agent server issues agent token with:
   - `sub`: Installation identifier (e.g., `android-installation-xyz789`)
   - `cnf.jwk`: The app's signing public key
   - `exp`: Hours to days
5. **Key rotation**: The app can rotate keys in the Android keystore and obtain new agent tokens with the same `sub`

**Key benefits for mobile apps:**

- **Installation-level identity**: Each app installation has a unique `sub` that persists across restarts
- **Platform attestation**: Leverage OS-provided proof of app authenticity
- **Refresh token continuity**: When the app rotates keys, refresh tokens remain valid (bound to agent identifier + `sub`)
- **Security**: Private keys protected by platform keystores (iOS Secure Enclave, Android Keystore)

### C.4. Desktop and CLI Applications

Desktop applications and command-line tools face unique challenges: they run on unmanaged devices, may have multiple installations per user, and need flexible authentication options.

**Common patterns:**

**1. Platform key vaults (Desktop apps):**

Modern operating systems provide secure credential storage that desktop apps can leverage:

- **macOS Keychain**: Apps can generate keys in the Secure Enclave or store keys in the keychain
- **Windows Credential Manager / TPM**: Apps can use the Trusted Platform Module for key generation and storage
- **Linux Secret Service**: Apps can use gnome-keyring or similar services

**Flow:**
1. **First launch**: App generates or retrieves keys from platform keystore, generates installation identifier
2. **User authentication**: User authenticates to the agent server (OAuth flow, passkeys, etc.)
3. **Token binding**: Agent server issues agent token binding the user's authorization to the app's installation
4. **Persistent identity**: Installation identifier (`sub`) persists across app restarts

**2. API keys with user binding (CLI tools):**

Command-line tools often use API keys for authentication but can enhance security with AAuth:

**Flow:**
1. **User authentication**: User runs `cli-tool login` which:
   - Opens browser for OAuth authentication to the agent server
   - Generates ephemeral or persisted key pair
   - Receives agent token bound to the authenticated user and this CLI installation
2. **Storage**: CLI stores the agent token and key (in user's home directory or platform keystore)
3. **API calls**: CLI uses agent token in `Signature-Key` header with HTTP Message Signatures
4. **Token refresh**: When agent token expires, CLI refreshes using the bound refresh token

**3. Device binding with hardware attestation (High-security scenarios):**

For sensitive enterprise deployments, desktop/CLI apps can use hardware-backed attestation:

**Flow:**
1. **Device enrollment**: Device is enrolled in enterprise system (MDM, device management)
2. **Hardware attestation**: App uses TPM, Secure Enclave, or similar to prove hardware identity
3. **Agent token issuance**: Agent server issues token bound to both user identity and hardware identity
4. **Policy enforcement**: Enterprise policies can require specific device posture (OS version, security updates, etc.)

**4. User-authorized ephemeral sessions (Simple CLI tools):**

For tools that don't persist state between runs:

**Flow:**
1. **Session start**: User runs `cli-tool --authenticate` which:
   - Generates ephemeral key pair (in-memory only)
   - Opens browser for user authentication
   - Obtains agent token for this session
2. **Session usage**: Tool makes API calls with signatures until session ends
3. **Session end**: When tool exits, ephemeral key is discarded
4. **Next session**: User must re-authenticate, generating a new ephemeral key

**Key benefits for desktop/CLI apps:**

- **Flexibility**: Multiple authentication options based on security requirements
- **User binding**: Agent tokens can tie automated API calls to specific user identities
- **Hardware security**: Leverage platform keystores and hardware attestation when available
- **Graceful degradation**: Simple API key fallback for environments without advanced security features
- **Installation tracking**: Each installation has a unique `sub` for auditing and revocation

### C.5. Browser-Based Applications

Browser-based applications act as agent delegates, with each browser session obtaining an agent token from the web server that hosts the application.

**Pattern:**

1. **Page load**: User loads web application in browser
2. **Key generation**: JavaScript generates ephemeral key pair using Web Crypto API (`crypto.subtle`)
3. **Session identity**: Browser retrieves or creates session identifier (stored in localStorage/IndexedDB)
4. **Agent token request**: Browser requests agent token from web server:
   - User authenticates to web server (login, or anonymous session)
   - Browser sends public key + session ID to web server
   - Web server (acting as agent server) issues agent token
5. **API calls**: Browser uses agent token to sign requests to external resources

**Technical capabilities:**

Modern browsers support the cryptographic operations required for HTTPSig through the Web Crypto API:
- Ed25519 and RSA-PSS with SHA-256
- Ephemeral key pair generation
- Non-extractable keys (Web Crypto flag prevents key export)
- Custom HTTP headers (`Content-Digest`, `Signature-Key`, `Signature`, `Signature-Input`)

**Defense in depth (JavaScript closures):**

Like the PHP pattern in Appendix B, browsers can use JavaScript closures to encapsulate the private key and provide only an HTTP signing function:

```javascript
const signer = (function() {
    let privateKey, publicKey;
    const allowedOrigins = ['https://resource.example', 'https://auth.example'];

    crypto.subtle.generateKey(
        { name: "Ed25519" },
        false, // non-extractable
        ["sign"]
    ).then(keyPair => {
        privateKey = keyPair.privateKey;
        publicKey = keyPair.publicKey;
    });

    return {
        signHTTPRequest: async function(method, uri, headers, body) {
            const origin = new URL(uri).origin;
            if (!allowedOrigins.includes(origin)) {
                throw new Error('Unauthorized origin');
            }
            // Generate HTTP Message Signature with privateKey
            return { 'Signature-Input': /* ... */, 'Signature': /* ... */ };
        },
        getJWK: async function() { /* export public key */ }
    };
})();
```

The private key remains in closure scope and cannot be exfiltrated. Malicious code can call `signHTTPRequest()`, but only for allowed origins, and cannot extract the key for use elsewhere.

**CORS requirements:**

Custom headers trigger CORS preflight. Resources and auth servers must configure CORS headers on all AAuth endpoints:
```http
Access-Control-Allow-Origin: https://webapp.example
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: content-type, content-digest, signature-key, signature, signature-input
Access-Control-Max-Age: 86400
```

**Key benefits:**

- **No long-lived credentials in browser**: Keys are ephemeral per session
- **Platform integration**: Leverages Web Crypto API standard
- **Session-level identity**: Each session has unique `sub` for tracking
- **Cross-origin API calls**: CORS-compatible HTTP Message Signatures

---

## Appendix B: Long Tail Agent Servers

### B.1. Overview

Long-tail web applications—WordPress, Drupal, Joomla, and similar platforms—often run on shared or self-hosted environments without access to hardware security modules or secrets management systems. These applications act as **agent servers** with their own agent identifier and published JWKS, but face key management challenges:

- Database backups are frequent and widely distributed
- Developers export database dumps for local testing
- Securing persistent private keys adds operational complexity
- File system security may be limited

**The ephemeral key pattern** solves this by keeping both private keys and JWKS in memory only—nothing is persisted to disk or database.

**Key advantage over OAuth/OIDC:** AAuth with ephemeral keys eliminates the need for secret management entirely. OAuth and OIDC typically require client secrets or long-lived credentials that must be securely stored, rotated, and protected from exposure in backups and logs. With AAuth's ephemeral keys, there are no secrets to manage and no persistent keys to protect.

### B.2. The Pattern

**Core principle:** Both private and public keys are ephemeral and memory-only. JWKS is served from memory, not persisted.

**How it works:**

1. **Startup:** Generate new key pair, store both private key and JWKS in memory only
2. **Operation:** Sign requests with in-memory private key, serve JWKS from memory
3. **Restart:** Previous private key is lost, generate new key, serve new JWKS
4. **Auth token impact:** Outstanding auth tokens become unusable (contain old key in `cnf.jwk`)
5. **Recovery:** Use refresh token with new key to obtain new auth token

**Why not persist JWKS:** If JWKS is stored in database, an attacker with database write access could inject their own public key and impersonate the server. Memory-only JWKS prevents this attack.

### B.3. Security Benefits

Memory-only keys and JWKS **dramatically reduce attack surface:**

**Attacks prevented:**
- Backup theft - no keys in backups
- Database dumps - developers exporting DB don't leak keys
- SQL injection - can't steal keys or inject malicious public keys
- Credential theft - stolen DB credentials don't expose keys
- Public key injection - attacker can't add their own keys to JWKS via DB write
- Persistent compromise - keys don't survive indefinitely

**Remaining risk:**
- Sophisticated malicious plugin using reflection/memory inspection (rare, requires active code execution)

**Key insight:** Common attacks (backup theft, DB dumps, SQLi, key injection) are prevented. The remaining attack requires sophisticated active exploitation, far less common in practice.

### B.4. Implementation Notes

**Recommended pattern:** Use PHP closures to encapsulate both the key pair and policy enforcement. The private key remains in closure scope and cannot be exfiltrated. Malicious code can still call the signing function, but cannot extract the key for use elsewhere or after process restart.

**Defense in depth:** Agent servers in AAuth only sign HTTP Message Signatures, so the closure should provide a specific HTTP request signing function, not a general-purpose signing oracle. Validate the target origin inside the closure - only sign requests to pre-configured resources and auth servers.

**Example structure:**
```php
$signer = (function() {
    $keyPair = generateKeyPair();
    $kid = 'key-' . time();
    $allowedOrigins = [
        'https://resource.example',
        'https://auth.example'
    ];

    return [
        'signHTTPRequest' => function($method, $uri, $headers, $body = null)
            use ($privateKey, $kid, $allowedOrigins) {

            // Validate origin inside closure
            $origin = parse_url($uri, PHP_URL_SCHEME) . '://' . parse_url($uri, PHP_URL_HOST);
            if (!in_array($origin, $allowedOrigins)) {
                throw new Exception('Unauthorized origin');
            }

            // Generate HTTP Message Signature
            return [
                'Signature-Input' => /* ... */,
                'Signature' => /* ... */
            ];
        },
        'getJWKS' => function() use ($publicKey, $kid) { /* ... */ }
    ];
})();
```

**Multi-instance consideration:** Each instance generates its own key pair and serves its own JWKS. For high-availability deployments where instances need to share keys, consider a shared signing service instead.

**Restart behavior:** Auth tokens become temporarily unusable on restart until refreshed. Refresh tokens remain valid and can be used with the new key to obtain new auth tokens.

### B.5. When to Use

**Ideal for:**
- Single-instance applications (WordPress, Drupal, Joomla)
- Shared or self-hosted environments
- Plugin/module architectures
- Applications without secrets infrastructure

**Not recommended for:**
- High-availability multi-instance deployments (use shared signing service)
- Applications with HSM or secrets manager access (use those instead)
- Scenarios requiring key escrow or recovery

### B.6. Comparison to Agent Delegates

Agent servers with ephemeral keys (this pattern) have their own agent identifier and publish their own JWKS using `sig=jwks`. Agent delegates (Appendix C) receive agent tokens from an agent server and use `sig=jwt`. Most WordPress/Drupal deployments only need the agent server pattern.

---

## Appendix D: Relationship to Web-Bot-Auth

### D.1. Overview

The IETF Web Bot Authentication (webbotauth) Working Group charter aims to standardize methods for websites to manage automated traffic (bots, crawlers, AI agents) and for these agents to prove their authenticity. The charter emphasizes:

- Replacing insecure patterns (IP allowlisting, User-Agent spoofing, shared API keys)
- Using cryptographic signatures for bot authentication
- Enabling websites to apply differentiated policies based on bot identity
- Supporting abuse mitigation and rate limiting

AAuth fulfills these charter goals using HTTP Message Signatures while extending to authorization and delegation use cases.

### D.2. Charter Goal: Flexible Website Policies

**Charter requirement:** Websites need flexibility in how they handle automated traffic—from rejecting all bots, to allowing pseudonymous signed requests, to requiring full identification.

**How AAuth addresses this:**

Websites can use the `Agent-Auth` response header to signal different authentication requirements:

**1. Require signatures without identity (abuse management):**
```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig
```

The website simply requires "sign your requests" without requiring "tell us who you are." Agents respond with pseudonymous signatures:

```http
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; x="JrQLj5P..."
```

**Benefits:**
- Cryptographic proof distinguishes automated requests from spoofed User-Agents
- Rate limiting per key prevents single-source abuse
- No registration barrier for experimental or privacy-preserving agents
- Replay prevention through timestamp verification

**2. Require identity (bot allowlisting/denylisting):**
```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; identity=?1
```

The website requires the agent to identify itself. Agents respond with:

```http
Signature-Key: sig=jwks; id="https://agent.example"; kid="key-1"
```

The website can now apply bot-specific policies (allowlist Googlebot, block scraper-bots, give higher rate limits to trusted crawlers).

**3. Progressive enforcement based on behavior:**

```http
# Initially: Accept pseudonymous requests with low rate limits
200 OK

# After detecting high volume: Ask for identity
429 Too Many Requests
Agent-Auth: httpsig; identity=?1
Retry-After: 60

# For protected resources: Require authorization
401 Unauthorized
Agent-Auth: httpsig; auth-token; resource="https://resource.example"; scope="data.read"
```

This flexibility addresses the charter's goal of letting websites choose their policy without forcing a single authentication model.

### D.3. Charter Goal: Bot Identity and Delegation

**Charter requirement:** Enable crawlers and bots to prove their identity using cryptographic signatures.

**How AAuth addresses this:**

AAuth provides bot identity through agent identifier (HTTPS URL) with published JWKS:

```http
Signature-Key: sig=jwks; id="https://crawler.example"; well-known="agent-server"; kid="key-1"
```

**Website verification:**
1. Fetch `https://crawler.example/.well-known/agent-server`
2. Retrieve JWKS from `jwks_uri` in metadata
3. Verify signature using public key matching `kid`
4. Confirm bot identity and apply appropriate policies

**Scaling challenge addressed:**

Large-scale crawlers (Googlebot, Bingbot) operate from thousands of distributed servers. Managing a single private key across all instances creates operational and security challenges.

**AAuth's solution: Agent delegation**

The crawler operator acts as an **agent server** and issues **agent tokens** to each crawler instance:

```
Crawler Operator (agent.example)
├── Instance 1 → agent token with ephemeral key
├── Instance 2 → agent token with ephemeral key
├── Instance 3 → agent token with ephemeral key
└── Instance N → agent token with ephemeral key
```

**Each instance:**
1. Generates ephemeral key pair on startup (kept in memory only)
2. Requests agent token from central server
3. Uses `sig=jwt` with agent token to prove delegated identity:

```http
Signature-Key: sig=jwt; jwt="<agent-token>"
```

**Agent token structure:**
```json
{
  "iss": "https://crawler.example",
  "sub": "instance-region-us-west-1",
  "cnf": {
    "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
  },
  "exp": 1730218200
}
```

**Benefits for large-scale crawlers:**
- No shared secrets across distributed instances
- Instance compromise doesn't expose other instances
- Ephemeral keys eliminate key management burden
- Rapid revocation (short-lived agent tokens)
- Per-instance identity in `sub` for tracking and debugging
- Central control (agent server) with distributed execution (instances)

Websites verify the agent token signature using the agent server's published JWKS, confirming both the crawler operator's identity and that this specific instance is authorized.

### D.4. Charter Goal: Abuse Mitigation

**Charter requirement:** Help websites distinguish legitimate bots from malicious traffic and apply appropriate rate limits.

**How AAuth addresses this:**

AAuth's progressive authentication levels (see Section 4.4 for technical details) enable tiered abuse mitigation. Websites can apply different rate limits based on authentication level—from unsigned requests (strictest limits), to pseudonymous signed requests (moderate limits with cryptographic proof), to identified bots (bot-specific policies and allowlisting), to authorized access (fine-grained control with highest limits).

**Example charter-compliant flow:**

```http
# New agent: Pseudonymous signature, low rate limit (10 req/min)
GET /api/data
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; x="..."
→ 200 OK (within limit)

# Repeated good behavior builds trust
# Rate limit hit after 10 requests
→ 429 Too Many Requests
   Agent-Auth: httpsig; identity=?1

# Agent identifies itself as trusted crawler
GET /api/data
Signature-Key: sig=jwks; id="https://trusted-crawler.example"; kid="key-1"
→ 200 OK (higher limit: 1000 req/min)
```

This addresses the charter's abuse mitigation goal while maintaining flexibility for legitimate bots.

### D.5. What AAuth Adds Beyond Web-Bot-Auth Charter

While fulfilling the web-bot-auth charter goals, AAuth extends to broader agent scenarios:

**Authorization (autonomous and user delegation):**
- Autonomous agents requesting auth tokens for machine-to-machine access
- Agents acting on behalf of users (AI assistants, automation tools) with consent
- Auth tokens binding agent + resource + permissions (with optional user identity)
- Fine-grained access control and policy enforcement beyond simple bot identity

**Interactive agents:**
- Browser-based applications with ephemeral credentials
- Mobile and desktop apps with per-installation identity
- Long-lived sessions with refresh tokens
- Progressive authentication from pseudonymous to fully authorized

**Unified protocol:**
- Single framework for bot identification AND authorization
- Natural on-ramp from abuse management → bot identity → user delegation
- Consistent HTTP Message Signatures across all authentication levels

### D.6. Summary

**AAuth fulfills the web-bot-auth charter by:**

1. **Flexible website policies** - Websites can require signatures without identity (abuse management), identity (bot allowlisting), or authorization (autonomous agents or user data access)

2. **Bot identity with delegation** - Crawlers prove identity using agent identifier and published JWKS, with agent tokens enabling massive scale through distributed instances with ephemeral keys

3. **Abuse mitigation** - Progressive rate limiting based on authentication level (unsigned → pseudonymous → identified → authorized)

**AAuth extends beyond the charter by:**

- Supporting authorization and user delegation use cases
- Providing a unified protocol for both bot identity and user authorization
- Enabling interactive agents (browser, mobile, desktop) alongside autonomous bots

The Signature-Key header's four schemes (sig=hwk, sig=jwks, sig=x509, sig=jwt) provide the flexibility to address both the web-bot-auth charter's requirements and the broader agent authorization scenarios that AAuth explores.

---

## Appendix E: Redirect Headers for Enhanced Security

This appendix describes how the Redirect-Query and Redirect-Origin headers could be used to enhance the security of redirect flows in AAuth, particularly for resource-initiated authorization with user interaction (Section 8.6).

**Status:** Redirect Headers is another proposal in this suite. See: [Redirect Headers](https://github.com/DickHardt/redirect-headers)

**Applicability:** These headers would provide additional security for scenarios where resources act as agents and require user interaction to acquire downstream authorization. When a resource cannot interact directly with users, it returns a `user_interaction` URL to the agent, which then redirects the user through the resource's interaction endpoint. Redirect headers would provide browser-mediated assurance that redirects have not been hijacked.

---

### E.1. Overview

Resources often need to act as agents to access downstream resources. When the downstream resource requires user interaction (consent or authentication), but the resource has no direct user interface, the resource must coordinate with the agent to facilitate the interaction. This creates a redirect chain:

1. Agent redirects user to resource's interaction endpoint (with `return_url`)
2. Resource redirects user to authorization server
3. Authorization server redirects user back to resource
4. Resource redirects user back to agent's `return_url`

Redirect attacks occur when an attacker manipulates redirect URLs to send users to unintended destinations. The Redirect-Query, Redirect-Origin, and Redirect-Path headers would provide three security enhancements:

1. **Query parameter integrity**: The Redirect-Query header would allow the destination to verify that query parameters were not modified during the redirect
2. **Origin validation**: The Redirect-Origin header would allow the destination to validate that the redirect came from an expected origin
3. **Path validation**: The Redirect-Path header would allow validation that redirect URLs use the expected path prefix

---

### E.2. How Redirect Headers Would Be Used

When an agent redirects a user to a resource's interaction endpoint, the agent would include the Redirect-Query and optionally Redirect-Path headers.

**Agent redirect:**
```http
HTTP/1.1 303 See Other
Location: https://resource-r.example/auth-flow?session=xyz789&request=abc&return_url=https://agent-a.example/callback
Redirect-Query: session=xyz789&request=abc&return_url=https%3A%2F%2Fagent-a.example%2Fcallback
Redirect-Path: /callback
```

**Properties:**
- Redirect-Query contains the complete query string with all parameters (URL-encoded)
- Redirect-Path specifies the expected path prefix for the return_url
- User agents supporting these headers would include a Redirect-Origin header in the subsequent request
- User agents would validate that the current path begins with any Redirect-Path provided

**Resource would receive:**
```http
GET /auth-flow?session=xyz789&request=abc&return_url=https://agent-a.example/callback HTTP/1.1
Host: resource-r.example
Redirect-Origin: https://agent-a.example
Redirect-Path: /callback
Redirect-Query: session=xyz789&request=abc&return_url=https%3A%2F%2Fagent-a.example%2Fcallback
```

**Validation:**
1. The resource extracts the `return_url` parameter from Redirect-Query (or falls back to query string)
2. If Redirect-Origin is present, validate that `return_url` starts with the Redirect-Origin value
3. If Redirect-Path is present, validate that `return_url` path starts with the Redirect-Path value
4. Combined: `return_url` MUST start with `Redirect-Origin` + `Redirect-Path`
5. If validation fails, reject the request with an error

**Security benefit:** The Redirect-Origin and Redirect-Path headers would be set by the user agent and cannot be spoofed by scripts or modified in transit. Even if an attacker modified the Location header or query parameters, these browser-controlled headers would reflect the true origin and path of the redirect, preventing redirect hijacking.

---

### E.3. Resource Redirects with Redirect-Query

When a resource (acting as an agent) redirects a user back to the original agent's `return_url`, the resource would also include the Redirect-Query header.

**Resource redirect:**
```http
HTTP/1.1 303 See Other
Location: https://agent-a.example/callback?session=xyz789&status=complete
Redirect-Query: session=xyz789&status=complete
```

**Agent would receive:**
```http
GET /callback?session=xyz789&status=complete HTTP/1.1
Host: agent-a.example
Redirect-Origin: https://resource-r.example
```

The agent could validate that the redirect came from the expected resource by checking that Redirect-Origin matches the resource's origin.

---

### E.4. Authorization Server Redirects

When resources (acting as agents) redirect users to authorization servers and back, Redirect-Query headers would provide additional security at each hop in the chain.

**Resource to Auth Server:**
```http
HTTP/1.1 303 See Other
Location: https://auth2.example/authorize?request=def456&redirect_uri=https://resource-r.example/callback
Redirect-Query: request=def456&redirect_uri=https%3A%2F%2Fresource-r.example%2Fcallback
```

**Auth Server to Resource:**
```http
HTTP/1.1 303 See Other
Location: https://resource-r.example/callback?code=abc123
Redirect-Query: code=abc123
```

At each step, the receiving party could validate the Redirect-Origin matches the expected sender.

---

### E.5. Implementation Considerations

**Feature detection:** Implementations would not be able to reliably detect whether a user agent supports Redirect-Query headers before sending a redirect. Therefore, implementations would need to gracefully handle both supporting and non-supporting user agents.

**Graceful degradation:** When Redirect-Origin is not present in a request, implementations would fall back to standard validation:
- Validate `return_url` uses HTTPS
- Validate `return_url` matches expected patterns or allowlists
- Enforce session timeouts and nonce validation

**When to use:** If adopted, implementations should include Redirect-Query headers in all redirect responses where query parameters contain security-sensitive information such as:
- `return_url` parameters
- Session identifiers
- Authorization codes
- State parameters

**Security improvement:** While not a replacement for existing security measures, Redirect-Query headers would provide defense-in-depth by making certain classes of redirect attacks significantly more difficult, particularly in scenarios where resources act as agents requiring user interaction.

---

### E.6. Example: Complete Flow with Redirect Headers

This example shows how Redirect headers would secure a flow where a resource acts as an agent and requires user interaction to acquire downstream authorization.

**Step 1: Agent redirects user to resource**
```http
HTTP/1.1 303 See Other
Location: https://resource-r.example/auth-flow?session=xyz789&return_url=https://agent-a.example/callback
Redirect-Query: session=xyz789&return_url=https%3A%2F%2Fagent-a.example%2Fcallback
Redirect-Path: /callback
```

**Step 2: User agent requests resource with origin and path validation**
```http
GET /auth-flow?session=xyz789&return_url=https://agent-a.example/callback HTTP/1.1
Host: resource-r.example
Redirect-Origin: https://agent-a.example
Redirect-Path: /callback
Redirect-Query: session=xyz789&return_url=https%3A%2F%2Fagent-a.example%2Fcallback
```

Resource validates:
- `return_url` starts with `https://agent-a.example` (from Redirect-Origin)
- `return_url` path starts with `/callback` (from Redirect-Path)

**Step 3: Resource (acting as agent) redirects user to auth server**
```http
HTTP/1.1 303 See Other
Location: https://auth2.example/authorize?request=def456&redirect_uri=https://resource-r.example/callback
Redirect-Query: request=def456&redirect_uri=https%3A%2F%2Fresource-r.example%2Fcallback
Redirect-Path: /callback
```

**Step 4: Auth server receives with validation**
```http
GET /authorize?request=def456&redirect_uri=https://resource-r.example/callback HTTP/1.1
Host: auth2.example
Redirect-Origin: https://resource-r.example
Redirect-Path: /callback
Redirect-Query: request=def456&redirect_uri=https%3A%2F%2Fresource-r.example%2Fcallback
```

Auth server validates:
- `redirect_uri` starts with Redirect-Origin + Redirect-Path

**Step 5: Auth server redirects back to resource**
```http
HTTP/1.1 303 See Other
Location: https://resource-r.example/callback?code=abc123
Redirect-Query: code=abc123
```

**Step 6: Resource receives authorization**
```http
GET /callback?code=abc123 HTTP/1.1
Host: resource-r.example
Redirect-Origin: https://auth2.example
Redirect-Query: code=abc123
```

Resource validates: Redirect-Origin matches expected auth server

**Step 7: Resource redirects user back to agent**
```http
HTTP/1.1 303 See Other
Location: https://agent-a.example/callback?session=xyz789
Redirect-Query: session=xyz789
```

**Step 8: Agent receives user back with validation**
```http
GET /callback?session=xyz789 HTTP/1.1
Host: agent-a.example
Redirect-Origin: https://resource-r.example
Redirect-Query: session=xyz789
```

Agent validates: Redirect-Origin matches expected resource origin

At each hop in this chain, the Redirect-Origin header would provide browser-mediated origin validation, significantly improving security for scenarios where resources act as agents requiring user interaction to acquire downstream authorization.

---

### E.7. Relationship to AAuth Use Cases

Redirect headers would be particularly valuable for:

1. **Resource-Initiated Authorization (Section 8.6)**: When resources need user interaction to acquire downstream authorization but cannot interact with users directly

2. **Nested authorization chains**: When resources acting as agents coordinate multiple levels of user interaction through various authorization servers

3. **Cross-domain authorization**: When resources need to acquire authorization from authorization servers in different domains, reducing the risk of redirect hijacking across domain boundaries

When adopted, these headers would complement AAuth's proof-of-possession model by providing additional redirect security at the user agent layer.

---

### E.8. References

- Redirect Headers proposal: https://github.com/DickHardt/redirect-headers
- Open redirect attacks: OWASP Top 10 A01:2021 - Broken Access Control

---

## Author's Address

Dick Hardt
Hellō Identity
Email: dick.hardt@hello.coop
URI: https://github.com/DickHardt
