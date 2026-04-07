%%%
title = "AAuth Protocol"
abbrev = "AAuth-Protocol"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["agent", "authentication", "authorization", "http", "signatures"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-aauth-protocol-latest"
stream = "IETF"

date = 2026-04-04T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

%%%

<reference anchor="OpenID.Core" target="https://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization>Salesforce</organization>
    </author>
    <date year="2014" month="November"/>
  </front>
</reference>

<reference anchor="OpenID.Enterprise" target="https://openid.net/specs/openid-connect-enterprise-extensions-1_0.html">
  <front>
    <title>OpenID Connect Enterprise Extensions 1.0</title>
    <author initials="D." surname="Hardt" fullname="Dick Hardt">
      <organization>Hellō</organization>
    </author>
    <author initials="K." surname="McGuinness" fullname="Karl McGuinness">
      <organization>Okta</organization>
    </author>
    <date year="2025"/>
  </front>
</reference>

<reference anchor="I-D.hardt-httpbis-signature-key" target="https://dickhardt.github.io/signature-key/add-signature-requirement-error/draft-hardt-httpbis-signature-key.html">
  <front>
    <title>HTTP Signature Headers</title>
    <author initials="D." surname="Hardt" fullname="Dick Hardt">
      <organization>Hellō</organization>
    </author>
    <author initials="T." surname="Meunier" fullname="Thibault Meunier">
      <organization>Cloudflare</organization>
    </author>
    <date year="2026"/>
  </front>
</reference>

<reference anchor="CommonMark" target="https://spec.commonmark.org/0.31.2/">
  <front>
    <title>CommonMark Spec</title>
    <author initials="J." surname="MacFarlane" fullname="John MacFarlane"/>
    <date year="2024"/>
  </front>
</reference>

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

This document defines the AAuth authorization protocol, a four-party protocol in which agents operating under a mission manager (MM) obtain proof-of-possession auth tokens from authorization servers (AS) to access resources on behalf of users and organizations. The MM manages missions — scoped authorization contexts that guide an agent's work — handles user consent and identity, and brokers all authorization by federating with resource ASes. It specifies three token types (agent, resource, and auth), mission lifecycle management, MM-to-AS federation, and the `AAuth-Requirement` response header for communicating authentication and authorization requirements. It builds on the HTTP Signature Headers specification ([@!I-D.hardt-httpbis-signature-key]) for HTTP Message Signatures and the `Signature-Error` response header.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*


This document is part of the AAuth specification family. Source for this draft and an issue tracker can be found at https://github.com/dickhardt/AAuth.

{mainmatter}

# Introduction

OAuth 2.0 [@!RFC6749] was created to solve a security problem: users were sharing their passwords with third-party web applications so those applications could access their data at other sites. OAuth replaced this anti-pattern with a delegation model — the user's browser redirects to the authorization server, the user consents, and the application receives an access token without ever seeing the user's credentials. OpenID Connect extended this to federated login.

But the landscape has changed. New use cases have emerged that OAuth and OIDC were not designed to address:

- **On-demand authorization** where agents do not know what resources they will require until runtime. Long-running agents may execute tasks over hours or days and discover new authorization needs as they progress.
- **Shared context** where multiple authorization decisions share a context that spans resources. An agent organizing a trip discovers it needs access to flight search, hotel booking, calendar, and payment — each requires its own authorization, but all are part of the same shared context. In OAuth, each authorization is an isolated decision with no broader context connecting them.
- **Authorization dialogs** where authorization decisions arise during a task, long after the user set the agent in motion. The user no longer has the context — the agent must explain what it is doing and why access is needed, within the shared context of the task. The user may need to ask questions before deciding. OAuth's binary approve/deny prompt has no mechanism for this dialog.
- **Multi-hop resource access** where a resource needs to obtain authorization to access a downstream resource to fulfill a request, with interaction requirements bubbling back to the user through the chain.
- **Cross-domain access** where agents and resources have different trust domains. In OAuth, the client and resource share the same authorization server. In dynamic ecosystems, agents routinely access resources governed by a different authorization server.

AAuth introduces the following features to address these use cases:

- **Agent identity without pre-registration**: HTTPS URLs with self-published metadata and JWKS enable agents to establish identity without registering at each authorization server.
- **Per-instance agent identity**: Each agent instance has its own identifier (`local@domain`) and signing key. Authorization grants are per-instance, not per-application.
- **Missions**: Agents operate within missions — scoped authorization contexts that define what the agent is trying to accomplish. Each resource access is evaluated against the mission, providing governance and centralized audit without micromanagement. The mission manager (MM) manages missions, handles user consent, and brokers all authorization by federating with resource authorization servers (ASes).
- **MM-to-AS federation**: The agent's MM federates with the resource's AS to obtain auth tokens, enabling cross-domain access. The MM handles user consent; the AS handles resource policy. Neither overlaps with the other's role.
- **Deferred responses**: `202 Accepted` with polling is a first-class primitive across all endpoints, supporting headless agents, long-running consent, and clarification chat.
- **Clarification chat with justification**: Agents declare why access is needed, and users can ask questions during consent. The agent can explain or adjust its request.
- **Resource identity and resource-defined authorization**: Mission-aware resources issue signed resource tokens binding the request to the resource's identity and the agent's key, preventing MITM and confused deputy attacks.
- **Multi-hop resource access**: A resource acts as an agent to access downstream resources, routing all authorization through the MM for a complete audit trail.

AAuth also provides enhancements over OAuth:

- **Proof-of-possession by default**: In OAuth, client authentication typically relies on shared secrets, PKCE protects authorization code transactions, and access to protected resources uses bearer tokens that can be stolen and replayed. In AAuth, all requests are signed with HTTP Message Signatures ([@!RFC9421]) using keys bound to tokens conveyed via the Signature-Key header ([@!I-D.hardt-httpbis-signature-key]), providing proof-of-possession, identity, and message integrity on every call.
- **Unified authentication and authorization**: OAuth and OIDC are separate protocols with separate flows and token types. AAuth uses a single auth token that can carry both identity claims and authorized scopes.
- **No protocol artifacts in browser redirects**: Unlike OAuth, where browser redirects carry authorization codes that are vulnerable to interception, AAuth uses browser redirects only to transition the user between parties.
- **Reuse of OpenID Connect vocabulary**: AAuth reuses OpenID Connect scope values, identity claims, and enterprise extensions, lowering the adoption barrier.


The HTTP Signature Headers specification ([@!I-D.hardt-httpbis-signature-key]) defines how signing keys are bound to JWTs and discovered via well-known metadata, and how agents present cryptographic identity using HTTP Message Signatures ([@!RFC9421]). This specification defines the `AAuth-Requirement` response header for communicating authentication and authorization requirements (#requirement-responses), and the authorization protocol — resource requests where the resource handles authorization directly, and mission requests where the agent's MM federates with the resource's AS.

AAuth is designed for incremental adoption by agents and resources — each can advertise and enable its capabilities independently, and rollout does not need to be coordinated. An agent that adopts AAuth signatures gains a cryptographic identity that any resource can verify. A resource that adds an authorization endpoint can link that agent identity to however it manages access today — including OAuth, OIDC, or internal policy — enabling on-demand authorization and authorization dialogs without replacing existing infrastructure. When both agents and resources become mission-aware — the agent adds an MM, the resource adds an AS — shared context, cross-domain access, mission governance, centralized audit, and multi-hop resource access are unlocked. See (#incremental-adoption) for details.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

- **Legal Person**: A user or organization on whose behalf an agent acts. The legal person is the accountable party for an agent's actions. A legal person trusts their mission manager to handle consent and authorization, and trusts their agent server to issue agent tokens only to authorized agents.
- **Agent**: An HTTP client ([@!RFC9110], Section 3.5) acting on behalf of a legal person. Identified by an agent identifier of the form `local@domain` (#agent-identifiers). An agent has exactly one mission manager that it sends all token requests to.
- **Agent Server**: A server that manages agent identity and issues agent tokens to agents. Trusted by the legal person to issue agent tokens only to authorized agents. Identified by an HTTPS URL (#server-identifiers) and publishes metadata at `/.well-known/aauth-agent.json`.
- **Agent Token**: A JWT issued by an agent server to an agent, binding the agent's signing key to the agent's identity (#agent-tokens).
- **Mission**: A scoped authorization context that guides and authorizes an agent's work across multiple resource accesses. Identified by the SHA-256 hash of its approved text (`s256`). Missions are proposed by agents and approved by the MM.
- **Mission Manager (MM)**: A server that represents the legal person to the rest of the protocol. Trusted by the legal person to manage missions, authenticate users, handle consent, assert user identity, and broker all authorization on behalf of agents. The MM is the only entity that calls authorization server token endpoints. Identified by an HTTPS URL (#server-identifiers) and publishes metadata at `/.well-known/aauth-mission.json`.
- **Authorization Server (AS)**: A policy engine for a resource. Trusted by the resource to evaluate token requests from MMs, apply resource policy, and issue auth tokens. Only called by MMs. The AS may require interaction or approval during trust establishment or policy evaluation. Identified by an HTTPS URL (#server-identifiers) and publishes metadata at `/.well-known/aauth-issuer.json`.
- **Auth Token**: A JWT issued by an AS that grants an agent access to a resource, containing user identity and/or authorized scopes (#auth-tokens).
- **Resource**: A server that requires authentication and/or authorization to protect access to its APIs and data. A resource trusts its authorization server to enforce access policy. Identified by an HTTPS URL (#server-identifiers) and publishes metadata at `/.well-known/aauth-resource.json`. A mission-aware resource has exactly one AS that it accepts auth tokens from.
- **Resource Token**: A JWT issued by a resource binding the agent's identifier (`sub`) and key thumbprint to the resource's AS (`aud`) (#resource-tokens).
- **HTTP Sig**: An HTTP Message Signature ([@!RFC9421]) created per the AAuth HTTP Message Signatures profile defined in this specification (#http-message-signatures-profile), using a key conveyed via the `Signature-Key` header ([@!I-D.hardt-httpbis-signature-key]).
- **Interaction**: User authentication, consent, or other action at an interaction endpoint. Triggered when a server returns `202 Accepted` with `requirement=interaction`.
- **Markdown String**: A human-readable text value formatted as Markdown ([@CommonMark]). Fields of this type MAY define recommended sections. Implementations MUST sanitize Markdown before rendering to users.
- **Justification**: A Markdown string provided by the agent declaring why access is needed, presented to the user by the MM during consent.
- **Clarification**: A Markdown string containing a question posed to the agent by the user during consent via the MM. The agent may respond with an explanation or an updated request.

# Protocol Overview

AAuth is a four-party protocol in which the legal person's MM and the resource's AS federate to bridge trust domains. The MM handles user consent and identity; the AS handles resource policy. The agent never calls the AS directly.

AAuth defines three proof-of-possession token types, all JWTs bound to a specific signing key: agent tokens (`aa-agent+jwt`) bind an agent's key to its identity, resource tokens (`aa-resource+jwt`) bind an access challenge to the resource's identity, and auth tokens (`aa-auth+jwt`) grant an agent access to a specific resource.

The following diagram shows the parties and their relationships:

~~~ ascii-art
              Agent Trust Domain   |  Resource Trust Domain

                    +-----------+
                    |  Legal    |
                    |  Person   |
                    +-----------+
                      |   |
                     (2) (4)
                      |   |
                    +-----------+       +-----------+
                    |  Mission  |       |   Auth    |
                    |  Manager  |--(5)--|   Server  |
                    +-----------+       +-----------+
                      |   |   |
                     (2) (4) (5)
                      |   |   |
+-----------+       +-----------+       +-----------+
|   Agent   |       |           |--(5)--|           |
|   Server  |--(1)--|   Agent   |--(3)--|  Resource |
+-----------+       +-----------+       +-----------+
~~~

- (1) (#obtaining-an-agent-token) agent server provisions the agent with an agent token
- (2) (#obtaining-a-mission) agent proposes and obtains a mission from its mission manager with approval of the legal person
- (3) (#obtaining-a-resource-token) agent requests access at the resource's authorization endpoint
- (4) (#obtaining-authorization) mission manager obtains user authorization from the legal person
- (5) (#obtaining-an-auth-token) mission manager obtains an auth token from the authorization server and returns it to the agent

Steps (4) and (5) MAY occur in either order or in parallel — the mission manager MUST NOT return the auth token to the agent until user authorization is complete. Steps 2, 4, and 5 may involve deferred responses (#deferred-responses). Detailed end-to-end flows are in (#detailed-flows). The following subsections describe each step.

## Obtaining an Agent Token

The agent obtains an agent token from its agent server. The agent generates a signing key pair, proves its identity to the agent server through a platform-specific mechanism, and receives an agent token binding the signing key to the agent's identifier. Agent token acquisition is platform-dependent — see (#agent-token-acquisition) for common patterns and (#agent-tokens) for token structure and normative requirements.

## Obtaining a Mission

The agent proposes a mission to its MM. The MM may involve the user — for review, clarification, or approval. The user may ask questions or request changes to the proposal. Once approved, the MM returns the mission with its `s256` identifier. See (#missions) for normative requirements.

~~~ ascii-art
Agent                        MM                         User
  |                          |                            |
  |  POST mission_endpoint   |                            |
  |  mission_proposal        |                            |
  |------------------------->|                            |
  |                          |                            |
  |  [clarification chat]    |  review, clarify, approve  |
  |<------------------------>|<-------------------------->|
  |                          |                            |
  |  mission (s256, approved text)                        |
  |<-------------------------|                            |
~~~

## Obtaining a Resource Token

The agent requests access at the resource's authorization endpoint, including the `AAuth-Mission` header. The resource returns a resource token containing the mission object. See (#resource-tokens) for normative requirements.

~~~ ascii-art
Agent                                       Resource
  |                                            |
  |  POST authorization_endpoint               |
  |  AAuth-Mission: manager=...; s256=...      |
  |------------------------------------------->|
  |                                            |
  |  resource_token (with mission object)      |
  |<-------------------------------------------|
~~~

## Obtaining Authorization

The agent sends the resource token to its MM's token endpoint. The MM evaluates the request against the mission scope and involves the user if consent is needed. See (#authorization) for normative requirements.

~~~ ascii-art
Agent                        MM                         User
  |                          |                            |
  |  POST token_endpoint     |                            |
  |  resource_token          |                            |
  |------------------------->|                            |
  |                          |                            |
  |                          |  review, approve           |
  |                          |<-------------------------->|
~~~

## Obtaining an Auth Token

The MM federates with the resource's AS to obtain an auth token and returns it to the agent. See (#mm-as-federation) for the federation flow and (#auth-tokens) for token structure.

~~~ ascii-art
Agent                        MM                          AS
  |                          |                            |
  |                          |  POST token_endpoint       |
  |                          |  resource_token            |
  |                          |--------------------------->|
  |                          |                            |
  |                          |  auth_token                |
  |                          |<---------------------------|
  |                          |                            |
  |  auth_token              |                            |
  |<-------------------------|                            |
~~~

# Bootstrapping

Before protocol flows begin, each entity must be established with its identity, keys, and relationships. The bootstrapping requirements depend on whether the agent and resource use resource requests or mission requests:

## Resource Request Bootstrapping

For resource requests (no mission), the following must be established:

### Agent Identity

An agent obtains an agent token from its agent server. The agent token binds the agent's signing key to its agent identifier (`local@domain`). See (#agent-token-acquisition) for common provisioning patterns.

### Entity Metadata

- Agent servers publish at `/.well-known/aauth-agent.json` — including JWKS URI, display name, and capabilities (#agent-server-metadata).
- Resources publish at `/.well-known/aauth-resource.json` — including authorization endpoint (#resource-metadata).

## Mission Bootstrapping

For mission requests, the following additional entities must be established:

### Mission Manager Association

An agent has exactly one mission manager that it sends all token requests to. How the agent learns its MM is out of scope — this is determined by configuration during agent setup (e.g., set by the agent server or chosen by the person deploying the agent).

### Person-Agent Association

The MM maintains the association between an agent and its legal person (user or organization). This association is typically established when the person first authorizes the agent at the MM via the interaction flow. An organization administrator may also pre-authorize agents for the organization.

The MM MAY establish a direct communication channel with the user (e.g., email, push notification, or messaging) to support out-of-band authorization, approval notifications, and revocation alerts.

### Additional Entity Metadata

- Mission managers publish at `/.well-known/aauth-mission.json` — including token endpoint, mission endpoint, permission endpoint, audit endpoint, and JWKS URI (#mm-metadata).
- Authorization servers publish at `/.well-known/aauth-issuer.json` — including token endpoint and JWKS URI (#auth-server-metadata).
- Resources additionally publish their AS reference in metadata (#resource-metadata).

### MM-AS Trust

The MM and the resource's AS must have a trust relationship before the AS will issue auth tokens. This trust may be pre-established (through a business relationship) or established dynamically through the AS's token endpoint responses — interaction, payment, or claims. When an organization controls both the MM and AS, trust is implicit. See (#mm-as-federation) for details.

# Requirement Responses {#requirement-responses}

Servers use the `AAuth-Requirement` response header to indicate protocol-level requirements to agents. The header MAY be sent with `401 Unauthorized` or `202 Accepted` responses. A `401` response indicates that authorization is required. A `202` response indicates that the request is pending and additional action is required — either user interaction (`requirement=interaction`) or third-party approval (`requirement=approval`).

`AAuth-Requirement` and `WWW-Authenticate` are independent header fields; a response MAY include both. A client that understands AAuth processes `AAuth-Requirement`; a legacy client processes `WWW-Authenticate`. Neither header's presence invalidates the other.

The header MAY also be sent with `402 Payment Required` when a server requires both authorization and payment. The `AAuth-Requirement` conveys the authorization requirement; the payment requirement is conveyed by a separate mechanism such as x402 [@x402] or the Machine Payment Protocol (MPP) ([@I-D.ryan-httpauth-payment]).

## AAuth-Requirement Header Structure

The `AAuth-Requirement` header field is a Dictionary ([@!RFC8941], Section 3.2). It MUST contain the following member:

- `requirement`: A Token ([@!RFC8941], Section 3.3.4) indicating the requirement type.

Additional members are defined per requirement value. Recipients MUST ignore unknown members.

Example:

```http
AAuth-Requirement: requirement=auth-token; resource-token="eyJ..."
```

## Requirement Values

The `requirement` value is an extension point. This document defines the following values:

| Value | Status Code | Meaning | Resource | MM | AS |
|-------|-------------|---------|:--------:|:--:|:--:|
| `auth-token` | `401` | Auth token required for resource access | Y | | |
| `interaction` | `202` | User action required at an interaction endpoint | Y | Y | Y |
| `approval` | `202` | Approval pending, poll for result | Y | Y | Y |
| `clarification` | `202` | Question posed to the recipient | Y | Y | Y |
| `claims` | `202` | Identity claims required | | | Y |

The `auth-token` requirement is defined in (#requirement-auth-token); the `interaction` and `approval` requirements are defined in this section;  `clarification` in (#requirement-clarification); and `claims` in (#requirement-claims).

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
  |  AAuth-Requirement:                                      |
  |    requirement=interaction;                              |
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

# Deferred Responses {#deferred-responses}

Any endpoint in AAuth — whether an MM token endpoint, AS token endpoint, or resource endpoint — MAY return a `202 Accepted` response ([@!RFC9110]) when it cannot immediately resolve a request. This is a first-class protocol primitive, not a special case. Agents MUST handle `202` responses regardless of the nature of the original request.

## Initial Request

The agent makes a request and signals its willingness to wait using the `Prefer` header ([@!RFC7240]):

```http
POST /token HTTP/1.1
Host: auth.example
Content-Type: application/json
Prefer: wait=45
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "resource_token": "eyJhbGc..."
}
```

## Pending Response

When the server cannot resolve the request within the wait period:

```http
HTTP/1.1 202 Accepted
Location: /pending/f7a3b9c
Retry-After: 0
Cache-Control: no-store
Content-Type: application/json

{
  "status": "pending"
}
```

Headers:

- `Location` (REQUIRED): The pending URL. The `Location` URL MUST be on the same origin as the responding server.
- `Retry-After` (REQUIRED): Seconds the agent SHOULD wait before polling. `0` means retry immediately.
- `Cache-Control: no-store` (REQUIRED): Prevents caching of pending responses.
- `AAuth-Requirement` (OPTIONAL): Present when user interaction or approval is required. The `url` and `code` parameters are defined in (#requirement-responses).

Body fields:

- `status` (REQUIRED): `"pending"` while the request is waiting. `"interacting"` when the user has arrived at the interaction endpoint. Agents MUST treat unrecognized `status` values as `"pending"` and continue polling.

Additional body fields may be present depending on the `AAuth-Requirement` value — for example, `clarification` and `timeout` with `requirement=clarification`, or `required_claims` with `requirement=claims`. See the specific requirement definitions for details.

## Polling with GET

After receiving a `202`, the agent switches to `GET` for all subsequent requests to the `Location` URL. The agent does NOT resend the original request body. **Exception**: During clarification chat, the agent uses `POST` to deliver a clarification response.

The agent MUST respect `Retry-After` values. If a `Retry-After` header is not present, the default polling interval is 5 seconds. If the server responds with `429 Too Many Requests`, the agent MUST increase its polling interval by 5 seconds (linear backoff, following the pattern in [@RFC8628], Section 3.5). The `Prefer: wait=N` header ([@!RFC7240]) MAY be included on polling requests to signal the agent's willingness to wait for a long-poll response.

## Deferred Response State Machine

The following state machine applies to any AAuth endpoint that returns a `202 Accepted` response — including MM token endpoints, AS token endpoints, and resource endpoints during call chaining. A non-`202` response terminates polling.

```
Initial request (with Prefer: wait=N)
    |
    +-- 200 --> done — process response body
    +-- 202 --> note Location URL, check requirement/code
    +-- 400 --> invalid request — check error field, fix and retry
    +-- 401 --> invalid signature — check credentials;
    |           obtain auth token if resource challenge
    +-- 402 --> payment required (settle payment, poll Location)
    +-- 500 --> server error — start over
    +-- 503 --> back off per Retry-After, retry
               |
               GET Location (with Prefer: wait=N)
               |
               +-- 200 --> done — process response body
               +-- 202 --> continue polling (check status/clarification)
               |           status=interacting → stop prompting user
               +-- 403 --> denied or abandoned — surface to user
               +-- 408 --> expired — MAY initiate a fresh request
               +-- 410 --> gone — MUST NOT retry
               +-- 429 --> slow down — increase interval by 5s
               +-- 500 --> server error — start over
               +-- 503 --> temporarily unavailable — back off per Retry-After
```

# JWKS Discovery and Caching {#jwks-discovery}

All AAuth token verification — agent tokens, resource tokens, and auth tokens — requires discovering the issuer's signing keys via the `{iss}/.well-known/{dwk}` pattern defined in the HTTP Signature Headers specification ([@!I-D.hardt-httpbis-signature-key]).

Implementations MUST cache JWKS responses and SHOULD respect HTTP cache headers (`Cache-Control`, `Expires`) returned by the JWKS endpoint. When an implementation encounters an unknown `kid` in a JWT header, it SHOULD refresh the cached JWKS for that issuer to support key rotation. To prevent abuse, implementations MUST NOT fetch a given issuer's JWKS more frequently than once per minute. If a JWKS fetch fails, implementations SHOULD use the cached JWKS if available and SHOULD retry with exponential backoff. Cached JWKS entries SHOULD be discarded after a maximum of 24 hours regardless of cache headers, to ensure removed keys are no longer trusted.

# Agent Token {#agent-tokens}

This section defines the agent token — a JWT that binds an agent's signing key to its identity. The agent token is the foundation of agent identity in AAuth: every signed request an agent makes carries its agent token, enabling any party to verify who the agent is and that the request was signed by the key bound to that identity.

## Agent Token Acquisition {#agent-token-acquisition-overview}

An agent MUST obtain an agent token from its agent server before participating in the AAuth protocol. The acquisition process follows these steps:

1. The agent generates an ephemeral signing key pair (EdDSA is RECOMMENDED).
2. The agent proves its identity to the agent server through a platform-specific mechanism.
3. The agent server verifies the agent's identity and issues an agent token binding the agent's ephemeral public key to the agent's identifier.

The mechanism for proving identity is platform-dependent. See (#agent-token-acquisition) for common patterns including server workloads (platform attestation), mobile applications (app attestation), desktop and CLI applications (user login or managed desktop attestation), and browser-based applications (WebAuthn).

## Agent Token Structure

An agent token is a JWT with `typ: aa-agent+jwt` containing:

Header:
- `alg`: Signing algorithm. EdDSA is RECOMMENDED. Implementations MUST NOT accept `none`.
- `typ`: `aa-agent+jwt`
- `kid`: Key identifier

Required payload claims:
- `iss`: Agent server URL
- `dwk`: `aauth-agent.json` — the well-known metadata document name for key discovery ([@!I-D.hardt-httpbis-signature-key])
- `sub`: Agent identifier (stable across key rotations)
- `jti`: Unique token identifier for replay detection and audit
- `cnf`: Confirmation claim ([@!RFC7800]) with `jwk` containing the agent's public key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp. Agent tokens SHOULD NOT have a lifetime exceeding 24 hours.

Optional payload claims:
- `aud`: Audience restriction. When present, the agent MUST only present this agent token to the specified server(s).

Agent servers MAY include additional claims in the agent token. Companion specifications may define additional claims for use by MMs or ASes in policy evaluation — for example, software attestation, platform integrity, secure enclave status, workload identity assertions, or software publisher identity. MMs and ASes MUST ignore unrecognized claims.

## Agent Token Usage

Agents present agent tokens via the `Signature-Key` header ([@!I-D.hardt-httpbis-signature-key]) using `scheme=jwt`:

```http
Signature-Key: sig=jwt; jwt="eyJhbGciOiJFZERTQSIsInR5cCI6ImFnZW50K2p3dCJ9..."
```

## Agent Token Verification

Verify the agent token per [@!RFC7515] and [@!RFC7519]:

1. Decode the JWT header. Verify `typ` is `aa-agent+jwt`.
2. Verify `dwk` is `aauth-agent.json`. Discover the issuer's JWKS via `{iss}/.well-known/{dwk}` per the HTTP Signature Headers specification ([@!I-D.hardt-httpbis-signature-key]). Locate the key matching the JWT header `kid` and verify the JWT signature.
3. Verify `exp` is in the future and `iat` is not in the future.
4. Verify `iss` is a valid HTTPS URL conforming to the Server Identifier requirements.
5. Verify `cnf.jwk` matches the key used to sign the HTTP request.
6. If `aud` is present, verify that the server's own identifier is listed.

# Mission {#missions}

This section defines missions — scoped authorization contexts that guide an agent's work across multiple resource accesses. The mission is proposed by the agent and approved by the MM. Once approved, the mission's `s256` identifier is included in all subsequent resource interactions, providing governance and centralized audit for the agent's actions.

## Mission Creation

The agent creates a mission by sending a `mission_proposal` to the MM's `mission_endpoint`. The MM evaluates the proposal — potentially deferring for human review or engaging in clarification chat — and returns the approved mission.

### Mission Proposal

The agent MUST send a signed POST to the MM's `mission_endpoint`. The request MUST include an HTTP Sig (#http-message-signatures-profile) and the agent MUST present its agent token via the `Signature-Key` header using `scheme=jwt`.

The `mission_proposal` is a Markdown string — a natural language description of what the agent intends to accomplish. The agent does not know what specific resources or scopes it will need ahead of time:

```json
{
  "mission_proposal": "# Research Competitors\n\nResearch our top 3 competitors' pricing pages and write a summary report comparing their offerings to ours.\n\n## Approach\n1. Search for competitor pricing\n2. Read and analyze each page\n3. Write comparison report in shared docs"
}
```

The MM MAY return a `202 Accepted` deferred response (#deferred-responses) if human review, clarification, or approval is needed before the mission can be approved.

### Mission Approval

When the MM approves the mission, it returns the approved mission text and its `s256` identifier:

```json
{
  "mission": {
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "approved": "# Research Competitors\n\nResearch our top 3 competitors (Acme Corp, Globex, Initech) pricing pages and write a summary report.\n\n## Context\n- Our current pricing is at https://docs.internal/pricing-v3\n- Focus on enterprise tier comparisons\n- Report goes in the Q2 competitive analysis folder"
  }
}
```

The `s256` field is the base64url-encoded SHA-256 hash of the `approved` text. This hash serves as the mission's permanent identifier and integrity proof. The MM MUST include the date and time of approval in the approved mission text to ensure the `s256` is globally unique — even if two agents propose identical mission text, each approval produces a distinct hash.

The approved text MAY differ from the proposal — the MM or user may refine, constrain, or expand the mission during review. The agent MUST use the `s256` from the approved mission in all subsequent `AAuth-Mission` headers.

## Mission Management

Missions have a lifecycle beyond creation. The following aspects of mission management are described here for completeness; normative requirements for mission management are TBD.

**Mission States.** Missions transition through the following states:

- **proposed**: Agent has submitted a mission proposal. The MM is evaluating.
- **active**: MM has approved the mission. The agent is authorized to operate within the mission scope.
- **suspended**: Mission temporarily halted. Token requests return an error. The MM may suspend a mission if the agent's behavior raises concerns.
- **completed**: Mission objective achieved. Terminal state.
- **revoked**: Mission withdrawn by user or administrator. Terminal state.
- **expired**: Mission time limit reached. Terminal state.

**Resource Access.** The agent includes the mission context in all resource interactions via the `AAuth-Mission` header. When the agent sends a resource token to its MM, the MM evaluates the request against the mission context before federating with the resource's AS.

**Completion.** Missions end through the mission control interface — they may be completed (objective achieved), revoked (withdrawn), or expired (time limit reached).

### Mission Control {#mission-control}

The MM MAY provide a mission control interface for managing mission lifecycle. This is an administrative interface — not part of the protocol flow — that allows users, administrators, and external systems to:

- List and inspect missions
- Suspend, resume, revoke, and complete missions
- View delegation trees showing the full chain of agent→resource→AS authorizations
- Integrate with external business systems (ticketing, CRM, procurement)

The mission control endpoint is advertised in the MM's metadata (#mm-metadata).

# Resource Access and Resource Tokens {#resource-tokens}

This section defines how agents request access to resources and how resources issue resource tokens. The flow begins when an agent signals its mission context via the `AAuth-Mission` header and requests access at the resource's authorization endpoint. The resource responds with a resource token — a signed JWT that cryptographically binds the resource's identity, the agent's identity, and the requested scope. The agent presents this resource token to its MM to obtain an auth token. A resource MAY also challenge an agent with a resource token via the `AAuth-Requirement` response header.

## AAuth-Mission Request Header

The `AAuth-Mission` header is a request header sent by the agent on initial requests to a resource when operating in a mission context. It signals to the resource that the agent has a mission manager and is operating within a mission.

```http
AAuth-Mission: manager="https://mm.example"; s256="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

Parameters:

- `manager`: The mission manager's HTTPS URL
- `s256`: The base64url-encoded SHA-256 hash of the approved mission text

When a mission-aware resource receives a request with the `AAuth-Mission` header, it includes the mission object (`manager` and `s256`) in the resource token it issues. When a resource does not support missions, it ignores the header.

Agents operating in a mission context MUST include the `AAuth-Mission` header on all requests to resources.

## Authorization Endpoint

A resource publishes an `authorization_endpoint` in its metadata. This is where agents request access to the resource. The behavior depends on whether the agent and resource support missions.

### Mission Request

When the agent includes the `AAuth-Mission` header and the resource is mission-aware, the resource returns a resource token containing the mission object:

**Request:**

```http
POST /authorize HTTP/1.1
Host: resource.example
Content-Type: application/json
AAuth-Mission: manager="https://mm.example"; s256="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
Signature-Input: sig=("@method" "@authority" "@path" "signature-key" "aauth-mission");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "scope": "data.read data.write"
}
```

**Response:**

```json
{
  "resource_token": "eyJhbGc..."
}
```

The resource's AS is identified by the `aud` claim in the resource token. The agent sends the resource token to its MM's token endpoint.

### Resource Request (No Mission)

When the agent does not include the `AAuth-Mission` header, or the resource does not support missions, the resource handles authorization itself. The resource evaluates the request and returns a deferred response if user interaction is needed:

**Request:**

```http
POST /authorize HTTP/1.1
Host: resource.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "scope": "data.read data.write"
}
```

**Response (authorization needed):**

```http
HTTP/1.1 202 Accepted
Location: https://resource.example/authorize/pending/abc123
Retry-After: 0
Cache-Control: no-store
AAuth-Requirement: requirement=interaction;
    url="https://resource.example/interaction"; code="A1B2-C3D4"
Content-Type: application/json

{
  "status": "pending"
}
```

The user completes interaction at the resource's own consent page. The agent polls the `Location` URL. When authorization is complete, the resource binds the authorization to the agent's key identity. No auth token is issued — the agent subsequently accesses the resource's API with signed requests, and the resource recognizes the agent's key as authorized.

**Response (immediate authorization):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "authorized",
  "scope": "data.read data.write"
}
```

### Authorization Endpoint Error Responses

| Error | Status | Meaning |
|-------|--------|---------|
| `invalid_request` | 400 | Missing or invalid parameters |
| `invalid_signature` | 401 | HTTP signature verification failed |
| `invalid_scope` | 400 | Requested scope not recognized by the resource |
| `server_error` | 500 | Internal error |

Error responses use the same format as the token endpoint (#error-response-format).

## Auth Token Required {#requirement-auth-token}

A resource MUST use `requirement=auth-token` with a `401 Unauthorized` response when an auth token is required. The header MUST include a `resource-token` parameter containing a resource token JWT (#resource-token-structure).

```http
HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=auth-token; resource-token="eyJ..."
```

The agent MUST extract the `resource-token` parameter, verify the resource token (#resource-challenge-verification), and present it to its MM's token endpoint to obtain an auth token (#mm-token-endpoint). A resource MAY also use `402 Payment Required` with the same `AAuth-Requirement` header when payment is additionally required (#requirement-responses).

A resource MAY return `requirement=auth-token` with a new resource token to a request that already includes an auth token — for example, when the request requires a higher level of authorization than the current token provides. Agents MUST be prepared for this step-up authorization at any time.

## Resource Token Structure

A resource token is a JWT with `typ: aa-resource+jwt` containing:

Header:
- `alg`: Signing algorithm. EdDSA is RECOMMENDED. Implementations MUST NOT accept `none`.
- `typ`: `aa-resource+jwt`
- `kid`: Key identifier

Payload:
- `iss`: Resource URL
- `dwk`: `aauth-resource.json` — the well-known metadata document name for key discovery ([@!I-D.hardt-httpbis-signature-key])
- `aud`: Auth server URL
- `jti`: Unique token identifier for audit
- `agent`: Agent identifier
- `agent_jkt`: JWK Thumbprint ([@!RFC7638]) of the agent's current signing key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp
- `scope`: Requested scopes (optional), as a space-separated string of scope values
- `mission`: Mission object (optional, present when the resource is mission-aware and the agent sent an `AAuth-Mission` header). Contains:
  - `manager`: mission manager URL
  - `s256`: SHA-256 hash of the approved mission text (base64url)

Resource tokens SHOULD NOT have a lifetime exceeding 5 minutes. The `jti` claim provides an audit trail for token requests; ASes are not required to enforce replay detection on resource tokens. If a resource token expires before the MM presents it to the AS (e.g., because user interaction was required), the agent MUST obtain a fresh resource token from the resource and submit a new token request to the MM. The MM SHOULD remember prior consent decisions within a mission so the user is not re-prompted when the agent resubmits a request for the same resource and scope.

## Resource Token Verification

Verify the resource token per [@!RFC7515] and [@!RFC7519]:

1. Decode the JWT header. Verify `typ` is `aa-resource+jwt`.
2. Verify `dwk` is `aauth-resource.json`. Discover the issuer's JWKS via `{iss}/.well-known/{dwk}` per the HTTP Signature Headers specification ([@!I-D.hardt-httpbis-signature-key]). Locate the key matching the JWT header `kid` and verify the JWT signature.
3. Verify `exp` is in the future and `iat` is not in the future.
4. Verify `aud` matches the AS's own identifier.
5. Verify `agent` matches the requesting agent's identifier.
6. Verify `agent_jkt` matches the JWK Thumbprint of the key used to sign the HTTP request.
7. If `mission` is present, verify `mission.manager` matches the MM that sent the token request.

## Resource Challenge Verification

When an agent receives a `401` response with `AAuth-Requirement: requirement=auth-token`:

1. Extract the `resource-token` parameter.
2. Decode and verify the resource token JWT.
3. Verify `iss` matches the resource the agent sent the request to.
4. Verify `agent` matches the agent's own identifier.
5. Verify `agent_jkt` matches the JWK Thumbprint of the agent's signing key.
6. Verify `exp` is in the future.
7. Send the resource token to the agent's MM's token endpoint.

# Authorization {#authorization}

This section defines how agents obtain authorization from their mission manager. When accessing a remote resource, the agent sends a resource token to the MM's token endpoint. When performing local actions not governed by a remote resource, the agent requests permission from the MM's permission endpoint. In both cases, the MM evaluates the request against mission scope, handles user consent if needed, and uses the same requirement response patterns.

## Mission Manager Token Endpoint {#mm-token-endpoint}

The MM's `token_endpoint` is where agents send token requests. The MM evaluates the request against mission scope, handles user consent if needed, and federates with the resource's AS.

### Mission Manager Token Endpoint Modes

| Mode | Key Parameters | Use Case |
|------|----------------|----------|
| Resource access | `resource_token` | Agent needs auth token for a resource |
| Call chaining | `resource_token` + `upstream_token` | Resource acting as agent |

### Concurrent Token Requests

An agent MAY have multiple token requests pending at the MM simultaneously — for example, when a mission requires access to several resources. Each request has its own pending URL and lifecycle. The MM MUST handle concurrent requests independently. Some requests may be resolved without user interaction (e.g., within existing mission scope), while others may require consent. The MM is responsible for managing concurrent user interactions — for example, by batching consent prompts or serializing them.

### Agent Token Request

The agent MUST make a signed POST to the MM's `token_endpoint`. The request MUST include an HTTP Sig (#http-message-signatures-profile) and the agent MUST present its agent token via the `Signature-Key` header using `scheme=jwt`.

**Request parameters:**

- `resource_token` (REQUIRED): The resource token.
- `upstream_token` (OPTIONAL): An auth token from an upstream authorization, used in call chaining (#call-chaining).
- `justification` (OPTIONAL): A Markdown string declaring why access is being requested. The MM SHOULD present this value to the user during consent. The MM MUST sanitize the Markdown before rendering to users. The MM MAY log the `justification` for audit and monitoring purposes. **TODO:** Define recommended sections.
- `login_hint` (OPTIONAL): Hint about who to authorize, per [@!OpenID.Core] Section 3.1.2.1.
- `tenant` (OPTIONAL): Tenant identifier, per OpenID Connect Enterprise Extensions 1.0 [@OpenID.Enterprise].
- `domain_hint` (OPTIONAL): Domain hint, per OpenID Connect Enterprise Extensions 1.0 [@OpenID.Enterprise].

**Example request:**
```http
POST /token HTTP/1.1
Host: mm.example
Content-Type: application/json
Prefer: wait=45
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "resource_token": "eyJhbGc...",
  "justification": "Find available meeting times"
}
```

### MM Response

**Direct grant response** (`200`):
```json
{
  "auth_token": "eyJhbGc...",
  "expires_in": 3600
}
```

**User interaction required response** (`202`):
```http
HTTP/1.1 202 Accepted
Location: /pending/abc123
Retry-After: 0
Cache-Control: no-store
AAuth-Requirement: requirement=interaction;
    url="https://mm.example/interaction"; code="ABCD1234"
Content-Type: application/json

{
  "status": "pending"
}
```

The MM may also pass through a clarification from the AS to the agent via the `202` response (#as-token-endpoint).

## User Interaction

When a server responds with `202` and `AAuth-Requirement: requirement=interaction`, the `url` and `code` parameters in the header tell the agent where to send the user (#requirement-responses). The agent constructs the user-facing URL as `{url}?code={code}` and directs the user using one of the methods defined in (#requirement-responses) (browser redirect, QR code, or display code).

When the agent has a browser, it MAY append a `callback` parameter:
```
{url}?code={code}&callback={callback_url}
```

The `callback` URL is constructed from the agent's `callback_endpoint` metadata. When present, the server redirects the user's browser to the `callback` URL after the user completes the action. If no `callback` parameter is provided, the server displays a completion page and the agent relies on polling to detect completion.

The `code` parameter is single-use: once the user arrives at the URL with a valid code, the code is consumed and cannot be reused.

## Clarification Chat

During user consent, the user may ask questions about the agent's stated justification. The MM delivers these questions to the agent, and the agent responds. This enables a consent dialog without requiring the agent to have a direct channel to the user.

Agents that support clarification chat SHOULD declare `"clarification_supported": true` in their agent server metadata. Individual requests MAY indicate clarification support by including `"clarification_supported": true` in the MM token endpoint request body.

### Clarification Required {#requirement-clarification}

A server MUST use `requirement=clarification` with a `202 Accepted` response when it needs the recipient to answer a question before proceeding. The response body MUST include a `clarification` field containing the question and MAY include `timeout` and `options` fields.

```http
HTTP/1.1 202 Accepted
Location: /pending/abc123
Retry-After: 0
Cache-Control: no-store
AAuth-Requirement: requirement=clarification
Content-Type: application/json

{
  "status": "pending",
  "clarification": "Why do you need write access to my calendar?",
  "timeout": 120
}
```

Body fields:

- `clarification` (REQUIRED): A Markdown string containing the question.
- `timeout` (OPTIONAL): Seconds until the server times out the request. The recipient MUST respond before this deadline.
- `options` (OPTIONAL): An array of string values when the question has discrete choices.

The recipient MUST respond with one of the actions defined in (#agent-response-to-clarification): a clarification response, an updated request, or a cancellation. This requirement is used by both MMs (delivering user questions to agents) and ASes (requesting clarification from MMs).

### Clarification Flow

When the user asks a question during consent, the MM returns a `202` with `AAuth-Requirement: requirement=clarification`.

### Agent Response to Clarification

The agent MUST respond to a clarification with one of:

1. **Clarification response**: POST a `clarification_response` to the pending URL.
2. **Updated request**: POST a new `resource_token` to the pending URL, replacing the original request with updated scope or parameters.
3. **Cancel request**: DELETE the pending URL to withdraw the request.

#### Clarification Response

The agent responds by POSTing JSON with `clarification_response` to the pending URL:

```http
POST /pending/abc123 HTTP/1.1
Host: mm.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "clarification_response": "I need to create a meeting invite for the participants you listed."
}
```

The `clarification_response` value is a Markdown string. **TODO:** Define recommended sections. After posting, the agent resumes polling with `GET`.

#### Updated Request

The agent MAY obtain a new resource token from the resource (e.g., with reduced scope) and POST it to the pending URL:

```http
POST /pending/abc123 HTTP/1.1
Host: mm.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "resource_token": "eyJ...",
  "justification": "I've reduced my request to read-only access."
}
```

The new resource token MUST have the same `iss`, `agent`, and `agent_jkt` as the original. The MM presents the updated request to the user. A `justification` is OPTIONAL but RECOMMENDED to explain the change to the user.

#### Cancel Request

The agent MAY cancel the request by sending DELETE to the pending URL:

```http
DELETE /pending/abc123 HTTP/1.1
Host: mm.example
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."
```

The MM terminates the consent session and informs the user that the agent withdrew its request. Subsequent requests to the pending URL return `410 Gone`.

### Clarification Limits

MMs SHOULD enforce limits on clarification rounds (recommended: 5 rounds maximum). Clarification responses from agents are untrusted input and MUST be sanitized before display to the user.

## Permission Endpoint {#permission-endpoint}

When an agent needs to perform an action not governed by a remote resource — for example, executing a tool call, writing a file, or sending a message on behalf of the user — it requests permission from the MM's `permission_endpoint`. This enables agents to work with an MM before any resources support AAuth.

The agent sends a signed POST with a proposed action in the context of a mission:

```http
POST /permission HTTP/1.1
Host: mm.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" \
    "content-type" "content-digest" "signature-key");\
    created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "mission_s256": "sha-256-hash-of-mission",
  "action": "send_email",
  "parameters": {
    "to": "alice@example.com",
    "subject": "Meeting notes",
    "body": "..."
  }
}
```

The request body MUST include:

- `mission_s256`: The `s256` identifier of the mission this action is part of.
- `action`: A string identifying the action the agent wants to perform.
- `parameters`: An object containing action-specific details.

### Permission Response

If the action falls within the mission's pre-approved scope, the MM returns `200 OK`:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "permitted": true,
  "permission_id": "perm-abc123"
}
```

The response MUST include:

- `permitted`: Boolean indicating whether the action is approved.
- `permission_id`: A unique identifier for this permission decision, for audit correlation.

If user consent is needed, the MM returns a deferred response (#deferred-responses) using the standard requirement patterns — `interaction`, `approval`, or `clarification` (#requirement-responses). The agent polls the pending URL until the user approves, denies, or the request times out.

If the action is denied, the MM returns `200 OK` with `"permitted": false` and a `reason` field.

### Mission Scope and Pre-Approved Actions

When a mission is approved, the MM MAY include a `permissions` field in the mission response indicating which action categories are pre-approved within the mission scope. Actions matching pre-approved categories do not require a call to the `permission_endpoint`.

The `permissions` field is an array of action category strings. The MM defines the action categories it recognizes. For example:

```json
{
  "mission_s256": "...",
  "text": "Book a flight to NYC under $500",
  "permissions": ["search", "read_file", "compare"]
}
```

Actions outside the pre-approved categories — or actions that cross a threshold defined by the MM (e.g., spending money, sending messages, deleting data) — require an explicit permission request.

## Audit Endpoint {#audit-endpoint}

The MM's `audit_endpoint` is published in its metadata (#mm-metadata). The agent sends a signed POST to log actions it has performed:

```http
POST /audit HTTP/1.1
Host: mm.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" \
    "content-type" "content-digest" "signature-key");\
    created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "mission_s256": "sha-256-hash-of-mission",
  "action": "search_flights",
  "parameters": {
    "destination": "NYC",
    "date": "2026-05-01"
  },
  "permission_id": "perm-abc123",
  "result": "found 3 flights under $500"
}
```

The request body MUST include:

- `mission_s256`: The mission this action was part of.
- `action`: The action performed.
- `parameters`: Action-specific details.

The request body MAY include:

- `permission_id`: The permission decision that authorized this action, if any.
- `result`: A summary of the action's outcome.

The MM returns `201 Created`. The audit endpoint is fire-and-forget — the agent MUST NOT block on the response. The MM MAY use audit records to detect anomalous behavior, alert the user, or revoke the mission.

## Re-authorization

AAuth does not have a separate refresh token or refresh flow. When an auth token expires, the agent obtains a fresh resource token from the resource's authorization endpoint and submits it to the MM's token endpoint — the same flow as the initial authorization. This gives the resource a voice in every re-authorization: the resource can adjust scope, require step-up authorization, or deny access based on current policy.

When an agent rotates its signing key, all existing auth tokens are bound to the old key and can no longer be used. The agent MUST re-authorize by obtaining fresh resource tokens and submitting them to the MM.

Agents SHOULD proactively obtain a new agent token and refresh all auth tokens before the current agent token expires, to avoid service interruptions. Auth tokens MUST NOT have an `exp` value that exceeds the `exp` of the agent token used to obtain them — a resource MUST reject an auth token whose associated agent token has expired.

# Auth Token {#auth-tokens}

This section defines auth tokens and the mechanisms by which they are issued. The auth token is the end result of the authorization flow — a JWT issued by an authorization server that grants an agent access to a specific resource. This section covers the AS token endpoint (called only by MMs), MM-AS federation, and the auth token structure.

## AS Token Endpoint {#as-token-endpoint}

The AS's `token_endpoint` is called only by MMs. The AS evaluates resource policy and issues auth tokens. It accepts JSON POST requests.

### MM-to-AS Token Request

The MM MUST make a signed POST to the AS's `token_endpoint`. The MM authenticates via an HTTP Sig (#http-message-signatures-profile).

**Request parameters:**

- `resource_token` (REQUIRED): The resource token issued by the resource.
- `agent_token` (REQUIRED): The agent's agent token.
- `upstream_token` (OPTIONAL): An auth token from an upstream authorization, used in call chaining (#call-chaining).

**Example request:**
```http
POST /token HTTP/1.1
Host: as.resource.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwks_uri;jwks_uri="https://mm.example/.well-known/jwks.json"

{
  "resource_token": "eyJhbGc...",
  "agent_token": "eyJhbGc..."
}
```

### AS Response

The MM calls the AS token endpoint and follows the standard deferred response loop (#deferred-responses): it handles `202` and `402` responses and continues until it receives a `200` with an auth token or a terminal error.

**Direct grant response** (`200`):
```json
{
  "auth_token": "eyJhbGc...",
  "expires_in": 3600
}
```

The AS MAY return `202 Accepted` with an `AAuth-Requirement` header indicating what is needed before it can issue an auth token:

- **`requirement=claims`** (#requirement-claims): The AS needs identity claims. The body includes `required_claims`. The MM MUST provide the requested claims (including a directed `sub` identifier for this AS) by POSTing to the `Location` URL. The AS cannot know what claims it needs until it has processed the resource token.
- **`requirement=clarification`** (#requirement-clarification): The AS needs a question answered. The MM triages who answers: itself (if mission context has the answer), the user, or the agent. The MM MAY pass the clarification down to the agent via a `202` response.
- **`requirement=interaction`** (#requirement-responses): The AS requires user interaction — for example, the user must authenticate at the AS to bind their MM, or the resource owner must approve access. The MM directs the user to the AS's interaction URL, or passes the interaction requirement back to the agent.
- **`requirement=approval`** (#requirement-responses): The AS is obtaining approval without requiring user direction.

**Payment required** (`402`):

The AS MAY return `402 Payment Required` when a billing relationship is required before it will issue auth tokens. The `402` response includes payment details per an applicable payment protocol such as x402 [@x402] or the Machine Payment Protocol (MPP) ([@I-D.ryan-httpauth-payment]). The response MUST include a `Location` header for the MM to poll after payment is settled.

```http
HTTP/1.1 402 Payment Required
Location: https://as.resource.example/token/pending/xyz
WWW-Authenticate: Payment id="x7Tg2pLq", method="stripe",
    request="eyJhbW91bnQiOiIxMDAw..."
```

The MM settles payment per the indicated protocol and polls the `Location` URL. When payment is confirmed, the AS continues processing the token request — which may result in a `200` with an auth token, or a further `202` requiring claims, interaction, or approval.

The MM caches the billing relationship per AS. Future token requests from the same MM to the same AS skip the billing step. The payment protocol, settlement mechanism, and billing terms are out of scope for this specification.

### Auth Token Delivery

When the AS issues an auth token (`200` response), the MM MUST verify the auth token before returning it to the agent:

1. Verify the auth token JWT signature using the AS's JWKS (#jwks-discovery).
2. Verify `iss` matches the AS the MM sent the token request to.
3. Verify `aud` matches the resource identified by the resource token's `iss`.
4. Verify `agent` matches the agent that submitted the token request.
5. Verify `cnf.jwk` matches the agent's signing key.
6. Verify `scope` is consistent with what was requested — not broader than the scope in the resource token.

After verification, the MM returns the auth token to the agent. The agent presents the auth token to the resource via the `Signature-Key` header (#auth-token-usage). The resource verifies the auth token against the AS's JWKS (#auth-token-verification).

The agent's own verification of the auth token (#auth-token-response-verification) is limited to checking that `aud`, `cnf`, and `agent` match its own values — the agent does not need to verify the auth token's signature since it received the token from its trusted MM.

## Claims Required {#requirement-claims}

A server MUST use `requirement=claims` with a `202 Accepted` response when it needs identity claims to process a request. The response body MUST include a `required_claims` field containing an array of claim names.

```http
HTTP/1.1 202 Accepted
Location: https://as.resource.example/token/pending/xyz
Retry-After: 0
Cache-Control: no-store
AAuth-Requirement: requirement=claims
Content-Type: application/json

{
  "status": "pending",
  "required_claims": ["email", "org"]
}
```

The recipient MUST provide the requested claims (including a directed user identifier as `sub`) by POSTing to the `Location` URL. The recipient MUST include an HTTP Sig (#http-message-signatures-profile) on the POST. Claims not recognized by the recipient SHOULD be ignored. This requirement is used by ASes to request identity claims from MMs during token issuance.

## MM-AS Federation {#mm-as-federation}

The MM is the only entity that calls AS token endpoints. When the MM receives a resource token from an agent, the resource token's `aud` claim identifies the resource's AS. The MM discovers the AS's metadata at `{aud}/.well-known/aauth-issuer.json` (#auth-server-metadata) and calls the AS's `token_endpoint` (#as-token-endpoint).

### MM-AS Trust Establishment

Trust between the MM and AS is not a separate registration step — it emerges from the AS's response to the MM's first token request. The AS evaluates the token request and responds based on its current policy:

- **Pre-established**: A business relationship configured between the MM and AS, potentially including payment terms, SLA, and compliance requirements. The AS recognizes the MM and processes the token request directly.
- **Interaction**: The AS returns `202` with `requirement=interaction`, directing the user to authenticate at the AS and confirm their MM. After this one-time binding, the AS trusts future requests from that MM for that user. This is the primary mechanism for establishing trust dynamically.
- **Payment**: The AS returns `402`, requiring the MM to establish a billing relationship before tokens will be issued. The MM settles payment per the indicated protocol and polls for completion. After billing is established, the AS trusts future requests from that MM.
- **Claims only**: The AS may trust any MM that can provide sufficient identity claims for a policy decision, without requiring a prior relationship.

These mechanisms may compose: for example, the AS may first require payment (`402`), then interaction for user binding (`202`), then claims (`202`) before issuing an auth token. Each step uses the same `Location` URL for polling.

~~~ ascii-art
MM                        User                    AS
  |                         |                       |
  |  POST /token            |                       |
  |  resource_token,        |                       |
  |  agent_token            |                       |
  |------------------------------------------------>|
  |                         |                       |
  |  402 Payment Required   |                       |
  |  Location: /token/pending/xyz                   |
  |<------------------------------------------------|
  |                         |                       |
  |  [MM settles payment per indicated protocol]    |
  |                         |                       |
  |  GET /token/pending/xyz |                       |
  |------------------------------------------------>|
  |                         |                       |
  |  202 Accepted           |                       |
  |  requirement=interaction|                       |
  |  url=".../authorize/abc"|                       |
  |<------------------------------------------------|
  |                         |                       |
  |  direct user to URL     |                       |
  |------------------------>|                       |
  |                         |  authenticate, bind MM|
  |                         |---------------------->|
  |                         |                       |
  |  GET /token/pending/xyz |                       |
  |------------------------------------------------>|
  |                         |                       |
  |  202 Accepted           |                       |
  |  requirement=claims     |                       |
  |<------------------------------------------------|
  |                         |                       |
  |  POST /token/pending/xyz|                       |
  |  {sub, email, org}      |                       |
  |------------------------------------------------>|
  |                         |                       |
  |  200 OK (auth_token)    |                       |
  |<------------------------------------------------|
  |                         |                       |
~~~
{: #fig-mm-as-trust title="MM-AS Trust Establishment (all steps shown — most requests skip some)"}

### AS Decision Logic (Non-Normative) {#as-decision-logic}

The following is a non-normative description of how an AS might evaluate a token request:

1. **MM = AS (same entity)**: Grant directly. When an organization controls both the MM and AS, the federation call is internal and trust is implicit.
2. **User has bound this MM at the AS**: Apply the user's configured policy for this MM.
3. **MM is pre-established (enterprise agreement)**: Apply the organization's configured policy.
4. **Resource is open or has a free tier**: Grant with restricted scope or rate limits.
5. **Resource requires billing**: Return `402` with payment details.
6. **Resource requires user binding**: Return `202` with `requirement=interaction`.
7. **AS needs identity claims to decide**: Return `202` with `requirement=claims`.
8. **Insufficient trust for requested scope**: Return `403`.

The AS is not required to follow this order. The decision logic is entirely at the AS's discretion based on resource policy.

### Organization Visibility

Organizations benefit from the trust model: an organization's agents share a single MM, and internal resources may share a single AS. The MM provides centralized audit across all agents and missions. Federation is only incurred at the boundary, when an internal agent accesses an external resource. When an organization controls both the MM and AS, the federation call is internal and trust is implicit — this is the degenerate case of the four-party model collapsing to fewer parties.

## Auth Token Structure

An auth token is a JWT with `typ: aa-auth+jwt` containing:

Header:
- `alg`: Signing algorithm. EdDSA is RECOMMENDED. Implementations MUST NOT accept `none`.
- `typ`: `aa-auth+jwt`
- `kid`: Key identifier

Required payload claims:
- `iss`: AS URL
- `dwk`: `aauth-issuer.json` — the well-known metadata document name for key discovery ([@!I-D.hardt-httpbis-signature-key])
- `aud`: The URL of the resource the agent is authorized to access.
- `jti`: Unique token identifier for replay detection and audit
- `agent`: Agent identifier
- `cnf`: Confirmation claim with `jwk` containing the agent's public key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp. Auth tokens MUST NOT have a lifetime exceeding 1 hour.

Conditional payload claims (at least one MUST be present):
- `sub`: Directed user identifier. The MM provides a pairwise pseudonymous identifier for each AS, preserving user privacy across trust domains.
- `scope`: Authorized scopes, as a space-separated string of scope values consistent with [@!RFC9068] Section 2.2.3

At least one of `sub` or `scope` MUST be present.

Optional payload claims:
- `mission`: Mission object. Present when the auth token was issued in the context of a mission. Contains:
  - `manager`: mission manager URL
  - `s256`: SHA-256 hash of the approved mission text (base64url)

The auth token MAY include additional claims registered in the IANA JSON Web Token Claims Registry [@!RFC7519] or defined in OpenID Connect Core 1.0 [@!OpenID.Core] Section 5.1.

## Auth Token Usage

Agents present auth tokens via the `Signature-Key` header ([@!I-D.hardt-httpbis-signature-key]) using `scheme=jwt`:

```http
Signature-Key: sig=jwt; jwt="eyJhbGciOiJFZERTQSIsInR5cCI6ImF1dGgrand0In0..."
```

## Auth Token Verification

When a resource receives an auth token, verify per [@!RFC7515] and [@!RFC7519]:

1. Decode the JWT header. Verify `typ` is `aa-auth+jwt`.
2. Verify `dwk` is `aauth-issuer.json`. Discover the issuer's JWKS via `{iss}/.well-known/{dwk}` per the HTTP Signature Headers specification ([@!I-D.hardt-httpbis-signature-key]). Locate the key matching the JWT header `kid` and verify the JWT signature.
3. Verify `exp` is in the future and `iat` is not in the future.
4. Verify `iss` is a valid HTTPS URL.
5. Verify `aud` matches the resource's own identifier.
6. Verify `agent` matches the agent identifier from the request's signing context.
7. Verify `cnf.jwk` matches the key used to sign the HTTP request.
8. Verify that at least one of `sub` or `scope` is present.

## Auth Token Response Verification {#auth-token-response-verification}

When an agent receives an auth token:

1. Verify the auth token JWT using the AS's JWKS.
2. Verify `iss` matches the AS identified in the resource token's `aud` claim.
3. Verify `aud` matches the resource the agent intends to access.
4. Verify `cnf.jwk` matches the agent's own signing key.
5. Verify `agent` matches the agent's own identifier.

## Upstream Token Verification {#upstream-token-verification}

When the MM receives an `upstream_token` parameter in a call chaining request:

1. Perform Auth Token Verification on the upstream token.
2. Verify `iss` is a trusted AS (an AS whose auth token the MM previously brokered).
3. Verify the `aud` in the upstream token matches the resource that is now acting as an agent (i.e., the upstream token was issued for the intermediary resource).
4. The MM evaluates its own policy based on the upstream token's claims and mission context. The resulting downstream authorization is not required to be a subset of the upstream scopes.

# HTTP Message Signatures Profile {#http-message-signatures-profile}

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

Servers MAY require additional covered components (e.g., `content-digest` ([@RFC9530]) for request body integrity). The agent learns about additional requirements from server metadata or from an `invalid_input` error response that includes `required_input`.

### Signature Parameters

The `Signature-Input` header ([@!RFC9421], Section 4.1) MUST include the following parameters:

- `created`: Signature creation timestamp as an Integer (Unix time). The agent MUST set this to the current time.

## Verification (Server) {#verification}

When a server receives a signed request, it MUST perform the following steps. Any failure MUST result in a `401` response with the appropriate `Signature-Error` header ([@!I-D.hardt-httpbis-signature-key]).

1. Extract the `Signature`, `Signature-Input`, and `Signature-Key` headers. If any are missing, return `invalid_request`.
2. Verify that the `Signature-Input` covers the required components defined in (#covered-components). If the server requires additional components, verify those are covered as well. If not, return `invalid_input` with `required_input`.
3. Verify the `created` parameter is present and within the server's signature validity window of the server's current time. The default window is 60 seconds. Servers MAY advertise a different window via their metadata (e.g., `signature_window` in resource metadata). Reject with `invalid_signature` if outside this window. Servers and agents SHOULD synchronize their clocks using NTP ([@RFC5905]).
4. Determine the signature algorithm from the `alg` parameter in the key. If the algorithm is not supported, return `unsupported_algorithm`.
5. Obtain the public key from the `Signature-Key` header according to the scheme, as specified in ([@!I-D.hardt-httpbis-signature-key]). Return `invalid_key` if the key cannot be parsed, `unknown_key` if the key is not found at the `jwks_uri`, `invalid_jwt` if a JWT scheme fails verification, or `expired_jwt` if the JWT has expired.
6. Verify the HTTP Message Signature ([@!RFC9421]) using the obtained public key and determined algorithm. Return `invalid_signature` if verification fails.

# Multi-Hop {#multi-hop}

This section defines how resources act as agents to access downstream resources on behalf of the original caller. In multi-hop scenarios, a resource that receives an authorized request needs to access another resource to fulfill that request. The resource acts as an agent — it has its own agent identity and signing key — and routes the downstream authorization through the MM, preserving a complete audit trail.

## Call Chaining {#call-chaining}

When a resource needs to access a downstream resource on behalf of the caller, it acts as an agent. It sends the downstream resource token to the MM along with its own agent token and the auth token it received from the original caller as the `upstream_token`.

The MM evaluates the downstream request per (#upstream-token-verification) and sees the complete delegation chain for audit.

Because the resource acts as an agent, it MUST have its own agent identity — it MUST publish agent metadata at `/.well-known/aauth-agent.json` so that downstream resources and ASes can verify its identity.

## Interaction Chaining {#interaction-chaining}

When the MM requires user interaction for the downstream access, it returns a `202` with `requirement=interaction`. Resource 1 chains the interaction back to the original agent by returning its own `202`.

When a resource acting as an agent receives a `202 Accepted` response with `AAuth-Requirement: requirement=interaction` from its MM, and the resource needs to propagate this interaction requirement to its caller, it MUST return a `202 Accepted` response to the original agent with its own `AAuth-Requirement` header containing `requirement=interaction` and its own interaction code. The resource MUST provide its own `Location` URL for the original agent to poll. When the user completes interaction and the resource obtains the downstream auth token, the resource completes the original request and returns the result at its pending URL.

When call chaining involves a mission-aware downstream resource, the intermediary resource's MM federates with the downstream AS. See (#mm-as-federation).

# Identifier and URL Requirements

## Server Identifiers

The `agent`, `resource`, `issuer`, and `mm` values that identify agent servers, resources, auth servers, and mission managers MUST conform to the following:

- MUST use the `https` scheme
- MUST contain only scheme and host (no port, path, query, or fragment)
- MUST NOT include a trailing slash
- MUST be lowercase
- Internationalized domain names MUST use the ASCII-Compatible Encoding (ACE) form (A-labels) as defined in [@!RFC5890]

Valid identifiers:

- `https://agent.example`
- `https://xn--nxasmq6b.example` (internationalized domain in ACE form)

Invalid identifiers:

- `http://agent.example` (not HTTPS)
- `https://Agent.Example` (not lowercase)
- `https://agent.example:8443` (contains port)
- `https://agent.example/v1` (contains path)
- `https://agent.example/` (trailing slash)

Implementations MUST perform exact string comparison on server identifiers.

## Agent Identifiers

Agent identifiers are of the form `local@domain` where `domain` is the agent server's domain. The `local` part MUST consist of lowercase ASCII letters (`a-z`), digits (`0-9`), hyphen (`-`), underscore (`_`), plus (`+`), and period (`.`). The `local` part MUST NOT be empty and MUST NOT exceed 255 characters. The `domain` part MUST be a valid domain name conforming to the server identifier requirements above (without scheme).

Valid agent identifiers:

- `assistant-v2@agent.example`
- `cli+instance.1@tools.example`

Invalid agent identifiers:

- `My Agent@agent.example` (uppercase letters and space in local part)
- `@agent.example` (empty local part)
- `agent@http://agent.example` (domain includes scheme)

Implementations MUST perform exact string comparison on agent identifiers (case-sensitive).

## Endpoint URLs

The `token_endpoint`, `authorization_endpoint`, `mission_endpoint`, and `callback_endpoint` values MUST conform to the following:

- MUST use the `https` scheme
- MUST NOT contain a fragment
- MUST NOT contain a query string

When `localhost_callback_allowed` is `true` in the agent's metadata, the agent MAY use a localhost callback URL as the `callback` parameter to the interaction endpoint.

## Other URLs

The `jwks_uri`, `tos_uri`, `policy_uri`, `logo_uri`, and `logo_dark_uri` values MUST use the `https` scheme.

# Metadata Documents

Participants publish metadata at well-known URLs ([@!RFC8615]) to enable discovery.

## Agent Server Metadata

Published at `/.well-known/aauth-agent.json`:

```json
{
  "agent": "https://agent.example",
  "jwks_uri": "https://agent.example/.well-known/jwks.json",
  "client_name": "Example AI Assistant",
  "logo_uri": "https://agent.example/logo.png",
  "logo_dark_uri": "https://agent.example/logo-dark.png",
  "callback_endpoint": "https://agent.example/callback",
  "localhost_callback_allowed": true,
  "clarification_supported": true,
  "tos_uri": "https://agent.example/tos",
  "policy_uri": "https://agent.example/privacy"
}
```

Fields:

- `agent` (REQUIRED): The agent server's HTTPS URL (the `domain` in agent identifiers it issues)
- `jwks_uri` (REQUIRED): URL to the agent server's JSON Web Key Set
- `client_name` (OPTIONAL): Human-readable agent name (per [@RFC7591])
- `logo_uri` (OPTIONAL): URL to agent logo (per [@RFC7591])
- `logo_dark_uri` (OPTIONAL): URL to agent logo for dark backgrounds
- `callback_endpoint` (OPTIONAL): The agent's HTTPS callback endpoint URL
- `localhost_callback_allowed` (OPTIONAL): Boolean. Default: `false`.
- `clarification_supported` (OPTIONAL): Boolean. Default: `false`.
- `tos_uri` (OPTIONAL): URL to terms of service (per [@RFC7591])
- `policy_uri` (OPTIONAL): URL to privacy policy (per [@RFC7591])

## MM Metadata {#mm-metadata}

Published at `/.well-known/aauth-mission.json`:

```json
{
  "manager": "https://mm.example",
  "token_endpoint": "https://mm.example/token",
  "mission_endpoint": "https://mm.example/mission",
  "permission_endpoint": "https://mm.example/permission",
  "audit_endpoint": "https://mm.example/audit",
  "mission_control_endpoint": "https://mm.example/mission-control",
  "jwks_uri": "https://mm.example/.well-known/jwks.json"
}
```

Fields:

- `manager` (REQUIRED): The MM's HTTPS URL. MUST match the URL used to fetch the metadata document.
- `token_endpoint` (REQUIRED): URL where agents send token requests
- `mission_endpoint` (REQUIRED): URL for mission lifecycle operations (proposal, status)
- `permission_endpoint` (OPTIONAL): URL where agents request permission for actions not governed by a remote resource (#permission-endpoint)
- `audit_endpoint` (OPTIONAL): URL where agents log actions performed (#audit-endpoint)
- `mission_control_endpoint` (OPTIONAL): URL for mission administrative interface (#mission-control)
- `jwks_uri` (REQUIRED): URL to the MM's JSON Web Key Set

## Auth Server Metadata

Published at `/.well-known/aauth-issuer.json`:

```json
{
  "issuer": "https://as.resource.example",
  "token_endpoint": "https://as.resource.example/token",
  "jwks_uri": "https://as.resource.example/.well-known/jwks.json"
}
```

Fields:

- `issuer` (REQUIRED): The AS's HTTPS URL. MUST match the URL used to fetch the metadata document.
- `token_endpoint` (REQUIRED): URL where MMs send token requests
- `jwks_uri` (REQUIRED): URL to the AS's JSON Web Key Set

## Resource Metadata

Published at `/.well-known/aauth-resource.json`:

```json
{
  "resource": "https://resource.example",
  "jwks_uri": "https://resource.example/.well-known/jwks.json",
  "client_name": "Example Data Service",
  "logo_uri": "https://resource.example/logo.png",
  "logo_dark_uri": "https://resource.example/logo-dark.png",
  "authorization_endpoint": "https://resource.example/authorize",
  "scope_descriptions": {
    "data.read": "Read access to your data and documents",
    "data.write": "Create and update your data and documents",
    "data.delete": "Permanently delete your data and documents"
  },
  "additional_signature_components": ["content-type", "content-digest"]
}
```

Fields:

- `resource` (REQUIRED): The resource's HTTPS URL
- `jwks_uri` (REQUIRED): URL to the resource's JSON Web Key Set
- `client_name` (OPTIONAL): Human-readable resource name (per [@RFC7591])
- `logo_uri` (OPTIONAL): URL to resource logo (per [@RFC7591])
- `logo_dark_uri` (OPTIONAL): URL to resource logo for dark backgrounds
- `authorization_endpoint` (REQUIRED): URL where agents request authorization (#authorization-endpoint)
- `scope_descriptions` (OPTIONAL): Object mapping scope values to Markdown strings for consent display. Scope values are resource-specific; resources that already define OAuth scopes SHOULD use the same scope values in AAuth. Identity-related scopes (e.g., `openid`, `profile`, `email`) follow [@!OpenID.Core].
- `signature_window` (OPTIONAL): Integer. The signature validity window in seconds for the `created` timestamp. Default: 60. Resources serving agents with poor clock synchronization (mobile, IoT) MAY advertise a larger value. High-security resources MAY advertise a smaller value.
- `additional_signature_components` (OPTIONAL): Array of HTTP message component identifiers ([@!RFC9421]) that agents MUST include in the `Signature-Input` covered components when signing requests to this resource, in addition to the base components required by the HTTP Message Signatures profile ([@!I-D.hardt-httpbis-signature-key])

# Error Responses

## Authentication Errors

A `401` response from any AAuth endpoint uses the `Signature-Error` header as defined in ([@!I-D.hardt-httpbis-signature-key]).

## Token Endpoint Error Response Format {#error-response-format}

Token endpoint errors use `Content-Type: application/json` ([@!RFC8259]) with the following members:

- `error` (REQUIRED): String. A single error code.
- `error_description` (OPTIONAL): String. A human-readable description.

## Token Endpoint Error Codes

| Error | Status | Meaning |
|-------|--------|---------|
| `invalid_request` | 400 | Malformed JSON, missing required fields |
| `invalid_agent_token` | 400 | Agent token malformed or signature verification failed |
| `expired_agent_token` | 400 | Agent token has expired |
| `invalid_resource_token` | 400 | Resource token malformed or signature verification failed |
| `expired_resource_token` | 400 | Resource token has expired |
| `server_error` | 500 | Internal error |

## Polling Error Codes

| Error | Status | Meaning |
|-------|--------|---------|
| `denied` | 403 | User or approver explicitly denied the request |
| `abandoned` | 403 | Interaction code was used but user did not complete |
| `expired` | 408 | Timed out |
| `invalid_code` | 410 | Interaction code not recognized or already consumed |
| `slow_down` | 429 | Polling too frequently — increase interval by 5 seconds |
| `server_error` | 500 | Internal error |

# Incremental Adoption {#incremental-adoption}

A key property of AAuth is that adoption does not require coordination between parties. Each party — agent, resource, MM, AS — can independently add support. The system works at every partial adoption state, and full functionality emerges naturally as more parties adopt.

## Agent Adoption Path

Each step builds on the previous one. An agent that adopts any step gains immediate value, and resources that don't recognize the new capability simply ignore it.

1. **Sign requests with a pseudonymous key** (`scheme=jkt`): The agent signs requests with a bare key. Resources that recognize AAuth can track the agent by JWK Thumbprint, initiate interactive authorization, and bind the result to the key. Resources that don't recognize AAuth ignore the signature headers.
2. **Establish a verifiable identity** (`scheme=jwks_uri` or `scheme=jwt`): The agent's key is bound to a domain (via a published JWKS) or to a JWT signed by an issuer (e.g., a workload identity token, platform attestation, or any JWT with a `cnf` claim). Resources can verify the agent's identity and apply identity-based policy.
3. **Obtain an agent token** (`scheme=jwt`, `typ: aa-agent+jwt`): The agent has a full AAuth identity with a `local@domain` identifier issued by an agent server, providing a stable, managed identity lifecycle.
4. **Operate under a mission manager**: The agent sends the `AAuth-Mission` header, enabling missions, cross-domain federation, and centralized audit. When accessing a resource without mission support, the agent falls back to the resource request flow.

## Resource Adoption Path

Each step builds on the previous one. A resource that adopts any step works with agents at all identity levels.

1. **Recognize AAuth signatures**: The resource verifies HTTP Message Signatures and responds with `Signature-Requirement` headers (`pseudonym` or `identity` levels) as defined in the HTTP Signature Headers specification ([@!I-D.hardt-httpbis-signature-key]). Resources that don't recognize AAuth ignore the signature headers — existing auth mechanisms continue to work.
2. **Publish an authorization endpoint**: The resource publishes an `authorization_endpoint` in its metadata. Agents can request on-demand authorization via the resource request flow, including interactive authorization with user consent. The resource binds authorization to the agent's key identity at any agent identity level.
3. **Deploy an authorization server**: The resource has an AS for policy enforcement. When an agent with an MM sends the `AAuth-Mission` header, the resource issues a resource token and the full four-party protocol engages. Agents without an MM fall back to the resource request flow.

## Adoption Matrix

The resource's authorization endpoint and interaction flow work with any agent identity level. Missions require an agent token and an MM.

| Agent Step | Resource Step | What Works |
|------------|--------------|------------|
| Pseudonymous key | Recognizes signatures | Resource tracks agent by key thumbprint, may challenge for identity |
| Verifiable identity | Recognizes signatures | Resource verifies agent identity, applies policy |
| Any identity level | Authorization endpoint | Resource handles auth via resource request flow, binds to agent key |
| Agent token + MM | Authorization endpoint (no AS) | Resource request mode — resource handles auth directly |
| Agent token + MM | Mission-aware (AS) | Full four-party protocol: MM-AS federation, missions, auth tokens |

**No coordination required** — each party adds support independently, and the system naturally converges to the full protocol once all parties support it.

# Security Considerations

## Proof-of-Possession

All AAuth tokens are proof-of-possession tokens. The holder must prove possession of the private key corresponding to the public key in the token's `cnf` claim.

## Token Security

- Agent tokens bind agent keys to agent identity
- Resource tokens bind access requests to resource identity, preventing confused deputy attacks
- Auth tokens bind authorization grants to agent keys

## Pending URL Security

- Pending URLs MUST be unguessable and SHOULD have limited lifetime
- Pending URLs MUST be on the same origin as the server that issued them
- Servers MUST verify the agent's identity on every poll
- Once a terminal response is returned, the pending URL MUST return `404`

## Clarification Chat Security

- MMs MUST enforce a maximum number of clarification rounds
- Clarification responses from agents are untrusted input and MUST be sanitized before display

## Interaction Code Misdirection

An attacker could attempt to trick a user into approving an authorization request by directing them to an interaction URL with the attacker's code. The MM mitigates this by displaying the full request context — the agent's identity, the resource being accessed, and the requested scope — so the user can recognize requests they did not initiate. A stronger mitigation is for the MM to interact directly with the user via a pre-established channel (push notification, email, or existing session) using `requirement=approval`, which eliminates the possibility of misdirection through attacker-supplied links entirely.

## AS Discovery

The resource's AS is identified by the `aud` claim in the resource token. Federation mechanics are described in (#mm-as-federation).

## MM as High-Value Target

The MM is a centralized authority that sees every authorization in a mission. MM implementations MUST apply appropriate security controls including access control, audit logging, and monitoring. Compromise of an MM could affect all agents and missions it manages.

## Call Chaining Identity

When a resource acts as an agent in call chaining, it uses its own signing key and presents its own credentials. The resource MUST publish agent metadata so downstream parties can verify its identity.

## Token Revocation

This specification does not define a token revocation mechanism. Auth tokens are short-lived (max 1 hour), proof-of-possession (useless without the bound signing key), and re-authorization is asynchronous to resource access — the agent obtains new auth tokens in the background before existing ones expire. Organizations have multiple control points to terminate access without revoking individual tokens:

- **Agent server**: Refuse to issue or renew agent tokens, immediately preventing the agent from authenticating.
- **Mission manager**: Suspend or revoke the mission, causing all subsequent token requests for that mission to fail.
- **Authorization server**: Deny token requests on re-authorization, preventing new auth tokens from being issued.
- **Token lifetime**: Shorter auth token lifetimes reduce the window of exposure. Organizations can configure token lifetimes based on their risk tolerance.

These control points take effect at the next re-authorization cycle. For high-security environments, shorter token lifetimes reduce the gap between a control action and its enforcement.

## TLS Requirements

All HTTPS connections MUST use TLS 1.2 or later, following the recommendations in BCP 195 [@!RFC9325].

# Privacy Considerations

## Directed Identifiers

The MM provides a pairwise pseudonymous user identifier (`sub`) for each AS, preventing ASes from correlating users across trust domains. Each AS sees a different `sub` for the same user, preserving user privacy.

## MM Visibility

The MM sees every authorization request made by its agents — including the resource being accessed, the requested scope, and the mission context. This centralized visibility is inherent to the architecture and enables governance and audit, but it also means the MM is a sensitive data aggregation point. MM implementations MUST apply appropriate access controls and data retention policies.

## Mission Text Exposure

The mission text is visible to the MM and, when included in resource tokens and auth tokens via the `s256` hash, its integrity is verifiable by any party that holds it. The approved mission text itself is shared between the agent and MM. Resources and ASes see only the `s256` hash and the MM URL, not the full mission text.

# IANA Considerations

## HTTP Header Field Registration

This specification registers the following HTTP header field in the "Hypertext Transfer Protocol (HTTP) Field Name Registry" established by [@!RFC9110]:

- Header Field Name: `AAuth-Requirement`
- Status: permanent
- Structured Type: Dictionary
- Reference: This document, (#requirement-responses)

## Well-Known URI Registrations

This specification registers the following well-known URIs per [@!RFC8615]:

| URI Suffix | Change Controller | Reference |
|---|---|---|
| `aauth-agent.json` | IETF | This document, (#agent-server-metadata) |
| `aauth-mission.json` | IETF | This document, (#mm-metadata) |
| `aauth-issuer.json` | IETF | This document, (#auth-server-metadata) |
| `aauth-resource.json` | IETF | This document, (#resource-metadata) |

## Media Type Registrations

This specification registers the following media types:

### application/aa-agent+jwt

- Type name: application
- Subtype name: aa-agent+jwt
- Required parameters: N/A
- Optional parameters: N/A
- Encoding considerations: binary; a JWT is a sequence of Base64url-encoded parts separated by period characters
- Security considerations: See (#security-considerations)
- Interoperability considerations: N/A
- Published specification: This document, (#agent-tokens)
- Applications that use this media type: AAuth agents, MMs, and ASes
- Fragment identifier considerations: N/A

### application/aa-auth+jwt

- Type name: application
- Subtype name: aa-auth+jwt
- Required parameters: N/A
- Optional parameters: N/A
- Encoding considerations: binary; a JWT is a sequence of Base64url-encoded parts separated by period characters
- Security considerations: See (#security-considerations)
- Interoperability considerations: N/A
- Published specification: This document, (#auth-tokens)
- Applications that use this media type: AAuth ASes, agents, and resources
- Fragment identifier considerations: N/A

### application/aa-resource+jwt

- Type name: application
- Subtype name: aa-resource+jwt
- Required parameters: N/A
- Optional parameters: N/A
- Encoding considerations: binary; a JWT is a sequence of Base64url-encoded parts separated by period characters
- Security considerations: See (#security-considerations)
- Interoperability considerations: N/A
- Published specification: This document, (#resource-tokens)
- Applications that use this media type: AAuth resources and ASes
- Fragment identifier considerations: N/A

## JWT Type Registrations

This specification registers the following JWT `typ` header parameter values in the "JSON Web Token Types" sub-registry:

| Type Value | Reference |
|---|---|
| `aa-agent+jwt` | This document, (#agent-tokens) |
| `aa-auth+jwt` | This document, (#auth-tokens) |
| `aa-resource+jwt` | This document, (#resource-tokens) |

## JWT Claims Registrations

This specification registers the following claims in the IANA "JSON Web Token Claims" registry established by [@!RFC7519]:

| Claim Name | Claim Description | Change Controller | Reference |
|---|---|---|---|
| `dwk` | Discovery Well-Known document name | IETF | This document |
| `agent` | Agent identifier | IETF | This document |
| `agent_jkt` | JWK Thumbprint of the agent's signing key | IETF | This document |
| `mission` | Mission object (manager, s256) in resource tokens and auth tokens | IETF | This document |

## AAuth Requirement Value Registry

This specification establishes the AAuth Requirement Value Registry. The registry policy is Specification Required ([@!RFC8126]).

| Value | Reference |
|-------|-----------|
| `interaction` | This document |
| `approval` | This document |
| `auth-token` | This document |
| `clarification` | This document |
| `claims` | This document |

# Implementation Status

*Note: This section is to be removed before publishing as an RFC.*

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in [@RFC7942]. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.

No implementations of this version of the specification are known at the time of writing.

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-aauth-protocol-00
  - Initial submission

# Acknowledgments

The author would like to thank reviewers for their feedback on concepts and earlier drafts: Aaron Pareki, Christian Posta, Frederik Krogsdal Jacobsen, Jared Hanson, Karl McGuinness, Nate Barbettini, Wils Dawson.

{backmatter}

# Agent Token Acquisition Patterns {#agent-token-acquisition}

This appendix describes common patterns for how agents obtain agent tokens from their agent server. In all patterns, the agent generates an ephemeral signing key pair, proves its identity to the agent server, and receives an agent token binding the ephemeral key to an agent identifier. Each pattern differs in how the agent proves its identity and what trust assumption the agent server relies on.

## Server Workloads

1. The agent generates an ephemeral signing key pair (e.g., Ed25519).
2. The agent obtains a platform attestation from its runtime environment — such as a SPIFFE SVID from a SPIRE agent, a WIMSE workload identity token, or a cloud provider instance identity document (AWS IMDSv2, GCP metadata, Azure IMDS).
3. The agent presents the attestation and its ephemeral public key to the agent server.
4. The agent server verifies the attestation against the platform's trust root and issues an agent token with the ephemeral key in the `cnf` claim.

On managed infrastructure, the platform may additionally attest the software identity (container image hash, binary signature) alongside the workload identity, allowing the agent server to restrict tokens to known software.

**Trust assumption:** The agent server trusts the platform's attestation that the workload is what it claims to be.

## Mobile Applications

1. The app generates an ephemeral signing key pair, optionally backed by the device's secure enclave (iOS Secure Enclave, Android StrongBox).
2. The app obtains a platform attestation — iOS App Attest assertion or Android Play Integrity verdict — binding the app identity and the ephemeral public key.
3. The app sends the attestation and public key to the agent server.
4. The agent server verifies the attestation against Apple's or Google's attestation service and issues an agent token.

The platform attestation proves the app is a genuine installation from the app store, running on a real device, and has not been tampered with. If the key is hardware-backed, the attestation also proves the key cannot be exported.

**Trust assumption:** The agent server trusts the platform's attestation that the app is a genuine, untampered installation running on a real device.

## Desktop and CLI Applications

Desktop platforms generally do not provide application-level attestation comparable to mobile platforms. Several patterns are available depending on the deployment context:

### User Login

1. The agent opens a browser and redirects the user to the agent server's web interface.
2. The user authenticates at the agent server.
3. The agent generates an ephemeral signing key pair, stores the private key in a platform vault (macOS Keychain, Windows TPM, Linux Secret Service), and sends the public key to the agent server.
4. The agent server issues an agent token binding the ephemeral key to an agent identifier and returns it to the agent (e.g., via localhost callback).

This is the most common pattern for user-facing desktop and CLI tools.

The agent may also hold a stable key in hardware (TPM, secure enclave) or a platform keychain. During the initial user login flow, the agent server records the stable public key alongside the agent identity. When the agent token expires, the agent can renew it by sending its new ephemeral public key in a `scheme=jkt-jwt` request signed by the stable key, without requiring the user to log in again.

**Trust assumption:** The agent server trusts the user's authentication but cannot verify which software is running — only that the user authorized the agent. For renewal via stable key, the agent server trusts that the key registered at enrollment continues to represent the same agent.

### Managed Desktops

On managed desktops (e.g., corporate MDM-enrolled devices), the management platform may provide device and software attestation similar to server workloads. The agent presents the platform attestation alongside its ephemeral key, and the agent server verifies the device is managed and the software is approved.

**Trust assumption:** The agent server trusts the management platform's attestation that the device is managed and the software is approved.

### Self-Hosted Agent Metadata

A user publishes agent metadata and a JWKS at a domain they control (e.g., `username.github.io/.well-known/aauth-agent.json`) — no active server is required, only static files. The agent's public key is included in the published JWKS. The corresponding private key is held on the user's machine — potentially in a secure enclave or hardware token. Agents generate ephemeral signing keys and use `scheme=jwt` to obtain agent tokens signed by the private key. Auth servers verify agent tokens against the published JWKS.

**Trust assumption:** The trust anchor is the published JWKS and the private key held by the user. No server-side logic is involved — verification relies entirely on the static metadata and key material.

## Browser-Based Applications


1. The web server — which acts as the agent server — authenticates the user. The recommended mechanism is WebAuthn, which binds authentication to the device and origin, preventing scripts or headless browsers from impersonating the web page to obtain an agent token.
2. The web app generates an ephemeral signing key pair using the Web Crypto API (non-extractable if supported) and sends it to the web server.
3. The web server issues an agent token binding the web app's ephemeral public key to an agent identifier and returns it.

The key pair and agent token exist only for the lifetime of the browser session. The web server controls both the agent identity and the issuance.

**Trust assumption:** The web server is the agent server and controls the entire lifecycle. The agent token lifetime is tied to the browser session. When WebAuthn is used, authentication is bound to the device and origin rather than relying solely on session credentials.

# Detailed Flows {#detailed-flows}

This appendix provides complete end-to-end flows combining the key interactions defined in the Protocol Overview.

## Autonomous Agent

A machine-to-machine agent obtains authorization directly without user interaction.

### Resource Challenge

The resource challenges the agent with a `401` response containing a resource token:

~~~ ascii-art
Agent                       Resource                        MM
  |                            |                            |
  |  HTTPSig request           |                            |
  |  (AAuth-Mission)           |                            |
  |--------------------------->|                            |
  |                            |                            |
  |  401 + resource_token      |                            |
  |<---------------------------|                            |
  |                            |                            |
  |  POST token_endpoint with resource_token                |
  |-------------------------------------------------------->|
  |                            |                            |
  |                            |  [MM federates with AS,    |
  |                            |   obtains auth_token]      |
  |                            |                            |
  |  auth_token                                             |
  |<--------------------------------------------------------|
  |                            |                            |
  |  HTTPSig request           |                            |
  |  (with auth-token)         |                            |
  |--------------------------->|                            |
  |                            |                            |
  |                            |  verify auth_token         |
  |                            |                            |
  |  200 OK                    |                            |
  |<---------------------------|                            |
  |                            |                            |
~~~

### Proactive Token Request

When the agent knows the resource's requirements from metadata, it can request a resource token proactively via the `authorization_endpoint`:

~~~ ascii-art
Agent                       Resource                        MM
  |                            |                            |
  |  POST                      |                            |
  |  authorization_endpoint    |                            |
  |  (AAuth-Mission)           |                            |
  |--------------------------->|                            |
  |                            |                            |
  |  resource_token            |                            |
  |<---------------------------|                            |
  |                            |                            |
  |  POST token_endpoint with resource_token                |
  |-------------------------------------------------------->|
  |                            |                            |
  |                            |  [MM federates with AS,    |
  |                            |   obtains auth_token]      |
  |                            |                            |
  |  auth_token                                             |
  |<--------------------------------------------------------|
  |                            |                            |
  |  HTTPSig request           |                            |
  |  (with auth-token)         |                            |
  |--------------------------->|                            |
  |                            |                            |
  |                            |  verify auth_token         |
  |                            |                            |
  |  200 OK                    |                            |
  |<---------------------------|                            |
  |                            |                            |
~~~

**Use cases:** Machine-to-machine API calls, automated pipelines, cron jobs, service-to-service communication where no user is involved.

## User Authorization

Full flow with user-authorized access. The agent obtains a resource token from the resource's `authorization_endpoint`, then requests authorization from the MM.

~~~ ascii-art
User           Agent                Resource                   MM
  |              |                     |                      |
  |              |  POST               |                      |
  |              |  authorization_endpoint                   |
  |              |-------------------->|                      |
  |              |                     |                      |
  |              |  resource_token     |                      |
  |              |<--------------------|                      |
  |              |                     |                      |
  |              |  POST token_endpoint                       |
  |              |  resource_token, scope                     |
  |              |  Prefer: wait=45                           |
  |              |------------------------------------------->|
  |              |                     |                      |
  |              |  202 Accepted                              |
  |              |  Location: /pending/abc                    |
  |              |  AAuth-Requirement:                          |
  |              |    requirement=interaction;                    |
  |              |    code="ABCD1234"                         |
  |              |<-------------------------------------------|
  |              |                     |                      |
  |  direct to   |                     |                      |
  |  {url}?code={code}                |                      |
  |<-------------|                     |                      |
  |              |                     |                      |
  |  authenticate and consent                                 |
  |---------------------------------------------------------->|
  |              |                     |                      |
  |  redirect to callback_url                                 |
  |<----------------------------------------------------------|
  |              |                     |                      |
  |  callback    |                     |                      |
  |------------->|                     |                      |
  |              |                     |                      |
  |              |  GET /pending/abc   |                      |
  |              |------------------------------------------->|
  |              |  200 OK, auth_token |                      |
  |              |<-------------------------------------------|
  |              |                     |                      |
  |              |  HTTPSig request    |                      |
  |              |  (with auth-token)  |                      |
  |              |-------------------->|                      |
  |              |                     |                      |
  |              |  200 OK             |                      |
  |              |<--------------------|                      |
  |              |                     |                      |
~~~

## Direct Approval

The MM obtains approval directly — from a user (e.g., push notification, existing session, email) — without the agent facilitating a redirect.

~~~ ascii-art
Agent               Resource                MM               User
  |                    |                   |                    |
  |  POST              |                   |                    |
  |  authorization_endpoint               |                    |
  |------------------->|                   |                    |
  |                    |                   |                    |
  |  resource_token    |                   |                    |
  |<-------------------|                   |                    |
  |                    |                   |                    |
  |  POST token_endpoint                   |                    |
  |  resource_token, scope                 |                    |
  |  Prefer: wait=45                       |                    |
  |--------------------------------------->|                    |
  |                    |                   |                    |
  |  202 Accepted                          |                    |
  |  Location: /pending/jkl                |                    |
  |  AAuth-Requirement: requirement=approval     |                    |
  |<---------------------------------------|                    |
  |                    |                   |                    |
  |                    |                   |  push / email /    |
  |                    |                   |  existing session  |
  |                    |                   |------------------->|
  |                    |                   |                    |
  |                    |                   |  approve           |
  |                    |                   |<-------------------|
  |                    |                   |                    |
  |  GET /pending/jkl  |                   |                    |
  |  Prefer: wait=45   |                   |                    |
  |--------------------------------------->|                    |
  |                    |                   |                    |
  |  200 OK, auth_token                    |                    |
  |<---------------------------------------|                    |
  |                    |                   |                    |
  |  HTTPSig request   |                   |                    |
  |  (with auth-token) |                   |                    |
  |------------------->|                   |                    |
  |                    |                   |                    |
  |  200 OK            |                   |                    |
  |<-------------------|                   |                    |
  |                    |                   |                    |
~~~

## Call Chaining

See (#call-chaining) for normative requirements. R1 acts as an agent, sending the downstream resource token plus its own agent token and the upstream auth token to the MM:

~~~ ascii-art
Agent          Resource 1        Resource 2           MM
  |                |                 |                  |
  |  HTTPSig req   |                 |                  |
  |  (auth_token)  |                 |                  |
  |--------------->|                 |                  |
  |                |                 |                  |
  |                |  verify         |                  |
  |                |  auth_token     |                  |
  |                |                 |                  |
  |                |  HTTPSig req    |                  |
  |                |  (as agent)     |                  |
  |                |  (AAuth-Mission)|                  |
  |                |---------------->|                  |
  |                |                 |                  |
  |                |  401 + resource_token              |
  |                |<----------------|                  |
  |                |                 |                  |
  |                |  POST token_endpoint               |
  |                |  resource_token from R2            |
  |                |  upstream_token                    |
  |                |  agent_token (R1's)                |
  |                |----------------------------------->|
  |                |                 |                  |
  |                |                 |  [MM federates   |
  |                |                 |   with R2's AS,  |
  |                |                 |   verifies chain]|
  |                |                 |                  |
  |                |  auth_token for R2                 |
  |                |<-----------------------------------|
  |                |                 |                  |
  |                |  HTTPSig req    |                  |
  |                |  (auth_token)   |                  |
  |                |---------------->|                  |
  |                |                 |                  |
  |                |  200 OK         |                  |
  |                |<----------------|                  |
  |                |                 |                  |
  |  200 OK        |                 |                  |
  |<---------------|                 |                  |
  |                |                 |                  |
~~~

### Interaction Chaining

See (#interaction-chaining) for normative requirements.

~~~ ascii-art
User         Agent          Resource 1        Resource 2       MM
  |            |                 |                 |             |
  |            |  HTTPSig req    |                 |             |
  |            |---------------->|                 |             |
  |            |                 |                 |             |
  |            |                 |  HTTPSig req    |             |
  |            |                 |  (as agent)     |             |
  |            |                 |  (AAuth-Mission)|             |
  |            |                 |---------------->|             |
  |            |                 |                 |             |
  |            |                 |  401 + resource_token         |
  |            |                 |<----------------|             |
  |            |                 |                 |             |
  |            |                 |  POST token_endpoint          |
  |            |                 |  resource_token,              |
  |            |                 |  upstream_token,              |
  |            |                 |  agent_token (R1's)           |
  |            |                 |------------------------------>|
  |            |                 |                 |             |
  |            |                 |  202 Accepted                 |
  |            |                 |  requirement=interaction;         |
  |            |                 |  code=WXYZ                    |
  |            |                 |<------------------------------|
  |            |                 |                 |             |
  |            |  202 Accepted   |                 |             |
  |            |  Location: /pending/xyz           |             |
  |            |  AAuth-Requirement:                 |             |
  |            |    requirement=interaction;           |             |
  |            |    code="MNOP"  |                 |             |
  |            |<----------------|                 |             |
  |            |                 |                 |             |
  |  direct to R1                |                 |             |
  |  {url}?code={code}          |                 |             |
  |<-----------|                 |                 |             |
  |            |                 |                 |             |
  |  {url}?code={code}          |                 |             |
  |----------------------------->|                 |             |
  |            |                 |                 |             |
  |  redirect to MM {url}       |                 |             |
  |<-----------------------------|                 |             |
  |            |                 |                 |             |
  |  authenticate and consent    |                 |             |
  |------------------------------------------------------------->|
  |            |                 |                 |             |
  |  redirect to R1 callback     |                 |             |
  |<-------------------------------------------------------------|
  |            |                 |                 |             |
  |            |            [R1 polls MM pending URL,            |
  |            |             receives auth_token for R2]         |
  |            |                 |                 |             |
  |            |                 |  HTTPSig req    |             |
  |            |                 |  (auth_token)   |             |
  |            |                 |---------------->|             |
  |            |                 |                 |             |
  |            |                 |  200 OK         |             |
  |            |                 |<----------------|             |
  |            |                 |                 |             |
  |  redirect to agent callback_url                |             |
  |<-----------------------------|                 |             |
  |            |                 |                 |             |
  |  callback  |                 |                 |             |
  |----------->|                 |                 |             |
  |            |                 |                 |             |
  |            |  GET /pending/xyz                 |             |
  |            |---------------->|                 |             |
  |            |                 |                 |             |
  |            |  200 OK         |                 |             |
  |            |<----------------|                 |             |
  |            |                 |                 |             |
~~~

# Design Rationale

## Why Standard HTTP Async Pattern

AAuth uses standard HTTP async semantics (`202 Accepted`, `Location`, `Prefer: wait`, `Retry-After`). This applies uniformly to all endpoints, aligns with RFC 7240, replaces OAuth device flow, supports headless agents, and enables clarification chat.

## Why No Authorization Code

AAuth eliminates authorization codes entirely. OAuth authorization codes require PKCE ([@RFC7636]) to prevent interception attacks, adding complexity for both clients and servers. AAuth avoids the problem: the user redirect carries only the callback URL, which has no security value to an attacker. The auth token is delivered exclusively via polling, authenticated by the agent's HTTP Message Signature.

## Why Every Agent Has a Legal Person

AAuth requires every agent to be associated with a legal person — a user or an organization. There are no truly autonomous agents. The MM maintains this association. This ensures there is always an accountable party for an agent's actions, which is essential for authorization decisions, audit, and liability.

## Why HTTPS-Based Agent Identity

HTTPS URLs as agent identifiers enable dynamic ecosystems without pre-registration.

## Why No Refresh Token

AAuth has no refresh tokens. When an auth token expires, the agent obtains a fresh resource token and submits it through the standard authorization flow. This gives the resource a voice in every re-authorization — the resource can adjust scope, require step-up authorization, or deny access based on current policy. A separate refresh token would bypass the resource entirely, and is unnecessary given that the standard flow is a single additional request.

## Why JSON Instead of Form-Encoded

JSON is the standard format for modern APIs. AAuth uses JSON for both request and response bodies.

## Why Callback URL Has No Security Role

Tokens never pass through the user's browser. The callback URL is purely a UX optimization.

## Why Reuse OpenID Connect Vocabulary

AAuth reuses OpenID Connect scope values, identity claims, and enterprise parameters. This lowers the adoption barrier.

## Why Not mTLS?

Mutual TLS (mTLS) authenticates the TLS connection, not individual HTTP requests. Different paths on the same resource may have different requirements — some paths may require no signature, others pseudonymous access, others verified identity, and others an auth token. Per-request signatures allow resources to vary requirements by path. Additionally, mTLS requires PKI infrastructure (CA, certificate provisioning, revocation), cannot express progressive requirements, and is stripped by TLS-terminating proxies and CDNs. mTLS remains the right choice for infrastructure-level mutual authentication (e.g., service mesh). AAuth addresses application-level identity where progressive requirements and intermediary compatibility are needed.

## Why Not DPoP?

DPoP ([@RFC9449]) binds an existing OAuth access token to a key, preventing token theft. AAuth differs in that agents can establish identity from zero — no pre-existing token, no pre-registration. At the `pseudonym` and `identity` signature requirement levels ([@!I-D.hardt-httpbis-signature-key]), AAuth requires no tokens at all, only a signed request. DPoP has a single mode (prove you hold the key bound to this token), while AAuth supports progressive requirements from pseudonymous access through verified identity to authorized access with interactive consent. DPoP is the right choice for adding proof-of-possession to existing OAuth deployments.

## Why Not Extend GNAP

GNAP ([@RFC9635]) shares several motivations with AAuth — proof-of-possession by default, client identity without pre-registration, and async authorization. A natural question is whether AAuth's capabilities could be achieved as GNAP extensions rather than a new protocol. There are several reasons they cannot.

**Resource tokens require an architectural change, not an extension.** In GNAP, as in OAuth, the resource server is a passive consumer of tokens — it verifies them but never produces signed artifacts that the authorization server consumes. AAuth's resource tokens invert this: the resource cryptographically asserts what is being requested, binding its own identity, the agent's key thumbprint, and the requested scope into a signed JWT. Adding this to GNAP would require changing its core architectural assumption about the role of the resource server.

**Interaction chaining requires a different continuation model.** GNAP's continuation mechanism operates between a single client and a single authorization server. When a resource needs to access a downstream resource that requires user consent, GNAP has no mechanism for that consent requirement to propagate back through the call chain to the original user. Supporting this would require rethinking GNAP's continuation model to support multi-party propagation through intermediaries.

**The federation model is fundamentally different.** In GNAP, the client must discover and interact with each authorization server directly. AAuth's model — where the agent only ever talks to its MM, and the MM federates with resource ASes — is a different trust topology, not a configuration option. Retrofitting this into GNAP would produce a profile so constrained that it would be a distinct protocol in practice.

**GNAP's generality is a liability for this use case.** GNAP is designed to be maximally flexible — interaction modes, key proofing methods, token formats, and access structures are all pluggable. This means implementers must make dozens of profiling decisions before arriving at an interoperable system. AAuth makes these decisions prescriptively: one token format (JWT), one key proofing method (HTTP Message Signatures), one interaction pattern (interaction codes with polling), and one identity model (`local@domain` with HTTPS metadata). For the agent-to-resource ecosystem, this prescriptiveness is a feature — it enables interoperability without bilateral agreements.

In summary, AAuth's core innovations — resource-signed challenges, interaction chaining through multi-hop calls, MM-to-AS federation, mission-scoped authorization, and clarification chat during consent — are architectural choices that would require changing GNAP's foundations rather than extending them. The result would be a heavily constrained GNAP profile that shares little with other GNAP deployments.

## Why Not Extend WWW-Authenticate?

`WWW-Authenticate` ([@!RFC9110], Section 11.6.1) tells the client which authentication scheme to use. Its challenge model is "present credentials" — it cannot express progressive requirements, authorization, or deferred approval, and it cannot appear in a `202 Accepted` response.

`AAuth-Requirement` and `Signature-Requirement` coexist with `WWW-Authenticate`. A `401` response MAY include multiple headers, and the client uses whichever it understands:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api"
Signature-Requirement: requirement=identity
```

A `402` response MAY include `WWW-Authenticate` for payment (e.g., the Payment scheme defined by the Micropayment Protocol ([@!I-D.ryan-httpauth-payment])) alongside `Signature-Requirement` for authentication or `AAuth-Requirement` for authorization:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLq", method="example",
    request="eyJhbW91bnQiOiIxMDAw..."
Signature-Requirement: requirement=pseudonym
```

## Why a Separate Mission Manager

The MM is distinct from the AS because they serve different parties with different concerns. The MM represents the agent and its user — it handles consent, identity, mission governance, and audit. The AS represents the resource — it evaluates policy and issues tokens. Combining these into a single entity would conflate the interests of the requesting party with the interests of the resource owner, which is the same conflation that makes OAuth insufficient for cross-domain agent ecosystems.
