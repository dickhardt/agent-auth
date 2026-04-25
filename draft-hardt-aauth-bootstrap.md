%%%
title = "AAuth Bootstrap"
abbrev = "AAuth-Bootstrap"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["agent", "authorization", "bootstrap", "http", "identity"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-aauth-bootstrap-latest"
stream = "IETF"

date = 2026-04-18T00:00:00Z

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

<reference anchor="I-D.hardt-httpbis-signature-key" target="https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key">
  <front>
    <title>HTTP Signature Keys</title>
    <author initials="D." surname="Hardt" fullname="Dick Hardt">
      <organization>Hellō</organization>
    </author>
    <date year="2026"/>
  </front>
</reference>

<reference anchor="OpenID.EnterpriseExtensions" target="https://openid.net/specs/openid-connect-enterprise-extensions-1_0.html">
  <front>
    <title>OpenID Connect Enterprise Extensions</title>
    <author>
      <organization>OpenID Foundation</organization>
    </author>
    <date year="2024"/>
  </front>
</reference>

<reference anchor="WebAuthn" target="https://www.w3.org/TR/webauthn-3/">
  <front>
    <title>Web Authentication: An API for accessing Public Key Credentials - Level 3</title>
    <author>
      <organization>W3C</organization>
    </author>
    <date year="2024"/>
  </front>
</reference>


.# Abstract

This document defines AAuth Bootstrap, an extension to the AAuth Protocol ([@!I-D.hardt-aauth-protocol]) that specifies how a SaaS browser agent, SaaS mobile agent, or B2B SaaS agent establishes its initial agent identity (`aauth:local@domain`) and agent token through a ceremony mediated by the user's Person Server (PS). Bootstrap establishes the binding between a user (as vouched for by the user's PS) and an agent identity minted by the vendor-operated agent server. Identity claims and scoped authorization are obtained separately through the standard three-party flow defined in AAuth Protocol. This specification defines the `bootstrap_token`, the `/bootstrap` endpoints on the PS and agent server, the signature schemes used at each step, and renewal flows that bypass the PS after the initial binding is established.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

This document is part of the AAuth specification family. Source for this draft and an issue tracker can be found at https://github.com/dickhardt/AAuth.

{mainmatter}

# Introduction

**Status: Exploratory Draft**

The AAuth Protocol ([@!I-D.hardt-aauth-protocol]) defines agent identities of the form `aauth:local@domain`, each bound to a signing key and published under a well-known JWKS. For self-hosted agents, server workloads, and developer tools, an agent identity can be established from durable local material at deployment time. These cases do not need bootstrap.

For SaaS browser agents, SaaS mobile agents, and B2B SaaS agents, the agent identity depends on which user opens the application. The identity cannot be pre-minted at build time because it is tied to a specific user, and the user's identity is vouched for by the user's PS rather than by the vendor. Bootstrap is the ceremony by which the user's PS conveys a directed user identifier to the vendor's agent server so that the agent server can mint an `aauth:local@domain` identity bound to that user.

Bootstrap is intentionally limited to establishing the identity binding. It does not carry `scope`, does not request identity claims, and does not issue a `resource_token`. Identity claims (email, profile, organizational membership, and so on) are obtained separately by the agent server running the standard three-party flow defined in AAuth Protocol. This separation keeps bootstrap focused on the binding, reuses existing protocol machinery for claims release, and lets the agent request claims incrementally rather than up front.

This document specifies that ceremony. It defines:

- The `bootstrap_token`, a short-lived JWT issued by the PS and consumed by the agent server.
- The `/bootstrap` endpoints on the PS and the agent server.
- Which signature schemes from [@!I-D.hardt-httpbis-signature-key] are used at each step.
- Renewal flows on the agent server that do not require re-involving the PS.
- B2B extensions that let the PS select an organizational identity when the user has more than one.

## In Scope

- SaaS browser agents (vendor-operated agent server).
- SaaS mobile agents (vendor-operated agent server).
- B2B SaaS agents (organization's PS, vendor's agent server).

## Out of Scope

- Self-hosted agents (including developer AI agents). These self-issue agent tokens from durable local keys published in their own JWKS.
- Command-line tools. Agent identity is established by deployment tooling that registers a public key with a JWKS-hosting endpoint.
- Server workloads and headless services. These use platform attestation mechanisms such as SPIFFE, WIMSE, or cloud instance identity.
- Organizational agents operating within a pre-established PS-AS trust relationship with administrative enrollment.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

## Terms Reused From AAuth Protocol

The following terms are defined in [@!I-D.hardt-aauth-protocol] and are used in this document with the same meaning. Summaries are provided for convenience; the referenced specification is authoritative.

- **Person**: The user or organization on whose behalf an agent acts. Referred to in this document as "the user".
- **Agent**: An HTTP client acting on behalf of a person, identified by an `aauth:local@domain` URI.
- **Agent Server**: A server that manages agent identity and issues agent tokens. In the context of this document, the agent server is operated by the vendor whose software the user is running.
- **Person Server (PS)**: A server that represents the person to the rest of the protocol. In the context of this document, the PS vouches for the user to the agent server during bootstrap.
- **Resource**: A server that protects access to its APIs. Not directly involved in bootstrap.
- **Agent Token**: A JWT issued by an agent server to establish the agent's identity.
- **Resource Token**: A JWT issued by a resource (or, in bootstrap, by the agent server acting as resource) describing the access an agent needs.
- **Auth Token**: A JWT issued by a PS or AS granting an agent access to a resource.
- **Interaction**: User authentication or consent at an interaction endpoint, triggered when a server returns `202 Accepted` with `requirement=interaction`.

## Terms Reused From HTTP Signature Keys

The following signature schemes are defined in [@!I-D.hardt-httpbis-signature-key] and used in this document without modification:

- **`hwk` scheme**: Conveys a public key inline in the `Signature-Key` header.
- **`jkt-jwt` scheme**: Chains a JWT signed by one key (e.g., a durable enclave key) to authorize a second key (e.g., an ephemeral HTTP signing key).
- **`jwt` scheme**: Conveys a JWT (e.g., an agent token) that names the signing key.

## Terms Defined in This Document

- **Bootstrap**: The PS-mediated ceremony defined in this document by which a SaaS or B2B agent obtains its initial agent token. Distinct from the developer-side ceremonies used by self-hosted agents and from platform attestation enrollment.
- **Ephemeral Key**: An HTTP signing key generated by the agent whose lifetime is bounded by the agent token. Typically hours to a day, not per-request.
- **Durable Key**: A platform-protected key whose lifetime is bounded by the application install. Typically months to years. On mobile, this is an enclave-protected key identified by a JWK thumbprint (`urn:jkt`).
- **bootstrap_token**: A short-lived JWT issued by the PS, directed at an agent server, and bound to an agent's ephemeral key via a `cnf` claim. Defined in (#bootstrap-token-issuance).
- **Binding**: The one-to-one association `(ps_url, user_sub) -> aauth:local@<agent-server-domain>` recorded by the agent server at the end of bootstrap, together with the device credentials associated with it.
- **Device Credential**: A credential held by the agent server and associated with a binding, used to authenticate renewal requests without re-involving the PS. A WebAuthn credential ID on browsers or an enclave-key thumbprint (`urn:jkt:sha-256:<thumbprint>`) on mobile.

# Parties and Topology

The bootstrap ceremony involves three parties:

- The **agent**, which generates key material and initiates the ceremony.
- The **PS**, which authenticates the user, collects consent, issues the `bootstrap_token`, and records the `aauth:local@domain` identifier of each agent the user bootstraps.
- The **agent server**, which verifies the `bootstrap_token`, performs attestation, records the `(user, agent)` binding, and issues the agent token.

Resources and access servers (AS) are not involved in bootstrap. After bootstrap, the agent interacts with them using the tokens returned by the agent server following the flows defined in [@!I-D.hardt-aauth-protocol].

# Bootstrap Overview {#bootstrap-overview}

The following sequence shows the bootstrap ceremony end to end. Attestation and renewal sub-flows are shown separately for clarity.

~~~ ascii-art
Agent                              PS              Agent Server
  |                                 |                    |
  | HTTPSig (hwk, ephemeral)        |                    |
  | POST bootstrap_endpoint (PS)    |                    |
  | { agent_server }                |                    |
  |-------------------------------->|                    |
  |                                 |                    |
  | 202 Accepted                    |                    |
  | Location: /bootstrap/pending/X  |                    |
  |<--------------------------------|                    |
  |                                 |                    |
  | [user interaction and consent]  |                    |
  |                                 |                    |
  | GET pending URL                 |                    |
  |-------------------------------->|                    |
  |                                 |                    |
  | bootstrap_token                 |                    |
  |<--------------------------------|                    |
  |                                 |                    |
  | [attestation ceremony -- see (#attestation)]         |
  |                                 |                    |
  | HTTPSig (hwk or jkt-jwt)        |                    |
  | POST bootstrap_endpoint         |                    |
  | { bootstrap_token,              |                    |
  |   <attestation> }               |                    |
  |----------------------------------------------------->|
  |                                 |                    |
  | { agent_token }                 |                    |
  |<-----------------------------------------------------|
  |                                 |                    |
  | HTTPSig (jwt, agent_token)      |                    |
  | POST bootstrap_endpoint (PS)    |                    |
  | (empty body)                    |                    |
  |-------------------------------->|                    |
  |                                 |                    |
  | 204 No Content                  |                    |
  |<--------------------------------|                    |
~~~
Figure: Bootstrap Ceremony {#fig-bootstrap}

At this point the PS has bound the user to the agent identifier and the agent holds an `agent_token`.

The subsequent renewal flow skips the PS and uses the device credential recorded at bootstrap:

~~~ ascii-art
Agent                                          Agent Server
  |                                                  |
  | [renewal attestation -- see (#attestation)]      |
  |                                                  |
  | HTTPSig (hwk or jkt-jwt, new ephemeral)          |
  | POST refresh_endpoint                            |
  | { <attestation> }                                |
  |------------------------------------------------->|
  |                                                  |
  | { agent_token } (new ephemeral)                  |
  |<-------------------------------------------------|
~~~
Figure: Renewal Ceremony {#fig-renewal}

# Agent Server Metadata Extensions {#agent-server-metadata}

This specification extends the `/.well-known/aauth-agent.json` document defined in [@!I-D.hardt-aauth-protocol] with the following fields:

Fields:

- **`bootstrap_endpoint`** (REQUIRED for agent servers that support this specification). The URL where the agent POSTs the `bootstrap_token` and attestation result per (#request-to-agent-server-bootstrap). MUST be an HTTPS URL within the agent server's origin.
- **`refresh_endpoint`** (REQUIRED for agent servers that support this specification). The URL where the agent POSTs renewal requests per (#renewal). MUST be an HTTPS URL within the agent server's origin.
- **`webauthn_endpoint`** (REQUIRED for agent servers that support browser-based clients). The URL from which the agent fetches a WebAuthn challenge and, for registration, WebAuthn ceremony options. Defined in (#webauthn-endpoint). MUST be an HTTPS URL within the agent server's origin.

Agents MUST NOT assume a fixed path for these endpoints; the agent MUST discover them from agent-server metadata. Agents MUST verify that all endpoint URLs share the origin of the `issuer` field.

Example aauth-agent.json file:
```json
{
  "issuer": "https://agent-server.example",
  "jwks_uri": "https://agent-server.example/.well-known/jwks.json",
  "client_name": "Example AI Assistant",
  "logo_uri": "https://agent-server.example/logo.png",
  "bootstrap_endpoint": "https://agent-server.example/bootstrap",
  "refresh_endpoint": "https://agent-server.example/refresh",
  "webauthn_endpoint": "https://agent-server.example/webauthn"
}
```


# WebAuthn Endpoint {#webauthn-endpoint}

The `webauthn_endpoint` issues WebAuthn challenges for both bootstrap (registration) and refresh (assertion). It is used by browser-based clients. The endpoint takes no user context on the request; the server tracks each challenge as an opaque single-use nonce and binds it to the user only when the ceremony result is submitted.

## Request

The agent issues a GET request with the ceremony type as a query parameter:

```
GET /webauthn?type=create HTTP/1.1
Host: agent-server.example
```

or

```
GET /webauthn?type=get HTTP/1.1
Host: agent-server.example
```

Query parameters:

- **`type`** (REQUIRED). Either `create` (for bootstrap registration) or `get` (for refresh assertion).

The request is unsigned. The agent MUST NOT include user identifiers on the challenge request.

## Response

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "challenge": "<base64url random bytes>",
  "creation_options": {
    "rp": { "id": "agent-server.example", "name": "Example AI Assistant" },
    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }, ...],
    "authenticatorSelection": { ... },
    "attestation": "none"
  }
}
```

Response members:

- **`challenge`** (REQUIRED). Server-generated random value of at least 16 bytes, base64url-encoded without padding. The agent server MUST store the challenge in a single-use, time-limited registry. The challenge SHOULD expire within 5 minutes.
- **`creation_options`** (REQUIRED when `type=create`). The non-user portions of a WebAuthn `PublicKeyCredentialCreationOptions` object ([@WebAuthn]): `rp`, `pubKeyCredParams`, `authenticatorSelection`, `attestation`, `timeout`, and related server-decided fields. The agent fills in the `challenge` field from this response and fills in the `user` field from the `bootstrap_token` (using `bootstrap_token.sub` as `user.id`). MUST be absent when `type=get`.

The response MUST NOT include user-identifying information. The agent server MUST NOT bind the challenge to a particular user in its issuing state; user context enters only when the ceremony result is submitted.

# Bootstrap Flow {#bootstrap-flow}

The bootstrap flow consists of the following steps.

## Key Generation

The agent generates an ephemeral signing key.

On mobile platforms, the agent also has (or generates on first install) a durable enclave-protected key with a stable JWK thumbprint of the form `urn:jkt:sha-256:<thumbprint>`.

On browsers and command-line environments, only the ephemeral key exists.

## Request to PS /bootstrap {#request-to-ps-bootstrap}

The agent sends an HTTP request to the PS's `/bootstrap` endpoint signed under the `hwk` scheme ([@!I-D.hardt-httpbis-signature-key]) using the ephemeral key:

```
POST /bootstrap HTTP/1.1
Host: ps.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<ephemeral-pubkey>"
Content-Type: application/json

{
  "agent_server": "https://agent-server.example"
}
```

The request body is a JSON object with the following members:

- **`agent_server`** (REQUIRED). The HTTPS URL identifying the agent server that will mint the agent identity. This value is placed in the `aud` claim of the issued `bootstrap_token`. This document uses the parameter name `agent_server` to align with the `"Agent Server"` terminology of [@!I-D.hardt-aauth-protocol]; implementations MUST NOT use alternative names such as `audience` or `client_id` for this field.
- **`domain_hint`** (OPTIONAL). Identifies which of the user's identities at this PS should be used when the user has more than one (for example a personal identity and a work identity). The value is a DNS domain, as defined in [@OpenID.EnterpriseExtensions]. When present, the PS SHOULD select the identity associated with the given domain without prompting the user to choose. When absent and more than one identity is available, the PS MAY prompt the user to choose.
- **`login_hint`** (OPTIONAL). A hint as defined in [@OpenID.EnterpriseExtensions] identifying the user (for example an email address) to help the PS select the appropriate identity.
- **`tenant`** (OPTIONAL). Organizational tenant identifier from [@OpenID.EnterpriseExtensions]. See (#b2b-extensions).

Additional parameters from [@OpenID.EnterpriseExtensions] MAY be included to select an organizational identity context.

## Interaction Response

The PS responds with an interaction requirement:

```
HTTP/1.1 202 Accepted
AAuth-Requirement: requirement=interaction
Location: /bootstrap/pending/<id>
```

The agent directs the user to the interaction URL. The PS authenticates the user and presents a consent screen asking the user to allow the agent server to establish an account bound to the user's identity at this PS. No identity claims are released at this step; claims flow through the standard AAuth three-party flow after bootstrap completes.

The consent screen SHOULD display the agent server's domain, name, and logo as retrieved from the agent server's `/.well-known/aauth-agent.json` metadata document. The user approves or denies the request.

The agent polls the pending URL indicated by `Location` until the interaction completes.

## bootstrap_token Issuance {#bootstrap-token-issuance}

On successful user approval, the PS returns a `bootstrap_token` from the pending URL.

The `bootstrap_token` is a signed JWT with the following structure.

### bootstrap_token Header

- **`alg`**: The signature algorithm, for example `EdDSA`.
- **`typ`**: `aa-bootstrap+jwt`.
- **`kid`**: Key identifier for the PS key used to sign the token.

### bootstrap_token Payload

- **`iss`** (REQUIRED). The PS URL.
- **`dwk`** (REQUIRED). The PS's well-known document name, typically `aauth-person.json`.
- **`aud`** (REQUIRED). The agent server URL (matches `agent_server` from the request).
- **`sub`** (REQUIRED). A pairwise user identifier, directed at `aud`, identifying the user to the agent server.
- **`cnf`** (REQUIRED). An object containing `jwk`, the agent's ephemeral public key. MUST match the `hwk` key used to sign the PS /bootstrap request.
- **`jti`** (REQUIRED). A unique token identifier.
- **`iat`** (REQUIRED). Issued-at time.
- **`exp`** (REQUIRED). Expiration time. SHOULD NOT exceed 5 minutes after `iat`.

The `bootstrap_token` does not carry `scope`, `agent`, or any claim describing user attributes. Its sole purpose is to convey a directed user identifier (`sub`) bound to an agent-side ephemeral key (`cnf`). Identity claims are obtained separately via the AAuth Protocol three-party flow after bootstrap.

The `bootstrap_token` differs from a resource token defined in [@!I-D.hardt-aauth-protocol]:

- It omits the `agent` claim, because the agent identity does not yet exist at bootstrap time. The binding to the agent is carried solely by `cnf`.
- It is directed at an agent server (not an AS or a PS as recipient of a resource token).

## Request to Agent Server /bootstrap {#request-to-agent-server-bootstrap}

Before calling `bootstrap_endpoint`, the agent performs the attestation ceremony appropriate to its platform. See (#attestation) for the ceremony details and for the logic by which the platform is chosen. The attestation result is carried in the POST body.

The agent sends a single POST to `bootstrap_endpoint`:

```
POST /bootstrap HTTP/1.1
Host: agent-server.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=<scheme>
Content-Type: application/json

{
  "bootstrap_token": "<jwt>",
  "attestation": {
    "type": "<attestation type>",
    ...
  }
}
```

The HTTP Message Signature scheme is determined by the platform:

- **Browser clients** use `hwk` with the agent's ephemeral key.
- **Mobile clients** use `jkt-jwt` ([@!I-D.hardt-httpbis-signature-key]), where the JWT header references the enclave key and the JWT payload's `cnf.jwk` is the ephemeral public key. The ephemeral key signs the HTTP message.

Request body members:

- **`bootstrap_token`** (REQUIRED). The JWT received from the PS.
- **`attestation`** (REQUIRED). The attestation result, whose shape is defined by the ceremony described in (#attestation). The `type` field identifies the ceremony (e.g., `webauthn`, `app-attest`, `play-integrity`) and MUST match the scheme implied by the HTTP signature.

On receiving the request, the agent server MUST:

1. Verify the HTTP Message Signature as defined in [@!I-D.hardt-httpbis-signature-key].
2. Resolve and validate the `bootstrap_token` signature by fetching the PS's JWKS using `iss` and `dwk`.
3. Verify that `bootstrap_token.aud` equals the agent server's own URL.
4. Verify that `bootstrap_token.cnf.jwk` matches the ephemeral public key used to sign the HTTP request.
5. Verify `iat`, `exp`, and `jti` per standard JWT rules; reject replays by `jti`.
6. Verify the `attestation` per the rules of the indicated ceremony in (#attestation), including that any ceremony challenge or nonce matches one issued by the agent server and has not expired or been consumed. Mark the ceremony challenge as consumed.
7. Create or look up the binding (#binding-creation).
8. Store the device credential derived from the attestation (a WebAuthn credential ID for browsers, or the enclave key thumbprint for mobile) on the binding.
9. Issue the agent token (#token-response).

If `bootstrap_token` verification fails, the agent server MUST respond `400 Bad Request`. If attestation verification fails, the agent server MUST respond `401 Unauthorized`.

## Binding Creation {#binding-creation}

The agent server looks up or creates a binding keyed by `(bootstrap_token.iss, bootstrap_token.sub)`:

```
(ps_url, user_sub) -> aauth:local@<agent-server-domain>
```

The binding is one-to-one: the same user at the same PS at the same agent server MUST map to the same `aauth:local@domain` identity, regardless of device.

The agent server stores the device credential obtained during attestation (a WebAuthn credential ID, or a `urn:jkt:sha-256:<enclave>` thumbprint) against the binding. Multiple device credentials MAY be associated with a single binding.

## Token Response {#token-response}

The agent server returns an agent token:

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "agent_token": "<jwt>"
}
```

The `agent_token` is a JWT as defined in [@!I-D.hardt-aauth-protocol] with:

- **`typ`**: `aa-agent+jwt`.
- **`iss`**: The agent server URL.
- **`dwk`**: `aauth-agent.json`.
- **`sub`**: The `aauth:local@<agent-server-domain>` identity from the binding.
- **`ps`**: The PS URL (from `bootstrap_token.iss`).
- **`cnf.jwk`**: The agent's ephemeral public key.

The agent server does not issue a `resource_token` at bootstrap. If the agent server needs to release user identity claims to itself (for example to populate a user profile page), it follows the standard AAuth Protocol three-party flow after bootstrap completes.

## Bootstrap Completion {#bootstrap-completion}

Once the agent holds the `agent_token`, it SHOULD announce its new agent identity to the PS so the PS can bind the identity to the user within the PS's bootstrap record. The agent SHOULD perform this announcement before rotating its ephemeral key (that is, before any call to `refresh_endpoint`), because the PS correlates the announcement to the bootstrap record by the ephemeral key's thumbprint.

### Announcement Request

The agent sends an empty POST to the PS's `/bootstrap` endpoint, signed under the `jwt` scheme ([@!I-D.hardt-httpbis-signature-key]) with the `agent_token` as the naming JWT:

```
POST /bootstrap HTTP/1.1
Host: ps.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=jwt;jwt="<agent_token>"
Content-Length: 0
```

The PS distinguishes the announcement from the initial bootstrap by the signature scheme and the empty body: the initial call uses `hwk` with a JSON body, the announcement uses `jwt` with an empty body.

### PS Processing

On receiving the announcement, the PS MUST:

1. Verify the HTTP Message Signature under the `jwt` scheme.
2. Verify the `agent_token` by resolving the agent server's JWKS via `agent_token.iss` and `agent_token.dwk` per [@!I-D.hardt-httpbis-signature-key].
3. Verify that `agent_token.ps` equals this PS's URL.
4. Look up the bootstrap record by the thumbprint of `agent_token.cnf.jwk`.
5. If a matching bootstrap record exists, record the binding between `agent_token.sub` (the `aauth:local@domain` identifier) and the `(user, agent_server)` tuple already on file, then respond `204 No Content`.
6. If no matching record exists, respond `404 Not Found`.

The announcement is idempotent: repeated calls for the same ephemeral thumbprint after a successful binding have no effect and respond `204 No Content`.

The PS retains the bootstrap record at least until `bootstrap_token.exp`. After that time, an announcement MAY fail with `404`, and the PS MAY instead learn the binding lazily from the `agent` claim of a `resource_token` presented at the PS `/token` endpoint during the standard three-party flow.

### Post-Bootstrap API Access

With the `agent_token` in hand (and, typically, after announcing to the PS), the agent uses the `agent_token` to call the agent server's APIs:

- **Identity-based calls**, where the agent server authorizes based solely on the agent's identity, use the `agent_token` directly per the identity-based mode of [@!I-D.hardt-aauth-protocol].
- **Calls requiring user claims** follow the standard three-party flow defined in [@!I-D.hardt-aauth-protocol]: the agent calls the agent server's `authorization_endpoint` to obtain a `resource_token`, exchanges that `resource_token` at the PS `/token` endpoint for an `auth_token` carrying the required claims, then calls the agent server's API with the `auth_token`.

Each claim-bearing call follows the same pattern, which lets the agent request claims incrementally rather than up front. The PS applies its own policy (including any user consent) when issuing each `auth_token`.

# Attestation {#attestation}

Every call in this specification that mints tokens for an agent (at bootstrap or at renewal) carries a platform-specific attestation. At bootstrap the attestation registers a device credential on the binding; at renewal it proves possession of that device credential. Without attestation an attacker who intercepted a `bootstrap_token` or replayed a refresh could obtain tokens from a machine the user does not control.

## Ceremony Selection

The agent selects the ceremony from its runtime platform. The agent server determines which ceremony to expect from the HTTP signature scheme on the `bootstrap_endpoint` or `refresh_endpoint` POST.

| Platform | Bootstrap ceremony | Renewal ceremony | HTTP signature scheme |
|----------|--------------------|------------------|-----------------------|
| Browser (incl. B2B web) | WebAuthn registration ([@WebAuthn]) | WebAuthn assertion ([@WebAuthn]) | `hwk` |
| Mobile (iOS) | App Attest | Enclave `jkt-jwt` | `jkt-jwt` |
| Mobile (Android) | Play Integrity | Enclave `jkt-jwt` | `jkt-jwt` |

An agent server that supports browser clients MUST publish `webauthn_endpoint` in its metadata (#agent-server-metadata). Mobile clients obtain ceremony nonces through platform-specific means; no corresponding metadata field is defined by this document because the ceremony details are platform-specific.

Agents that cannot perform any of the ceremonies above (for example, a command-line tool with no platform authenticator and no enclave) are outside the scope of this specification.

## Browser: WebAuthn

Browser clients use the same `webauthn_endpoint` (#webauthn-endpoint) for both bootstrap (`type=create`) and renewal (`type=get`). The ceremony result is carried in the POST body to `bootstrap_endpoint` or `refresh_endpoint`.

### Registration (at Bootstrap)

The agent first fetches a challenge and creation options from `webauthn_endpoint`:

```
GET /webauthn?type=create HTTP/1.1
Host: agent-server.example
```

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "challenge": "<base64url random bytes>",
  "creation_options": {
    "rp": { "id": "agent-server.example", "name": "Example AI Assistant" },
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "authenticatorSelection": {
      "residentKey": "required",
      "userVerification": "preferred"
    },
    "attestation": "none"
  }
}
```

The agent invokes `navigator.credentials.create()` using those options, filling `user.id` with `bootstrap_token.sub` and supplying `user.name` and `user.displayName` from agent-side data. The resulting `PublicKeyCredential` is included in the POST to `bootstrap_endpoint`:

```
POST /bootstrap HTTP/1.1
Host: agent-server.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<ephemeral-pubkey>"
Content-Type: application/json

{
  "bootstrap_token": "<jwt>",
  "attestation": {
    "type": "webauthn",
    "credential": {
      "id": "<base64url credential id>",
      "rawId": "<base64url>",
      "response": {
        "clientDataJSON": "<base64url>",
        "attestationObject": "<base64url>"
      },
      "type": "public-key"
    }
  }
}
```

The agent server verifies the WebAuthn registration ([@WebAuthn]) including that `clientDataJSON.challenge` matches a challenge it issued via `webauthn_endpoint`, and records the credential ID as a device credential on the binding.

### Assertion (at Renewal)

The agent first fetches a challenge from `webauthn_endpoint`:

```
GET /webauthn?type=get HTTP/1.1
Host: agent-server.example
```

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "challenge": "<base64url random bytes>"
}
```

The agent invokes `navigator.credentials.get()` with that challenge and the agent server's `rpId`, using a discoverable credential (no `allowCredentials`). The resulting `PublicKeyCredential` is included in the POST to `refresh_endpoint`:

```
POST /refresh HTTP/1.1
Host: agent-server.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<new-ephemeral-pubkey>"
Content-Type: application/json

{
  "attestation": {
    "type": "webauthn",
    "credential": {
      "id": "<base64url credential id>",
      "rawId": "<base64url>",
      "response": {
        "clientDataJSON": "<base64url>",
        "authenticatorData": "<base64url>",
        "signature": "<base64url>",
        "userHandle": "<base64url>"
      },
      "type": "public-key"
    }
  }
}
```

The agent server looks up the binding by the credential's `rawId` and verifies the WebAuthn assertion ([@WebAuthn]) including that `clientDataJSON.challenge` matches a challenge it issued via `webauthn_endpoint`.

## Mobile: Platform Attestation and Enclave Proof

Mobile clients use App Attest (iOS) or Play Integrity (Android) at bootstrap to enroll the enclave key as the device credential. At renewal, the enclave key signature in the `jkt-jwt` HTTP Message Signature is itself sufficient proof; no additional ceremony is required.

### Initial Attestation (at Bootstrap)

The mobile platform produces an attestation keyed to a server-nominated nonce. The nonce handshake is platform-specific (App Attest on iOS, Play Integrity on Android) and out of scope of this document.

Once the ceremony has produced an attestation, the agent POSTs to `bootstrap_endpoint`:

```
POST /bootstrap HTTP/1.1
Host: agent-server.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=jkt-jwt;jwt="<jkt-jwt-token>"
Content-Type: application/json

{
  "bootstrap_token": "<jwt>",
  "attestation": {
    "type": "app-attest",
    "key_id": "<base64url>",
    "attestation_object": "<base64url>",
    "client_data_hash": "<base64url>"
  }
}
```

For Play Integrity the `attestation` object has the form:

```json
{
  "type": "play-integrity",
  "integrity_token": "<JWS-encoded attestation>"
}
```

The agent server verifies the attestation per the platform's published rules, including that the nonce was one it nominated, and records the enclave key thumbprint (`urn:jkt:sha-256:<thumbprint>`) as the device credential on the binding.

### Enclave Proof (at Renewal)

The agent generates a new ephemeral key, has the enclave sign a `jkt-jwt` binding that key, and POSTs to `refresh_endpoint`:

```
POST /refresh HTTP/1.1
Host: agent-server.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=jkt-jwt;jwt="<jkt-jwt-token>"
```

The request body is empty. The agent server computes the enclave key thumbprint from the `jkt-jwt` header, looks up the binding, and issues a fresh `agent_token`. No `attestation` member appears in the body because the `jkt-jwt` signature itself is the proof.

# Signature Scheme Summary

The following signature schemes from [@!I-D.hardt-httpbis-signature-key] are used at each step of bootstrap and renewal:

| Context | Scheme | Key material |
|---|---|---|
| PS /bootstrap initial request | `hwk` | Ephemeral (inline) |
| PS /bootstrap announcement request | `jwt` | Ephemeral (via agent_token) |
| Agent Server webauthn_endpoint request (browser) | unsigned | (no signature) |
| Agent Server bootstrap_endpoint request (browser) | `hwk` | Ephemeral (same as PS call) |
| Agent Server bootstrap_endpoint request (mobile) | `jkt-jwt` | Enclave signs ephemeral |
| Post-bootstrap resource calls | `jwt` | agent_token wrapping ephemeral |
| Agent Server refresh_endpoint request (mobile) | `jkt-jwt` | Enclave signs new ephemeral |
| Agent Server refresh_endpoint request (browser) | `hwk` + WebAuthn assertion in body | New ephemeral + user proof |

# Renewal {#renewal}

Agent tokens expire. Per [@!I-D.hardt-aauth-protocol] the maximum lifetime is 24 hours. Renewal bypasses the PS because the agent server already holds the `(user, agent)` binding and the device credential recorded at bootstrap.

Agent servers that support this specification MUST expose a `refresh_endpoint` as defined in (#agent-server-metadata). The endpoint issues a fresh `agent_token` bound to a new ephemeral key.

## Renewal Flow

Before calling `refresh_endpoint`, the agent performs the renewal attestation ceremony appropriate to its platform. See (#attestation) for the ceremony details. The ceremony result, if any, is carried in the POST body.

```
POST /refresh HTTP/1.1
Host: agent-server.example
Signature-Input: sig=...
Signature: sig=...
Signature-Key: sig=<scheme>
Content-Type: application/json

{
  "attestation": {
    "type": "<attestation type>",
    ...
  }
}
```

The HTTP Message Signature scheme is determined by the platform:

- **Browser clients** use `hwk` with a newly generated ephemeral key.
- **Mobile clients** use `jkt-jwt` ([@!I-D.hardt-httpbis-signature-key]), where the enclave key signs a `jkt-jwt` binding a newly generated ephemeral key; the ephemeral key signs the HTTP message. For mobile, the request body MAY be empty because the `jkt-jwt` signature itself proves possession of the device credential.

Request body members:

- **`attestation`** (REQUIRED for browser clients; omitted for mobile clients). The assertion result defined by the renewal ceremony in (#attestation).

On receiving the request, the agent server MUST:

1. Verify the HTTP Message Signature.
2. Look up the binding:
   - For browser clients, by the credential ID (`rawId`) in the WebAuthn assertion.
   - For mobile clients, by the enclave key thumbprint (`urn:jkt:sha-256:<thumbprint>`) derived from the `jkt-jwt` header.
3. Verify the renewal attestation per the rules of the indicated ceremony in (#attestation), including that any ceremony challenge matches one it issued and has not expired or been consumed. Mark the challenge as consumed.
4. Issue a fresh agent token bound to the new ephemeral key.

## Refresh Response

On success, the agent server returns:

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "agent_token": "<jwt>"
}
```

The `agent_token` has the same structure as in (#token-response) but bound to the new ephemeral key.

## Renewal Failure

Renewal MUST fail in the following conditions. The agent server MUST respond with `401 Unauthorized` (for credential failures) or `404 Not Found` (for missing bindings), and the agent MUST repeat the full PS-mediated bootstrap flow from (#bootstrap-flow):

- The enclave key has been regenerated (for example, after mobile reinstall) and the `urn:jkt` is no longer recognized.
- The WebAuthn credential is no longer usable (for example, browser storage cleared or hardware key removed).
- The binding has been revoked at the agent server.
- The PS has stopped vouching for the user (for example, B2B deprovisioning). In this case the subsequent PS `/bootstrap` call will fail at the interaction step, and the agent will be unable to re-establish the binding.

# Agent-Person Binding Invariant

Per [@!I-D.hardt-aauth-protocol], each agent is bound to exactly one person. In bootstrap:

- `(ps_url, user_sub) -> aauth:local@<agent-server-domain>` is one-to-one.
- The same user at the same PS maps to the same `aauth:local@<agent-server-domain>` regardless of device.
- Multiple devices per binding MAY exist through multiple associated device credentials.
- Revoking a binding at the agent server revokes access for all devices bound to it.

This supports:

- Account switching, where an agent holds multiple agent tokens for multiple `(user, agent)` bindings and selects among them at runtime.
- Multi-device use, where a single `aauth:local` identity has device credentials on several devices.
- Immediate cross-device revocation, where disabling the binding at the agent server invalidates all device credentials simultaneously.

# Out-of-Band User Channel

After first bootstrap, the PS knows the `(user, agent_server)` binding and MAY establish a communication channel with the user (push, email, or an authenticated session). PSes that establish such a channel at first bootstrap can use it to prompt the user for consent on subsequent `auth_token` requests from the agent server without requiring an in-app interaction.

This does not change the bootstrap protocol itself; bootstrap produces only the binding. It enables a smoother user experience for the standard three-party flow by letting the PS reach the user out of band when a token request requires consent.

PS implementations that wish to support out-of-band consent SHOULD establish a direct user communication channel at first bootstrap.

# B2B Extensions {#b2b-extensions}

Bootstrap extends to B2B use cases by carrying enterprise parameters on the PS `/bootstrap` request:

```json
{
  "agent_server": "https://vendor.example",
  "tenant": "acme-corp",
  "domain_hint": "acme.example",
  "login_hint": "employee@acme.example"
}
```

These parameters are drawn from [@OpenID.EnterpriseExtensions] and tell the PS which organizational identity context to use when creating the binding. They affect which pairwise `sub` the PS issues and which organizational identity subsequent token requests resolve against.

No enterprise claims (`org`, `groups`, `roles`) are carried in the `bootstrap_token`. Those claims are released in the `auth_token` issued by the PS on subsequent three-party flows, per [@!I-D.hardt-aauth-protocol]. This lets the vendor apply organization-based authorization without running a per-customer SAML or OIDC integration, using the same claim-release machinery as any other AAuth flow.

# Security Considerations

## bootstrap_token Replay

The `bootstrap_token` carries a `cnf` claim binding it to the agent's ephemeral public key. Possession of the token alone is insufficient; the holder MUST also control the corresponding private key. Agent servers MUST reject `bootstrap_token`s that are not accompanied by an HTTP request signed with the key named in `cnf.jwk`, and MUST reject replay by `jti`.

## Consent Phishing

The user sees the agent server's domain, name, and logo at the PS consent screen. This relies on user recognition of the agent server. The PS SHOULD retrieve the agent server's display metadata from its `/.well-known/aauth-agent.json` document and present it at the consent screen.

## Key-to-User Binding Without Attestation

The bootstrap flow as specified relies on platform attestation at the agent server step. Environments without a platform attestation mechanism cannot safely use this flow because a remote process may impersonate a local user by relaying ephemeral keys through them. This is the reason command-line tools are out of scope.

## Enclave Key Compromise

On mobile, compromise of the enclave key breaks the chain of delegated ephemeral keys. Implementations SHOULD use the shortest practical `jkt-jwt` lifetimes.

## Agent Server Compromise

Compromise of an agent server breaks all agent identities minted by that server. Bootstrap does not introduce this risk, but centralizes it at the agent server.

## PS Compromise

The PS is already a high-value target in [@!I-D.hardt-aauth-protocol]. Bootstrap does not change the risk profile, but makes the PS load-bearing for agent identity creation.

## Bootstrap Completion Announcement

The announcement POST to the PS (#bootstrap-completion) is bound to possession of the agent's ephemeral key plus a signed `agent_token` issued to that key. An attacker would need both the ephemeral private key and a valid `agent_token` for the target `aauth` identifier. These are the same credentials that protect the rest of bootstrap; the announcement introduces no new attack surface.

# Privacy Considerations

## Directed User Identifiers

The `bootstrap_token.sub` claim MUST be a pairwise user identifier directed at the agent server. This prevents cross-vendor correlation of users across different agent servers.

## Mobile Enclave Identity

The PS sees only the ephemeral `hwk` key. The agent server sees the `jkt-jwt` carrying the enclave identity. The PS therefore cannot track a device across bootstraps at different agent servers.

## Out-of-Band Consent Channel

The user communication channel held by the PS after first bootstrap is privacy-sensitive. PS implementations SHOULD document their user communication practices.

## Agent Identifier Registry at the PS

After bootstrap completion (#bootstrap-completion), the PS knows the `aauth:local@domain` identifier of each agent the user has bootstrapped. This supports user-facing features such as a dashboard of connected agents and targeted revocation ("disconnect from agent X"). PS implementations SHOULD make this list visible to the user.

# IANA Considerations

## Media Type Registration

This document requests registration of the following media type in the IANA Media Types registry:

- **`application/aa-bootstrap+jwt`**: JWT used by the AAuth Bootstrap protocol.

## JWT Claims

This document does not introduce new JWT claims. The `bootstrap_token` uses existing claims and those defined in [@!I-D.hardt-aauth-protocol].

## AAuth Agent Server Metadata Registration

This document registers the following parameters in the AAuth Agent Server Metadata registry established by [@!I-D.hardt-aauth-protocol]:

| Parameter | Description | Reference |
|-----------|-------------|-----------|
| `bootstrap_endpoint` | URL of the agent server's bootstrap endpoint | This document, (#agent-server-metadata) |
| `refresh_endpoint` | URL of the agent server's refresh endpoint | This document, (#agent-server-metadata) |
| `webauthn_endpoint` | URL of the agent server's WebAuthn challenge endpoint | This document, (#webauthn-endpoint) |

# Implementation Status

*Note: This section is to be removed before publishing as an RFC.*

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in [@RFC7942]. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.

There are currently no known implementations.

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-aauth-bootstrap-00
  - Initial submission.

# Acknowledgments

TBD.

{backmatter}

# Relationship to Other Specifications

- **AAuth Protocol ([@!I-D.hardt-aauth-protocol])**: Bootstrap produces an `agent_token` in the shape defined by the main specification, and consumes the HTTP Message Signatures profile defined there. Identity claims and scoped authorization use the three-party flow from the main specification; bootstrap does not duplicate it.
- **HTTP Signature Keys ([@!I-D.hardt-httpbis-signature-key])**: Bootstrap uses the `hwk`, `jkt-jwt`, and `jwt` schemes defined there.
- **OpenID Provider Commands (OPC)**: A complementary protocol for lifecycle events. Bootstrap handles initial onboarding (user-initiated, pull). OPC handles lifecycle events (system-initiated, push). The two compose but operate independently.
- **OpenID Connect Enterprise Extensions ([@OpenID.EnterpriseExtensions])**: Source of the enterprise parameters (`tenant`, `domain_hint`, `login_hint`) used on the PS /bootstrap request to select an organizational identity. Enterprise claims (`org`, `groups`, `roles`) are released in `auth_tokens` through the standard three-party flow, not in the `bootstrap_token`.

