# Agent Auth (AAuth)


## Introduction

The internet has evolved since the release of OAuth 2.0. 

- Security incidents from exfiltration of bearer tokens and cookies a
- digitally signatures and verification using public / private key pairs is readily available
- Tightly bound client / server relationships are being subsumed / replaced / dismantled MCP Clients want to access arbitrary MCP Servers. An MCP Client is able to interact with an arbitrary MCP Server. 

- web bot auth is proposing HTTP Message Signing. 

Course grained scopes are insufficient for agent access. 

AAuth proposes to reset the OAuth model and decouple the relationships between the different parties 
Simplification by being prescriptive in authentication and flows.


OpenID Connect 1.0
OAuth 2.0/2.1
GNAP 1.0

Terminology


- agent server
- agent
- resource
- authorization server 
- agent token
- delegation token 
- user 




> **AAuth** extends
> [Web-Bot-Auth](https://datatracker.ietf.org/doc/draft-rundgren-http-message-signatures-bot-auth/)
> ---\
> bringing the same verifiable agent identity model to
> **authorization**.\
> It lets autonomous web agents graduate from being merely
> **identified** to being **authorized**,\
> using **HTTP Message Signing** for every interaction.

------------------------------------------------------------------------

## Design Rationale

### From Agent Identity → Authorized Agent

Web-Bot-Auth gives agents a way to authenticate using **HTTP Message
Signing** and a public key resolved from an HTTPS URL.\
That establishes **agent identity** --- a way for any web service to
verify *who* is making a request.

**AAuth** builds on that foundation to allow those same agents to act on
behalf of users or organizations ---\
to become **authorized agents**.\
It defines how an agent can obtain, use, and refresh authorization
tokens while preserving the verifiable, decentralized nature of the Web.

------------------------------------------------------------------------

### Why not just OAuth?

AAuth reuses familiar OAuth 2.0 components --- authorization servers,
tokens, scopes, and metadata ---\
but it changes the **binding model**.

  -----------------------------------------------------------------------
  OAuth 2.x                                    AAuth
  -------------------------------------------- --------------------------
  Clients are registered and identified by a   Agents are identified by
  `client_id`.                                 an **HTTPS URL** that
                                               returns a JWKS.

  Tokens are bearer credentials.               Tokens are
                                               **proof-of-possession**,
                                               verified by **HTTP Message
                                               Signing**.

  RS and AS are pre-registered and coupled.    The RS dynamically
                                               declares its AS via
                                               metadata.

  Client authentication relies on secrets or   Authentication is through
  MTLS.                                        message-level signatures.
  -----------------------------------------------------------------------

AAuth doesn't replace OAuth --- it **extends its ecosystem** to support
autonomous software agents and cross-domain resource interaction with
verifiable identity.

------------------------------------------------------------------------

### Why HTTP Message Signing everywhere

-   **Always use HTTP Message Signing:** all agent, RS, and AS requests
    and responses must be signed.\
-   **No bearer tokens:** every call is signed and verifiable.\
-   **Uniform integrity model:** same mechanism for RS and AS.\
-   **Cryptographic binding:** tokens include a `cnf.jkt` thumbprint
    referencing the signing key.\
-   **Key agility:** agents rotate keys by updating their JWKS at their
    `jwks_uri` without changing any metadata.

------------------------------------------------------------------------

### Why dynamic metadata

-   Agents, resources, and authorization servers remain **loosely
    coupled**.\
-   Each publishes a discoverable HTTPS metadata document describing
    keys, scopes, and endpoints.\
-   Enables the AS to build a **dynamic consent UX** showing both the
    agent and the resource context.

------------------------------------------------------------------------

### Optional direct-grant flow

Because both the **agent** and **resource** have strong cryptographic
identities, an AS can sometimes skip user mediation:

> If policy allows, the AS **MAY** return an `agent_token` directly in
> response to the agent's signed authorization request, rather than
> returning an `authorization_uri` for user consent.

This supports **machine-to-machine** or **service-to-service** use cases
without user redirection, while maintaining verifiable authorization.

------------------------------------------------------------------------

## Protocol Overview

    Agent → RS : Signed request via HTTP Message Signing
    RS → Agent : 401 + WWW-Authenticate (resource_metadata + scope)
    Agent → RS metadata : fetch resource metadata
    Agent → AS metadata : discover agent_request_endpoint
    Agent → AS : signed authorization request with Delegation-Token
    AS → User : consent (agent + resource scopes)
    User → AS : approves
    AS → Agent : agent_token (possibly direct)
    Agent → RS : signed request with agent_token
    RS → Agent : success

------------------------------------------------------------------------

## Metadata Documents

### Resource Metadata

Returned from the URL in the `resource_metadata` parameter of the
`WWW-Authenticate: AAuth` header.

``` json
{
  "resource": "https://api.resource.example.com",
  // new metadata properties
  "agent_authorization_metadata": "https://as.example.com/.well-known/oauth-authorization-server",
  "agent_signing_algorithms_supported": "ecdsa-p256-sha256"]
}
```

> The `agent_authorization_metadata` value defines **the only
> Authorization Server** trusted by this Resource Server.\
> The RS **MUST** reject any `agent_token` whose `iss` does not match
> the `issuer` in that metadata.

### Authorization Server Metadata

The URL referenced by `agent_authorization_metadata` may point to an RFC
8414 or OpenID Connect discovery document.

``` json
{
  "issuer": "https://as.example.com",
  "jwks_uri": "https://as.example.com/.well-known/jwks.json",
  "authorization_endpoint": "https://as.example.com/authorize",
  // new metadata properties
  "agent_request_endpoint": "https://as.example.com/aauth/request",
  "agent_token_endpoint": "https://as.example.com/aauth/token",
  "agent_signing_algorithms_supported": ["ecdsa-p256-sha256"]
}
```

### Agent Metadata

Fetched from the `agent_id` URL with `.well-known/agent-metadata`.

``` json
{
  "agent_id": "https://agent.example.com/",
  "jwks_uri": "https://agent.example.com/jwks.json",
  "name": "Example Agent",
  "logo_uri": "https://agent.example.com/logo.png",
  "policy_uri": "https://agent.example.com/privacy",
  "terms_of_service_uri": "https://agent.example.com/terms",
  "homepage": "https://agent.example.com"
}
```

> The `agent_id` is **always an HTTPS URL**. Dereferencing it returns
> the agent metadata document containing the `jwks_uri` for key
> discovery and rotation.

------------------------------------------------------------------------

## Agent Token Semantics

### Top-level claims

All identity claims appear **flat** at the top of the token. There is
**no id_token**.

``` jsonc
{
  "iss": "https://as.example.com",
  "aud": "https://api.resource.example",
  "agent_id": "https://agent.example.com/", // identifies the agent (resolvable)
  "cnf": { "jkt": "QG7JxQ..." },         // required proof key binding
  "exp": 1730123456,
  "iat": 1730120000,

  "sub": "user-sub-248289761001",         // always the user subject
  "scope": "data.read data.write",

  // flat identity values
  "email": "alice@example.com",
  "email_verified": true,
  "amr": ["hwk", "pin"],
  "auth_time": 1730119800,
  "acr": "urn:rs:high"
}
```

### Key and replay model

-   **Always proof-of-possession:** all tokens are bound via `cnf.jkt`.\
-   **HTTP Message Signing only:** DPoP and bearer tokens are not used.\
-   **No nonce or jti:** tokens and delegation tokens are designed for
    reuse; replay resistance is provided by per-request HTTP signatures
    and short token lifetimes.\
-   **Short-lived tokens:** AS SHOULD issue brief expiry (e.g., ≤15 min)
    and rely on HTTP signatures for request integrity.

------------------------------------------------------------------------

## Endpoints

### agent_request_endpoint

The agent sends a signed request containing the resource identifier, opaque
scope:

``` json
{
  "resource": "https://api.resource.example",
  "scope": "data.read data.write",
}
```

**Response:** identical for both `agent_request_endpoint` and
`token_endpoint`.

``` json
{
  "result": "authorized",
  "agent_token": "eyJhbGciOi...",
  "token_type": "httpsig",
  "expires_in": 900,
  "refresh_token": "rft.ABCDEF..."
}
```

------------------------------------------------------------------------

## WWW-Authenticate Challenges

### Opaque scopes

    WWW-Authenticate: AAuth as="https://as.example.com",\
      rs="https://api.resource.example",\
      scope="data.read data.write",\
      realm="resource"

### Request Descriptor URL

    WWW-Authenticate: AAuth as="https://as.example.com",\
      rs="https://api.resource.example",\
      request_uri="https://rs.example.com/auth/req/3f5a",\
      realm="payments"


------------------------------------------------------------------------

## Security Considerations

-   **No bearer tokens**: all communication is protected by HTTP Message
    Signing.
-   **agent_id is a URL**: its metadata and JWKS define verification
    keys.
-   **Key rotation**: achieved by updating the JWKS at `jwks_uri`; other
    metadata remains stable.
-   **Replay resistance**: achieved by per-request signing, not nonces
    or jti.
-   **Token reuse**: delegation and agent tokens are reusable for their
    valid lifetime.
-   **Short expiry**: AS SHOULD use brief expirations to limit exposure.
-   **Interoperability**: AS, RS, and Agent agree on supported signing
    algorithms via metadata.

------------------------------------------------------------------------

## IANA Considerations (Proposed)

-   Register `AAuth` as an HTTP Authentication Scheme.\
-   Register headers:
    -   `Agent-Token` --- AS → RS authorization token\
    -   `Delegation-Token` --- Parent → AS delegation token\
-   Register metadata parameters:
    -   `agent_authorization_metadata` (RS metadata)\
    -   `agent_request_endpoint` (AS metadata)\
    -   `agent_signing_algorithms_supported` (AS & RS metadata)

------------------------------------------------------------------------

© 2025 Hellō Identity --- Draft authored by [Dick
Hardt](https://github.com/DickHardt).
