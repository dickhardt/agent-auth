%%%
title = "AAuth Protocol"
abbrev = "AAuth"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["agent", "authentication", "authorization", "http", "signatures"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-aauth-latest"
stream = "IETF"

date = 2026-03-02T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@hello.coop"

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

.# Abstract

AAuth is an authentication and authorization protocol for modern distributed systems. It provides progressive authentication from abuse prevention to full authorization, verified agent identity alongside user identity, cryptographic proof of resource legitimacy, and unified authentication and authorization in a single flow. The protocol uses HTTP Message Signatures for proof-of-possession on every request, eliminating bearer tokens and shared secrets. Any endpoint may return deferred responses using standard HTTP async semantics (202 Accepted, Location, Prefer: wait), enabling uniform handling of user interaction, long-running authorization, and clarification chat.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

Source for this draft and an issue tracker can be found at https://github.com/DickHardt/draft-hardt-aauth.

{mainmatter}

# Introduction

OAuth 2.0 [@!RFC6749] was created to solve a security problem: users were sharing their passwords with third-party web applications so those applications could access their data at other sites. OAuth replaced this anti-pattern with a delegation model — the user's browser redirects to the authorization server, the user consents, and the application receives an access token without ever seeing the user's credentials. OpenID Connect extended this to federated login. Together, they serve these use cases well and continue to be the right choice for them.

But the landscape has changed. New use cases have emerged that OAuth and OIDC were not designed to address:

- **Autonomous agents** that operate without a browser, cannot receive redirects, and interact with servers they were never pre-registered with.
- **Dynamic ecosystems** like the Model Context Protocol (MCP) where any agent may call any server and pre-registration of client credentials is impractical at scale.
- **Headless and long-running processes** that need authorization but have no user interface for redirect-based flows.
- **Progressive trust** where a resource needs different levels of assurance for different operations — from rate limiting anonymous requests to requiring full user authorization — within a single protocol.
- **Multi-hop resource access** where a resource needs to obtain authorization to access a downstream resource to fulfill a request.

The AAuth protocol is designed for these new use cases. It complements OAuth and OIDC rather than replacing them — where pre-registered clients, browser redirects, bearer tokens, and static scopes work well, they remain the right choice.

AAuth provides:

- **Proof-of-possession by default**: HTTP Message Signatures on every request eliminate bearer tokens and shared secrets.
- **Agent identity without pre-registration**: HTTPS URLs with self-published metadata and JWKS enable open ecosystems.
- **Decoupled resources and auth servers**: Resources and auth servers operate independently. Authorization requirements are expressed in resource tokens at request time, so resources can change what they require without coordinating with the auth server.
- **Polling-based token delivery**: Deferred responses (`202 Accepted` + `Location` + `Prefer: wait`) support headless agents, long-running consent, and clarification chat.
- **Progressive authentication**: A single protocol covers pseudonymous access, verified identity, and full authorization.
- **Unified AuthN and AuthZ token**: Authentication and authorization work in a single flow and auth token.
- **Multi-hop support**: Resources can act as agents, passing auth tokens downstream and bubbling interaction requirements back up to the user.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Agent
: An application or software component acting on behalf of a user or autonomously. In AAuth, agents have cryptographic identity and all requests are signed. An agent may also request auth tokens for itself — for SSO (user identity) or first-party resource access — where the agent is the audience.

Agent Server
: A server that manages agent identity and issues agent tokens to agent delegates. Identified by an HTTPS URL and publishes metadata at `/.well-known/aauth-agent.json`.

Agent Delegate
: An instance of an agent that holds an agent token and makes requests on behalf of the agent. Each delegate has its own signing key and unique identifier.

Agent Token
: A JWT issued by an agent server to an agent delegate, binding the delegate's signing key to the agent's identity.

Session Identifier
: An opaque string identifying an agent session, assigned by the agent server.
The agent server conveys the session identifier to auth servers and resources
either as the `aauth_sid` claim in the agent token, or via the `AAuth-Session`
request header when no token carrying `aauth_sid` is present in the request.
The auth server copies `aauth_sid` into every auth token it issues within the
session and records it in the audit log alongside every token issuance event.
The agent server determines when a session begins and ends.

Auth Server
: A server that authenticates users, obtains consent, evaluates authorization policies, and issues auth tokens. Publishes metadata at `/.well-known/aauth-issuer.json`.

Auth Token
: A JWT issued by an auth server that grants an agent access to a resource, containing user identity and/or authorized scopes.

Resource
: A protected API at a service that requires authentication and/or authorization. Like agents, resources have cryptographic identity via an HTTPS URL and publish metadata at `/.well-known/aauth-resource.json`.

Resource Token
: A JWT issued by a resource that binds an access request to the resource's identity, preventing confused deputy attacks (#security-considerations).

Interaction Endpoint
: A URL where the user is sent for authentication, consent, or other interaction. Declared as `interaction_endpoint` in entity metadata. Both auth servers and resources may have interaction endpoints.

Interaction Code
: A short alphanumeric code that links an agent's pending request to the user's interaction at an interaction endpoint.


# Protocol Overview

AAuth has three server types — agents, resources, and auth servers — and a user who may or may not be involved. An agent is always present: it makes requests to resources, to auth servers, or both. A user may direct the agent, authorize requests, or be entirely absent in machine-to-machine scenarios.

## Identity and Discovery

Every participant — agent, resource, and auth server — is identified by an HTTPS URL and publishes metadata and public keys at a well-known endpoint (#metadata-documents). This means any agent can discover any resource (and vice versa) without pre-registration. There are no shared secrets and no out-of-band setup required.

## Request Signing

Every AAuth request is signed using HTTP Message Signatures ([@!RFC9421]). There are no bearer tokens — every token is bound to the signer's key via a `cnf` (confirmation) claim ([@!RFC7800]), so a stolen token is useless without the corresponding private key (#http-message-signing-profile).

An agent can sign requests at three levels of identity assurance:

- **Pseudonymous**: The agent includes its public key directly. The signature proves key possession without revealing identity.
- **Identified**: The agent presents a verifiable identity via its JWKS URL or an agent token issued by its agent server.
- **Authorized**: The agent presents an auth token issued by an auth server, granting access to a specific resource.

## Challenge and Response

Resources tell agents what they need using the `AAuth-Challenge` HTTP response header (#aauth-challenge-http-response-header). A resource that requires authorization returns `401` with an `AAuth-Challenge` header indicating the requirement level and a resource token that binds the challenge to the resource's identity. The agent takes this resource token to the indicated auth server's token endpoint to obtain an auth token, then retries the request.

This decouples resources from auth servers — the resource decides *what* authorization is needed, the auth server decides *whether* to grant it. Either side can change independently.

## Tokens

AAuth defines three proof-of-possession token types, all JWTs bound to a specific signing key:

- **Agent Token** (`agent+jwt`): Issued by an agent server to a delegate, binding the delegate's key to the agent's identity (#agent-tokens).
- **Resource Token** (`resource+jwt`): Issued by a resource in response to a request, binding the access challenge to the resource's identity. This prevents confused deputy attacks (#resource-tokens).
- **Auth Token** (`auth+jwt`): Issued by an auth server, granting an agent access to a specific audience. A single auth token can carry both identity claims (such as `sub` and `email`) and authorization scopes (such as `data.read`), unifying authentication and authorization (#auth-tokens).

## Deferred Responses

When authorization requires time — user consent, policy evaluation, external approval — the auth server returns `202 Accepted` with a `Location` header pointing to a pending URL. The agent polls this URL until the auth token is ready. This standard HTTP async pattern means the protocol never requires redirects or callbacks between protocol participants (#deferred-responses).

User interaction — login pages, consent screens, push notifications — happens outside the protocol. The auth server provides an interaction code and an interaction endpoint URL; how the agent gets the user there (browser redirect, QR code, deep link, clipboard) is an application-level concern. This is what makes AAuth work for headless agents, CLI tools, and browser-based apps alike.

## Scopes

Scopes may request identity claims (using OpenID Connect scope values such as `openid`, `profile`, `email`) or resource authorization (using scopes defined by the resource, such as `data.read` or `calendar.write` as defined in the resource's `scope_descriptions` metadata), or both.

When the agent is the audience, scopes typically request identity claims. When accessing a resource, scopes are defined in the resource's `scope_descriptions` metadata.

When an agent needs additional scopes beyond its current authorization, it requests a new auth token from the auth server's `token_endpoint` — with a new `resource_token` when accessing another resource, or with the new `scope` values when the agent is the audience. The new auth token replaces the previous one.

## Flows

### Pseudonymous Access

An agent accesses a resource that requires pseudonymous identity. The resource challenges with `require=pseudonym`, and the agent retries with a signed request using an inline public key. The resource can track the agent by key thumbprint without knowing its identity.

~~~ ascii-art
Agent                          Resource
  |                               |
  |  unsigned request             |
  |------------------------------>|
  |                               |
  |  401 Unauthorized             |
  |  AAuth-Challenge: require=pseudonym     |
  |<------------------------------|
  |                               |
  |  HTTPSig request              |
  |  (scheme=hwk)                 |
  |------------------------------>|
  |                               |  verify signature,
  |                               |  track by key
  |                               |  thumbprint
  |                               |
  |  200 OK                       |
  |<------------------------------|
  |                               |
~~~

If the agent already knows the resource requires pseudonymous access (from a previous interaction or metadata), it MAY sign the initial request directly without waiting for a `401` challenge.

**Use cases:** Rate limiting anonymous requests, tracking repeat visitors by key thumbprint, spam prevention without requiring verified identity.

### Agent Identity Only

An agent accesses a resource using its verified agent identity, without authorization from an auth server.

~~~ ascii-art
Agent                          Resource
  |                               |
  |  HTTPSig request              |
  |------------------------------>|
  |                               |
  |  401 Unauthorized             |
  |  AAuth-Challenge: require=identity      |
  |<------------------------------|
  |                               |
  |  HTTPSig request              |
  |  (scheme=jwks_uri or jwt)     |
  |------------------------------>|
  |                               |  verify agent identity,
  |                               |  apply policy
  |                               |
  |  200 OK                       |
  |<------------------------------|
  |                               |
~~~

If the agent already knows the resource requires agent identity, it MAY present its identity on the initial request without waiting for a `401` challenge.

**Use cases:** API access policies based on known agents, webhook signature verification, allowlisting trusted agents for elevated rate limits.

### Resource Interaction

When a resource requires user interaction — such as login, consent, payment confirmation, or terms acceptance — it returns `202 Accepted` with a `Location` header and `AAuth-Challenge: require=interaction; code="..."`. This is a deferral, not a denial — the request has been accepted but requires user action before it can complete.

The agent directs the user to the resource's `interaction_endpoint` with the interaction code. The resource handles the interaction directly, which may involve its own OAuth, OIDC, or login flow with an identity provider. After completion, the resource redirects the user back to the agent's callback URL. The agent polls the `Location` URL with `GET` until the response is ready.

~~~ ascii-art
User            Agent                Resource
  |               |                      |
  |               |  HTTPSig request     |
  |               |--------------------->|
  |               |                      |
  |               |  202 Accepted        |
  |               |  Location: /pending/xyz
  |               |  AAuth-Challenge: require=interaction;
  |               |         code="MNOP3456"
  |               |<---------------------|
  |               |                      |
  |  direct to resource                  |
  |  interaction_endpoint with code      |
  |<--------------|                      |
  |               |                      |
  |  login / consent / confirm           |
  |------------------------------------->|
  |               |                      |
  |               |   [Resource may perform
  |               |    OAuth, OIDC, or its
  |               |    own login flow]
  |               |                      |
  |  redirect to callback_url           |
  |<-------------------------------------|
  |               |                      |
  |  callback     |                      |
  |-------------->|                      |
  |               |                      |
  |               |  GET /pending/xyz    |
  |               |--------------------->|
  |               |                      |
  |               |  200 OK              |
  |               |<---------------------|
  |               |                      |
~~~

**Use cases:** Resource requires user login via its own identity provider, payment confirmation before a purchase, terms of service acceptance, user consent for a specific operation.

### Autonomous Agent

A machine-to-machine agent obtains authorization directly without user interaction. The auth server evaluates policy based on the agent's identity and the resource token, and either grants or denies the request immediately.

#### Resource Challenge

The resource challenges the agent with a `401` response containing a resource token:

~~~ ascii-art
Agent                    Resource                  Auth Server
  |                         |                          |
  |  HTTPSig request        |                          |
  |------------------------>|                          |
  |                         |                          |
  |  401 + resource_token   |                          |
  |  + auth_server          |                          |
  |<------------------------|                          |
  |                         |                          |
  |  POST token_endpoint with resource_token           |
  |--------------------------------------------------->|
  |                         |                          |
  |                         |  validate resource_token,|
  |                         |  evaluate policy         |
  |                         |                          |
  |  auth_token                                        |
  |<---------------------------------------------------|
  |                         |                          |
  |  HTTPSig request        |                          |
  |  (with auth-token)      |                          |
  |------------------------>|                          |
  |                         |                          |
  |          verify auth_token                         |
  |                         |                          |
  |  200 OK                 |                          |
  |<------------------------|                          |
  |                         |                          |
~~~

#### Proactive Token Request

When the agent knows the resource's requirements from metadata, it can request a resource token proactively via the `resource_token_endpoint`:

~~~ ascii-art
Agent                    Resource                  Auth Server
  |                         |                          |
  |  POST                   |                          |
  |  resource_token_endpoint|                          |
  |------------------------>|                          |
  |                         |                          |
  |  resource_token         |                          |
  |  + auth_server          |                          |
  |<------------------------|                          |
  |                         |                          |
  |  POST token_endpoint with resource_token           |
  |--------------------------------------------------->|
  |                         |                          |
  |                         |  validate resource_token,|
  |                         |  evaluate policy         |
  |                         |                          |
  |  auth_token                                        |
  |<---------------------------------------------------|
  |                         |                          |
  |  HTTPSig request        |                          |
  |  (with auth-token)      |                          |
  |------------------------>|                          |
  |                         |                          |
  |          verify auth_token                         |
  |                         |                          |
  |  200 OK                 |                          |
  |<------------------------|                          |
  |                         |                          |
~~~

**Use cases:** Machine-to-machine API calls, automated pipelines, cron jobs, service-to-service communication where no user is involved.

### Agent as Audience

An agent requests an auth token where it is the audience — either for SSO (obtaining user identity) or for first-party resource access by its delegates. The agent calls the token endpoint with `scope` (and no `resource_token`), since the agent itself is the resource.

~~~ ascii-art
User           Agent                        Auth Server
  |              |                               |
  |              |  POST token_endpoint          |
  |              |  scope (no resource_token)    |
  |              |  Prefer: wait=45              |
  |              |------------------------------>|
  |              |                               |
  |              |  202 Accepted                 |
  |              |  Location: /pending/def       |
  |              |  AAuth-Challenge: require=interaction;  |
  |              |         code="EFGH5678"       |
  |              |<------------------------------|
  |              |                               |
  |  direct to   |                               |
  |  interaction_endpoint with code              |
  |<-------------|                               |
  |              |                               |
  |  authenticate and consent                    |
  |--------------------------------------------->|
  |              |                               |
  |  redirect to callback_url                    |
  |<---------------------------------------------|
  |              |                               |
  |              |  GET /pending/def             |
  |              |------------------------------>|
  |              |  200 OK, auth_token           |
  |              |<------------------------------|
  |              |                               |
  |              |  auth_token used for:         |
  |              |  1. User identity (SSO)       |
  |              |  2. API access by delegates   |
  |              |                               |
~~~

**Use cases:** Single sign-on (obtaining user identity claims such as email and name), enabling agent delegates to access protected resources at the agent on behalf of the user.

### Third-Party Initiated Login

A third party — such as an auth server, enterprise portal, app marketplace, or partner site — directs the user to the agent's `login_endpoint` with enough context to start a login flow. The agent then initiates a standard "agent as audience" flow. Because the user may already be authenticated at the auth server, the interaction step can resolve near-instantly.

~~~ ascii-art
User         Third Party        Agent                    Auth Server
  |               |               |                          |
  |  select agent |               |                          |
  |-------------->|               |                          |
  |               |               |                          |
  |  redirect to login_endpoint   |                          |
  |  (issuer, tenant, start_path) |                          |
  |<--------------|               |                          |
  |               |               |                          |
  |  login_endpoint               |                          |
  |------------------------------>|                          |
  |               |               |                          |
  |               |               |  POST token_endpoint     |
  |               |               |  scope, tenant           |
  |               |               |  Prefer: wait=45         |
  |               |               |------------------------->|
  |               |               |                          |
  |               |               |  202 Accepted            |
  |               |               |  Location: /pending/ghi  |
  |               |               |  AAuth-Challenge:        |
  |               |               |    require=interaction;  |
  |               |               |    code="JKLM9012"       |
  |               |               |<-------------------------|
  |               |               |                          |
  |  direct to interaction_endpoint                          |
  |  with code    |               |                          |
  |<------------------------------|                          |
  |               |               |                          |
  |  auth server recognizes user  |                          |
  |  (existing session),          |                          |
  |  auto-approves                |                          |
  |------------------------------------------------------>--|
  |               |               |                          |
  |  redirect to callback_url     |                          |
  |<----------------------------------------------------------
  |               |               |                          |
  |  callback     |               |                          |
  |------------------------------>|                          |
  |               |               |                          |
  |               |               |  GET /pending/ghi        |
  |               |               |------------------------->|
  |               |               |  200 OK, auth_token      |
  |               |               |<-------------------------|
  |               |               |                          |
  |  redirect to start_path       |                          |
  |<------------------------------|                          |
  |               |               |                          |
~~~

The third party does not need to be the auth server. Any party that knows the agent's `login_endpoint` (from agent metadata) and the appropriate `issuer` can initiate the flow. The agent treats the redirect as untrusted input — it verifies the auth server through normal metadata discovery and initiates a signed flow.

If the user is already authenticated at the auth server, the interaction at the auth server's `interaction_endpoint` resolves immediately — the auth server recognizes the user from its own session and auto-approves. If the user is not authenticated, the auth server conducts a normal authentication and consent flow before redirecting back.

**Use cases:** Enterprise portal SSO, app marketplace "connect" buttons, partner site deep links, auth server dashboard launching an agent.

### User Authorization

Full flow with user-authorized access. The agent obtains a resource token from the resource's `resource_token_endpoint`, then requests authorization from the auth server. The auth server returns a deferred response while the user authenticates and consents.

~~~ ascii-art
User            Agent                Resource           Auth Server
  |               |                      |                    |
  |               |  POST                |                    |
  |               |  resource_token_endpoint                  |
  |               |--------------------->|                    |
  |               |                      |                    |
  |               |  resource_token      |                    |
  |               |  + auth_server       |                    |
  |               |<---------------------|                    |
  |               |                      |                    |
  |               |  POST token_endpoint                      |
  |               |  resource_token, scope                    |
  |               |  Prefer: wait=45                          |
  |               |------------------------------------------>|
  |               |                      |                    |
  |               |  202 Accepted                             |
  |               |  Location: /pending/abc                   |
  |               |  AAuth-Challenge: require=interaction;              |
  |               |         code="ABCD1234"                   |
  |               |<------------------------------------------|
  |               |                      |                    |
  |  direct to    |                      |                    |
  |  interaction_endpoint                |                    |
  |  with code    |                      |                    |
  |<--------------|                      |                    |
  |               |                      |                    |
  |  authenticate and consent            |                    |
  |----------------------------------------------------->----|
  |               |                      |                    |
  |  redirect to callback_url                                |
  |<---------------------------------------------------------|
  |               |                      |                    |
  |  callback     |                      |                    |
  |-------------->|                      |                    |
  |               |                      |                    |
  |               |  GET /pending/abc    |                    |
  |               |------------------------------------------>|
  |               |  200 OK, auth_token  |                    |
  |               |<------------------------------------------|
  |               |                      |                    |
  |               |  HTTPSig request     |                    |
  |               |  (with auth-token)   |                    |
  |               |--------------------->|                    |
  |               |                      |                    |
  |               |  200 OK              |                    |
  |               |<---------------------|                    |
  |               |                      |                    |
~~~

**Use cases:** User-delegated access to third-party APIs, accessing user data at a resource on behalf of the user, requesting specific scopes that require user consent.

### Direct Approval

The auth server obtains approval directly — from a user (e.g., push notification, existing session, email) — without the agent facilitating a redirect. The agent simply polls until the request resolves. The user is shown to the right of the auth server to highlight that the auth server mediates between the agent and the user.

~~~ ascii-art
Agent              Resource          Auth Server             User
  |                    |                   |                    |
  |  POST              |                   |                    |
  |  resource_token_endpoint               |                    |
  |------------------->|                   |                    |
  |                    |                   |                    |
  |  resource_token    |                   |                    |
  |  + auth_server     |                   |                    |
  |<-------------------|                   |                    |
  |                    |                   |                    |
  |  POST token_endpoint                   |                    |
  |  resource_token, scope                 |                    |
  |  Prefer: wait=45                       |                    |
  |--------------------------------------->|                    |
  |                    |                   |                    |
  |  202 Accepted                          |                    |
  |  Location: /pending/jkl               |                    |
  |  AAuth-Challenge: require=approval              |                    |
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
  |  200 OK, auth_token|                   |                    |
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

In this flow, the auth server handles the approval process directly. The `require=approval` value tells the agent that the request is waiting on external approval, but the agent does not need to facilitate any user interaction.

**Use cases:** Push notification approval on a user's device, admin approval workflows, approval via an existing authenticated session, email-based authorization.

### Call Chaining

**Editor's Note:** Call chaining is an exploratory feature. The mechanism described here may change in future versions.

When a resource needs to access a downstream resource on behalf of the caller, it acts as an agent. The resource presents the downstream resource's resource token along with the auth token it received from the original caller as the `upstream_token`. This allows the downstream auth server to verify the authorization chain.

The downstream auth server (AS2) evaluates its own policy based on both the upstream auth token and the resource token from Resource 2. The resulting authorization is not necessarily a subset of the upstream scopes — AS2 may grant scopes that are independent of those in the upstream auth token. For example, an upstream token granting `calendar.read` on Resource 1 might lead AS2 to grant `availability.read` on Resource 2 based on an organizational policy that allows calendar services to query availability. The upstream token provides provenance and user identity context, not a scope ceiling.

Because the resource acts as an agent, it MUST publish agent metadata at `/.well-known/aauth-agent.json` (#agent-server-metadata) so that downstream resources and auth servers can verify its identity. The resource / agent MAY use the same `jwks_uri` in the `/.well-known/aauth-resource.json` and the `/.well-known/aauth-agent.json`.

#### Direct Grant

When the downstream auth server can issue a token without user interaction:

~~~ ascii-art
Agent          Resource 1        Resource 2         AS1           AS2
  |                |                  |               |             |
  |  HTTPSig req   |                  |               |             |
  |  (auth_token   |                  |               |             |
  |   from AS1)    |                  |               |             |
  |--------------->|                  |               |             |
  |                |                  |               |             |
  |           verify auth_token       |               |             |
  |                |                  |               |             |
  |                |  HTTPSig req     |               |             |
  |                |  (as agent)      |               |             |
  |                |----------------->|               |             |
  |                |                  |               |             |
  |                |  401 + resource_token            |             |
  |                |  + auth_server=AS2               |             |
  |                |<-----------------|               |             |
  |                |                  |               |             |
  |                |  POST token_endpoint             |             |
  |                |  resource_token from R2,         |             |
  |                |  upstream_token (from AS1)       |             |
  |                |----------------------------------------------->|
  |                |                  |               |             |
  |                |                  |       verify upstream_token,|
  |                |                  |       evaluate policy       |
  |                |                  |       (fetch AS1 JWKS)      |
  |                |                  |               |             |
  |                |  auth_token for R2                |            |
  |                |<-----------------------------------------------|
  |                |                  |               |             |
  |                |  HTTPSig req     |               |             |
  |                |  (auth_token     |               |             |
  |                |   from AS2)      |               |             |
  |                |----------------->|               |             |
  |                |                  |               |             |
  |                |  200 OK          |               |             |
  |                |<-----------------|               |             |
  |                |                  |               |             |
  |  200 OK        |                  |               |             |
  |<---------------|                  |               |             |
  |                |                  |               |             |
~~~

#### Interaction Chaining

When the downstream auth server requires user interaction, Resource 1 chains the interaction back to the original agent. Resource 1 receives a `202` with `require=interaction` from the downstream auth server, then returns its own `202` with `require=interaction` to the agent. The agent directs the user to Resource 1's interaction endpoint, and Resource 1 redirects the user onward to the downstream interaction endpoint. This keeps the downstream interaction URL opaque to the agent — each link in the chain manages only its own interaction redirect.

~~~ ascii-art
User         Agent          Resource 1        Resource 2          AS2
  |            |                 |                 |                |
  |            |  HTTPSig req    |                 |                |
  |            |---------------->|                 |                |
  |            |                 |                 |                |
  |            |                 |  HTTPSig req    |                |
  |            |                 |  (as agent)     |                |
  |            |                 |---------------->|                |
  |            |                 |                 |                |
  |            |                 |  401 + resource_token            |
  |            |                 |  + auth_server=AS2               |
  |            |                 |<----------------|                |
  |            |                 |                 |                |
  |            |                 |  POST token_endpoint             |
  |            |                 |  with upstream_token             |
  |            |                 |--------------------------------->|
  |            |                 |                 |                |
  |            |                 |  202 Accepted                    |
  |            |                 |  require=interaction;            |
  |            |                 |  code=WXYZ                       |
  |            |                 |<---------------------------------|
  |            |                 |                 |                |
  |            |  202 Accepted   |                 |                |
  |            |  Location: /pending/xyz           |                |
  |            |  AAuth-Challenge: require=interaction;      |                |
  |            |         code="MNOP"               |                |
  |            |<----------------|                 |                |
  |            |                 |                 |                |
  |  direct to R1                |                 |                |
  |  interaction_endpoint        |                 |                |
  |  with code |                 |                 |                |
  |<-----------|                 |                 |                |
  |            |                 |                 |                |
  |  interaction_endpoint        |                 |                |
  |----------------------------->|                 |                |
  |            |                 |                 |                |
  |  redirect to AS2 interaction_endpoint          |                |
  |<-----------------------------|                 |                |
  |            |                 |                 |                |
  |  authenticate and consent    |                 |                |
  |---------------------------------------------------------------->|
  |            |                 |                 |                |
  |  redirect to R1 callback     |                 |                |
  |<----------------------------------------------------------------|
  |            |                 |                 |                |
  |            |            [R1 polls AS2 pending URL,              |
  |            |             receives auth_token for R2]            |
  |            |                 |                 |                |
  |            |                 |  HTTPSig req    |                |
  |            |                 |  (auth_token    |                |
  |            |                 |   from AS2)     |                |
  |            |                 |---------------->|                |
  |            |                 |                 |                |
  |            |                 |  200 OK         |                |
  |            |                 |<----------------|                |
  |            |                 |                 |                |
  |  redirect to agent callback_url                |                |
  |<-----------------------------|                 |                |
  |            |                 |                 |                |
  |  callback  |                 |                 |                |
  |----------->|                 |                 |                |
  |            |                 |                 |                |
  |            |  GET /pending/xyz                 |                |
  |            |---------------->|                 |                |
  |            |                 |                 |                |
  |            |  200 OK         |                 |                |
  |            |<----------------|                 |                |
  |            |                 |                 |                |
~~~

# Identifier and URL Requirements

## Server Identifiers

The `agent`, `resource`, and `issuer` values that identify agents, resources, and auth servers MUST conform to the following:

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

Implementations MUST perform exact string comparison on server identifiers. The lowercase and ACE requirements ensure that normalization happens at the source rather than requiring comparison logic at every point of use.

## Endpoint URLs

The `token_endpoint`, `interaction_endpoint`, `resource_token_endpoint`, and `callback_endpoint` values MUST conform to the following:

- MUST use the `https` scheme
- MUST NOT contain a fragment
- MUST NOT contain a query string

When `localhost_callback_allowed` is `true` in the agent's metadata, the agent MAY use a localhost callback URL as the `callback` parameter to the interaction endpoint. Localhost callback URLs MUST use the `http` scheme with a loopback address (`127.0.0.1`, `[::1]`, or `localhost`), MUST include a port, MAY include a path, and MUST NOT contain a query string or fragment.

## Other URLs

The `jwks_uri`, `tos_uri`, `policy_uri`, `logo_uri`, and `logo_dark_uri` values MUST use the `https` scheme.

# AAuth-Challenge HTTP Response Header

Servers use the `AAuth-Challenge` response header to indicate authentication and interaction requirements. The header value is a Structured Fields Dictionary ([@!RFC8941]) with a `require` key whose token value indicates the requirement level. Additional parameters provide context for the requirement.

## Pseudonym Required

When a resource requires only a signed request:

```http
HTTP/1.1 401 Unauthorized
AAuth-Challenge: require=pseudonym
```

## Identity Required

When a resource requires verified agent identity:

```http
HTTP/1.1 401 Unauthorized
AAuth-Challenge: require=identity
```

## Auth Token Required

When a resource requires an auth token:

```http
HTTP/1.1 401 Unauthorized
AAuth-Challenge: require=auth-token; resource-token="..."; auth-server="https://auth.example"
```

Parameters:

- `resource-token`: A resource token binding this request to the resource's identity
- `auth-server`: The auth server URL where the agent should obtain an auth token

## Interaction Required

When a server requires user interaction, it returns `202 Accepted` per the Deferred Responses protocol with an `AAuth-Challenge` header and a JSON body:

```http
HTTP/1.1 202 Accepted
Location: /pending/res_abc123
Retry-After: 0
Cache-Control: no-store
AAuth-Challenge: require=interaction; code="ABCD1234"
Content-Type: application/json

{
  "status": "pending",
  "location": "/pending/res_abc123",
  "require": "interaction",
  "code": "ABCD1234"
}
```

The `code` field is REQUIRED when `require` is `"interaction"`. The agent MUST direct the user to the server's `interaction_endpoint` with the code and poll the `Location` URL with `GET` for the result.

## Approval Pending

When the auth server is obtaining approval directly — from a user (e.g., push notification, existing session) — without the agent's involvement:

```http
HTTP/1.1 202 Accepted
Location: /pending/res_def456
AAuth-Challenge: require=approval
Retry-After: 0
Cache-Control: no-store
Content-Type: application/json

{
  "status": "pending",
  "location": "/pending/res_def456",
  "require": "approval"
}
```

The agent knows the request is waiting on external approval but does not need to take any action. The agent polls the `Location` URL until the request resolves.

## Interaction Started

When the user has arrived at the interaction endpoint and interaction is in progress, the server returns `202 Accepted` with `status=interacting` on a polling response:

```http
HTTP/1.1 202 Accepted
Location: /pending/res_abc123
Retry-After: 5
Cache-Control: no-store
Content-Type: application/json

{
  "status": "interacting",
  "location": "/pending/res_abc123"
}
```

This signals the agent that the user has begun the interaction flow. The agent SHOULD stop prompting the user to visit the interaction endpoint (e.g., stop displaying the code or QR code) and simply poll the `Location` URL until the request resolves.

A server transitions from `status=pending` to `status=interacting` when the user presents the interaction code at the interaction endpoint. The server MAY continue returning `status=pending` with `require=interaction` if it does not track whether the user has arrived.

# AAuth-Session HTTP Request Header

The `AAuth-Session` header conveys the session identifier to a server when the
request does not already carry `aauth_sid` in a token. An agent MUST NOT
include `AAuth-Session` if the request includes a token that contains an
`aauth_sid` claim — the claim in the token is authoritative and the header
would be redundant.

The agent server SHOULD include `AAuth-Session` on requests to both auth
servers and resources whenever `aauth_sid` is not already present in a token
being sent with the request. This ensures that resources can correlate session
activity even on pseudonymous or identity-only requests where no auth token is
present.

```http
AAuth-Session: sess_7f3a9b2c
```

The value MUST be an opaque string assigned by the agent server. The
`AAuth-Session` header MUST be included in the covered components of the HTTP
Message Signature when present.

# Agent Tokens

Agent tokens enable agent servers to delegate signing authority to agent delegates while maintaining a stable agent identity.

## Agent Token Structure

An agent token is a JWT with `typ: agent+jwt` containing:

Header:
- `alg`: Signing algorithm
- `typ`: `agent+jwt`
- `kid`: Key identifier

Required payload claims:
- `iss`: Agent server URL (the agent identifier)
- `sub`: Agent delegate identifier (stable across key rotations)
- `jti`: Unique token identifier for replay detection and audit
- `cnf`: Confirmation claim ([@!RFC7800]) with `jwk` containing the delegate's public key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

Optional payload claims:
- `aud`: Audience restriction. When present, the agent delegate MUST only present this agent token to the specified server(s). The value is a single URL or an array of URLs identifying the auth server(s) or resource(s) where this token is valid. Servers receiving an agent token with an `aud` claim MUST verify that their own identifier is listed.
- `aud_sub`: The user identifier (`sub` value) from a previous auth token issued by the auth server in `aud`. This signals to the auth server which user the agent server believes the delegate is acting on behalf of, enabling the auth server to skip interactive identification and proceed directly to authorization. The auth server MUST verify this claim against its own records and MAY ignore it if the binding is no longer valid.
- `aauth_sid`: Session identifier assigned by the agent server. When present, the auth server MUST copy this value unchanged into every auth token issued in response to this request.

When `aud` is absent, the agent token establishes agent identity across all interactions — the delegate uses the same agent token regardless of which resource or auth server it communicates with. When `aud` is present, the agent server is restricting the delegate to specific interactions, which limits exposure if the delegate's key is compromised.

Agent servers MAY include additional claims in the agent token to convey attestation evidence about the delegate's environment — for example, platform integrity, secure enclave status, or workload identity assertions. The semantics and verification of such claims are outside the scope of this specification but provide an extension point for deployments requiring stronger trust signals about agent delegates.

## Agent Token Usage

Agent delegates present agent tokens via the `Signature-Key` header using `scheme=jwt`:

```http
Signature-Key: sig=jwt; jwt="eyJhbGciOiJFZERTQSIsInR5cCI6ImFnZW50K2p3dCJ9..."
```

# Resource Tokens

Resource tokens provide cryptographic proof of resource identity, preventing confused deputy and MITM attacks.

## Resource Token Structure

A resource token is a JWT with `typ: resource+jwt` containing:

Header:
- `alg`: Signing algorithm
- `typ`: `resource+jwt`
- `kid`: Key identifier

Payload:
- `iss`: Resource URL
- `aud`: Auth server URL
- `jti`: Unique token identifier for replay detection and audit
- `agent`: Agent identifier
- `agent_jkt`: JWK Thumbprint ([@!RFC7638]) of the agent's current signing key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp
- `scope`: Requested scopes (optional)
- `txn`: Transaction identifier (optional). When present, correlates this resource token with the resulting auth token and all related protocol exchanges across parties and audit logs.

## Resource Token Usage

Resources include resource tokens in the `AAuth-Challenge` header when requiring authorization:

```http
AAuth-Challenge: require=auth-token; resource-token="eyJ..."; auth-server="https://auth.example"
```

## Resource Token Endpoint

When a resource publishes a `resource_token_endpoint` in its metadata, agents MAY request a resource token proactively — without first making an API call and receiving a `401` challenge. This enables two patterns:

- **Pre-authorization**: The agent knows the scopes it needs (from the resource's `scope_descriptions` metadata) and obtains authorization before making its first API call.
- **Scope upgrade**: The agent already has an auth token but needs additional scopes. It requests a new resource token with the broader scope, obtains a new auth token, and retries.

**Request:**

```http
POST /resource-token HTTP/1.1
Host: resource.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "scope": "data.read data.write"
}
```

**Response:**

```json
{
  "resource_token": "eyJhbGc...",
  "auth_server": "https://auth.example",
  "scope": "data.read data.write"
}
```

The resource generates and signs a resource token and returns it along with the auth server URL and the granted scope. The `scope` in the response reflects what the resource included in the resource token, which MAY be narrower than what was requested. The agent then proceeds to the auth server's token endpoint as in the standard flow.

The resource MAY reject the request if the requested scopes are invalid or if the resource does not support proactive token requests for the given scopes:

```json
{
  "error": "invalid_scope",
  "error_description": "Unknown scope: data.admin"
}
```

# Auth Tokens

Auth tokens grant agents access to resources after authentication and authorization.

## Auth Token Structure

An auth token is a JWT with `typ: auth+jwt` containing:

Header:
- `alg`: Signing algorithm
- `typ`: `auth+jwt`
- `kid`: Key identifier

Required payload claims:
- `iss`: Auth server URL
- `aud`: The URL of the resource the agent is authorized to access. When the agent is accessing its own resources (SSO or first-party use), the `aud` is the agent server's URL.
- `jti`: Unique token identifier for replay detection and audit
- `agent`: Agent identifier
- `cnf`: Confirmation claim with `jwk` containing the agent's public key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

Conditional payload claims (at least one MUST be present):
- `sub`: User identifier
- `scope`: Authorized scopes

Conditional payload claims (REQUIRED when present in the resource token):
- `txn`: Transaction identifier copied from the resource token's `txn` claim. Enables correlation of the authorization grant with the original resource request across all parties and audit logs.
- `aauth_sid`: Session identifier. REQUIRED when the agent token contains an `aauth_sid` claim or when the request included an `AAuth-Session` header. The auth server MUST copy this value unchanged from the agent token claim or the `AAuth-Session` header into the auth token. MUST be carried forward unchanged on every token refresh.

**Editor's Note:** A future version may define a URI-based authorization claim (referencing a Rich Authorization Request document with a SHA-256 hash of the contents) as an alternative to scope.

The auth token MAY include additional claims registered in the IANA JSON Web Token Claims Registry [@!RFC7519] or defined in OpenID Connect Core 1.0 [@OpenID.Core] Section 5.1.

## Auth Token Usage

Agents present auth tokens via the `Signature-Key` header using `scheme=jwt`:

```http
Signature-Key: sig=jwt; jwt="eyJhbGciOiJFZERTQSIsInR5cCI6ImF1dGgrand0In0..."
```

# Deferred Responses

Any endpoint in AAuth — whether an auth server token endpoint or a resource endpoint — MAY return a `202 Accepted` response ([@!RFC9110]) when it cannot immediately resolve a request. This is a first-class protocol primitive, not a special case. Agents MUST handle `202` responses regardless of the nature of the original request.

Reasons a `202` MAY be returned include:

- Human approval or interaction is required
- Long-running computation or downstream processing
- Authorization is pending evaluation

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

The `wait` preference tells the server the agent is willing to hold the connection open for up to N seconds before the server MUST respond. The server confirms the honored duration with `Preference-Applied`:

```http
Preference-Applied: wait=45
```

The server SHOULD respond within the requested wait duration. If the request cannot be resolved within that time, it returns a `202`.

## Pending Response

When the server cannot resolve the request within the wait period:

```http
HTTP/1.1 202 Accepted
Location: /pending/f7a3b9c
Retry-After: 0
Cache-Control: no-store
Content-Type: application/json

{
  "status": "pending",
  "location": "/pending/f7a3b9c"
}
```

Headers:

- `Location` (REQUIRED): The pending URL. The server embeds its state in the URL path. The `Location` URL MUST be on the same origin as the responding server.
- `Retry-After` (REQUIRED): Seconds the agent SHOULD wait before polling. `0` means retry immediately.
- `Cache-Control: no-store` (REQUIRED): Prevents caching of pending responses.

Every `202` response MUST include a `Location` header, making each response self-contained.

Body fields:

- `status` (REQUIRED): `"pending"` while the request is waiting. `"interacting"` when the user has arrived at the interaction endpoint and interaction is in progress — the agent SHOULD stop prompting the user and simply poll. Agents MUST treat unrecognized `status` values as `"pending"` and continue polling.
- `location` (REQUIRED): The pending URL (echoes the `Location` header).
- `require` (OPTIONAL): The requirement level. `"interaction"` when the agent must direct the user to an interaction endpoint (with `code`). `"approval"` when the auth server is obtaining approval directly from a user.
- `code` (OPTIONAL): The interaction code. Present only with `require: "interaction"`. The agent MUST direct the user to the server's `interaction_endpoint` with this code.
- `clarification` (OPTIONAL): A question from the user during consent. Present during clarification chat.

## Polling with GET

After receiving a `202`, the agent switches to `GET` for all subsequent requests to the `Location` URL:

```http
GET /pending/f7a3b9c HTTP/1.1
Host: auth.example
Prefer: wait=45
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."
```

- The agent does NOT resend the original request body
- The `Location` URL contains all state the server needs
- The agent SHOULD include `Prefer: wait=N` on every poll
- While still pending, the server responds with `202` including the same `Location`
- **Exception**: During clarification chat, the agent uses `POST` to deliver a clarification response to the pending URL (#clarification-chat). This is the only case where the agent sends a non-`GET` request to a pending URL.

The distinction between POST and GET is intentional:

- **POST** — "here is my request, process this" — creates the pending context
- **GET** — "give me the result" — idempotent, safe to retry on network failure

## Terminal Responses

A non-`202` response terminates polling. The agent MUST stop polling and handle the response.

| Status | Meaning | Agent Behavior |
|--------|---------|----------------|
| `200` | Success | Process response body |
| `403` | Denied or abandoned | Surface to user; check `error` field |
| `408` | Expired | MAY initiate a fresh request |
| `410` | Gone — permanently invalid | MUST NOT retry |
| `500` | Internal server error | Start over |

Once a terminal response is returned, the `Location` URL is no longer valid. Subsequent `GET` requests to it MUST return `404`.

## Transient Non-Terminal Responses

| Status | Meaning | Agent Behavior |
|--------|---------|----------------|
| `202` | Pending | Continue polling with `Prefer: wait` |
| `503` | Server temporarily unavailable | Back off using `Retry-After`; MUST honor over `Prefer: wait` |

Error responses during deferred processing use the standard error response format defined in the Error Responses section.

## Agent State Machine

```
Initial POST (with Prefer: wait=N)
    |
    +-- 200 --> done (direct grant)
    +-- 202 --> note Location URL, check require/code
    +-- 400 --> invalid_request or invalid_resource_token — fix and retry
    +-- 401 --> invalid_signature — check credentials
    +-- 500 --> server_error — start over
    +-- 503 --> back off (Retry-After), retry
               |
               GET Location (with Prefer: wait=N)
               |
               +-- 200 --> done
               +-- 202 --> continue polling (check status and clarification)
               |           status=interacting → stop prompting user
               +-- 403 --> denied or abandoned — surface to user
               +-- 408 --> expired — MAY retry with fresh request
               +-- 410 --> invalid_code — do not retry
               +-- 500 --> server_error — start over
               +-- 503 --> temporarily_unavailable — back off (Retry-After)
```

# Token Endpoint

The auth server's `token_endpoint` is the endpoint for initiating authorization requests and refreshing auth tokens. Polling and clarification use the pending URL returned in `202` responses (#deferred-responses).

## Token Endpoint Modes

The token endpoint serves multiple functions depending on the parameters provided:

| Mode | Key Parameters | Use Case |
|------|----------------|----------|
| Resource access | `resource_token` | Agent needs auth token for a resource |
| Self-access (SSO/1P) | `scope` (no `resource_token`) | Agent needs auth token for itself |
| Call chaining | `resource_token` + `upstream_token` | Resource acting as agent |
| Token refresh | `auth_token` (expired) | Renew expired token |

## Authorization Request

The agent makes a signed POST to the `token_endpoint` to initiate an authorization request.

**Request parameters:**

- `resource_token` (CONDITIONAL): The resource token from a resource's AAuth challenge or from the resource's `resource_token_endpoint` (#resource-token-endpoint). Required when requesting access to another resource.
- `scope` (CONDITIONAL): Space-separated scope values. Used when the agent requests authorization to itself (agent is resource).
- `upstream_token` (OPTIONAL): An auth token from an upstream authorization, used in call chaining when a resource acts as an agent to access a downstream resource. Allows the auth server to verify the authorization chain.
- `purpose` (OPTIONAL): Human-readable string declaring why access is being requested.
- `login_hint` (OPTIONAL): Hint about who to authorize, per [@OpenID.Core] Section 3.1.2.1.
- `tenant` (OPTIONAL): Tenant identifier, per OpenID Connect Enterprise Extensions 1.0 [@OpenID.Enterprise].
- `domain_hint` (OPTIONAL): Domain hint, per OpenID Connect Enterprise Extensions 1.0 [@OpenID.Enterprise].

**Editor's Note:** Future drafts may define additional parameters to indicate how the auth server should process the request, such as authentication strength requirements.

**Example request:**
```http
POST /token HTTP/1.1
Host: auth.example
Content-Type: application/json
Prefer: wait=45
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "resource_token": "eyJhbGc...",
  "purpose": "Find available meeting times"
}
```

## Auth Server Response

The auth server validates the request and responds based on policy.

**Direct grant response** (`200` — no user interaction needed):
```json
{
  "auth_token": "eyJhbGc...",
  "expires_in": 3600
}
```

**User interaction required response** (`202` — deferred):
```http
HTTP/1.1 202 Accepted
Location: /pending/abc123
Retry-After: 0
Cache-Control: no-store
AAuth-Challenge: require=interaction; code="ABCD1234"
Content-Type: application/json

{
  "status": "pending",
  "location": "/pending/abc123",
  "require": "interaction",
  "code": "ABCD1234"
}
```

The `location` field contains the pending URL the agent polls with `GET`. When `require` is `"interaction"`, the agent directs the user to the auth server's `interaction_endpoint` with the `code`. When `require` is `"approval"`, the auth server is obtaining approval directly from a user and the agent simply polls.

**Error response** (request validation failed):
```json
{
  "error": "invalid_resource_token",
  "error_description": "Resource token has expired"
}
```

See Token Endpoint Error Codes in the Error Responses section for the full set of error codes.

Polling, terminal responses, and error handling follow the Deferred Responses protocol described above.

## Clarification Chat

Agents that support clarification chat MUST declare `"clarification_supported": true` in their agent server metadata. Auth servers SHOULD only send clarification questions to agents that declare support. If the field is absent or `false`, the auth server MUST NOT include `clarification` in polling responses.

During user consent, the user may ask questions about the agent's stated purpose. The auth server delivers these questions to the agent, and the agent responds:

~~~ ascii-art
User                  Agent                     Auth Server
  |                     |                            |
  |      [Agent has Location URL;                    |
  |       user is at interaction_endpoint]           |
  |                     |                            |
  |                     |  GET /pending/abc          |
  |                     |  Prefer: wait=45           |
  |                     |--------------------------->|
  |                     |       [connection held open]
  |                     |                            |
  |  "Why do you need calendar access?"              |
  |------------------------------------------------->|
  |                     |                            |
  |                     |  202 with clarification    |
  |                     |  "Why do you need          |
  |                     |   calendar access?"        |
  |                     |<---------------------------|
  |                     |                            |
  |                     |  POST /pending/abc         |
  |                     |  "I need to find           |
  |                     |   available meeting        |
  |                     |   times for your           |
  |                     |   Tokyo trip next week"    |
  |                     |--------------------------->|
  |                     |                            |
  |  display agent response                          |
  |<-------------------------------------------------|
  |                     |                            |
  |  grant consent      |                            |
  |------------------------------------------------->|
  |                     |                            |
  |                     |  GET /pending/abc          |
  |                     |  Prefer: wait=45           |
  |                     |--------------------------->|
  |                     |  200 OK, auth_token        |
  |                     |<---------------------------|
  |                     |                            |
~~~

A `202` polling response may include a `clarification` field containing the user's question:

```json
{
  "status": "pending",
  "location": "/pending/abc123",
  "clarification": "Why do you need access to my calendar?"
}
```

The agent responds by POSTing JSON with `clarification_response` to the pending URL:

```http
POST /pending/abc123 HTTP/1.1
Host: auth.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "clarification_response": "I need to find available meeting times for your Tokyo trip next week"
}
```

Auth servers SHOULD enforce limits on clarification rounds (recommended: 5 rounds maximum) and overall timeout to prevent abuse.

## User Interaction

When a server responds with `202` and `AAuth-Challenge: require=interaction; code="..."`, the agent directs the user to the server's `interaction_endpoint` with the interaction code. The agent has three options:

**Manual entry**: Display the `interaction_endpoint` and the code separately. The agent MAY insert hyphens into the code for readability (e.g., `ABCD-1234`). The code itself MUST NOT contain hyphens.

**QR code**: Encode the full URL for scanning:
```
{interaction_endpoint}?code={interaction_code}
```

**Direct redirect** (when the agent has a browser): Navigate the user directly, optionally with a callback:
```
{interaction_endpoint}?code={interaction_code}&callback={callback_url}
```

**Example redirect URL:**
```
https://auth.example/interact?code="ABCD1234"&callback=https%3A%2F%2Fagent.example%2Fcallback%3Fstate%3Dabc123
```

The server authenticates the user and displays consent information (including the agent's `purpose`, identity, and requested scopes).

**After consent, the server determines the callback behavior:**

If the agent provided a `callback` parameter, the server redirects the user to that URL:

```http
HTTP/1.1 303 See Other
Location: https://agent.example/callback?state=abc123
```

If no `callback` was provided, the server displays a completion page telling the user they may close the window.

## Third-Party Initiated Login

When a third party directs a user to the agent's `login_endpoint`, the agent initiates a standard "agent as audience" login flow with the specified auth server.

**Login endpoint parameters:**

- `issuer` (REQUIRED): The auth server URL. The agent MUST verify this is a valid auth server by fetching its metadata at `/.well-known/aauth-issuer.json`.
- `domain_hint` (OPTIONAL): Domain hint, per OpenID Connect Enterprise Extensions 1.0 [@OpenID.Enterprise].
- `tenant` (OPTIONAL): Tenant identifier, per OpenID Connect Enterprise Extensions 1.0 [@OpenID.Enterprise].
- `start_path` (OPTIONAL): Path on the agent's origin where the user should be directed after login completes. The agent MUST validate that `start_path` is a relative path on its own origin.

**Example login URL:**
```
https://agent.example/login?issuer=https://auth.example&tenant=corp&start_path=/projects/tokyo-trip
```

Upon receiving a request at its `login_endpoint`, the agent:

1. Validates the `issuer` by fetching the auth server's metadata.
2. POSTs to the auth server's `token_endpoint` with `scope` and any provided `domain_hint` or `tenant` parameters.
3. Proceeds with the standard deferred response flow — directing the user to the auth server's `interaction_endpoint` with the interaction code.
4. After obtaining the auth token, redirects the user to `start_path` if provided, or to the agent's default landing page.

If the user is already authenticated at the auth server, the interaction step resolves near-instantly — the auth server recognizes the user from its own session. If not, the user completes a normal authentication and consent flow.

## Token Refresh

When an auth token expires, the agent requests a new one by presenting the expired auth token.

**Request:**
```http
POST /token HTTP/1.1
Host: auth.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "auth_token": "eyJhbGc..."
}
```

**Response:**
```json
{
  "auth_token": "eyJhbGc...",
  "expires_in": 3600
}
```

The auth server verifies the agent's HTTP signature, validates the expired auth token, and issues a new auth token. The auth server MAY reject the refresh if the token has been expired beyond its refresh window.

The auth server MUST carry the `aauth_sid` claim forward unchanged from the expired auth token into the newly issued auth token.

# Agent Delegate User Binding

An agent delegate SHOULD be associated with at most one user. The auth server tracks the association between an agent delegate (identified by the `sub` claim in the agent token) and the user who authorized it. The user may be anonymous to the agent and to the resource, but the auth server always knows who authorized the delegate.

This association enables:

- **Re-authorization for long-running tasks**: When an agent delegate needs to refresh an expired auth token or re-authorize access, the auth server can associate the request with the original authorizing user without requiring a new interactive flow.
- **Organizational authorization**: In enterprise contexts, any authorized person within a tenant can approve access for the agent delegate. The auth server tracks which user authorized the delegate, but the agent need not know the user's identity.
- **Audit trail**: The auth server maintains a record of which user authorized which agent delegate, enabling compliance and security review.

# Observability

## Session Identifier

The session identifier (`aauth_sid`) provides end-to-end correlation across all
authorization events within an agent session. Session boundaries are determined
by the agent server — the agent server assigns `aauth_sid` and decides when a
new session begins.

The agent server conveys `aauth_sid` to servers in exactly one of two ways per
request, never both simultaneously:

- As the `aauth_sid` claim in the agent token, when an agent token is included
  in the request
- As the `AAuth-Session` request header, when no token carrying `aauth_sid` is
  included in the request

The auth server copies `aauth_sid` into every auth token issued during the
session and records it in the audit log alongside every token issuance event.

Because `aauth_sid` travels in every auth token, every resource the agent
accesses within the session receives it. On pseudonymous and identity-only
requests — where no auth token is present — the `AAuth-Session` header conveys
the session identifier directly to the resource.

This enables:

- **Resource-side correlation**: Resources can associate all requests from a
  session without maintaining their own session state.
- **Auth server audit**: A complete log of all tokens issued in a session is
  queryable by `aauth_sid`.
- **Cross-party tracing**: Operators can reconstruct which agent did what, in
  which session, using which authorization, by joining on `aauth_sid` across
  auth server and resource logs.

### Session Identifier Format

`aauth_sid` is an opaque string. Servers MUST NOT interpret its structure. The
agent server SHOULD generate `aauth_sid` using at least 128 bits of
cryptographically random entropy.

Recommended format: a URL-safe prefix followed by a base64url-encoded random
value without padding, for example `sess_` followed by 22 base64url characters
representing 16 random bytes.

### Relationship to `jti`

`aauth_sid` and `jti` serve complementary but distinct purposes:

| Claim | Assigned by | Scope | Purpose |
|-------|-------------|-------|---------|
| `aauth_sid` | Agent server | Session — spans many tokens and many resources | Correlate all activity within a session |
| `jti` | Token issuer | Token — one specific token | Replay detection; uniquely identify a token |

`aauth_sid` answers "what happened in this session across all resources and
tokens". `jti` answers "has this exact token been seen before". Both SHOULD be
recorded in audit logs. Joining on `aauth_sid` across auth server and resource
logs reconstructs the full session history; `jti` values within that history
identify the specific tokens authorizing each action.

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
  "login_endpoint": "https://agent.example/login",
  "callback_endpoint": "https://agent.example/callback",
  "localhost_callback_allowed": true,
  "clarification_supported": true,
  "tos_uri": "https://agent.example/tos",
  "policy_uri": "https://agent.example/privacy"
}
```

Fields:

- `agent` (REQUIRED): The agent's HTTPS URL
- `jwks_uri` (REQUIRED): URL to the agent's JSON Web Key Set
- `client_name` (OPTIONAL): Human-readable agent name (per [@RFC7591])
- `logo_uri` (OPTIONAL): URL to agent logo (per [@RFC7591])
- `logo_dark_uri` (OPTIONAL): URL to agent logo for dark backgrounds
- `login_endpoint` (OPTIONAL): URL where third parties direct users to initiate a login flow at the agent. Accepts `issuer` (REQUIRED), `domain_hint` (OPTIONAL), `tenant` (OPTIONAL), and `start_path` (OPTIONAL) as query parameters. If absent, the agent does not support third-party initiated login.
- `callback_endpoint` (OPTIONAL): The agent's HTTPS callback endpoint URL. The agent MAY append path and query parameters at runtime to construct the callback URL — any URL on the same origin is valid. If absent, the agent does not support callbacks.
- `localhost_callback_allowed` (OPTIONAL): Boolean indicating whether the agent supports localhost callbacks (for CLI tools and desktop applications). Default: `false`. When `true`, any `http` URL with a loopback address (`127.0.0.1`, `[::1]`, or `localhost`) and a port is permitted as a callback URL at runtime.
- `clarification_supported` (OPTIONAL): Boolean indicating whether the agent supports clarification chat during consent. Default: `false`.
- `tos_uri` (OPTIONAL): URL to terms of service (per [@RFC7591])
- `policy_uri` (OPTIONAL): URL to privacy policy (per [@RFC7591])

## Auth Server Metadata

Published at `/.well-known/aauth-issuer.json`:

```json
{
  "issuer": "https://auth.example",
  "token_endpoint": "https://auth.example/token",
  "interaction_endpoint": "https://auth.example/interact",
  "jwks_uri": "https://auth.example/.well-known/jwks.json"
}
```

Fields:

- `issuer` (REQUIRED): The auth server's HTTPS URL
- `token_endpoint` (REQUIRED): Single endpoint for all agent-to-auth-server communication
- `interaction_endpoint` (REQUIRED): URL where users are sent for authentication and consent
- `jwks_uri` (REQUIRED): URL to the auth server's JSON Web Key Set

## Resource Metadata

Published at `/.well-known/aauth-resource.json`:

```json
{
  "resource": "https://resource.example",
  "jwks_uri": "https://resource.example/.well-known/jwks.json",
  "client_name": "Example Data Service",
  "logo_uri": "https://resource.example/logo.png",
  "logo_dark_uri": "https://resource.example/logo-dark.png",
  "resource_token_endpoint": "https://resource.example/resource-token",
  "interaction_endpoint": "https://resource.example/interact",
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
- `resource_token_endpoint` (OPTIONAL): URL where agents can proactively request a resource token for specific scopes without first making an API call. See Resource Token Endpoint.
- `interaction_endpoint` (OPTIONAL): URL where users are sent for resource-level interaction
- `scope_descriptions` (OPTIONAL): Object mapping scope names to human-readable descriptions, for the auth server to use in consent UI
- `additional_signature_components` (OPTIONAL): Additional HTTP message components that must be covered in signatures

# Purpose

The `purpose` parameter is an optional human-readable string that an agent passes to the auth server when requesting an auth token. It declares why access is being requested, providing context for authorization decisions without requiring the auth server or resource to evaluate or enforce the stated purpose.

## Usage

When an agent requests an auth token from the auth server, it MAY include a `purpose` parameter that describes the reason for the access request in terms meaningful to the authorizing user.

The auth server SHOULD present the `purpose` value to the user during consent. The auth server MAY log the `purpose` for audit and monitoring purposes. The `purpose` is also available to the user during clarification chat.

## Security Considerations for Purpose

The `purpose` parameter enables an agent to provide context for a request that is part of a larger task initiated earlier. A user may have numerous outstanding tasks managed by different agents, and the purpose helps the user understand which task triggered a particular authorization request. For example:

- "Find available meeting times for your Tokyo trip next week" — links calendar access to a specific travel-planning task
- "Summarize the Q3 revenue spreadsheet you shared yesterday" — links file access to a prior document review
- "Check inventory levels for the restock order you approved this morning" — links supply chain data access to an earlier purchasing decision
- "Update your project timeline based on the delay Bob reported" — links project management access to a team communication context

Without purpose, the user sees only "Agent X wants calendar.read" with no way to distinguish which of their active tasks prompted the request.

The `purpose` parameter is self-asserted by the requesting agent or application. Auth servers and users SHOULD treat it as informational context, not as a trusted assertion. A malicious agent could declare a benign purpose while intending harmful actions.

However, the declared purpose creates accountability. If an agent declares its purpose is to "find available meeting times" but then reads email content, the discrepancy between declared purpose and actual behavior is detectable by monitoring systems.

# HTTP Message Signing Profile

AAuth uses HTTP Message Signatures ([@!RFC9421]) for request authentication.

## Required Headers

All AAuth requests MUST include:

- `Signature-Key`: Public key or key reference for signature verification
- `Signature-Input`: Signature metadata including covered components
- `Signature`: The HTTP message signature

## Signature-Key Header

The `Signature-Key` header ([@!I-D.hardt-httpbis-signature-key]) provides keying material:

- `scheme=hwk`: Header Web Key (inline public key)
- `scheme=jwks_uri`: Reference to JWKS endpoint
- `scheme=jwt`: JWT containing public key in `cnf` claim
- `scheme=x509`: X.509 certificate

## Covered Components

HTTP Message Signatures in AAuth MUST cover:

- `@method`: HTTP method
- `@authority`: Target host
- `@path`: Request path
- `signature-key`: The Signature-Key header value

Resources MAY require additional components via `additional_signature_components` in metadata.

- `aauth-session`: The `AAuth-Session` header. MUST be included in the covered components when the `AAuth-Session` header is present in the request.

## Signature Parameters

The `Signature-Input` header MUST include:

- `created`: Signature creation timestamp (Unix time)

The `created` timestamp MUST NOT be more than 60 seconds in the past or future.

# Request Verification

When a server (resource or auth server) receives a signed request, it MUST perform the following verification steps. Any failure MUST result in a `401` response with the appropriate error code.

## HTTP Signature Verification

1. Extract the `Signature`, `Signature-Input`, and `Signature-Key` headers. If any are missing, return `invalid_signature`.
2. Verify that the `Signature-Input` covers the required components: `@method`, `@authority`, `@path`, and `signature-key`. If the resource requires additional components via `additional_signature_components`, verify those are covered as well.
3. Verify the `created` parameter is present and within 60 seconds of the current time. Reject if outside this window.
4. Obtain the public key from the `Signature-Key` header according to the scheme:
   - `scheme=hwk`: Use the inline public key.
   - `scheme=jwks_uri`: Fetch the JWKS from the specified URI and select the key matching the signature's `keyid`.
   - `scheme=jwt`: Extract the public key from the JWT's `cnf` claim (#jwt-verification).
   - `scheme=x509`: Extract the public key from the certificate.
5. Verify the HTTP Message Signature ([@!RFC9421]) using the obtained public key.

## JWT Verification

When a request includes a JWT (agent token or auth token) via `scheme=jwt`, the server MUST verify the JWT per [@!RFC7515] and [@!RFC7519]:

1. Decode the JWT header. Verify `typ` matches the expected token type (`agent+jwt` or `auth+jwt`).
2. Verify the JWT signature using the issuer's public key, obtained by fetching the issuer's JWKS from `jwks_uri` in the issuer's metadata and selecting the key matching the JWT's `kid` header parameter. Keys are JSON Web Keys as defined in [@!RFC7517].
3. Verify the `exp` claim is in the future. Verify the `iat` claim is not in the future.
4. **Key binding**: Verify that the public key in the JWT's `cnf` claim ([@!RFC7800]) matches the key used to sign the HTTP request. This binds the JWT to the request signer.

### Agent Token Verification

When verifying an agent token (`typ: agent+jwt`):

1. Perform JWT Verification above using the agent server's JWKS (fetched from `jwks_uri` in `/.well-known/aauth-agent.json` at the `iss` URL).
2. Verify `iss` is a valid HTTPS URL conforming to the Server Identifier requirements.
3. Verify the `cnf.jwk` matches the key used to sign the HTTP request.
4. If `aud` is present, verify that the server's own identifier is listed in the `aud` claim. If the server's identifier is not listed, reject the token.

### Auth Token Verification

When verifying an auth token (`typ: auth+jwt`):

1. Perform JWT Verification above using the auth server's JWKS (fetched from `jwks_uri` in `/.well-known/aauth-issuer.json` at the `iss` URL).
2. Verify `iss` is a valid HTTPS URL conforming to the Server Identifier requirements.
3. Verify `aud` matches the resource's own identifier (or the agent's identifier for self-access tokens).
4. Verify `agent` matches the agent identifier from the request's signing context.
5. Verify `cnf.jwk` matches the key used to sign the HTTP request.
6. Verify that at least one of `sub` or `scope` is present.

### Resource Token Verification

When an auth server receives a resource token (`typ: resource+jwt`) in a token request:

1. Perform JWT Verification above using the resource's JWKS (fetched from `jwks_uri` in `/.well-known/aauth-resource.json` at the `iss` URL).
2. Verify `aud` matches the auth server's own identifier.
3. Verify `agent` matches the requesting agent's identifier.
4. Verify `agent_jkt` ([@!RFC7638]) matches the JWK Thumbprint of the key used to sign the HTTP request.
5. Verify `exp` is in the future.
6. Verify `jti` has not been seen before (replay detection). The auth server SHOULD maintain a cache of seen `jti` values for the token's lifetime.
7. If `txn` is present, carry it forward into the issued auth token.

# Response Verification

Agents MUST verify responses from auth servers and resources to prevent token injection and confused deputy attacks.

## Auth Token Response Verification

When an agent receives an auth token from an auth server (either as a direct grant or via polling):

1. Verify the auth token JWT per the JWT Verification steps above, using the auth server's JWKS.
2. Verify `iss` matches the auth server the agent sent the token request to.
3. Verify `aud` matches the resource the agent intends to access (or the agent's own identifier for self-access tokens).
4. Verify `cnf.jwk` matches the agent's own signing key.
5. Verify `agent` matches the agent's own identifier.

## Resource Challenge Verification

When an agent receives a `401` response with `AAuth-Challenge: require=auth-token`:

1. Extract the `resource-token` and `auth-server` parameters from the `AAuth-Challenge` header.
2. Decode the resource token JWT header and verify `typ` is `resource+jwt`.
3. Verify the resource token JWT signature using the resource's JWKS (fetched from `jwks_uri` in `/.well-known/aauth-resource.json`).
4. Verify `iss` matches the resource the agent sent the request to.
5. Verify `agent` matches the agent's own identifier.
6. Verify `agent_jkt` matches the JWK Thumbprint of the agent's signing key.
7. Verify `exp` is in the future.

These checks prevent a malicious intermediary from substituting a different resource token or redirecting the agent to a different auth server.

# Error Responses

AAuth defines error responses for both `401` authentication challenges and deferred response error codes. Token and signature errors use `401` with JSON error bodies. Deferred response errors use standard HTTP status codes with JSON error bodies as defined in the Deferred Responses section.

## Error Response Format

```json
{
  "error": "invalid_request",
  "error_description": "Human-readable description"
}
```

## Authentication Error Codes

These errors are returned as `401` responses to API requests.

### invalid_signature

The HTTP Message Signature is missing, malformed, or verification failed. When the signature is missing required components, the response SHOULD include `required_components`:

```json
{
  "error": "invalid_signature",
  "error_description": "Signature missing required components",
  "required_components": ["@method", "@authority", "@path", "signature-key"]
}
```

### invalid_agent_token

The agent token is missing, malformed, expired, or signature verification failed.

### invalid_resource_token

The resource token is missing, malformed, expired, or signature verification failed.

### invalid_auth_token

The auth token is missing, malformed, expired, or signature verification failed.

### key_binding_failed

The key binding verification failed. The public key used to sign the request does not match the key bound in the token.

## Token Endpoint Error Codes

Errors returned in response to the initial POST to the token endpoint:

| Error | Status | Meaning |
|-------|--------|---------|
| `invalid_request` | 400 | Malformed JSON, missing required fields, or invalid parameter values |
| `invalid_resource_token` | 400 | Resource token is invalid, expired, or malformed |
| `invalid_signature` | 401 | HTTP signature verification failed |
| `invalid_auth_token` | 400 | Expired auth token presented for refresh is invalid or beyond the refresh window |
| `server_error` | 500 | Internal error |

## Polling Error Codes

Errors returned as terminal responses when polling a pending URL:

| Error | Status | Meaning |
|-------|--------|---------|
| `denied` | 403 | User or approver explicitly denied the request |
| `abandoned` | 403 | Interaction code was used but the user did not complete the interaction |
| `expired` | 408 | Timed out — interaction code was never used |
| `invalid_code` | 410 | Interaction code not recognized or already consumed |
| `server_error` | 500 | Internal error |

Agents MUST treat unknown `error` values as fatal.

# Design Rationale

## Why Standard HTTP Async Pattern

AAuth uses standard HTTP async semantics (`202 Accepted`, `Location`, `Prefer: wait`, `Retry-After`) rather than custom polling mechanisms. This pattern:

- **Applies uniformly to all endpoints**: Token endpoint, resource endpoints, and any future endpoints use the same deferred response protocol without per-endpoint async documentation.
- **Aligns with RFC 7240**: The `Prefer: wait` semantics negotiate connection hold duration between agent and server.
- **Enables transparent async upgrades**: Resources that were synchronous can become async (requiring user interaction, long-running computation) without breaking existing agents.
- **Replaces OAuth device flow**: The `Location` URL serves as the device code, `Prefer: wait` replaces the polling interval, and standard status codes replace custom error strings.
- **Supports headless agents**: CLI tools, background services, and IoT devices can obtain authorization without hosting a redirect endpoint.
- **Enables long-running consent**: Complex authorization decisions (enterprise approvals, multi-party consent) can take minutes or hours.
- **Enables clarification chat**: The agent can respond to user questions during consent via the same polling mechanism.
- **Eliminates authorization code interception**: There is no authorization code in the redirect URL to intercept or replay.

## Why No Authorization Code

OAuth 2.0 uses an authorization code as an intermediary: the auth server redirects the user to the client with a code in the URL, and the client exchanges the code for tokens via a back-channel request. This two-step process was designed to prevent tokens from appearing in browser history and server logs. However, authorization codes introduce their own attack surface:

- **Code interception**: Authorization codes pass through the user's browser via URL query parameters, making them vulnerable to interception by malicious browser extensions, open redirectors, or referrer leakage. PKCE mitigates but does not eliminate this risk.
- **Code replay**: Without PKCE, intercepted codes can be replayed. With PKCE, the code is bound to a verifier, but the complexity of correct PKCE implementation has led to widespread deployment errors.
- **Redirect URI validation**: The auth server must validate redirect URIs to prevent code delivery to attacker-controlled endpoints. This validation is a frequent source of security vulnerabilities.

AAuth eliminates authorization codes entirely. The user redirect carries only the callback URL (which the agent chose and may include its own state), which has no security value to an attacker — it cannot be exchanged for tokens. The auth token is delivered exclusively via polling on the pending URL, authenticated by the agent's HTTP Message Signature. This means:

- No sensitive material passes through the user's browser
- No redirect URI validation is needed for token security (callback URLs serve only UX purposes)
- No PKCE-equivalent is needed since there is no code to protect
- Token delivery is authenticated end-to-end between agent and auth server

## Why HTTPSig on Every Request

AAuth requires HTTP Message Signatures on every request to the auth server and resources. This differs from OAuth 2.0 where client authentication is optional or uses separate mechanisms (client secrets, mTLS, DPoP).

- **Message integrity, not just token binding**: HTTPSig covers the HTTP method, path, authority, and optionally body, providing tamper detection that DPoP and mTLS do not offer.
- **Survives proxies and CDNs**: Unlike mTLS which terminates at the first TLS endpoint, HTTPSig signatures survive through proxies, load balancers, and CDNs.
- **No bearer tokens**: Every request proves possession of the signing key. There are no bearer tokens to exfiltrate.
- **Consistent across all auth levels**: The same signing mechanism works for pseudonym, identity, and auth-token requests.

## Why HTTPS-Based Agent Identity

AAuth uses HTTPS URLs as agent identifiers rather than pre-registered client IDs. Agents publish metadata and JWKS at well-known endpoints.

- **Dynamic ecosystems without pre-registration**: Agents can interact with any auth server or resource without prior registration, enabling open ecosystems like MCP.
- **Self-published metadata**: Agent metadata (name, logo, callback URLs, policies) is published by the agent and discoverable by any party.
- **Works with ephemeral keys**: Agent delegates use short-lived keys bound to the agent's stable HTTPS identity, enabling frequent key rotation without registration changes.

## Why Interaction Codes Instead of Opaque Tokens

- **Human-enterable**: Short alphanumeric codes (e.g., `ABCD1234`) can be typed, read aloud, or entered from a different device.
- **QR-friendly**: Short codes produce simple QR codes that scan reliably.
- **Displayable**: Codes fit on any screen, terminal, or notification without truncation.
- **Self-contained tokens would be too long**: A token carrying cryptographic binding, expiry, and issuer information would be too long for manual entry or simple QR codes.

## Why Pending URLs Instead of Tokens

- **Standard HTTP resource**: The pending URL is a standard HTTP resource polled with `GET`. No custom token exchange endpoint is needed.
- **Supports repeated polling**: Unlike OAuth's authorization code (presented once to exchange for tokens), the pending URL supports repeated polling and long-hold connections via `Prefer: wait`.
- **Enables clarification chat**: The agent can POST clarification responses to the same URL during consent.
- **Server-controlled state**: The agent treats the URL as opaque. The server may embed state in the URL path or use it as a reference to server-side state.

## Why No Refresh Token

- **HTTP signatures prove identity on every request**: The agent's signing key already proves it is the legitimate token holder. A separate refresh token would be redundant proof.
- **Expired auth token provides authorization context**: The expired token carries the audience, scope, and user binding. The auth server can issue a new token from this context.
- **Simpler agent implementation**: Agents store one token per resource, not two. No refresh token rotation or revocation logic is needed.

## Why JSON Instead of Form-Encoded

- **Modern API convention**: JSON is the standard format for modern APIs. Form encoding is an OAuth legacy from browser form POST origins.
- **Structured data**: JSON naturally represents nested objects (e.g., token endpoint responses with multiple fields). Form encoding requires flattening.
- **Consistent across request and response**: Both request bodies and response bodies use JSON, avoiding format asymmetry.

## Why Callback URL Has No Security Role

- **Tokens never pass through the user's browser**: The auth token is delivered exclusively via polling. The callback URL carries no sensitive material.
- **No redirect URI validation needed for security**: Unlike OAuth's authorization code flow, there is no code in the redirect to protect. Callback validation is unnecessary.
- **Purely a UX optimization**: The callback wakes the agent up immediately rather than waiting for the next poll interval. If an attacker redirects the callback, the agent simply polls sooner — no tokens are exposed.

## Why Separate Approval and Interaction

- **Unambiguous agent action**: `require=interaction` means the agent must facilitate a redirect with the interaction code. `require=approval` means the AS is handling approval directly — the agent just polls.
- **Different user experiences**: Interaction requires the agent to present a code or redirect a user. Approval may use push notifications, existing sessions, or email — none requiring agent involvement.
- **Prevents unnecessary UX**: Without distinct values, agents would not know whether to prompt the user or wait silently.

## Why Interaction Started Is a Separate State

- **Stops redundant prompting**: Once the user has arrived at the interaction endpoint, the agent no longer needs to display the code, QR code, or redirect link. Without `status=interacting`, the agent would keep prompting the user who is already in the middle of the consent flow.
- **Better UX for multi-device flows**: When the user scans a QR code on their phone, the agent (e.g., a CLI on a laptop) can update its display from "scan this code" to "waiting for you to complete authorization" — a meaningful status change.
- **Status, not requirement**: `interacting` is a progress signal, not something the server requires from the agent. Using the `status` field (rather than `require`) reflects this — the server is informing the agent, not asking it to act.
- **Optional for servers**: Servers that do not track user arrival can continue returning `status=pending` with `require=interaction` throughout. The transition to `status=interacting` is an improvement, not a requirement.

## Why Restrict Interaction Code Character Set

Interaction codes are restricted to unreserved URI characters ([@!RFC3986] Section 2.3: `A-Z a-z 0-9 - . _ ~`). Unreserved characters do not require percent-encoding in URI query parameters, eliminating double-encoding, missing encoding, and inconsistent encoding across implementations.

# Security Considerations

## Proof-of-Possession

All AAuth tokens are proof-of-possession tokens. The holder must prove possession of the private key corresponding to the public key in the token's `cnf` claim.

## HTTP Message Signature Security

HTTP Message Signatures provide:

1. **Request Integrity**: The signature covers HTTP method, target URI, and headers
2. **Replay Protection**: The `created` timestamp limits signature validity
3. **Key Binding**: Signatures are bound to specific keys via `Signature-Key`

## Token Security

- Agent tokens bind delegate keys to agent identity
- Resource tokens bind access requests to resource identity, preventing confused deputy attacks
- Auth tokens bind authorization grants to agent keys

## Interaction Code Security

- Interaction code values MUST be single-use, time-limited, and bound to the pending request
- Callback URLs are agent-specified; agents SHOULD include unguessable state values to prevent CSRF

## Pending URL Security

- Pending URLs (`Location` values in `202` responses) MUST be unguessable and SHOULD have limited lifetime
- Pending URLs MUST be on the same origin as the server that issued them
- Servers MUST verify the agent's identity on every `GET` poll to the pending URL
- Once a terminal response is returned, the pending URL MUST return `404` on subsequent requests

## Clarification Chat Security

- Auth servers MUST enforce a maximum number of clarification rounds to prevent abuse
- Auth servers SHOULD enforce a timeout on clarification exchanges
- Clarification responses from agents are untrusted input and MUST be sanitized before display to users

## Auth Server Discovery

Resources include the `auth-server` parameter in their `AAuth-Challenge` response header when returning a resource token. The agent MUST use the auth server URL from the resource's challenge — the resource determines which auth server to use for its tokens.

An agent MUST NOT substitute a different auth server than the one specified by the resource. Auth servers MUST verify that the resource token's `aud` matches their own identifier.

## JWKS Caching

Servers that fetch JWKS documents for signature verification SHOULD cache the results with a TTL appropriate to their risk tolerance (recommended: 5 minutes for auth servers, 60 minutes for resources). Servers SHOULD support standard HTTP caching headers (`Cache-Control`, `Expires`) on JWKS responses.

When signature verification fails due to an unknown `kid`, the server SHOULD re-fetch the JWKS once before returning an error, to handle key rotation.

## Call Chaining Identity

When a resource acts as an agent in call chaining, it uses its own signing key and presents its own credentials to the downstream resource. The downstream resource sees Resource 1 as the requesting agent. Resource 1 MUST publish agent metadata (`/.well-known/aauth-agent.json`) so that downstream resources and auth servers can verify its identity.

The `upstream_token` parameter in the token request allows the downstream auth server to verify the authorization chain — it can confirm that Resource 1 was authorized by the original user to access the upstream resource.

## Token Revocation

This specification does not define a token revocation mechanism. Auth tokens are short-lived and bound to specific signing keys, limiting the window of exposure. Auth servers SHOULD issue auth tokens with the shortest practical lifetime. When a resource detects misuse, it can reject the token and require re-authorization.

Auth servers MAY implement revocation by maintaining a deny list of `jti` values. Resources can check revocation by querying the auth server, though this adds latency to every request. A future specification may define a standardized revocation mechanism.

## Third-Party Initiated Login Security

The agent's `login_endpoint` accepts parameters from untrusted sources — any party can redirect a user to it. Agents MUST treat all login endpoint parameters as untrusted input:

- **Issuer validation**: The agent MUST verify that the `issuer` is a valid auth server by fetching its metadata. The agent SHOULD restrict the set of accepted `issuer` values to known and trusted auth servers.
- **`start_path` validation**: The agent MUST validate that `start_path` is a relative path on its own origin. Accepting arbitrary URLs would make the agent an open redirector.
- **No pre-authorized state**: The login endpoint does not carry any tokens, codes, or pre-authorized state. The agent initiates a standard signed flow with the auth server, which independently authenticates the user through its own session. This eliminates authorization code interception and session fixation attacks — the agent never accepts identity assertions from the redirect itself.

## Replay Protection

The `created` timestamp in HTTP Message Signatures limits signature validity to a 60-second window, providing basic replay protection. Servers MAY maintain a cache of recently seen signatures to detect replays within this window.

Resource tokens include a `jti` claim for replay detection at the auth server. Auth servers SHOULD maintain a cache of seen `jti` values for at least the token's lifetime to prevent resource token replay.

# IANA Considerations

## Well-Known URI Registrations

This specification registers the following Well-Known URIs:

- `aauth-agent.json`: Agent server metadata
- `aauth-issuer.json`: Auth server metadata
- `aauth-resource.json`: Resource metadata

## Media Type Registrations

This specification registers the following media types:

- `application/agent+jwt`: Agent token
- `application/auth+jwt`: Auth token
- `application/resource+jwt`: Resource token

## HTTP Header Field Registrations

This specification registers the following HTTP header:

- `AAuth-Challenge`: Authentication, authorization, and interaction requirements

## JWT Claim Registrations

This specification registers the following JWT claim in the IANA JSON Web Token
Claims Registry:

| Claim | Description | Change Controller | Reference |
|-------|-------------|-------------------|-----------|
| `aauth_sid` | Session identifier assigned by the agent server and propagated by the auth server into auth tokens. | IETF | This document |

## Additional HTTP Header Field Registrations

This specification registers the following HTTP request header field:

| Header | Description | Reference |
|--------|-------------|-----------|
| `AAuth-Session` | Conveys the session identifier from the agent to auth servers and resources when the session identifier is not present as a claim in a token included in the request. | This document |

{backmatter}

# Agent Token Acquisition Patterns

This appendix describes common patterns for how agent delegates obtain agent tokens from their agent server. The specific mechanism is out of scope for this specification.

## Server Workloads

Server workloads include containerized services, microservices, and serverless functions. These workloads prove identity using platform attestation.

**SPIFFE-based**: The workload obtains a SPIFFE SVID from the Workload API, generates an ephemeral key pair, and presents the SVID to the agent server via mTLS. The agent server issues an agent token with `sub` set to the SPIFFE ID.

**WIMSE-based**: The workload authenticates using platform credentials (cloud provider instance identity, Kubernetes service account tokens). The agent server evaluates delegation policies before issuing tokens.

## Mobile Applications

Mobile apps prove legitimate installation using platform attestation APIs (iOS App Attest, Android Play Integrity API). Each installation generates a persistent ID and key pair. The agent server validates the attestation and issues an agent token with an installation-level `sub`.

## Desktop and CLI Applications

Desktop and CLI tools use platform vaults (macOS Keychain, Windows TPM, Linux Secret Service) or ephemeral keys. After user authentication, the agent server issues tokens with an installation-level `sub` that persists across key rotations.

## Browser-Based Applications

Browser-based applications generate ephemeral key pairs using the Web Crypto API. The web server acts as agent server and issues agent tokens to the browser session. Each session has a unique `sub` for tracking.

# Acknowledgments

The author would like to thank reviewers for their feedback on concepts and earlier drafts: Aaron Pareki, Christian Posta, Frederik Krogsdal Jacobsen, Jared Hanson, Karl McGuinness, Nate Barbettini, Wils Dawson.
