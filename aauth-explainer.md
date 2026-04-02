# AAuth Explainer

## What OAuth Was Designed For — and What Has Changed

OAuth 2.0 was designed for a specific problem: a user authorizing a registered web application to access their data at a specific API provider. The user's browser redirects to the provider, the user consents, and the application receives a bearer token. OpenID Connect extended this to federated login. Together, they serve these use cases well and continue to be the right choice for them.

AAuth is not intended as a replacement for OAuth or OIDC. It is not OAuth 3.0. It is a separate protocol for new use cases where the assumptions behind OAuth — pre-registered clients, browser redirects, bearer tokens, static scopes — are not a good fit.

**Autonomous agents operate without browsers.** In environments like the Model Context Protocol (MCP), agents interact with servers they were never pre-registered with. Many are headless processes that cannot receive browser redirects. Pre-registration of client credentials is impractical when any agent may call any server.

**On-demand authorization across trust domains.** Long-running agents discover authorization needs at runtime — they do not know what resources they will require until they encounter them. Resources may be governed by different auth servers than the agent's own, requiring cross-domain federation that OAuth's single-authorization-server model does not support.

**Progressive trust is needed.** Resources need different levels of assurance for different operations — rate limiting anonymous requests, verifying agent identity, or requiring full user authorization — but OAuth provides only a binary authenticated/unauthenticated model.

**Consent needs context.** OAuth scopes like `read` or `write` convey what access is requested but not why or under what conditions. Users cannot ask questions about what an agent intends to do.

**Security has evolved.** Bearer token exfiltration is a common attack vector. Proof-of-possession with digital signatures is now practical and widely supported, yet bearer tokens and shared secrets remain the default. Applications are distributed across desktop, mobile, and CLI environments where a single shared secret is impractical.

## How AAuth Addresses These Gaps

**Proof-of-possession by default.** HTTP Message Signatures on every request eliminate bearer tokens. Signatures cover method, path, and headers, providing message integrity that DPoP and mTLS do not offer, and survive proxies and CDNs unlike mTLS.

**Agent identity without pre-registration.** Agents use HTTPS URLs as server identifiers with self-published metadata and JWKS. Each agent instance has its own identifier (`local@domain`) and signing key, so authorization grants are per-instance, not per-application. Any party can verify agent identity without prior registration, enabling open ecosystems.

**Polling-based token delivery.** Deferred responses (`202 Accepted` + `Location` + `Prefer: wait`) decouple token delivery from browser redirects. Headless agents, CLI tools, and background services obtain authorization via polling. Long-running consent flows and clarification chat use the same mechanism.

**Progressive authentication.** A single protocol covers pseudonymous access (signed requests for rate limiting), verified identity (agent tokens with JWKS), and full authorization (auth tokens with user delegation). Resources declare which level they require.

**Justification and clarification.** A `justification` parameter declares why access is requested. Clarification chat lets users ask the agent questions during consent. The auth server logs the declared justification alongside the authorization decision, creating an audit trail for behavioral drift detection.

**Unified auth and authz.** AAuth combines authentication and authorization in a single flow, eliminating the friction of coordinating separate OAuth and OIDC deployments.

**Cross-domain federation.** An agent's auth server can call a resource's auth server to obtain an auth token on behalf of its agent, enabling cross-domain access without the agent or resource being aware of the federation.

## Why Adopt AAuth

### 1. No registration, no shared secrets — agents work everywhere immediately

OAuth requires every client to pre-register with every auth server it will ever talk to, exchanging client IDs and secrets out of band. This breaks down in open ecosystems where any agent might need to talk to any resource — MCP, autonomous agents, multi-vendor toolchains. AAuth agents self-publish identity at an HTTPS URL. Any agent can interact with any auth server or resource on first contact with no admin portal, no client credentials, and no onboarding friction. This is the difference between "works in a walled garden" and "works on the internet."

### 2. Stolen tokens are worthless

Every OAuth deployment starts with bearer tokens. Bolting on proof-of-possession (DPoP, mTLS) is optional and partial — DPoP does not cover request integrity, mTLS terminates at the first proxy. AAuth has no bearer path. Every request is signed with HTTP Message Signatures. Every token is bound to the signer's key via a `cnf` claim. A leaked token, a leaked log line, a compromised CDN cache — none of these yield usable credentials. This is not a hardening option; it is the only mode.

### 3. Resources have cryptographic identity — not just agents

In OAuth, the resource is a passive token consumer that trusts whatever the auth server issued. In AAuth, the resource signs a resource token that binds the access challenge to its own identity, specifying exactly what is being requested, by whom, and for what scope. The auth server validates the resource's signature before issuing an auth token. This prevents confused deputy attacks at the protocol level and decouples resources from auth servers so either side can change independently.

### 4. One async pattern handles every interaction model

OAuth has separate specs for browser redirects, device flow, client credentials, token exchange, and CIBA — each with its own mechanics. AAuth has one pattern: `202 Accepted` + `Location` + `Prefer: wait`. It handles immediate grants, user consent, headless polling, enterprise approval workflows, push notifications, and clarification chat during consent — all through the same state machine. An agent that can handle a `202` response can handle every authorization scenario, including ones that do not exist yet. A resource that was synchronous can become async without breaking any client.

### 5. Progressive trust without protocol switching

OAuth is binary: you have an access token or you do not. If a resource just needs to rate-limit anonymous requests or verify which agent is calling, OAuth has no answer short of full authorization. AAuth provides a trust ladder within a single protocol: pseudonymous (sign with a bare key, tracked by thumbprint), identified (present agent identity, policy based on who you are), and authorized (present an auth token, full user-delegated access). A resource can start at pseudonymous and escalate on demand using the same `AAuth-Requirement` mechanism. A single API can serve anonymous browsing, known-agent access, and fully authorized operations with the same protocol, same signing, and same headers.

## How AAuth Differs from OAuth 2.0/OIDC

### Identity Model

| Aspect | OAuth 2.0 | AAuth |
|--------|-----------|-------|
| Client identity | Pre-registered `client_id` | `local@domain` identifier with published metadata |
| Client metadata | Stored at authorization server | Self-published at `/.well-known/aauth-agent.json` |
| Key management | Client secrets or registered public keys | Ephemeral keys bound via agent tokens |
| Multiple instances | Share single `client_id` and secret | Each instance has unique `local@domain` and signing key |
| Discovery | Optional (RFC 8414) | Built-in via well-known metadata |

### Token Delivery

| Aspect | OAuth 2.0 | AAuth |
|--------|-----------|-------|
| Token delivery | Redirect with authorization code | 202 + Location URL, poll with GET |
| User return | Carries authorization code | Redirect to agent's callback URL (no tokens) |
| Headless clients | Requires device authorization grant (RFC 8628) | Native support via polling |
| Long-running consent | Limited by redirect timeout | Unlimited (Prefer: wait + polling) |

### Security Model

| Aspect | OAuth 2.0 | AAuth |
|--------|-----------|-------|
| Request signing | Optional (DPoP, mTLS) | Required (HTTPSig) on every request |
| Token type | Bearer (default) | Proof-of-possession only |
| Message integrity | Not provided | HTTPSig covers method, path, headers |
| Resource identity | None | Resource tokens with JWKS |
| Proxy survival | mTLS terminates at proxy | HTTPSig survives proxies |

### User Consent

| Aspect | OAuth 2.0 | AAuth |
|--------|-----------|-------|
| What is requested | Scopes | Scopes + justification |
| Why it's requested | Not conveyed | `justification` parameter |
| User questions | Not supported | Clarification chat during consent |
| Enterprise hints | Separate extensions | Built-in: `login_hint`, `tenant`, `domain_hint` |

## Deferred Responses and Interaction Codes

OAuth uses several types of opaque strings for state management: authorization codes, state parameters, PKCE verifiers. Each has specific semantics and handling requirements.

AAuth consolidates these into a simpler model built on standard HTTP async patterns. When a request cannot be resolved immediately, the server returns `202 Accepted` with a `Location` header pointing to a pending URL and a JSON body echoing the status and location. The agent polls that URL with `GET` until the response is ready.

When user interaction is needed, the server includes an `AAuth-Requirement: requirement=interaction; code="ABCD1234"` header in the 202 response. The **interaction code** is a short alphanumeric string that binds the user's interaction to the pending request. The agent directs the user to the auth server's `interaction_endpoint` (from metadata) with the code as a query parameter. Users can enter the code manually, scan a QR code, or be redirected directly.

The agent may include a **callback URL** in the interaction redirect. The callback is a UX optimization — the agent is already polling and will get its answer regardless. The callback wakes the agent up immediately.

The key insight is that token delivery is decoupled from user return. In OAuth, the authorization code is the bridge between user consent and token issuance. In AAuth, the pending URL fills that role — the agent polls it directly. No sensitive material passes through the user's browser. This eliminates authorization code interception as an attack vector.

## Interaction Model

### OAuth: Redirect + Code Exchange

```
Agent → User → Auth Server → User → Agent (with code) → Auth Server (exchange code) → Agent (token)
```

The token passes through the user's browser as an authorization code, then is exchanged via back-channel.

### AAuth: POST + 202 + Poll

```
Agent → Auth Server (POST, get 202 + Location + interaction code) → User → Auth Server → User → Agent (callback)
Agent → Auth Server (GET Location URL) → Agent (token)
```

The token never passes through the user's browser. The agent polls the pending URL directly.

## Clarification Chat

During OAuth consent, the user sees a permissions screen and either approves or denies. There is no mechanism for the user to ask questions.

AAuth introduces clarification chat: during consent, the user can ask the agent questions about its justification. For example:

- User: "Why do you need access to my calendar?"
- Agent: "I need to find available meeting times for your Tokyo trip next week."
- User: "Will you access events from other calendars?"
- Agent: "No, I will only read events from your primary calendar."

The auth server mediates this exchange via polling responses on the pending URL. The agent's responses are displayed to the user, providing transparency into agent intent.

This is particularly valuable for AI agents, where the justification may be complex or context-dependent. It enables informed consent that scopes alone cannot provide.

Auth servers enforce limits on clarification rounds and overall timeout to prevent abuse.

## Enterprise Scenarios

AAuth includes enterprise hint parameters on the initial request to the token endpoint:

- **`login_hint`** (per OIDC Core Section 3.1.2.1): Suggests which user to authenticate, reducing friction in enterprise SSO flows.
- **`tenant`** (per OpenID Connect Enterprise Extensions 1.0): Identifies the organizational tenant, enabling the auth server to route to the correct identity provider.
- **`domain_hint`** (per OpenID Connect Enterprise Extensions 1.0): Hints at the user's domain, enabling domain-based identity provider discovery.

### Organizational Authorization

In enterprise contexts, authorization may not be tied to a specific user. AAuth supports organizational authorization where any authorized person within a tenant can approve access for an agent delegate. The auth server tracks which user approved, but the agent need not know the user's identity.

This is useful for:
- **Shared service agents**: An agent that syncs data between systems on behalf of an organization, not a specific user.
- **Approval workflows**: Multiple people may be authorized to approve an agent's access request.
- **Compliance**: The auth server maintains an audit trail of who authorized what, even when the agent operates with organizational scope.

## Agent Delegate User Binding

An agent delegate SHOULD be associated with at most one user. This binding, maintained by the auth server, enables:

- **Re-authorization**: When a long-running agent delegate needs to refresh or extend access, the auth server can re-authorize without requiring a new interactive consent flow, provided the original user's authorization is still valid.
- **Revocation**: Revoking a user's authorization revokes all access for agent delegates associated with that user.
- **Audit**: The auth server can report which user authorized which agent delegate's actions.

The agent itself need not know the user's identity. The binding is an auth-server-side concern.

## Audience-Restricted Agent Tokens

By default, agent tokens have no audience restriction — a delegate uses the same agent token with any resource or auth server. But agent servers may optionally restrict a delegate to specific servers by including an `aud` claim. This limits exposure if the delegate's key is compromised.

Agent servers may also include an `aud_sub` claim — the user identifier from a previous auth token — to signal to the auth server which user the delegate is acting for. This enables the auth server to skip interactive identification and proceed directly to authorization, improving the experience for re-authorization of long-running agents.

## Relationship to Web-Bot-Auth

The IETF Web Bot Authentication (webbotauth) Working Group is developing standards for websites to manage automated traffic. AAuth's progressive authentication levels directly address the webbotauth charter goals:

- **Pseudonym** (`requirement=pseudonym`): Signed requests prove consistent identity for rate limiting, without revealing who the agent is. This addresses bot abuse mitigation.
- **Identified** (`requirement=identity`): Verified agent identity via JWKS or agent tokens. This addresses bot allowlisting and differentiated policies.
- **Authorized** (`requirement=auth-token`): Full authorization for user-delegated or autonomous access.

AAuth extends beyond the webbotauth charter by supporting authorization flows, user delegation, and interactive agents (browser, mobile, desktop) alongside autonomous bots. The same protocol serves both bot identity and user authorization.

## No Refresh Tokens

OAuth 2.0 uses refresh tokens to obtain new access tokens after expiry. The refresh token is a long-lived secret that must be stored securely and rotated carefully.

AAuth eliminates refresh tokens entirely. When an auth token expires, the agent presents the expired token to the token endpoint along with an HTTP Message Signature. The expired token provides authorization context (audience, scope, user binding), and the signature proves the agent is the legitimate holder. The auth server issues a new token without requiring user interaction.

This works because AAuth's proof-of-possession model already authenticates the agent on every request. A refresh token would be redundant proof of the same thing the signature already demonstrates.

## JSON Request and Response Format

OAuth 2.0 uses `application/x-www-form-urlencoded` for token requests — a legacy of its origin in browser form POSTs. Responses use JSON, creating format asymmetry.

AAuth uses JSON for both requests and responses. JSON naturally represents structured data, aligns with modern API conventions, and eliminates the need for form encoding/decoding logic.

## Auth Server Direct Approval

AAuth supports two distinct deferred response modes:

- **`requirement=interaction`**: The agent must facilitate a redirect — presenting an interaction code to the user via manual entry, QR code, or direct redirect to the auth server's interaction endpoint.
- **`requirement=approval`**: The auth server is obtaining approval directly, without the agent's involvement. The approval may come from a user (via push notification, existing session, or email) or from policy evaluation. The agent simply polls until the request resolves.

The distinction matters because it tells the agent exactly what action to take (or not take). With `requirement=interaction`, the agent must actively help the user reach the auth server. With `requirement=approval`, the agent waits passively — no UX is needed.

## Design Rationale

### Why Interaction Codes Instead of Opaque Tokens

Interaction codes are short alphanumeric strings (e.g., `ABCD1234`) rather than long opaque tokens. Short codes can be typed by users, read aloud, displayed on any screen, and encoded as simple QR codes. A self-contained token carrying cryptographic binding, expiry, and issuer information would be too long for manual entry. The interaction code is a reference to server-side state, not a bearer credential — it has no value without the corresponding pending URL that only the agent knows.

### Why Pending URLs Instead of Tokens

OAuth uses an authorization code: a one-time token exchanged for access tokens. AAuth replaces this with a pending URL — a standard HTTP resource the agent polls with GET.

The pending URL supports repeated polling (the authorization code is single-use), long-hold connections via `Prefer: wait` (reducing polling overhead), and clarification chat (the agent can POST responses to user questions at the same URL). The agent treats the URL as opaque. The server controls whether state is embedded in the URL path or stored server-side.

### Why No Refresh Token

Every AAuth request includes an HTTP Message Signature that proves the agent holds the private key. When an auth token expires, the expired token already contains the authorization context (audience, scope, user). Presenting the expired token with a valid signature is sufficient for the auth server to issue a replacement. A separate refresh token would duplicate what the signature already proves.

This simplifies agent implementation (one token per resource, not two) and eliminates refresh token rotation, storage, and revocation as concerns.

### Why .json Extension on Well-Known URLs

AAuth metadata documents use `.json` extensions (`aauth-agent.json`, `aauth-issuer.json`, `aauth-resource.json`) rather than extensionless paths like OAuth's `oauth-authorization-server`.

- **Content type clarity**: The `.json` extension makes the expected format unambiguous to developers, HTTP caches, and tooling. No content negotiation is needed.
- **Simpler static hosting**: Static file servers and CDNs serve `.json` files with correct `Content-Type` headers automatically. Extensionless paths often require explicit configuration.
- **Consistency**: All three metadata documents follow the same naming convention.

### Why Server Identifiers Have No Path

AAuth server identifiers (agent, resource, issuer) are restricted to scheme + host only — no port, path, query, or fragment. For example, `https://agent.example` is valid but `https://agent.example/v1` is not.

- **Exact string comparison**: Without paths, identifier comparison is a simple string match. No URL normalization (trailing slashes, path canonicalization, case folding) is needed.
- **Unambiguous metadata location**: The well-known URL is always `https://{host}/.well-known/aauth-*.json`. Paths would require path-aware well-known resolution, which RFC 8615 does not define.
- **Simpler security model**: Each host has exactly one identity. Path-based multi-tenancy would require additional isolation guarantees that are out of scope for the initial protocol.
- **Future extensibility**: Path support can be added in a future version if multi-tenant hosting patterns emerge. Starting without paths is a simpler, safer default.

### Why Unified Auth Instead of Separate AuthN and AuthZ

OAuth 2.0 provides authorization (delegated access to resources). OpenID Connect adds authentication (user identity via ID tokens) as a layer on top. In practice, most applications need both — a user logs in (authN) and the application accesses APIs on their behalf (authZ). This requires coordinating two protocols with different token types, validation rules, and metadata formats.

AAuth collapses this into a single "auth" concept. The auth token carries both user identity (`sub`) and resource authorization (`aud`, `scope`). An agent that needs SSO requests an auth token with scopes from an auth server — the same flow, endpoint, and token format whether the goal is user identity, API access, or both. This eliminates the OAuth/OIDC coordination tax and the class of bugs that arise from mismatched token handling.

### Why Callback URLs Have No Security Role

In OAuth, redirect URI validation is critical because the authorization code passes through the user's browser. An attacker who controls the redirect URI receives the code.

In AAuth, the callback URL carries no tokens or codes. It exists purely to wake the agent up after user interaction. If an attacker redirects the callback, the worst outcome is a premature poll — the agent was already polling and would have received the token regardless. No redirect URI validation is needed for security.

## Call Chaining

When a resource needs to access a downstream resource on behalf of the caller, it acts as an agent. The resource presents the downstream resource's resource token along with the auth token it received from the original caller (as an `upstream_token`), allowing the downstream auth server to verify the authorization chain. Because the resource acts as an agent, it must publish agent metadata so downstream parties can verify its identity.

The downstream auth server evaluates its own policy based on both the upstream auth token and the downstream resource token. The resulting authorization is not necessarily a subset of the upstream scopes — the downstream auth server may grant independent scopes based on organizational policy. For example, an upstream token granting `calendar.read` might lead the downstream auth server to grant `availability.read` based on a policy that allows calendar services to query availability. The upstream token provides provenance and user identity context, not a scope ceiling.

If the downstream auth server requires user interaction, the resource chains the interaction back to the original agent. The resource returns its own `202` with an interaction code to the agent, and when the user arrives at the resource's interaction endpoint, the resource redirects them onward to the downstream interaction endpoint. Each link in the chain manages only its own interaction redirect — the downstream interaction URL is never exposed to the upstream agent.

This enables multi-hop resource access where authorization passes downstream and interaction requirements bubble up, without any participant needing visibility into the full chain.

## Agent as Audience (SSO and First-Party Access)

An agent can request an auth token where it is the audience — either for SSO (obtaining user identity) or for first-party resource access by its delegates. The agent calls the token endpoint with `scope` and no `resource_token`, since the agent itself is the resource.

This is the same flow, endpoint, and token format as resource access. The auth token's `aud` is the agent server's URL, and the `sub` identifies the authenticated user. This unified model means SSO, user login, and API authorization all use the same protocol — there is no separate "ID token" concept as in OpenID Connect.

## Resource Interaction

Resources — not just auth servers — can return deferred responses. When a resource requires user interaction (login, consent for downstream access), it returns `202 Accepted` with an interaction code, just like an auth server would. The agent directs the user to the resource's `interaction_endpoint`. This means any endpoint in AAuth can defer, and agents handle all `202` responses uniformly regardless of origin.

## Mobile Interaction

AAuth's interaction model maps cleanly onto mobile platform APIs. The agent needs to open a URL and receive a callback — the platform decides how.

On iOS, the agent app uses `ASWebAuthenticationSession` to open the auth server's interaction endpoint with the code. On Android, Chrome Custom Tabs or Auth Tab serve the same role. Both are system-managed browser contexts that keep the auth server's session isolated from the app.

The advantage over OAuth on mobile is structural. OAuth's redirect carries an authorization code — a sensitive credential that grants token access. The entire reason `ASWebAuthenticationSession` and Auth Tab exist is to protect that code from interception by other apps. PKCE adds another layer of defense. With AAuth, the callback carries nothing sensitive. It is a wake-up signal. If a malicious app captured the redirect, it gets nothing useful — it cannot poll the pending URL without the agent's signing key.

If the auth server has a native app with an iOS Extensible SSO extension deployed via MDM, `ASWebAuthenticationSession` routes through the SSO extension automatically — native UI, biometrics, no browser. The agent app does not need to know or care.

The protocol does not prescribe how the user reaches the interaction endpoint. Whether the platform uses `ASWebAuthenticationSession`, an SSO extension, a system browser, or the user manually types a code on a different device, the protocol works the same.

For the `requirement=approval` flow, the auth server can reach the user via push notification to a native app or PWA, email, or an existing browser session. The agent just polls — the auth server chooses the channel. The mobile agent has no interaction responsibility at all.

## Proactive Authorization (Resource Token Endpoint)

In the standard flow, an agent discovers authorization requirements by making an API call and receiving a `401` challenge with a resource token. But sometimes the agent already knows what scopes it needs — from the resource's published `scope_descriptions` metadata.

When a resource publishes a `resource_token_endpoint` in its metadata, agents can request a resource token proactively without first triggering a `401`. This enables two patterns:

- **Pre-authorization**: The agent obtains authorization before making its first API call, avoiding the initial `401` round-trip.
- **Scope upgrade**: The agent already has an auth token but needs additional scopes. It requests a new resource token with the broader scope, obtains a new auth token, and retries. The new auth token replaces the previous one.

The resource returns the resource token, the auth server URL, and the granted scope (which may be narrower than requested). The agent then proceeds to the auth server's token endpoint as in the standard flow.

## Agent Token Attestation

Agent tokens provide an extension point for attestation. Agent servers may include additional claims in the agent token to convey evidence about the delegate's environment — platform integrity, secure enclave status, or workload identity assertions. This allows auth servers and resources to make trust decisions based on the delegate's runtime properties, not just the agent's identity.

## Missions

### The Problem: Authorization for Open-Ended Work

AAuth's core protocol handles individual resource access — an agent needs a specific scope at a specific resource, and obtains an auth token for it. But AI agents often perform multi-step work that spans many resources: research a topic across multiple sources, analyze the results, draft a document, book a reservation. The agent doesn't know at the outset every resource it will need. Pre-enumerating scopes is impractical for the same reason that detailed battle plans don't survive first contact.

### Mission Command as a Model

AAuth's mission model draws from *Auftragstaktik* (mission command), the command philosophy developed by the Prussian army in the 19th century and adopted by the US Army (ADP 6-0) and NATO. The core principle: communicate the objective and intent, then let subordinates decide how to accomplish it — intervening only when they go off course.

The contrast is *Befehlstaktik* (detailed command): specify every step in advance, require approval before each action. This works when the environment is predictable. It fails when conditions change faster than orders can flow up and back down. As Moltke observed, no plan of operations extends with certainty beyond first contact.

OAuth's model — pre-registered clients, static scopes, upfront consent — is detailed command. It works for predictable interactions between known parties. AAuth missions are mission command: approve the objective, let the agent execute, evaluate each action against the approved intent, and intervene when necessary.

### How It Works

The agent submits a **mission proposal** to its Mission Authority (MA) — its own auth server. The MA evaluates the proposal (potentially deferring for human review or engaging in clarification chat) and returns an approved mission, identified by the SHA-256 hash of the approved text.

As the agent works, it includes the mission identifier in each token request. The MA evaluates whether each resource access is consistent with the mission and can deny requests that fall outside scope. Because the agent always routes token requests through its MA — even for cross-domain resources — the MA has a complete audit trail of every authorization decision within the mission. Decentralized execution with centralized visibility.

### Mission Control

Mission Control is the administrative interface to the MA. Because the MA is in the authorization path for every mission action, it already holds all mission data — Mission Control simply exposes it.

**Example: a travel planning mission.** A user asks their agent to plan a week in Tokyo — research flights, find hotels near the conference venue, book dinner reservations, and compile an itinerary. The MA approves the mission. As the agent works, each authorization flows through the MA:

```
10:00  Agent → flights.example      scope: search        granted
10:02  Agent → flights.example      scope: fare.hold     granted
10:05  Agent → hotels.example       scope: search        granted
10:08  Agent → hotels.example       scope: reserve       granted
10:12  Agent → restaurants.example  scope: book          granted
10:15  Agent → payments.example     scope: charge        denied — outside mission scope
```

The user sees this in Mission Control as a live audit trail. The MA denied the payment charge because the approved mission was to *plan* the trip, not pay for it. The agent can see the denial and explain to the user what happened, or the user can amend the mission.

**Suspension.** Midway through, the user notices the agent is searching for hotels in Osaka instead of Tokyo. From Mission Control, they suspend the mission. All in-flight token requests immediately start returning errors — the agent cannot access any more resources until the user investigates. After reviewing the audit trail and correcting the agent, the user resumes the mission.

**Delegation tree.** The hotel booking involved a chain: the agent called hotels.example, which called availability.example downstream to check room inventory. Mission Control shows the full delegation tree — every agent, resource, and auth server involved — so the user can see exactly where their data flowed.

**Completion.** When the agent finishes the itinerary, it declares the mission complete. Alternatively, the mission could complete automatically when the user's calendar event for the trip passes, via a business event from the calendar system.

Missions progress through states: **proposed → active → completed**, with **suspended**, **revoked**, and **expired** as intervention and terminal states. Users can inspect their own missions. Administrators can manage any mission in their organization. The MA's audit trail is the authoritative record of what happened, when, and why.
