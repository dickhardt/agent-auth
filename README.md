# AAuth

**Author:** Dick Hardt (dick.hardt@gmail.com)

## HTTP Clients Need Their Own Identity

In [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) and [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html), the client has no independent identity. Client identifiers are issued by each authorization server or OpenID provider — a `client_id` at Google is meaningless at GitHub. The client's identity exists only in the context of each server it has pre-registered with. This made sense when the web had a manageable number of integrations and a human developer could visit each portal to register.

API keys are the same model pushed further: a shared secret issued by a service, copied to the client, and used as a bearer credential. The problem is that any secret that must be copied to where the workload runs will eventually be copied somewhere it shouldn't be.

SPIFFE and WIMSE brought workload identity to enterprise infrastructure — a workload can prove who it is without shared secrets. But these operate within a single enterprise's trust domain. They don't help an agent that needs to access resources across organizational boundaries, or a developer's tool that runs outside any enterprise platform.

AAuth starts from this premise: every agent has its own cryptographic identity. An agent identifier (`aauth:local@domain`) is bound to a signing key, published at a well-known URL, and verifiable by any party — no pre-registration, no shared secrets, no dependency on a particular server. At its simplest, an agent signs a request and a resource decides what to do based on who the agent is. This identity-based access can replace API keys and is the foundation that authorization, governance, and federation build on incrementally.

## Agents Are Different

Traditional software knows at build time what services it will call and what permissions it needs. Registration, key provisioning, and scope configuration happen before the first request. This works when the set of integrations is fixed and known in advance.

Agents don't work this way. They discover resources at runtime. They execute long-running tasks that span multiple services across trust domains. They need to explain what they're doing and why. They need authorization decisions mid-task, long after the user set them in motion. They may need to ask the user questions, or have the user ask them questions, before authorization can proceed. A protocol designed for pre-registered clients with fixed integrations cannot serve agents that discover their needs as they go.

## What AAuth Provides

- **Agent identity without pre-registration**: A domain, static metadata, and a JWKS establish identity with no portal, no bilateral agreement, no shared secret.
- **Per-instance identity**: Each agent instance gets its own identifier (`aauth:local@domain`) and signing key.
- **Proof-of-possession on every request**: HTTP Message Signatures bind every request to the agent's key — a stolen token is useless without the private key.
- **Two-party mode with first-call registration**: An agent calls a resource it has never contacted before; the resource returns `AAuth-Requirement`; a browser interaction can handle account creation, payment, and user consent. The first API call is the registration.
- **Tool-call governance**: A person server (PS) represents the user and manages what tools the agent can call, providing permission and audit for tool use — no resource involved.
- **Missions**: Optional scoped authorization contexts that span multiple resources. The agent proposes what it intends to do; the user reviews; every resource access is evaluated in context.
- **Cross-domain federation**: The PS federates with access servers (AS) — the policy engines that guard resources — to enable access across trust domains without the agent needing to know about each one.
- **Clarification chat**: Users can ask questions during consent; agents can explain or adjust their requests.
- **Progressive adoption**: Each party can adopt independently; modes build on each other.

## What AAuth Does Not Do

- Does not require centralized identity providers — agents publish their own identity
- Does not use shared secrets or bearer tokens — every credential is bound to a signing key and useless without it
- Does not require coordination to adopt — each party adds support independently
- Does not replace OAuth — complements it for browser-based user login

For the full story, see [aauth.dev](https://www.aauth.dev).

## Specifications

### HTTP Signature Keys (Foundation)

A standalone HTTP specification that AAuth builds on. Defines well-known key discovery, the `Signature-Key` header for conveying public keying material alongside HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)), and the `Signature-Error` header for structured error reporting.

* [Editor's Copy](https://dickhardt.github.io/signature-key/draft-hardt-httpbis-signature-key.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-hardt-httpbis-signature-key)
* [Compare Editor's Copy to Individual Draft](https://dickhardt.github.io/signature-key/#go.draft-hardt-httpbis-signature-key.diff)

### AAuth Protocol

The authorization protocol for agent-to-resource access. Defines four resource access modes (identity-based, resource-managed, PS-managed, federated), three proof-of-possession token types (agent, resource, auth), agent governance (missions, permissions, audit), deferred responses with clarification chat, and call chaining for multi-hop resource access.

* [Editor's Copy](https://dickhardt.github.io/AAuth/draft-hardt-aauth-protocol.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-hardt-aauth-protocol)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-hardt-aauth-protocol)
* [Compare Editor's Copy to Individual Draft](https://dickhardt.github.io/AAuth/#go.draft-hardt-aauth-protocol.diff)

#### Implementations

| Language | Repository |
|----------|------------|
| TypeScript | [github.com/hellocoop/AAuth](https://github.com/hellocoop/AAuth) |
| Python | [github.com/christian-posta/aauth-full-demo](https://github.com/christian-posta/aauth-full-demo) |
| Java (Keycloak) | [github.com/christian-posta/keycloak-aauth-extension](https://github.com/christian-posta/keycloak-aauth-extension) |

### AAuth R3 (Exploratory)

**[draft-hardt-aauth-r3](draft-hardt-aauth-r3.md)**

Rich Resource Requests. Vocabulary-based authorization using formats agents already understand (MCP, OpenAPI, gRPC, GraphQL). Content-addressed R3 documents provide human-readable consent display and permanent audit provenance.

### AAuth Bootstrap (Exploratory)

**[draft-hardt-aauth-bootstrap](draft-hardt-aauth-bootstrap.md)**

Bootstrap ceremony for SaaS browser, SaaS mobile, and B2B SaaS agents. Defines the `bootstrap_token`, the PS and agent-server bootstrap endpoints, per-platform attestation (WebAuthn, App Attest, Play Integrity), and renewal flows that bypass the PS after the initial binding is established.

## Links

| Resource | Link |
|----------|------|
| **Website** | https://www.aauth.dev |
| **GitHub Repository** | https://github.com/dickhardt/AAuth |

## Building

```sh
make
```


Each `draft-*.md` file produces a corresponding HTML file.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to participate. Discussion happens on [GitHub Issues](https://github.com/dickhardt/AAuth/issues).

---

> Founding sponsor: [Geffen Posner](https://www.linkedin.com/in/geffenpo/)

