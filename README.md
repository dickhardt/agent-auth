# AAuth Specification Family

**Author:** Dick Hardt (dick.hardt@gmail.com)

AAuth is an authentication and authorization protocol for autonomous agents and dynamic ecosystems. It is not intended as a replacement for OAuth or OIDC — it addresses new use cases where pre-registered clients, browser redirects, and bearer tokens are not a good fit.

AAuth is defined by a family of layered specifications. Each layer builds on the one below it, providing primitives that higher layers use.

## Signature-Key

**[Signature-Key](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/)** (I-D.hardt-httpbis-signature-key) — Status: Internet-Draft

The foundation. A standalone HTTP specification (not AAuth-specific) that defines the `Signature-Key` header for conveying public keying material alongside HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)). Provides a standard way for a signer to tell a verifier which key to use — the building block that all AAuth signing depends on.

**Primitives:** key conveyance, signature verification bootstrapping

## AAuth Headers

**HTTP AAuth Headers** (draft-hardt-aauth-headers) — Status: Internet-Draft

* [Editor's Copy](https://dickhardt.github.io/AAuth/draft-hardt-aauth-headers.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-hardt-aauth-headers)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-hardt-aauth-headers)
* [Compare Editor's Copy to Individual Draft](https://dickhardt.github.io/AAuth/#go.draft-hardt-aauth-headers.diff)

Profiles HTTP Message Signatures + Signature-Key for the AAuth context. Defines two HTTP response headers:

- **`AAuth-Requirement`** — progressive requirement levels: `pseudonym` → `identity` → `interaction` → `approval`
- **`AAuth-Error`** — structured error codes for signature and authentication failures

**Primitives:** requirement signaling, signed request authentication, error reporting

## AAuth Protocol

**AAuth Protocol** (draft-hardt-aauth-protocol) — Status: Internet-Draft

* [Editor's Copy](https://dickhardt.github.io/AAuth/draft-hardt-aauth-protocol.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-hardt-aauth-protocol)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-hardt-aauth-protocol)
* [Compare Editor's Copy to Individual Draft](https://dickhardt.github.io/AAuth/#go.draft-hardt-aauth-protocol.diff)

The authorization protocol built on the Headers layer. Defines:

- Three token types: **agent** (delegate identity), **resource** (access challenge), **auth** (user-delegated authorization)
- A unified **token endpoint** with deferred response support (`202 Accepted` + polling)
- **Clarification chat** during consent flows
- **Call chaining** for multi-hop resource access
- **Cross-domain AS federation** between auth servers

**Primitives:** token issuance, federation, deferred authorization, user delegation

## AAuth Mission

**[AAuth Mission](draft-hardt-aauth-mission.md)** (draft-hardt-aauth-mission) — Status: Exploratory

Optional extension to the Protocol for multi-step agent workflows, inspired by military Mission Command (Auftragstaktik). Defines:

- **Mission proposals** — natural language descriptions of intended work
- **Mission-scoped token issuance** — each resource access evaluated against mission context
- **MA countersignatures** — cryptographic proof the Mission Authority approved each step
- **Mission control** — administrative interface for lifecycle management and audit

**Primitives:** scoped authorization contexts, centralized audit, mission lifecycle management

## AAuth Rich Resource Requests (R3)

**[AAuth R3](draft-hardt-aauth-r3.md)** (draft-hardt-aauth-r3) — Status: Exploratory

Optional extension to the Protocol for structured, vocabulary-based authorization. Defines:

- **Vocabularies** — resource operations expressed in formats agents already understand (MCP, OpenAPI, gRPC, etc.)
- **R3 documents** — content-addressed authorization definitions published by resources
- **Vocabulary-based grants** — auth tokens carry granted operations in the same vocabulary format

**Primitives:** human-readable and machine-precise authorization definitions, content-addressed audit provenance

## Non-Normative

| Document | Description |
|----------|-------------|
| **[Explainer](aauth-explainer.md)** | Overview of AAuth concepts, comparisons to OAuth/OIDC, and design rationale |

## Links

| Resource | Link |
|----------|------|
| **GitHub Repository** | https://github.com/dickhardt/AAuth |
| **Website (coming)** | https://aauth.ai |
| **TypeScript Implementation** | [github.com/hellocoop/AAuth](https://github.com/hellocoop/AAuth) |

## Building

This repository uses the [i-d-template](https://github.com/martinthomson/i-d-template) build system. To build HTML from all draft documents:

```sh
make
```

Each `draft-*.md` file produces a corresponding HTML file.

## Versions

| Date | Link |
|------|------|
| **Latest** | [Editor's Copy](https://dickhardt.github.io/AAuth/) |
| **2026-03-02** | [draft-hardt-aauth.html](https://dickhardt.github.io/AAuth/2026-03-02/draft-hardt-aauth.html) |
| **2026-01-09** | [draft-hardt-aauth.html](https://dickhardt.github.io/AAuth/2026-01-09/draft-hardt-aauth.html) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to participate.

Discussion happens on [GitHub Issues](https://github.com/dickhardt/AAuth/issues).
