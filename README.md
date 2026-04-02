# AAuth

**Author:** Dick Hardt (dick.hardt@hello.coop)

AAuth is an authentication and authorization protocol for autonomous agents and dynamic ecosystems. It is not intended as a replacement for OAuth or OIDC — it addresses new use cases where pre-registered clients, browser redirects, and bearer tokens are not a good fit.

## Document Suite

AAuth is defined by a family of specifications. Each document covers a distinct aspect of the protocol:

| Document | Description | Status |
|----------|-------------|--------|
| **[HTTP AAuth Headers](draft-hardt-aauth-headers.md)** | AAuth-Challenge and AAuth-Error headers, HTTP Message Signing profile, pseudonymous/identity/interaction/approval requirement levels | Draft |
| **[AAuth Protocol](draft-hardt-aauth-protocol.md)** | Token types (agent, resource, auth), token endpoint, deferred responses, clarification chat, call chaining, cross-domain federation | Draft |
| **[AAuth Rich Resource Requests (R3)](draft-hardt-aauth-r3.md)** | Vocabulary-based authorization: structured R3 documents, proactive resource token acquisition, and vocabulary-format grants in auth tokens | Exploratory |
| **[AAuth Mission Protocol](draft-hardt-aauth-mission-protocol.md)** | Mission-scoped authorization, MA countersignatures, centralized audit for multi-step agent workflows | Exploratory |
| **[AAuth Mission Control](draft-hardt-aauth-mission-control.md)** | API surface for managing and auditing missions: list, inspect, suspend, revoke, complete | Exploratory |
| **[Explainer](aauth-explainer.md)** | Non-normative overview of AAuth concepts, comparisons to OAuth/OIDC, and design rationale | — |

The original monolithic draft (`draft-hardt-aauth.md`) is retained for reference during the transition to the multi-document structure.

## Links

| Resource | Link |
|----------|------|
| **GitHub Repository** | https://github.com/dickhardt/AAuth |
| **Website** | https://aauth.ai |
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
