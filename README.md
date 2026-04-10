# AAuth

**Author:** Dick Hardt (dick.hardt@gmail.com)

Autonomous agents need to authenticate and authorize across services they've never seen before — without pre-registration, without browser redirects, and without bearer tokens that can be stolen and replayed. Existing standards (OAuth, OIDC) were designed for a world where applications are pre-registered with authorization servers and users are present in a browser. AAuth addresses the gap.

## Why AAuth

- **No pre-registration**: Agents establish identity from HTTPS URLs and self-published keys. They work everywhere immediately.
- **Proof-of-possession**: Every token is bound to a signing key via HTTP Message Signatures. Stolen tokens are worthless.
- **Incremental adoption**: Resources can adopt AAuth signatures and the authorization endpoint without replacing their existing OAuth/OIDC infrastructure. The resource handles authorization itself and binds it to the agent's key.
- **Mission governance**: When deeper control is needed, agents operate under a Mission Manager (MM) that manages missions, handles user consent, and federates with resource Authorization Servers (ASes) — providing centralized audit across all agent activity.
- **Rich authorization**: R3 documents express authorization in vocabularies agents already understand (MCP, OpenAPI, gRPC), with human-readable display for consent and content-addressed audit provenance.

For the full story, see [aauth.ai](https://aauth.ai).

## Specifications

AAuth is built on three specifications:

### HTTP Signature Headers (Signature-Key)

**HTTP Signature Headers** (draft-hardt-httpbis-signature-key) — Status: Internet-Draft

[Editor's Copy (with latest updates)](https://dickhardt.github.io/signature-key/add-signature-requirement-error/draft-hardt-httpbis-signature-key.html) · [Datatracker](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/)

The foundation. A standalone HTTP specification (not AAuth-specific) that defines:

- **`Signature-Key` header** — conveys public keying material alongside HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421))
- **`Signature-Requirement` header** — communicates server signature requirements to clients
- **`Signature-Error` header** — structured error reporting for signature verification failures

### AAuth Protocol

**AAuth Protocol** (draft-hardt-aauth-protocol) — Status: Internet-Draft

[Editor's Copy](https://dickhardt.github.io/AAuth/draft-hardt-aauth-protocol.html) · [Datatracker](https://datatracker.ietf.org/doc/draft-hardt-aauth-protocol)

The four-party authorization protocol (Agent, Resource, MM, AS). Defines:

- **HTTP Message Signatures profile** — algorithms, keying material, signing, and verification for AAuth
- **Requirement responses** — progressive requirement levels (pseudonym → identity → interaction → approval)
- **Resource authorization endpoint** — where agents request access, with two modes: resource requests (resource handles auth) and mission requests (MM↔AS federation)
- **Missions** — scoped authorization contexts with lifecycle management and centralized audit
- **Three token types** — agent (identity), resource (challenge), auth (authorization grant)
- **Deferred responses** with clarification chat during consent
- **Call chaining** for multi-hop resource access through the MM

### AAuth R3

**[AAuth R3](draft-hardt-aauth-r3.md)** (draft-hardt-aauth-r3) — Status: Exploratory

Rich Resource Requests. Vocabulary-based authorization using formats agents already understand (MCP, OpenAPI, gRPC, GraphQL). Content-addressed R3 documents provide human-readable consent display and permanent audit provenance.

## Links

| Resource | Link |
|----------|------|
| **Website** | https://aauth.ai |
| **GitHub Repository** | https://github.com/dickhardt/AAuth |
| **TypeScript Implementation** | [github.com/hellocoop/AAuth](https://github.com/hellocoop/AAuth) |

## Building

```sh
make
```


Each `draft-*.md` file produces a corresponding HTML file.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to participate. Discussion happens on [GitHub Issues](https://github.com/dickhardt/AAuth/issues).

---

> Founding sponsor: [Greffen Posner](https://www.linkedin.com/in/geffenpo/)

