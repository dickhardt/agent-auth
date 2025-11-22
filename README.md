# AAuth

**Author:** Dick Hardt (dick.hardt@hello.coop)

AAuth is an authentication and authorization protocol for autonomous agents and dynamic ecosystems. It is not intended as a replacement for OAuth or OIDC — it addresses new use cases where pre-registered clients, browser redirects, and bearer tokens are not a good fit.

## Documents

| Document | Link |
|----------|------|
| **IETF Draft (Editor's Copy)** | [draft-hardt-aauth.html](https://dickhardt.github.io/draft-hardt-aauth/draft-hardt-aauth.html) |
| **Explainer** | [aauth-explainer.md](aauth-explainer.md) |
| **TypeScript Implementation** | [github.com/hellocoop/AAuth](https://github.com/hellocoop/AAuth) |

## Versions

| Date | Link |
|------|------|
| **Latest** | [Editor's Copy](https://dickhardt.github.io/draft-hardt-aauth/draft-hardt-aauth.html) |
| **2026-03-02** | [draft-hardt-aauth.html](https://dickhardt.github.io/draft-hardt-aauth/2026-03-02/draft-hardt-aauth.html) |
| **2026-01-09** | [draft-hardt-aauth.html](https://dickhardt.github.io/draft-hardt-aauth/2026-01-09/draft-hardt-aauth.html) |

## Changelog

**2026-03-02 vs [2026-01-09](https://dickhardt.github.io/draft-hardt-aauth/2026-01-09/draft-hardt-aauth.html)**

- Replaced authorization code flow with HTTP async pattern (`202 Accepted`, `Location`, `Prefer: wait`)
- Introduced `AAuth` response header with `require=` structured syntax (SF Dictionary)
- Five requirement levels: `pseudonym`, `identity`, `auth-token`, `interaction`, `approval`
- Dropped refresh tokens — agent presents expired auth token to refresh; HTTP signatures already prove agent identity
- Switched all token endpoint requests from form-encoded to JSON
- Added `purpose` parameter for agent-declared intent during authorization requests
- Added clarification chat during user consent (via polling)
- Added enterprise hint parameters: `login_hint`, `tenant`, `domain_hint`
- Added `require=approval` for auth server direct approval without agent-facilitated redirect
- Added agent delegate user binding
- Enriched metadata with `client_name`, `logo_uri`, `logo_dark_uri`, `callback_endpoint`, `localhost_callback_allowed`, `tos_uri`, `policy_uri`, `scope_descriptions`
- Added resource `interaction_endpoint` for resource-level user interaction
- Added call chaining with `upstream_token` for multi-hop resource access
- Added design rationale section
- Rewrote introduction to clarify relationship to OAuth/OIDC
- Wrote substantive explainer document

**[2026-01-09](https://dickhardt.github.io/draft-hardt-aauth/2026-01-09/draft-hardt-aauth.html)**

- Initial IETF draft
