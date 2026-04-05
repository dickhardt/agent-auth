# Mission-Centric Architecture

*Design notes from architectural discussion, 2026-04-03*

## Motivation

The original AAuth architecture positions the Authorization Server (AS) as the agent's primary authority, with missions as an optional governance layer. This rethinking inverts that relationship: the Mission Manager (MM) becomes fundamental to the protocol, and the AS becomes a deterministic policy engine serving resources.

Key insight: an agent doesn't need "an AS" -- but an agent doing purposeful work needs a Mission Manager. The MM knows who the agent is, who it represents, what it's trying to accomplish, and brokers all authorization on the agent's behalf.

---

## Two-Layer Model

### Layer 1 -- AAuth Headers 

For agents without missions, or resources that don't support missions.

- HTTP Message Signatures (RFC 9421 profile)
- AAuth-Requirement header (pseudonym, identity, interaction, approval)
- Signature-Error header
- No AS involvement, no federation, no auth tokens
- Resource manages its own authentication (redirects to its own IdP, etc.)
- Agent proves identity via agent server + signatures

### Layer 2 -- Missions (Authorization Protocol)

For agents operating in a mission context, accessing mission-aware resources.

- Agent sends AAuth-Mission header on initial request
- Resource returns `requirement=auth-token` + resource token (with mission object)
- Agent sends resource token to its MM
- MM interacts with user and gets consent
- MM federates with resource's AS
- AS evaluates policy, issues auth token
- MM returns auth token to agent
- Agent presents auth token to resource

---

## Entities

### Agent

- Has an agent server (identity, key binding) -- unchanged
- Optionally has a Mission Manager (for mission-context work)
- Discovers its MM the same way it discovers its AS in the current spec
- When operating in a mission, always sends AAuth-Mission header

### Mission Manager (MM)

The agent's central authority for mission-context work. Combines IdP + mission authority roles:

- **Knows the user**: authenticates the user, holds user-agent association
- **Knows the mission**: manages mission lifecycle, scope, context
- **Handles consent**: presents R3 display information to user in mission context
- **Asserts identity**: provides directed user identifier (`sub`) per AS
- **Brokers authorization**: the only entity that calls resource ASes
- **Maintains audit**: sees every authorization in the mission, records complete trails
- Has a `.well-known` document for discovery
- Has a registration endpoint for dynamic MM-AS trust establishment

### Authorization Server (AS)

A deterministic policy engine serving one or more resources:

- **Only called by MAs** -- never by agents or other ASes
- **Evaluates policy**: processes resource token, applies rules, issues auth tokens
- **No user interaction**: the MM handles all user-facing consent/interaction
- **Determines required claims after processing resource token** -- can't know what identity claims it needs until it sees what's being requested
- Has a `.well-known` document for discovery
- Token endpoint accepts JSON POST (not form-encoded)

### Resource

Two kinds of resources in AAuth:

- **AAuth-aware**: Understands AAuth headers (signatures, AAuth-Requirement, Signature-Error). Manages its own auth via Layer 1 (interaction, approval, identity, pseudonym).
- **Mission-aware**: Full AAuth + missions. Has an AS. Returns `requirement=auth-token` with resource token containing mission object. Supports dual mode -- falls back to Layer 1 for non-mission agents (AS is not involved since only MAs call ASes).

---

## AAuth-Mission Header

Defined in the AAuth Protocol spec (not the Headers spec -- it is a request header from agent to resource, unlike AAuth-Requirement and Signature-Error which are response headers from server to agent).

Sent by the agent on its initial request to a resource when operating in a mission context.

```
AAuth-Mission: manager="https://mm.example.com"; s256="base64url-hash"
```

- `manager` -- the Mission Manager's URL
- `s256` -- the SHA-256 hash of the approved mission text (base64url)
- Mission-aware agents always send this header
- Resources that don't understand missions ignore it (backwards compatible)
- The resource may use it to tailor its AAuth-Requirement response

---

## Flows

### Non-Mission Flow (Layer 1)

```
Agent --> Resource (with AAuth signature, no AAuth-Mission)
Resource --> Agent (AAuth-Requirement: interaction/approval/identity/pseudonym)
[Resource handles its own auth -- redirects to its IdP, etc.]
```

### Mission Flow (Layer 2)

```
Agent --> Resource
  Headers: AAuth-Mission: iss="https://ma.example.com"; s256="abc123..."

Resource --> Agent
  401 + AAuth-Requirement: requirement=auth-token
  + resource token (contains mission object: iss, s256)

Agent --> MM (resource token + agent token)

  MM fetches R3 document (for user consent -- display fields)
  MM checks mission scope, confirms with user if needed

  MM --> AS: POST /token (JSON)
    { resource_token, agent_token }

  AS fetches R3 document (for policy -- operations)
  AS processes resource token, evaluates policy

  AS --> MM: 200 + auth token
    OR
  AS --> MM: 202 + Location header + required claims/clarification
    MM --> AS: POST /location { sub, email, org, ... }
    AS --> MM: 200 + auth token

MM --> Agent (auth token)

Agent --> Resource (signed request + auth token)
```

### R3 Conditional (Per-Call Challenge)

Same pattern as the mission flow. When the agent attempts a conditional operation:

```
Agent --> Resource (auth token with r3_conditional for this operation)
Resource --> Agent (new resource token with actual parameters)
Agent --> MM --> AS --> auth token for this specific call
Agent --> Resource (with specific auth token)
```

---

## MM <-> AS Mechanics

### Trust Establishment

- **Pre-established**: Business registration between MM and AS. May include payment terms, SLA, compliance requirements. This is the primary model.
- **Dynamic registration**: MM registers with AS on first encounter. The AS has a registration endpoint. Trust bootstrap for dynamic registration is an **open question**.

### Token Request

The MM sends a JSON POST to the AS's token endpoint:

```json
POST /token HTTP/1.1
Content-Type: application/json
Signature-Input: ...
Signature: ...
Signature-Key: ...

{
  "resource_token": "eyJ...",
  "agent_token": "eyJ..."
}
```

The MM authenticates via HTTP Message Signatures. Mission context is in the resource token (not repeated in the request body).

### AS Response

**Immediate approval (200)**:
```json
{
  "auth_token": "eyJ..."
}
```

**Needs more information (202)**:
```
HTTP/1.1 202 Accepted
Location: https://as.example/token/pending/xyz
Content-Type: application/json

{
  "required_claims": ["email", "org"]
}
```

The MM posts the required claims to the Location URL:
```json
POST /token/pending/xyz HTTP/1.1
Content-Type: application/json

{
  "sub": "directed-user-id-for-this-as",
  "email": "user@example.com",
  "org": "Acme Corp"
}
```

**Clarification (202)**:
The AS can also send a clarification question (not just claim requirements):
```json
{
  "clarification": "Multiple access levels available. Which tier?",
  "options": ["read_only", "read_write", "full_admin"]
}
```

The MM triages who answers: itself (if mission context has the answer), the user, or the agent. The MM may pass the clarification down to the agent (returning a 202 to the agent with the clarification).

### Directed Identifiers

The MM provides a pairwise pseudonymous `sub` for each AS. The same user gets a different `sub` per AS, preserving privacy.

### R3 Dual Fetch

Both MM and AS independently fetch the R3 document at `r3_uri` and verify the hash matches `r3_s256`:

- **MM uses R3 for consent**: reads `display` fields (summary, implications, data_accessed, irreversible) to present to the user in mission context. The MM decides whether this fits the mission and gets user approval *before* calling the AS.
- **AS uses R3 for policy**: reads `operations` (vocabulary, tools/endpoints) to evaluate what to grant. Produces `r3_granted` and `r3_conditional` in the auth token.

### Separation of Concerns

| Responsibility | MM | AS |
|---------------|----|----|
| User authentication | Yes | No |
| User consent | Yes | No |
| Mission scope checking | Yes | No |
| Identity assertion | Yes (directed sub) | Consumes |
| Policy evaluation | No | Yes |
| Auth token issuance | No | Yes |
| Audit trail | Yes (centralized) | Per-resource |

---

## Auth Token

JWT issued by the resource's AS, returned to the MM, passed to the agent, presented to the resource.

```json
{
  "iss": "https://as.resource.example",
  "aud": "https://resource.example",
  "sub": "directed-user-id-for-this-as",
  "iat": 1712150400,
  "exp": 1712154000,
  "jti": "unique-token-id",

  "agent": "local@agent.example.com",
  "cnf": { "jkt": "agent-key-thumbprint" },

  "r3_uri": "https://resource.example/r3/calendar-write",
  "r3_s256": "hash-of-r3-doc",
  "r3_granted": {
    "vocabulary": "urn:aauth:vocabulary:mcp",
    "operations": [{ "tool": "list_calendar_events" }]
  },
  "r3_conditional": {
    "vocabulary": "urn:aauth:vocabulary:mcp",
    "operations": [{ "tool": "create_calendar_event" }]
  },

  "mission_s256": "hash-of-mission",
  "mission_iss": "https://ma.example.com"
}
```

The resource verifies:
- Token signature (from AS)
- Agent identity (request signature matches `cnf.jkt`)
- Operations (match request against `r3_granted` / `r3_conditional`)

---

## Call Chaining

When a resource (R1) needs to call another resource (R2) to fulfill a request, R1 acts as both resource and agent.

```
Agent A --> R1 (with auth token brokered by MM)
  R1 needs to call R2
  R1 --> R2 (with AAuth-Mission header)
  R2 --> R1 (resource token for R2)

  R1 --> MM: POST /token {
    agent_token: R1's own agent token,
    upstream_token: Agent A's auth token for R1,
    resource_token: R2's resource token
  }

  MM verifies the chain: Agent A --> R1 --> R2
  MM federates with R2's AS
  MM --> R1 (auth token for R2)

  R1 --> R2 (with auth token)
```

R1 has its own agent identity (agent server, agent token). The upstream token proves the chain from Agent A. The MM sees and records the complete delegation chain for audit.

---

## Eliminated Concepts

| Concept | Replaced By |
|---------|------------|
| Agent has an AS | Agent has an MM (for mission flows) |
| AS-to-AS federation | MM-to-AS federation (only MMs call ASes) |
| Countersigning (`ma_token`, `~` separator) | MM brokering is sufficient (MM obtained the token) |
| `requirement=interaction` at the AS (user redirected to AS) | MM handles all user interaction |

---

## Unchanged from Current Specs

- Agent token format and issuance (agent server)
- Mission lifecycle: proposed, active, suspended, completed, revoked, expired
- Mission identification: SHA-256 hash of approved text (s256)
- R3 documents: content-addressed, vocabulary-based operations, display fields
- HTTP Message Signatures profile (RFC 9421)
- AAuth-Requirement and Signature-Error headers (Layer 1)
- Resource token format (plus mission object for mission-aware resources)
- Auth token presentation (signed request + auth token in header)

---

## Open Questions

1. **Dynamic registration trust bootstrap**: When an MM encounters an AS it has never worked with, how does the AS decide to trust the MM? This is a business registration process (may include payment terms, compliance) but the trust bootstrap mechanism is unresolved.

2. **Exact `.well-known` document formats**: Both MM and AS have `.well-known` documents for discovery. Both include an `issuer` property (must match the URL, same pattern as OIDC discovery). Exact schema TBD.

## Resolved

3. ~~**AAuth-Mission header syntax**~~: `manager` (MM URL) and `s256` (mission hash). Defined in the protocol spec.
4. ~~**`.well-known` document formats**~~: Defined in protocol spec — `aauth-mission.json` (MM), `aauth-issuer.json` (AS), `aauth-resource.json` (resource with `authorization_endpoint`).

---

## Implementation Status

These design notes have been implemented in the spec documents:

- `draft-hardt-aauth-protocol.md` — merged with mission spec, four-party model, authorization endpoint, MM↔AS federation
- `draft-hardt-aauth-r3.md` — updated with MM as R3 consumer (dual fetch)
- `README.md` — rewritten with problem statement, adoption path, three-spec structure
- `draft-hardt-aauth-mission.md` — to be archived (content merged into protocol)
- `aauth-explainer.md` — to be archived (content moves to aauth.ai)
