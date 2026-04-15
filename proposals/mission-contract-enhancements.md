# Proposed Mission Contract Enhancements

**Author:** Nick Gamb, Strata Identity  
**Date:** 2026-04-15  
**Status:** Proposal  
**Applies to:** draft-hardt-aauth-protocol-01, Section 8 (Mission)

## Background

These proposals are informed by our implementation of intent-bound authorization
for MCP (Model Context Protocol) tool governance. We originally developed a
"Desired Outcome Contract" (DOC) protocol that shares core concepts with AAuth
Mission Contracts — immutable, SHA-256-hashed authorization contexts governing
agent tool access with human-in-the-loop approval.

After evaluating both approaches, we are aligning with AAuth and migrating our
implementation to Mission Contracts. During this migration, we identified several
capabilities from our DOC work that address gaps in the current AAuth Mission
spec. These are proposed as optional extensions that complement the existing
design without changing the core protocol.

A reference implementation demonstrating all five proposals is available at:
https://github.com/strata-io/orchestrator-blueprints (branch: `aauth-poc`)

---

## Proposal 1: Tamper-Evident Mission Log via Hash Chaining

### Problem

The mission log (Section 8.3) is maintained by the PS as an ordered record of
agent interactions, but the spec provides no integrity mechanism. A compromised
or malfunctioning PS could silently modify, reorder, or omit log entries without
detection.

### Proposal

Add OPTIONAL hash chaining to audit entries (Section 7.5) in the mission log.
Each audit record includes a `hash` and `prev_hash` field, creating an
append-only, tamper-evident chain:

```
hash = SHA-256(prev_hash | action | parameters | result)
```

The first entry in a mission's audit chain seeds from the mission's `s256` hash,
cryptographically binding the execution log to the approved mission.

### Suggested Spec Addition (Section 7.5.2)

> The PS MAY maintain a hash chain across audit entries within a mission. When
> hash chaining is enabled, each audit log entry includes:
>
> - `hash`: SHA-256 hash of the concatenation of prev_hash, action, parameters,
>   and result, using pipe (U+007C) as delimiter
> - `prev_hash`: The hash of the previous audit entry, or the mission's s256
>   for the first entry
>
> This creates an append-only, tamper-evident log that can be independently
> verified by any party with access to the mission log.

### Rationale

This is complementary to the PS's role as log maintainer. It doesn't change who
maintains the log — just adds cryptographic integrity that enables independent
verification. Particularly valuable for compliance-sensitive domains (financial
services, healthcare) where audit log integrity is a regulatory requirement.

---

## Proposal 2: Mission Template Discovery

### Problem

AAuth missions are proposed by agents in natural language (Section 8.1), which
provides flexibility but offers no structured discovery mechanism. An agent
accessing a new resource has no way to learn what kinds of missions the resource
or PS supports, leading to poorly-scoped proposals that require more
clarification rounds.

### Proposal

Add an OPTIONAL `templates` endpoint to the PS that returns structured mission
templates — descriptions of common mission types with suggested tools,
capabilities, and constraints:

```json
{
  "aauth_extension": "mission-templates",
  "version": "0.1.0",
  "templates": [
    {
      "id": "account_inquiry",
      "name": "Account Inquiry",
      "description": "Read-only access to account information",
      "suggested_tools": [
        {"name": "listAccounts", "description": "List accounts"},
        {"name": "getAccount", "description": "Get account details"}
      ],
      "capabilities": ["interaction"],
      "suggested_constraints": {
        "max_tool_calls": 10,
        "timeout_seconds": 300
      }
    }
  ]
}
```

Templates are suggestions, not constraints — the agent MAY use them to compose
better proposals, or ignore them and propose freeform missions.

### Suggested Spec Addition (PS Discovery Metadata)

> The PS MAY expose a `templates_endpoint` in its metadata. This endpoint
> returns an array of mission template objects that help agents compose
> well-scoped mission proposals. Templates are advisory — they do not constrain
> what missions can be proposed.

### Rationale

This follows the same pattern as OAuth's discovery metadata — structured
information that helps clients interact more effectively without being mandatory.
It reduces clarification rounds and improves the quality of initial mission
proposals, particularly for agents interacting with a PS for the first time.

---

## Proposal 3: Mission Constraint Budgets

### Problem

AAuth missions have no mechanism for hard limits on agent execution. The PS
evaluates requests contextually, but there is no way to express "this mission
allows at most N tool calls" or "this mission expires after T seconds." Without
budgets, a misbehaving agent could make unbounded requests under a single
approved mission.

### Proposal

Add OPTIONAL constraint fields to the mission blob (Section 8.2):

```json
{
  "approver": "https://ps.example",
  "agent": "aauth:assistant@agent.example",
  "approved_at": "2026-04-07T14:30:00Z",
  "description": "...",
  "approved_tools": [...],
  "constraints": {
    "max_tool_calls": 10,
    "timeout_seconds": 300
  }
}
```

The PS enforces these constraints as part of its evaluation logic. When a
constraint is violated, the PS denies the request and MAY terminate the mission.

### Suggested Spec Addition (Section 8.2)

> The mission blob MAY include:
>
> - `constraints`: A JSON object containing budget limits for the mission.
>   When present, the PS SHOULD enforce these limits. Supported fields:
>   - `max_tool_calls` (integer): Maximum number of audited tool calls
>     permitted within this mission.
>   - `timeout_seconds` (integer): Maximum duration in seconds from
>     `approved_at` after which the mission is automatically terminated.

### Rationale

Budgets are a safety mechanism that complements contextual governance. They
provide a hard ceiling that prevents runaway execution even if the PS's
contextual evaluation is permissive. This is especially important for
high-sensitivity operations (financial transactions, PII access) where
unbounded agent activity poses real risk.

---

## Proposal 4: Tool Ordering Constraints

### Problem

Some tool operations have inherent ordering requirements that are difficult for
contextual governance to discover without deep domain knowledge. For example, a
banking API might require reading account details before modifying account
status, or prohibit certain sequences of operations for safety reasons.

### Proposal

Add OPTIONAL ordering constraint fields to the mission constraints:

```json
{
  "constraints": {
    "required_predecessors": {
      "updateAccountStatus": "getAccount"
    },
    "prohibited_sequences": [
      ["deleteRecord", "createRecord"]
    ]
  }
}
```

- `required_predecessors`: A map where keys are tool names and values are tools
  that must appear in the audit log before the key tool can be permitted.
- `prohibited_sequences`: An array of [A, B] pairs where calling B immediately
  after A is denied.

### Suggested Spec Addition (Section 8.2, within constraints)

> The constraints object MAY include:
>
> - `required_predecessors` (object): Maps tool names to prerequisite tools.
>   The PS MUST deny a permission request for a tool if its prerequisite has
>   not been recorded in the mission's audit log.
> - `prohibited_sequences` (array of arrays): Each element is a pair [A, B]
>   where tool B MUST NOT be permitted immediately after tool A in the audit
>   log.

### Rationale

These constraints encode domain safety rules that would otherwise require the PS
to have deep knowledge of every resource's business logic. By including them in
the mission blob (potentially derived from templates), the PS can enforce them
mechanically while reserving contextual evaluation for higher-level decisions.
This bridges the gap between AAuth's deliberate avoidance of policy language and
the practical need for basic operational ordering.

---

## Proposal 5: Denial Category Classification

### Problem

The permission endpoint (Section 7.4.2) returns only `"granted"` or `"denied"`
with an optional reason string. When a request is denied, the agent and
observability systems have no structured way to understand what layer of
governance caused the denial — was it a scope issue, a mission scope issue, or
an execution history issue?

### Proposal

Add an OPTIONAL `denial_category` field to the permission response:

```json
{
  "permission": "denied",
  "reason": "Tool not in approved_tools and outside mission scope",
  "denial_category": "intent_denied"
}
```

Defined categories:

| Category | Meaning |
|---|---|
| `authorization_denied` | Missing scope or token (WHO + WHAT layer) |
| `intent_denied` | Action not aligned with mission intent (WHY layer) |
| `trajectory_denied` | Execution history violation (budget, ordering) |

### Suggested Spec Addition (Section 7.4.2)

> The permission response MAY include:
>
> - `denial_category` (string): A structured classification of why the
>   request was denied. Defined values:
>   - `authorization_denied`: The agent lacks required authorization
>     (scopes, tokens) for this action.
>   - `intent_denied`: The action is not aligned with the approved mission's
>     intent or scope.
>   - `trajectory_denied`: The action violates execution history constraints
>     (budget exceeded, ordering violation).
>
> This field is advisory and intended for observability. The `reason` field
> remains the human-readable explanation.

### Rationale

Three-tier denial classification provides significantly richer observability
signal. An `authorization_denied` suggests the agent needs different credentials;
an `intent_denied` suggests the agent should propose a different mission; a
`trajectory_denied` suggests the agent has exceeded its approved execution
budget. Without this classification, operators must parse reason strings to
understand denial patterns across their fleet.

---

## Implementation Reference

All five proposals are implemented in the Strata Identity orchestrator-blueprints
repository (`aauth-poc` branch):

- **Proposal 1** (hash chaining): `apps/person-server/audit.go`
- **Proposal 2** (template discovery): `apps/person-server/templates.go`
- **Proposal 3** (constraint budgets): `apps/person-server/permission.go`
- **Proposal 4** (ordering constraints): `apps/person-server/permission.go`
- **Proposal 5** (denial categories): `apps/person-server/permission.go`

The implementation uses these extensions alongside a full AAuth Mission Contract
lifecycle (proposal, approval with HITL, per-call permission, audit logging)
governing an Enterprise Ledger MCP server with tools of varying sensitivity
levels.
