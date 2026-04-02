%%%
title = "AAuth Mission"
abbrev = "AAuth-Mission"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["agent", "authorization", "mission", "audit"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-aauth-mission-latest"
stream = "IETF"

date = 2026-04-02T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

%%%

.# Abstract

AAuth Mission is an optional layer for AAuth that provides mission-scoped authorization and centralized audit for multi-step agent workflows. A mission is a construct that guides and authorizes an agent's work — the agent proposes what it intends to do, the Mission Authority approves and enriches the proposal, and every subsequent authorization is evaluated against that mission context. This document defines mission creation, mission-scoped token issuance, MA countersignatures, mission lifecycle management, and the mission control administrative interface.

This document is part of the AAuth specification family. See https://github.com/dickhardt/AAuth for the complete set of AAuth documents.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

This document is part of the AAuth specification family. Source for this draft and an issue tracker can be found at https://github.com/dickhardt/AAuth.

{mainmatter}

# Introduction

**Status: Exploratory Draft**

The AAuth Protocol specification defines how agents obtain authorization from auth servers, including cross-domain federation between auth servers. This specification extends that model with missions — scoped authorization contexts that guide and authorize an agent's work across multiple resource accesses.

The concept draws from the military doctrine of Mission Command (Auftragstaktik), in which commanders give subordinate units a mission — the objective, the intent, and the constraints — then empower them to execute autonomously. The unit does not ask for permission at every step; it operates within the bounds of the mission. AAuth Mission applies the same principle to software agents: the Mission Authority approves a mission that defines what the agent is trying to accomplish, then the agent operates autonomously within that scope. Each resource access is evaluated against the mission context, but the agent is not micro-managed.

A mission provides:

- **Scoped authorization**: Each resource access is evaluated against the mission context
- **Centralized audit**: The Mission Authority sees every authorization in the chain
- **Content-addressable identity**: Missions are identified by the SHA-256 hash of their approved text, providing both a permanent identifier and integrity proof

This specification defines two endpoint concepts:

- **Mission endpoint**: The MA's token endpoint, extended with mission parameters for proposal submission and mission-scoped token issuance
- **Mission control endpoint**: An administrative interface on the MA for managing mission lifecycle, inspecting audit trails, and integrating with external systems

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

- **Mission**: A scoped authorization context that guides and authorizes an agent's work across multiple resource accesses. Identified by the SHA-256 hash of its approved text.
- **Mission Authority (MA)**: The agent's auth server, acting as the centralized point for mission approval, authorization evaluation, and audit. The agent always sends token requests to its MA.
- **Mission Proposal**: A natural language markdown document submitted by an agent describing the work it intends to perform. The MA evaluates the proposal and may approve, modify, or reject it.
- **Mission Endpoint**: The MA's token endpoint, extended with mission parameters.
- **Mission Control Endpoint**: The administrative interface on the MA for managing mission lifecycle.

# Mission Authority (MA)

The agent's auth server acts as the Mission Authority for all missions it approves. The agent always sends token requests to its MA, even when the target resource is governed by a different AS — this is the standard AAuth model where agents always talk to their own auth server.

# Mission Lifecycle

## Creation

The agent sends a `mission_proposal` to the MA's mission endpoint (the MA's token endpoint). The proposal is a natural language markdown document — the agent doesn't know what resources or scopes it will need ahead of time:

```json
{
  "mission_proposal": "# Research Competitors\n\nResearch our top 3 competitors' pricing pages and write a summary report comparing their offerings to ours.\n\n## Approach\n1. Search for competitor pricing\n2. Read and analyze each page\n3. Write comparison report in shared docs"
}
```

The MA evaluates the proposal — potentially deferring for human review or engaging in clarification chat — and returns the approved mission. The MA may add context it knows about the user or organization:

```json
{
  "mission": {
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "approved": "# Research Competitors\n\nResearch our top 3 competitors (Acme Corp, Globex, Initech) pricing pages and write a summary report.\n\n## Context\n- Our current pricing is at https://docs.internal/pricing-v3\n- Focus on enterprise tier comparisons\n- Report goes in the Q2 competitive analysis folder"
  }
}
```

The `s256` field is the base64url-encoded SHA-256 hash of the `approved` text. This hash serves as the mission's permanent identifier and integrity proof — anyone with the approved text can compute the hash and verify it matches. The `approved` field is a markdown string containing the MA's version of the mission, which may include organizational context, constraints, or clarifications.

It is RECOMMENDED that the MA include unique context (such as a timestamp or reference) in the approved text to ensure distinct missions produce distinct hashes.

## Resource Access

The agent includes `mission_s256` alongside `resource_token` in token requests to the MA. The MA evaluates each request against the mission context.

## Completion

Missions end via the mission control endpoint: agent declaration, administrator action, business event, MA timeout, or explicit revocation. See (#mission-control).

# Mission Claim in Auth Tokens

Auth tokens issued within a mission contain:

```json
{
  "mission": {
    "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "auth": "https://ma.example"
  }
}
```

The `s256` field is the SHA-256 hash of the approved mission text. The `auth` field identifies the Mission Authority. This claim enables downstream ASes to identify the MA and call back for authorization during chained calls.

# MA Token (Countersignature)

When the MA is not the issuer of an auth token (cross-domain case), the MA countersigns by appending a JWT with a `~` separator:

`<auth_token>~<ma_token>`

The ma_token structure:

- `typ`: `ma+jwt`
- `iss`: MA URL
- `ath`: Base64url SHA-256 hash of the auth token
- `mission_s256`: SHA-256 hash of the approved mission text
- `iat`, `exp`: Timestamps

Verifiers check both independently: auth token against the issuing AS's keys, ma_token against the MA's keys (discovered from `mission.auth`).

When `mission.auth` equals the auth token's `iss`, the MA issued the token directly and no ma_token is needed.

# Mission Context in Cross-Domain Federation

Cross-domain federation between auth servers is defined in the AAuth Protocol specification. When a mission is active, the mission adds context to that federation flow — the MA includes mission information in federation calls and evaluates the results against the mission scope before countersigning.

## Flow

~~~ ascii-art
Agent                MA                  AS2
  |                    |                   |
  |  POST /token       |                   |
  |  resource_token    |                   |
  |  mission_s256      |                   |
  |------------------->|                   |
  |                    |                   |
  |                    |  resource_token   |
  |                    |  aud=AS2          |
  |                    |                   |
  |                    |  POST /token      |
  |                    |  resource_token   |
  |                    |  mission {...}    |
  |                    |  request_doc      |
  |                    |------------------>|
  |                    |                   |
  |                    |  auth_token       |
  |                    |  risk_context     |
  |                    |<------------------|
  |                    |                   |
  |                    |  evaluate against
  |                    |  mission scope +
  |                    |  risk context,
  |                    |  sign ma_token
  |                    |                   |
  |  auth_token        |                   |
  |  ~ma_token         |                   |
  |<-------------------|                   |
  |                    |                   |
~~~

The MA sends the resource token and mission context to AS2. AS2 evaluates, creates the auth token, and returns it with a `risk_context` — its interpretation of the risk and what the requested scopes mean. The MA then evaluates the full picture (mission context + AS risk assessment) before countersigning.

Any step may return 202 with clarification.

# Mission Context in Call Chaining

Call chaining is defined in the AAuth Protocol specification. When a resource (R1) acts as an agent and needs a downstream resource (R2), the mission claim in the auth token it received enables the chain to route through the MA.

## Flow

~~~ ascii-art
R1/Agent2           AS2                MA                AS3
  |                   |                  |                  |
  |  POST /token      |                  |                  |
  |  resource_token   |                  |                  |
  |   (from R2,       |                  |                  |
  |    aud=AS3)       |                  |                  |
  |  upstream_token   |                  |                  |
  |   (has mission    |                  |                  |
  |    claim)         |                  |                  |
  |------------------>|                  |                  |
  |                   |                  |                  |
  |                   |  sees mission.auth = MA             |
  |                   |  sees resource_token aud=AS3        |
  |                   |                  |                  |
  |                   |  POST /token     |                  |
  |                   |  resource_token                     |
  |                   |  request_doc     |                  |
  |                   |  upstream_token                     |
  |                   |  mission {...}   |                  |
  |                   |----------------->|                  |
  |                   |                  |                  |
  |                   |                  |  POST /token     |
  |                   |                  |  resource_token  |
  |                   |                  |  request_doc     |
  |                   |                  |  mission {...}   |
  |                   |                  |----------------->|
  |                   |                  |                  |
  |                   |                  |  auth_token      |
  |                   |                  |  risk_context    |
  |                   |                  |<-----------------|
  |                   |                  |                  |
  |                   |                  |  evaluate,       |
  |                   |                  |  sign ma_token   |
  |                   |                  |                  |
  |                   |  auth_token~ma_token                |
  |                   |<-----------------|                  |
  |                   |                  |                  |
  |  auth_token       |                  |                  |
  |  ~ma_token        |                  |                  |
  |<------------------|                  |                  |
  |                   |                  |                  |
~~~

**Pattern at every hop:** `agentN → its AS → MA → target AS`

The MA sees every authorization in the chain, providing a single audit trail for the entire mission.

# Mission Endpoint Extensions

The mission endpoint is the MA's token endpoint, extended with the following parameters for mission operations.

## Additional Request Parameters

| Parameter | Sent by | Description |
|-----------|---------|-------------|
| `mission_proposal` | Agent → MA | Markdown string describing proposed mission |
| `mission_s256` | Agent → MA | SHA-256 hash of approved mission text (resource access) |
| `mission` | AS → MA, MA → AS | Mission context `{s256, auth}` in federation calls |
| `request_document` | MA → AS, AS → MA | Authorization request details |
| `risk_context` | AS → MA (response) | AS-provided risk assessment |

The `upstream_token` parameter (already in core AAuth for call chaining) carries the mission claim through the chain.

## Risk Context

Returned by a resource's AS alongside the auth token:

```json
{
  "risk_context": {
    "level": "high",
    "reason": "Bulk data export, first access by this agent"
  }
}
```

The MA uses this alongside mission context to make informed approval decisions. Vocabulary TBD.

# Mission Control {#mission-control}

The Mission Authority holds all mission data as a consequence of being in the authorization path for every mission action. Mission Control is the administrative interface to that data, exposed via the mission control endpoint.

This section describes what Mission Control could look like. It is not a normative protocol specification — implementations are free to design their own administrative interfaces. The API surface sketched here illustrates the capabilities and data model that a Mission Control implementation would expose.

## Mission States

A mission progresses through the following states:

```
                    ┌──────────┐
                    │ proposed │
                    └────┬─────┘
                         │ approve
                         ▼
                    ┌──────────┐
              ┌────►│  active  │◄────┐
              │     └──┬───┬───┘     │
              │        │   │         │
           resume      │   │      resume
              │        │   │         │
              │   suspend  │         │
              │        │   │         │
              ▼        ▼   │         │
         ┌──────────┐  │  │    ┌──────────┐
         │suspended │  │  │    │          │
         └──────────┘  │  │    │          │
                       │  │    │          │
              ┌────────┘  │    │          │
              │           │    │          │
              ▼           ▼    ▼          │
         ┌─────────┐ ┌─────────┐  ┌──────┴───┐
         │completed│ │ revoked │  │ expired  │
         └─────────┘ └─────────┘  └──────────┘
```

- **proposed**: Mission proposal submitted, awaiting approval
- **active**: Mission approved and in progress
- **suspended**: Temporarily halted; all token requests return an error until resumed
- **completed**: Successfully finished (agent declaration, administrator action, or business event)
- **revoked**: Permanently terminated by administrator or policy
- **expired**: MA timeout — mission exceeded its maximum duration

Terminal states: `completed`, `revoked`, `expired`. Missions in terminal states cannot be reactivated.

## Potential API Surface

The following sketches a REST API that a Mission Control implementation could expose. The actual paths, parameters, and response formats are implementation-specific.

### List Missions

Retrieve missions for a user, agent, or organization. Supports filtering by state.

```http
GET /missions?state=active&agent=https://agent.example
```

```json
{
  "missions": [
    {
      "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      "state": "active",
      "created": "2026-03-19T10:00:00Z",
      "agent": "https://agent.example",
      "summary": "Research Competitors"
    }
  ]
}
```

### Inspect Mission

View the proposal, approved document, current state, and audit trail.

```http
GET /missions/dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

```json
{
  "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "state": "active",
  "created": "2026-03-19T10:00:00Z",
  "agent": "https://agent.example",
  "approved": "# Research Competitors\n\n...",
  "authorizations": [
    {
      "timestamp": "2026-03-19T10:05:00Z",
      "resource": "https://search.example",
      "scope": "web.search",
      "decision": "granted"
    },
    {
      "timestamp": "2026-03-19T10:07:00Z",
      "resource": "https://docs.example",
      "scope": "docs.write",
      "decision": "granted"
    }
  ]
}
```

### Suspend Mission

Temporarily halt a mission. All token requests for this mission return an error until resumed.

```http
POST /missions/{s256}/suspend

{
  "reason": "Reviewing agent behavior"
}
```

### Resume Mission

Resume a suspended mission.

```http
POST /missions/{s256}/resume
```

### Revoke Mission

Permanently terminate a mission.

```http
POST /missions/{s256}/revoke

{
  "reason": "Agent exceeded expected scope"
}
```

### Complete Mission

Mark a mission as successfully finished.

```http
POST /missions/{s256}/complete
```

### Delegation Tree

View the full chain of agents, resources, and auth servers involved in a mission.

```http
GET /missions/{s256}/delegation-tree
```

```json
{
  "s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  "root_agent": "https://agent.example",
  "delegations": [
    {
      "agent": "https://agent.example",
      "resource": "https://api.example",
      "as": "https://auth.example",
      "scope": "data.read",
      "timestamp": "2026-03-19T10:05:00Z"
    },
    {
      "agent": "https://api.example",
      "resource": "https://downstream.example",
      "as": "https://auth2.example",
      "scope": "records.read",
      "timestamp": "2026-03-19T10:05:30Z",
      "chained_from": "https://api.example"
    }
  ]
}
```

## Business Event Integration

External systems (ticketing, CRM, procurement) could signal events that trigger mission state changes. For example:

```http
POST /missions/{s256}/event

{
  "type": "ticket_closed",
  "source": "https://tickets.example",
  "reference": "TICKET-1234",
  "action": "complete"
}
```

The MA would validate the event source and apply the requested state transition.

## Access Control

Access to Mission Control operations would be governed by the MA's own policies. Typical access patterns:

- **User**: Can list and inspect their own missions, complete missions they initiated
- **Administrator**: Can list, inspect, suspend, resume, and revoke any mission within their organization
- **Agent**: Can complete missions it is executing
- **External system**: Can send business events for missions it is associated with

The authentication and authorization mechanism for Mission Control is outside the scope of this document.

# Error Responses

When a token request references a mission that is not in an active state, the MA returns an error. Error codes and semantics TBD. Expected categories:

- Mission not active (suspended, completed, revoked, expired)
- Request outside mission scope
- Delegation depth exceeded
- Mission not found

# Metadata Extension

Auth servers that support missions advertise:

```json
{
  "mission_supported": true,
  "mission_control_endpoint": "https://ma.example/missions"
}
```

Resources are unaware of missions. They verify auth tokens and ma_tokens using published keys.

# Security Considerations

## Mission Integrity

The `s256` hash provides content-addressable identification. Any party with the approved mission text can verify it matches the hash in tokens. This prevents mission document tampering after approval.

## MA as Single Audit Point

The MA sees every authorization decision within a mission. This provides a centralized audit trail but also makes the MA a high-value target. Implementations SHOULD apply appropriate security controls to MA infrastructure.

## Mission Scope Enforcement

The MA evaluates each resource access against the mission context. This is a policy decision — the MA may use AI, rule engines, or human review to determine whether a request is within scope.

## Audit Trail Integrity

The MA's audit trail is the authoritative record of all authorization decisions within a mission. Implementations should protect audit data against tampering.

## Suspension Propagation

When a mission is suspended, in-flight token requests for that mission should be rejected. Outstanding auth tokens already issued remain valid until their expiration.

## Business Event Validation

Business events from external systems are untrusted input. The MA should validate the event source and verify consistency with the mission's current state.

# IANA Considerations

## JWT Claims

This specification registers the following JWT claim:

- `mission`: Mission context containing `s256` (SHA-256 hash of approved mission text) and `auth` (Mission Authority URL)

## Media Type Registrations

- `application/ma+jwt`: Mission Authority countersignature token

{backmatter}

# Open Questions

- **Mission evolution**: Can the agent renegotiate the mission mid-flight (e.g., send an updated proposal referencing the mission s256), or must it propose a new mission?
- **Request document format**: Standardized or resource-specific?
- **Risk context vocabulary**: Standard fields TBD.
- **MA availability**: Fail closed if MA is unreachable?
- **Partial approval**: Can the MA narrow scopes, or strictly approve/deny?
- **Suspension scope**: Should suspension trigger revocation of outstanding auth tokens, or only block new token issuance?
- **State change notifications**: Should the MA notify agents and external systems of state changes via webhooks?
- **Multi-user missions**: Can a mission span multiple users within an organization?
- **Mission templates**: Can organizations define reusable mission templates with pre-approved scopes?

# Implementation Status

*Note: This section is to be removed before publishing as an RFC.*

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in [@RFC7942]. The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.

There are currently no known implementations.

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-aauth-mission-00
  - Initial submission

# Acknowledgments

The author would like to thank Karl McGuinness for his writing on agent authorization that informed the mission lifecycle and control plane concepts.
