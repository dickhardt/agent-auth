%%%
title = "Agent Auth Protocol"
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

date = 2025-01-09T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@hello.coop"

%%%

.# Abstract

Agent Auth (AAuth) is an authentication and authorization protocol for modern distributed systems. It provides progressive authentication from abuse prevention to full authorization, verified agent identity alongside user identity, cryptographic proof of resource legitimacy, and unified authentication and authorization in a single flow. The protocol uses HTTP Message Signatures for proof-of-possession on every request, eliminating bearer tokens and shared secrets.

{mainmatter}

# Introduction

OAuth was created to replace the anti-pattern of users providing their passwords to applications to scrape their data from web sites. With OAuth, users could authorize an application to scoped access of their data without sharing their passwords. The internet has evolved significantly since the release of OAuth 2.0.

**Security requirements have changed.** Exfiltration of bearer tokens has become a common attack vector. While proof-of-possession with digital signatures is now practical and widely supported, bearer tokens and shared secrets are still used in most deployments.

**Applications are distributed and more diverse.** When OAuth 2.0 was created, the client was typically a server. Today it may also be one of many widely distributed instances of a desktop, mobile, or command line application where managing a single long lived shared secret or private key is impractical.

**Agents have loosened the client-server model.** Tightly bound, pre-registered client and server relationships are giving way to more open and dynamic ecosystems. In environments like the Model Context Protocol (MCP), a client may interact with any server, not just those it was pre-registered with.

**Enterprise systems span multiple trust domains.** Organizations deploy hundreds of applications across vendors, each requiring access to resources in different security contexts. Role-based authorization is often insufficient. Fine-grained, dynamic access control often requires verifying both the calling application and user's identity.

**OAuth scopes have become insufficient for modern authorization.** Traditional OAuth scopes like read or write provide only coarse-grained labels that fail to convey what data will be accessed, under what conditions, for what purpose, or for how long. This opacity prevents meaningful user consent and makes it impossible to enforce least privilege.

**Resources have varying auth requirements.** Resources need different levels of protection for different operations. Public endpoints rely on IP addresses for rate limiting and abuse prevention. Application identity is verified through IP whitelisting, mTLS, or long-lived credentials. Authorization uses API keys, manually provisioned tokens, or OAuth flows. These varying requirements have led to fragmented solutions.

**Applications require both authentication and authorization.** OAuth 2.0 provides authorization (delegated access). OpenID Connect provides authentication (user identity via SSO). Both protocols excel in their designed use cases, but applications often need both authentication and authorization in contexts where the separation creates friction.

AAuth is an exploratory specification examining what new capabilities and features may be useful to address use cases that are not well-served by existing protocols like OAuth 2.0, OpenID Connect (OIDC), and SAML.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Agent
: An application or software component acting on behalf of a user or autonomously. In AAuth, agents have cryptographic identity and make signed requests.

Agent Server
: A server that manages agent identity and issues agent tokens to agent delegates. Identified by an HTTPS URL and publishes metadata at `/.well-known/aauth-agent`.

Agent Delegate
: An instance of an agent that holds an agent token and makes requests on behalf of the agent. Each delegate has its own signing key and a unique `sub` identifier.

Agent Token
: A JWT issued by an agent server to an agent delegate, binding the delegate's signing key to the agent's identity.

Auth Server
: A server that authenticates users, obtains consent, and issues auth tokens. Publishes metadata at `/.well-known/aauth-issuer`.

Auth Token
: A JWT issued by an auth server that grants an agent access to a resource, containing agent identity, user identity (if applicable), and authorized scopes.

Resource
: A protected API or service that requires authentication and/or authorization. May publish metadata at `/.well-known/aauth-resource`.

Resource Token
: A JWT issued by a resource that binds an access request to the resource's identity, preventing confused deputy attacks.

# Protocol Overview

AAuth uses a three-party model where agents access resources with authorization from auth servers. All requests are signed using HTTP Message Signatures ([@!RFC9421]).

## Participants

- **Agent**: Makes signed requests to resources
- **Resource**: Protected API that may require authentication or authorization
- **Auth Server**: Issues auth tokens after authenticating users and obtaining consent

## Token Types

AAuth defines three token types, all of which are proof-of-possession tokens:

- **Agent Token** (`agent+jwt`): Binds an agent delegate's key to an agent server's identity
- **Resource Token** (`resource+jwt`): Binds an access request to a resource's identity
- **Auth Token** (`auth+jwt`): Grants an agent access to a resource

## Authentication Levels

Resources can require different authentication levels via the `Agent-Auth` response header:

1. **Pseudonymous** (`httpsig`): Signed request proves consistent identity without verification
2. **Identified** (`httpsig; identity=?1`): Agent identity verified via JWKS or agent token
3. **Authorized** (`auth-token`): Full authorization with auth token

# Agent-Auth Response Header

Resources use the `Agent-Auth` response header to indicate authentication requirements when returning 401 Unauthorized.

## Signature Required

When a resource requires only a signed request:

```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig
```

## Identity Required

When a resource requires verified agent identity:

```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; identity=?1
```

## Authorization Required

When a resource requires an auth token:

```http
HTTP/1.1 401 Unauthorized
Agent-Auth: httpsig; auth-token; resource_token="..."; auth_server="https://auth.example"
```

Parameters:

- `resource_token`: A resource token binding this request to the resource's identity
- `auth_server`: The auth server URL where the agent should obtain an auth token

# Agent Tokens

Agent tokens enable agent servers to delegate signing authority to agent delegates while maintaining a stable agent identity.

## Agent Token Structure

An agent token is a JWT with `typ: agent+jwt` containing:

Header:
- `alg`: Signing algorithm
- `typ`: `agent+jwt`
- `kid`: Key identifier

Payload:
- `iss`: Agent server URL (the agent identifier)
- `sub`: Agent delegate identifier (stable across key rotations)
- `cnf`: Confirmation claim with `jwk` containing the delegate's public key
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

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
- `agent`: Agent identifier
- `agent_jkt`: JWK thumbprint of the agent's current signing key
- `exp`: Expiration timestamp
- `scope`: Requested scopes (optional)

## Resource Token Usage

Resources include resource tokens in the `Agent-Auth` header when requiring authorization:

```http
Agent-Auth: httpsig; auth-token; resource_token="eyJ..."; auth_server="https://auth.example"
```

# Auth Tokens

Auth tokens grant agents access to resources after authentication and authorization.

## Auth Token Structure

An auth token is a JWT with `typ: auth+jwt` containing:

Header:
- `alg`: Signing algorithm
- `typ`: `auth+jwt`
- `kid`: Key identifier

Payload:
- `iss`: Auth server URL
- `aud`: Resource URL(s)
- `agent`: Agent identifier
- `cnf`: Confirmation claim with `jwk` containing the agent's public key
- `sub`: User identifier (if user-delegated access)
- `scope`: Authorized scopes
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

## Auth Token Usage

Agents present auth tokens via the `Signature-Key` header using `scheme=jwt`:

```http
Signature-Key: sig=jwt; jwt="eyJhbGciOiJFZERTQSIsInR5cCI6ImF1dGgrand0In0..."
```

# Metadata Documents

Participants publish metadata at well-known URLs to enable discovery.

## Agent Server Metadata

Published at `/.well-known/aauth-agent`:

```json
{
  "agent": "https://agent.example",
  "jwks_uri": "https://agent.example/.well-known/jwks.json"
}
```

## Auth Server Metadata

Published at `/.well-known/aauth-issuer`:

```json
{
  "issuer": "https://auth.example",
  "agent_token_endpoint": "https://auth.example/token",
  "agent_auth_endpoint": "https://auth.example/authorize",
  "jwks_uri": "https://auth.example/.well-known/jwks.json"
}
```

## Resource Metadata

Published at `/.well-known/aauth-resource`:

```json
{
  "resource": "https://resource.example",
  "jwks_uri": "https://resource.example/.well-known/jwks.json",
  "additional_signature_components": ["content-type", "content-digest"]
}
```

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

## Signature Parameters

The `Signature-Input` header MUST include:

- `created`: Signature creation timestamp (Unix time)

The `created` timestamp MUST NOT be more than 60 seconds in the past or future.

# Error Responses

AAuth uses the OAuth 2.0 error response format ([@!RFC6749] Section 5.2).

## Error Response Format

```json
{
  "error": "invalid_request",
  "error_description": "Human-readable description"
}
```

## Error Codes

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

# IANA Considerations

## Well-Known URI Registrations

This specification registers the following Well-Known URIs:

- `aauth-agent`: Agent server metadata
- `aauth-issuer`: Auth server metadata
- `aauth-resource`: Resource metadata

## Media Type Registrations

This specification registers the following media types:

- `application/agent+jwt`: Agent token
- `application/auth+jwt`: Auth token
- `application/resource+jwt`: Resource token

## HTTP Header Field Registrations

This specification registers the following HTTP header:

- `Agent-Auth`: Authentication and authorization requirements

{backmatter}

# Acknowledgments

The author would like to thank reviewers for their feedback on this specification.
