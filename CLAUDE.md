# AAuth Project Instructions

## Archive

The `archive/` folder contains historical and superseded documents. Do NOT modify archived files. Contents:

- `aauth-monolith.md` — original monolithic AAuth specification
- `appendixes.md` — orphaned appendix content
- `draft-hardt-aauth-mission.md` — superseded; mission content merged into protocol spec
- `aauth-explainer.md` — superseded; content moving to aauth.ai website
- `comparison-klrc-aauth.md` — comparison document
- `mission-centric-architecture.md` — architectural design notes (superseded; implemented in protocol spec)

## Specifications

All new work happens in these documents:

- `draft-hardt-aauth-headers.md` — AAuth Headers specification (AAuth-Requirement, Signature-Error, HTTP Message Signatures profile)
- `draft-hardt-aauth-protocol.md` — AAuth Protocol specification (four-party protocol: Agent, Resource, MM, AS; includes missions, authorization endpoint, MM-AS federation)
- `draft-hardt-aauth-r3.md` — R3 (Rich Resource Requests) specification

## Building

HTML and TXT outputs are generated from the markdown sources using `mmark` or similar tooling. The `.html` and `.txt` files are generated artifacts.
