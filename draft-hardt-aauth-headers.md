%%%
title = "HTTP AAuth Headers"
abbrev = "AAuth-Headers"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["agent", "authentication", "http", "signatures"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-aauth-headers-latest"
stream = "IETF"

date = 2026-04-10T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

%%%

.# Abstract

This document is obsolete. The content previously defined here has been incorporated into other specifications:

- The `Signature-Error` response header and its error code registry have moved to the HTTP Signature Keys specification ([@!I-D.hardt-httpbis-signature-key]).
- The `AAuth-Requirement` response header, the `interaction` and `approval` requirement values, and the HTTP Message Signatures profile (algorithms, keying material, signing, and verification) have moved to the AAuth Protocol specification ([@!I-D.hardt-aauth-protocol]).
- The `pseudonym` and `identity` requirement values have been replaced by the `Accept-Signature` response header defined in the HTTP Signature Keys specification ([@!I-D.hardt-httpbis-signature-key]).

This document is retained for historical reference only. Implementers MUST use the specifications listed above.

{mainmatter}

# Introduction

This document previously defined the `AAuth-Requirement` and `Signature-Error` HTTP response headers and profiled HTTP Message Signatures for request authentication. That content has been split across two successor specifications as described in the abstract.

This document will not be updated further.

## Content Migration Summary

| Content | Moved To |
|---------|----------|
| `Signature-Error` header and error codes | HTTP Signature Keys ([@!I-D.hardt-httpbis-signature-key]) |
| `AAuth-Requirement` header | AAuth Protocol ([@!I-D.hardt-aauth-protocol]) |
| `interaction` requirement value | AAuth Protocol ([@!I-D.hardt-aauth-protocol]) |
| `approval` requirement value | AAuth Protocol ([@!I-D.hardt-aauth-protocol]) |
| `pseudonym` requirement value | Replaced by `Accept-Signature` in HTTP Signature Keys ([@!I-D.hardt-httpbis-signature-key]) |
| `identity` requirement value | Replaced by `Accept-Signature` in HTTP Signature Keys ([@!I-D.hardt-httpbis-signature-key]) |
| HTTP Message Signatures profile | AAuth Protocol ([@!I-D.hardt-aauth-protocol]) |
| Keying material (Signature-Key schemes) | HTTP Signature Keys ([@!I-D.hardt-httpbis-signature-key]) |

# Security Considerations

This document defines no new protocol elements. See the security considerations of the successor specifications.

# IANA Considerations

This document has no IANA actions. The registries previously proposed here are now defined by the successor specifications.

# Document History

*Note: This section is to be removed before publishing as an RFC.*

- draft-hardt-aauth-headers-01
  - Marked as obsolete; all content migrated to HTTP Signature Keys and AAuth Protocol specifications

- draft-hardt-aauth-headers-00
  - Initial submission, renamed from draft-hardt-aauth-header
  - Added Signature-Error header with extensible error code registry
  - Added `interaction` and `approval` requirement levels
  - Added `url` parameter to interaction for self-contained challenge
  - Renamed terminology from "resource" to "server"

# Acknowledgments

TBD

{backmatter}
