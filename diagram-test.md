%%%
title = "Diagram Comparison Test"
abbrev = "DiagTest"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["test"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-diagram-test-latest"
stream = "IETF"

date = 2026-02-27T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@hello.coop"

%%%

.# Abstract

Test document comparing ASCII art and aasvg diagram rendering.

{mainmatter}

# Plain ASCII Art

## Autonomous Agent (ASCII)

~~~ ascii-art
+-------+              +----------+             +-----------+
| Agent |              | Resource |             | Auth      |
|       |              |          |             | Server    |
+---+---+              +-----+----+             +-----+-----+
    |                        |                        |
    |  HTTPSig request       |                        |
    |----------------------->|                        |
    |                        |                        |
    |  401 + resource_token  |                        |
    |  + auth_server         |                        |
    |<-----------------------|                        |
    |                        |                        |
    |  POST token_endpoint with resource_token        |
    |------------------------------------------------>|
    |                        |                        |
    |                        |    validate             |
    |                        |    resource_token,      |
    |                        |    evaluate policy      |
    |                        |                        |
    |  auth_token (direct grant)                      |
    |<------------------------------------------------|
    |                        |                        |
    |  HTTPSig request       |                        |
    |  (scheme=jwt with      |                        |
    |   auth-token)          |                        |
    |----------------------->|                        |
    |                        |                        |
    |  200 OK                |                        |
    |<-----------------------|                        |
    |                        |                        |
~~~

## User Authorization (ASCII)

~~~ ascii-art
+------+  +-------+  +----------+  +-----------+
| User |  | Agent |  | Resource |  | Auth      |
|      |  |       |  |          |  | Server    |
+--+---+  +---+---+  +-----+----+  +-----+-----+
   |          |             |             |
   |          | HTTPSig     |             |
   |          | request     |             |
   |          |------------>|             |
   |          |             |             |
   |          | 401 +       |             |
   |          | resource_   |             |
   |          | token       |             |
   |          |<------------|             |
   |          |             |             |
   |          | POST token_endpoint       |
   |          | resource_token, purpose,  |
   |          | callback_url,             |
   |          | callback_url           |
   |          |-------------------------->|
   |          |             |             |
   |          | Location URL,           |
   |          | interaction_code,       |
   |          | interval, expires_in      |
   |          |<--------------------------|
   |          |             |             |
   | redirect to            |             |
   | interaction_endpoint   |             |
   | + interaction_code   |             |
   |<---------|             |             |
   |          |             |             |
   | authenticate           |             |
   | and consent            |             |
   |------------------------------------->|
   |          |             |             |
   |          | POST token_endpoint       |
   |          | + Location URL          |
   |          |  - - - - - - - - - - - -->|
   |          |             |             |
   |          | authorization_pending     |
   |          |<- - - - - - - - - - - - --|
   |          |             |             |
   | redirect to callback_url            |
   | + callback_url      |             |
   |<-------------------------------------|
   |          |             |             |
   | callback |             |             |
   |--------->|             |             |
   |          |             |             |
   |          | POST token_endpoint       |
   |          | + Location URL          |
   |          |-------------------------->|
   |          |             |             |
   |          | auth_token +              |
   |          | refresh_token             |
   |          |<--------------------------|
   |          |             |             |
   |          | HTTPSig request           |
   |          | (auth-token)|             |
   |          |------------>|             |
   |          |             |             |
   |          | 200 OK      |             |
   |          |<------------|             |
   |          |             |             |
~~~

## Clarification Chat (ASCII)

~~~ ascii-art
+------+            +-------+            +-----------+
| User |            | Agent |            | Auth      |
|      |            |       |            | Server    |
+--+---+            +---+---+            +-----+-----+
   |                    |                      |
   |  Note: Agent has Location URL,          |
   |  user is at interaction_endpoint          |
   |                    |                      |
   |                    | POST token_endpoint  |
   |                    | + Location URL     |
   |                    | Accept: text/        |
   |                    | event-stream         |
   |                    |--------------------->|
   |                    |                      |
   |                    |    SSE connection     |
   |                    |    opened             |
   |                    |                      |
   | "Why do you need   |                      |
   |  calendar access?" |                      |
   |------------------------------------------->
   |                    |                      |
   |                    | SSE: clarification   |
   |                    | "Why do you need     |
   |                    |  calendar access?"   |
   |                    |<.....................|
   |                    |                      |
   |                    | POST token_endpoint  |
   |                    | + Location URL,    |
   |                    | clarification_       |
   |                    | response             |
   |                    |--------------------->|
   |                    |                      |
   |  display agent     |                      |
   |  response          |                      |
   |<------------------------------------------|
   |                    |                      |
   | grant consent      |                      |
   |------------------------------------------->
   |                    |                      |
   |                    | SSE: auth_token      |
   |                    |<.....................|
   |                    |                      |
~~~

# aasvg Diagrams

## Autonomous Agent (aasvg)

~~~ aasvg
+-------+              +----------+             +-----------+
| Agent |              | Resource |             | Auth      |
|       |              |          |             | Server    |
+---+---+              +-----+----+             +-----+-----+
    |                        |                        |
    |  HTTPSig request       |                        |
    |----------------------->|                        |
    |                        |                        |
    |  401 + resource_token  |                        |
    |  + auth_server         |                        |
    |<-----------------------|                        |
    |                        |                        |
    |  POST token_endpoint with resource_token        |
    |------------------------------------------------>|
    |                        |                        |
    |                        |    validate             |
    |                        |    resource_token,      |
    |                        |    evaluate policy      |
    |                        |                        |
    |  auth_token (direct grant)                      |
    |<------------------------------------------------|
    |                        |                        |
    |  HTTPSig request       |                        |
    |  (scheme=jwt with      |                        |
    |   auth-token)          |                        |
    |----------------------->|                        |
    |                        |                        |
    |  200 OK                |                        |
    |<-----------------------|                        |
    |                        |                        |
~~~

## User Authorization (aasvg)

~~~ aasvg
+------+  +-------+  +----------+  +-----------+
| User |  | Agent |  | Resource |  | Auth      |
|      |  |       |  |          |  | Server    |
+--+---+  +---+---+  +-----+----+  +-----+-----+
   |          |             |             |
   |          | HTTPSig     |             |
   |          | request     |             |
   |          |------------>|             |
   |          |             |             |
   |          | 401 +       |             |
   |          | resource_   |             |
   |          | token       |             |
   |          |<------------|             |
   |          |             |             |
   |          | POST token_endpoint       |
   |          | resource_token, purpose,  |
   |          | callback_url,             |
   |          | callback_url           |
   |          |-------------------------->|
   |          |             |             |
   |          | Location URL,           |
   |          | interaction_code,       |
   |          | interval, expires_in      |
   |          |<--------------------------|
   |          |             |             |
   | redirect to            |             |
   | interaction_endpoint   |             |
   | + interaction_code   |             |
   |<---------|             |             |
   |          |             |             |
   | authenticate           |             |
   | and consent            |             |
   |------------------------------------->|
   |          |             |             |
   |          | POST token_endpoint       |
   |          | + Location URL          |
   |          |  - - - - - - - - - - - -->|
   |          |             |             |
   |          | authorization_pending     |
   |          |<- - - - - - - - - - - - --|
   |          |             |             |
   | redirect to callback_url            |
   | + callback_url      |             |
   |<-------------------------------------|
   |          |             |             |
   | callback |             |             |
   |--------->|             |             |
   |          |             |             |
   |          | POST token_endpoint       |
   |          | + Location URL          |
   |          |-------------------------->|
   |          |             |             |
   |          | auth_token +              |
   |          | refresh_token             |
   |          |<--------------------------|
   |          |             |             |
   |          | HTTPSig request           |
   |          | (auth-token)|             |
   |          |------------>|             |
   |          |             |             |
   |          | 200 OK      |             |
   |          |<------------|             |
   |          |             |             |
~~~

## Clarification Chat (aasvg)

~~~ aasvg
+------+            +-------+            +-----------+
| User |            | Agent |            | Auth      |
|      |            |       |            | Server    |
+--+---+            +---+---+            +-----+-----+
   |                    |                      |
   |  Note: Agent has Location URL,          |
   |  user is at interaction_endpoint          |
   |                    |                      |
   |                    | POST token_endpoint  |
   |                    | + Location URL     |
   |                    | Accept: text/        |
   |                    | event-stream         |
   |                    |--------------------->|
   |                    |                      |
   |                    |    SSE connection     |
   |                    |    opened             |
   |                    |                      |
   | "Why do you need   |                      |
   |  calendar access?" |                      |
   |------------------------------------------->
   |                    |                      |
   |                    | SSE: clarification   |
   |                    | "Why do you need     |
   |                    |  calendar access?"   |
   |                    |<.....................|
   |                    |                      |
   |                    | POST token_endpoint  |
   |                    | + Location URL,    |
   |                    | clarification_       |
   |                    | response             |
   |                    |--------------------->|
   |                    |                      |
   |  display agent     |                      |
   |  response          |                      |
   |<------------------------------------------|
   |                    |                      |
   | grant consent      |                      |
   |------------------------------------------->
   |                    |                      |
   |                    | SSE: auth_token      |
   |                    |<.....................|
   |                    |                      |
~~~

{backmatter}
