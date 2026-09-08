# ARCHITECTURE.md

## High-level flow

```mermaid
flowchart TD
    U[User] --> AUTH[Authentication Layer]
    AUTH -->|Google OAuth| GP[GmailProvider]
    AUTH -->|Microsoft OAuth| MP[MicrosoftGraphProvider]
    UPLOAD[".eml upload (no auth needed)"] --> PARSE

    GP --> RETR[Mail Retrieval\nnative pagination]
    MP --> RETR
    RETR --> PARSE[Canonical Email Parser\nemail_parser.py]
    PARSE --> NORM[NormalizedEmail]

    NORM --> ORCH[Analysis Orchestrator\nanalysis_service.py]
    ORCH --> CHEAP[Cheap header/auth checks\nsender, Reply-To, Return-Path,\nSPF/DKIM/DMARC, Received chain, URLs]

    CHEAP --> HASATT{Has attachment?}
    HASATT -->|No| SKIP[attachment_analysis:\nscanned=false, reason='No attachments'\nYARA never invoked]
    HASATT -->|Yes| ATT[Attachment Analysis\nmagic bytes -> SHA-256 -> YARA]

    SKIP --> AI
    ATT -->|has_high_severity conditionally forces deeper scan| AI[AI / Body Analysis\nml_classifier.py]

    AI --> TI[Threat Intelligence\nPhishTank + Spamhaus + local heuristics]
    TI --> GEO[Geolocation / Infrastructure]
    GEO --> RISK[Composite Risk Engine]
    ATT -.->|YARA high/medium match forces a floor,\ncannot be diluted by a low AI score| RISK

    RISK --> RESULT[Explainable Result]
    RESULT --> STORE[(Session-scoped result store)]
    RESULT --> UI[SOC Dashboard]
```

**Why attachment-first/conditional**: attachment metadata and bytes
are available immediately after parsing, before any network call or
model inference - the cheapest possible signal. When an email has no
attachments, `attachment_analysis.py` returns immediately
(`scanned: false, reason: "No attachments"`) without touching the
YARA module or the magic-byte detector at all, so most emails (which
have no attachments) never pay that cost. When an email does have
attachments, a high-severity finding (executable/script extension,
macro-enabled document, disguised double extension, extension/magic-
byte mismatch, or a YARA match) conditionally forces the deeper
rule-based text scan in the AI stage even when the ML phishing
probability alone is low - additive only, it never skips a stage for
any email. A YARA high/medium-severity match additionally forces an
explicit risk floor (>= HIGH) in the composite risk engine, so a
convincingly bland email body cannot dilute away real attachment
evidence - this is a deliberate, documented policy, not "YARA
matched -> automatic 100".

**Functional names vs internal labels**: "M1"-"M6" were this
project's internal team-task labels only. The functional names are:
Email Parser, Header & Authentication Analysis, AI Threat
Classification, Threat Intelligence Engine, Attachment Security
Engine, YARA Scanner, URL/Domain Analysis, IP Geolocation &
Infrastructure Analysis, Risk Engine, Mail Provider Layer, OAuth
Authentication, SOC Dashboard. The internal Python module names
(`m1_header_analyzer.py`, variables named `m1_result`, etc.) are
implementation detail and were not renamed this pass to avoid
touching working, tested code; the *API response* attachment/security
fields already use functional shapes (`attachment_analysis`,
`attachments[].yara`, `attachments[].detected_type`, etc.) rather than
"M1"/"M2" labels. Fully renaming the remaining internal `m1`/`m2`/`m3`/`m4`
dict keys in the API response is tracked as a known limitation, not
done in this pass (see PROJECT_CONTEXT.md).

## Provider abstraction

```mermaid
classDiagram
    class MailProvider {
        <<abstract>>
        +get_current_user()
        +list_messages(page_size, page_token)
        +get_message(message_id)
        +disconnect()
    }
    class GmailProvider {
        +Gmail API, raw RFC822, nextPageToken
    }
    class MicrosoftGraphProvider {
        +Graph /me/messages, @odata.nextLink
    }
    MailProvider <|-- GmailProvider
    MailProvider <|-- MicrosoftGraphProvider
```

Nothing above the provider layer branches on which provider produced
a message. Both `get_message()` implementations return the same
`NormalizedEmail` shape (`backend/app/schemas/email_message.py`).

## Session / OAuth flow (Google shown; Microsoft is structurally identical)

```mermaid
sequenceDiagram
    participant Browser
    participant FastAPI
    participant Google

    Browser->>FastAPI: GET /auth/google/login
    FastAPI->>FastAPI: create session, set signed HttpOnly cookie
    FastAPI->>FastAPI: store state -> session_id
    FastAPI-->>Browser: 302 redirect to Google consent (with state)
    Browser->>Google: consent
    Google-->>Browser: 302 redirect to /auth/google/callback?code&state
    Browser->>FastAPI: GET /auth/google/callback
    FastAPI->>FastAPI: verify state, exchange code for tokens
    FastAPI->>FastAPI: store credentials under session_id only
    FastAPI-->>Browser: 302 redirect to /
```

The cookie only ever carries a signed random session id. Tokens never
reach the browser (no localStorage, no URL params).

## User isolation

Every cached analysis result and every scan is keyed by
`(session_id, provider, account_id, message_id)`. There is no global
`CURRENT_USER` / `CURRENT_MAILBOX` anywhere in the codebase. See
`backend/app/services/store.py` and `backend/app/auth/session.py`.

## Batch scan concurrency

```mermaid
flowchart LR
    START[POST /api/scan] --> LIST[List N message ids\nvia provider pagination]
    LIST --> SEM["asyncio.Semaphore(5)"]
    SEM --> W1[worker: fetch + analyze msg 1]
    SEM --> W2[worker: fetch + analyze msg 2]
    SEM --> W3[worker: ...]
    W1 --> APPEND[append result, update progress]
    W2 --> APPEND
    W3 --> APPEND
    APPEND --> POLL[GET /api/scan/scan_id\npolled by dashboard]
```

A single message's failure (parse error, provider timeout) is caught
per-worker and recorded as `status: analysis_failed` without aborting
the other workers - verified in integration testing (see
MERGE_LOG.md).
