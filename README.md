# AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

One FastAPI backend, one dashboard, one provider-independent analysis
pipeline. Supports Gmail and Microsoft mailboxes (via OAuth) or a
direct `.eml` file upload with no authentication required.

See **PROJECT_CONTEXT.md** for full architecture/contracts/limitations,
**ARCHITECTURE.md** for diagrams, and **MERGE_LOG.md** for what was
merged/replaced/ignored and why.

## Quick start

```bash
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn backend.app.main:app --reload --port 8000
```

Open http://localhost:8000.

**No OAuth credentials yet?** You don't need them to see the pipeline
work: the dashboard shows an "Analyze a file" panel whenever no
mailbox is connected. Upload any `.eml` file (e.g. `original1.eml`,
`pinterest1.eml`, or a SCOPE-style newsletter) and it runs through the
full M1 -> M2 -> M3 -> M4 -> risk-engine pipeline immediately.

## Setting up Gmail OAuth
1. Google Cloud Console -> APIs & Services -> Credentials -> Create
   OAuth client ID -> **Web application**.
2. Add `http://localhost:8000/auth/google/callback` as an authorized
   redirect URI.
3. Enable the Gmail API for the project.
4. Put the client ID/secret into `.env` as `GOOGLE_CLIENT_ID` /
   `GOOGLE_CLIENT_SECRET`; leave `GOOGLE_REDIRECT_URI` as the default
   unless you're deploying elsewhere.
5. If the OAuth consent screen is in "Testing" mode, add every Gmail
   account you'll demo with as a test user.

## Setting up Microsoft OAuth
1. Azure Portal -> App registrations -> New registration.
2. Redirect URI: `http://localhost:8000/auth/microsoft/callback`
   (type: Web).
3. Certificates & secrets -> create a client secret.
4. API permissions -> Microsoft Graph -> Delegated -> add `Mail.Read`,
   `User.Read`, `offline_access`. Grant admin consent if required by
   your tenant.
5. Put the values into `.env` as `MICROSOFT_CLIENT_ID` /
   `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT_ID` (use `common` to
   allow both personal and work/school accounts).

## How mailbox pagination works
The dashboard lets you pick 5/10/20/50/100 emails per page. This maps
directly to provider-native pagination - Gmail's `nextPageToken` or
Microsoft Graph's `@odata.nextLink` - so the backend never downloads
an entire mailbox to slice it locally. Use Previous/Next to move
between pages; each page's token is cached client-side so going back
doesn't re-request from page 1.

## How scanning works
Clicking **Scan Inbox** analyzes the emails on the *current page*
(1-100 messages) with bounded concurrency (5 at a time). Progress
polls every 700ms. If one message fails to parse or fetch, it's
marked `analysis_failed` and the rest of the batch continues - you'll
see a final `Requested / Analyzed / Failed / Skipped` summary.

## Security model
- OAuth tokens are held server-side only, keyed by a signed, random,
  HttpOnly session cookie (`itsdangerous`). Tokens never reach
  frontend JS, localStorage, or URL parameters.
- OAuth `state` is verified on callback (CSRF protection).
- Every cached result and scan is scoped to `(session_id, provider,
  account_id, message_id)` - there is no global "current mailbox."
- Core threat detection (M3) requires no end-user API keys; PhishTank
  and Spamhaus DROP are bundled local feeds.
- `sih.py` (hardcoded IMAP credentials, old architecture) is not used
  anywhere in this codebase.

## Known limitations
See the "Known limitations" section of **PROJECT_CONTEXT.md** -
in-memory-only storage, OAuth requiring real credentials to actually
run, an ML model quirk on very short text, and a scikit-learn version
mismatch warning (models load and predict fine regardless).
