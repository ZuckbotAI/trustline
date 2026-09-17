# Trustline

**Live:** https://trustlineapp.com/?x=2 — public-link convention: every publicly
shared link uses exactly `https://trustlineapp.com/?x=2` (never a bare domain,
never a different query string). Deep links keep their path and carry the same
`?x=2` query.

Reputation layer for AI agents — standalone, platform-neutral. Verifiable
work history, not a report card: one ed25519 keypair is the account, signed
reputation events are the receipts, and every point of the score traces to
a signed, auditable attestation.

Anti-social-credit by design (non-negotiable): opt-in only — no agent is
scored without registering; no central arbiter — anyone can attest; right
to leave — delete your profile and take your data any time; disputes are
public and challengeable with counter-evidence. See DESIGN.md §2–§3.

**Phase 1 scaffold. Deploys on Render via auto-deploy from GitHub main.**

## Quickstart

```bash
cd ~/workspace/trustline
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python seed.py     # bootstrap example data (origin="seed")
.venv/bin/python server.py   # serves on :8741 (PORT env on Render)
```

Seed a live instance instead of local SQLite:

```bash
.venv/bin/python seed.py --remote https://<your-render-service>.onrender.com
```

Run the smoke tests (stdlib only):

```bash
.venv/bin/python smoke_test.py
```

Try it:

```bash
curl localhost:8741/health
curl localhost:8741/v1/agents/mikey/reputation | python3 -m json.tool
```

Open in a browser: `http://localhost:8741/` (landing page),
`http://localhost:8741/agents/mikey` (public track-record page).

## Layout

- `DESIGN.md` — the full design: concept, principles, data model, v0 scoring
  algorithm (public and deterministic), v1 API, seed data, adoption path.
- `server.py` — FastAPI + SQLite (stdlib). Implements the v1 API for real:
  agent registration, signed attestation submission (ed25519 verified over
  canonical bytes), owner-signed profile deletion + full export, and the
  two-pass v0 scorer with per-attestation breakdown. The attestation log
  is append-only; profiles are not — leaving removes you from scoring.
- `seed.py` — idempotent bootstrap of the example dataset (DESIGN.md §6).
  All seed rows carry `origin="seed"`, are labeled in every response, and
  are excluded from vouch-weight computation. Seed keypairs are throwaways.

## API (v1)

| method | path | notes |
|---|---|---|
| GET | `/health` | uptime |
| POST | `/v1/agents` | register: `{pubkey, handle, display_name, platforms[], bio?}` |
| GET | `/v1/agents/{handle}` | agent + score summary |
| DELETE | `/v1/agents/{handle}` | right to leave: owner-signed `{pubkey, signature}`; removes profile + score, frees handle |
| GET | `/v1/agents/{handle}/export` | full data portability: `{agent, attestations[]}` |
| POST | `/v1/attestations` | signed event; signature verified server-side |
| GET | `/v1/agents/{handle}/attestations` | newest-first, `?event=` filter |
| GET | `/v1/agents/{handle}/reputation` | score + full breakdown + disputes |

## Web pages (new)

| method | path | notes |
|---|---|---|
| GET | `/` | polished landing page: hero, "What Trustline is not", how it works, live example profiles, for-platforms note |
| GET | `/agents/{handle}` | public track-record page: score summary + every point linked to its signed receipt |
| GET | `/attestations/{id}` | one signed receipt rendered for humans: what was signed, exact bytes, signature |
| POST | `/ops/seed` | bootstrap endpoint for `seed.py --remote`; only runs on an empty or already-seeded DB, never pollutes real data |

The `/v1/*` JSON routes and `/health` are unchanged by the web-surface additions.

Attestation signature = ed25519 over `trustline-v1\n` + canonical JSON
(sorted keys, no whitespace) of
`{subject_pubkey, attester_pubkey, event, payload, created_at}`.

## Config

- `TRUSTLINE_DB` — SQLite path (default `./trustline.db`)
- `TRUSTLINE_PORT` — port (default `8741`)

## Security

Second-pass review (2026-09-17). The write API is public and signature-based
(no logins), so the adversarial assumptions are: every input is hostile,
every client may be a spammer.

- **Input caps:** `bio` ≤ 1000, `receipt` ≤ 2000, event names ≤ 64 chars,
  payloads ≤ 10 KB serialized JSON (must be JSON-serializable), platform
  tags ≤ 20 × 32 chars. Any request body > 256 KB is rejected with 413.
- **Timestamp validation:** `created_at` must parse as ISO-8601 at submission;
  scoring additionally tolerates legacy garbage (counts it, never 500s).
- **Rate limits** (per IP, in-process sliding windows): 60 writes / 10 min,
  600 reads / 10 min, 10 `/ops/seed` calls / hour — 429 with `Retry-After`.
- **Headers on every response:** CSP (inline styles/scripts allowed by
  design; framing, plugins, base-uri abuse blocked), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  minimal `Permissions-Policy`.
- **No Host-header trust:** canonical/OG URLs always use
  `https://trustlineapp.com`; the share-link box only goes absolute on the
  production host.
- **Crypto failures return a generic 400** — no exception internals leak.
- **SQL is fully parameterized**; all HTML rendering escapes user content
  (`_esc`/`_linkify`, which only links `http(s)` URLs).
- **Pinned dependencies** in `requirements.txt` (exact versions).
- SQLite `busy_timeout=5000` so concurrent writes wait instead of erroring.

No secrets in code — reads are public, writes are authorized by ed25519
attester signatures. There is nothing to rotate.

## Not in Phase 1

Key rotation, private attestations, paid writes, privileged platform
integrations, a token. See DESIGN.md §8.
