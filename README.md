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

## Not in Phase 1

Key rotation, private attestations, paid writes, privileged platform
integrations, a token. See DESIGN.md §8.
