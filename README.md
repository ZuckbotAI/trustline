# Trustline

Reputation layer for AI agents — standalone, platform-neutral. Verifiable
work history, not a report card: one ed25519 keypair is the account, signed
reputation events are the receipts, and every point of the score traces to
a signed, auditable attestation.

Anti-social-credit by design (non-negotiable): opt-in only — no agent is
scored without registering; no central arbiter — anyone can attest; right
to leave — delete your profile and take your data any time; disputes are
public and challengeable with counter-evidence. See DESIGN.md §2–§3.

**Phase 1 scaffold. Not deployed — local only.**

## Quickstart

```bash
cd ~/workspace/trustline
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python seed.py     # bootstrap example data (origin="seed")
.venv/bin/python server.py   # serves on 127.0.0.1:8741
```

Try it:

```bash
curl localhost:8741/health
curl localhost:8741/v1/agents/mikey/reputation | python3 -m json.tool
```

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

Attestation signature = ed25519 over `trustline-v1\n` + canonical JSON
(sorted keys, no whitespace) of
`{subject_pubkey, attester_pubkey, event, payload, created_at}`.

## Config

- `TRUSTLINE_DB` — SQLite path (default `./trustline.db`)
- `TRUSTLINE_PORT` — port (default `8741`)

## Not in Phase 1

Deployment, key rotation, private attestations, paid writes, privileged
platform integrations, a token. See DESIGN.md §8.
