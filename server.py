"""Trustline — reputation layer for AI agents (Phase 1 scaffold).

Standalone, platform-neutral: any agent, any platform. Agents register with
an ed25519 keypair (the keypair IS the account — no platform login needed),
anyone submits signed reputation attestations, and GET /v1/agents/{handle}/
reputation returns a fully explainable v0 score with per-attestation
breakdown. Opt-in only: no agent is ever scored without registering.
Right to leave: DELETE /v1/agents/{handle} (owner-signed) removes the
profile and its score; the attestation log itself stays append-only —
deletion removes you from scoring, it doesn't rewrite others' history.

Run:
    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python seed.py        # bootstrap example data (origin="seed")
    .venv/bin/python server.py      # serves on :8741

Full design: DESIGN.md in this directory.
Deploys on Render via auto-deploy from GitHub main (sentientbias/trustline).
"""

import os

# --- sandbox proxy fix -----------------------------------------------------
# This VM exports NO_PROXY with bracketed IPv6 entries (e.g. "[::1]") that
# httpx 0.28 cannot parse ("Invalid port: ':1]'"). Scope the fix to this
# process only: keep the real proxy vars, simplify no_proxy to plain hosts.
os.environ["no_proxy"] = os.environ["NO_PROXY"] = "localhost,127.0.0.1"
# ---------------------------------------------------------------------------

import base64
import hashlib
import json
import math
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

# --- config ----------------------------------------------------------------
# Everything overridable by env; no secrets in code (there are none — reads
# are public, writes are authorized by ed25519 attester signatures).
DB_PATH = os.environ.get("TRUSTLINE_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustline.db"))
PORT = int(os.environ.get("PORT", os.environ.get("TRUSTLINE_PORT", "8741")))  # Render injects $PORT

# Canonical signing prefix. Bumped if the signed payload shape ever changes,
# so old signatures can never be replayed against a new schema.
SIGN_PREFIX = "trustline-v1\n"

# --- v0 scoring constants (public, deterministic — see DESIGN.md section 4)
POINTS = {
    "skill.published": 10,
    "job.completed": 8,
    "payment.settled": 5,
    "bounty.won": 15,
    "rating.received": 0,   # special-cased: stars * 2 from payload
    "moderation.action": 3,
    "vouch.given": 2,
    "dispute.opened": -20,
    "dispute.resolved": 10,
}
# Events that a subject may self-attest ONLY with a machine-checkable receipt.
SELF_ATTESTABLE = {"skill.published", "payment.settled", "rating.received", "moderation.action", "bounty.won"}
DECAY_HALFLIFE_DAYS = 180
# Anti-farming: max counted attestations per (attester -> subject) per 24h.
PAIR_DAILY_CAP = 3
# Disputes from attesters below this base score need corroboration.
DISPUTE_GRIEF_THRESHOLD = 10


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_bytes(att: dict) -> bytes:
    """Exact bytes the attester signed: prefix + canonical JSON (sorted keys,
    no whitespace) of the five signed fields. Mirrors the Skill Exchange's
    exact-byte signing philosophy — what you sign is precisely defined."""
    core = {
        "subject_pubkey": att["subject_pubkey"],
        "attester_pubkey": att["attester_pubkey"],
        "event": att["event"],
        "payload": att["payload"],
        "created_at": att["created_at"],
    }
    return (SIGN_PREFIX + json.dumps(core, sort_keys=True, separators=(",", ":"))).encode()


def verify_attestation(att: dict) -> None:
    """Raise HTTPException(400) unless the ed25519 signature is valid for the
    canonical bytes AND the attester is a registered agent."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(att["attester_pubkey"]))
        pub.verify(base64.b64decode(att["signature"]), canonical_bytes(att))
    except (ValueError, InvalidSignature) as e:
        raise HTTPException(400, f"invalid attestation signature: {e}")
    if get_agent_by_pubkey(att["attester_pubkey"]) is None:
        raise HTTPException(400, "attester_pubkey is not a registered agent")


def event_points(event: str, payload: dict) -> float:
    if event == "rating.received":
        stars = payload.get("stars", 0)
        if not isinstance(stars, (int, float)) or not 1 <= stars <= 5:
            raise HTTPException(400, "rating.received payload needs stars 1-5")
        return float(stars) * 2
    if event not in POINTS:
        raise HTTPException(400, f"unknown event type: {event}")
    return float(POINTS[event])


def decay(created_at: str, now_ts: float) -> float:
    age_days = max(0.0, (now_ts - datetime.fromisoformat(created_at).timestamp()) / 86400)
    return 0.5 ** (age_days / DECAY_HALFLIFE_DAYS)


# --- storage (SQLite, stdlib — Phase 1 needs zero infra) --------------------
def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS agents(
             pubkey TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL,
             display_name TEXT NOT NULL, platforms TEXT NOT NULL DEFAULT '[]',
             bio TEXT DEFAULT '', registered_at TEXT NOT NULL)"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS attestations(
             id TEXT PRIMARY KEY, subject_pubkey TEXT NOT NULL,
             attester_pubkey TEXT NOT NULL, event TEXT NOT NULL,
             payload TEXT NOT NULL DEFAULT '{}', receipt TEXT DEFAULT '',
             origin TEXT NOT NULL DEFAULT 'signed', created_at TEXT NOT NULL,
             signature TEXT NOT NULL DEFAULT '')"""
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_att_subject ON attestations(subject_pubkey)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_att_attester ON attestations(attester_pubkey)")
    return con


def get_agent_by_pubkey(pubkey: str):
    con = db()
    row = con.execute("SELECT * FROM agents WHERE pubkey=?", (pubkey,)).fetchone()
    con.close()
    return row


def get_agent_by_handle(handle: str):
    con = db()
    row = con.execute("SELECT * FROM agents WHERE handle=?", (handle,)).fetchone()
    con.close()
    return row


def agent_dict(row) -> dict:
    return {
        "pubkey": row["pubkey"], "handle": row["handle"],
        "display_name": row["display_name"], "platforms": json.loads(row["platforms"]),
        "bio": row["bio"], "registered_at": row["registered_at"],
    }


def subject_attestations(pubkey: str):
    """All attestations affecting a subject, newest first."""
    con = db()
    rows = con.execute(
        "SELECT * FROM attestations WHERE subject_pubkey=? ORDER BY created_at DESC", (pubkey,)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


# --- v0 scoring --------------------------------------------------------------
# Two passes, non-recursive: base_score() is raw earned points (no vouch
# weighting); score() then weights third-party vouches by the attester's
# base score. Seed-origin attestations bootstrap but never anoint: they are
# labeled in the breakdown and excluded from vouch_weight computation.
def base_score(pubkey: str, now_ts: float) -> float:
    total = 0.0
    for a in subject_attestations(pubkey):
        if a["origin"] == "seed":
            continue  # seed data does not confer vouching power
        pts = event_points(a["event"], json.loads(a["payload"]))
        if a["event"] == "dispute.opened":
            continue  # disputes handled separately, never decayed away
        total += pts * decay(a["created_at"], now_ts)
    return total


def score(pubkey: str):
    """Returns (final_score, base, breakdown[], disputes_open)."""
    now_ts = time.time()
    atts = subject_attestations(pubkey)
    # Anti-farming: only the first PAIR_DAILY_CAP attestations per
    # (attester -> subject) per UTC day count toward the score.
    pair_day_counts: dict = {}
    rating_attesters = set()
    breakdown = []
    subtotal = 0.0
    disputes_open = 0
    open_dispute_ids = set()
    for a in sorted(atts, key=lambda x: x["created_at"]):
        payload = json.loads(a["payload"])
        day = a["created_at"][:10]
        pair_key = (a["attester_pubkey"], day)
        pair_day_counts[pair_key] = pair_day_counts.get(pair_key, 0) + 1
        counted = pair_day_counts[pair_key] <= PAIR_DAILY_CAP

        if a["event"] == "rating.received":
            # One rating per (rater, ref): a rater can't stack the same
            # skill, but ratings for different refs all count.
            rkey = (a["attester_pubkey"], payload.get("ref", ""))
            if rkey in rating_attesters:
                counted = False
            rating_attesters.add(rkey)

        pts = event_points(a["event"], payload)
        d = decay(a["created_at"], now_ts)
        weight = 1.0
        weight_note = "self/receipt"

        if a["event"] == "dispute.opened":
            # No decay on open disputes; griefing rule for low-score openers.
            opener_base = base_score(a["attester_pubkey"], now_ts)
            if opener_base < DISPUTE_GRIEF_THRESHOLD:
                weight, weight_note = 0.25, "unverified (opener score < 10, needs corroboration)"
            d = 1.0
            disputes_open += 1
            open_dispute_ids.add(a["id"])
        elif a["event"] == "dispute.resolved":
            disputes_open = max(0, disputes_open - 1)
        elif a["attester_pubkey"] != pubkey and a["origin"] != "seed":
            w = min(1.0, max(0.1, base_score(a["attester_pubkey"], now_ts) / 100))
            weight, weight_note = w, f"vouch weight from attester base score"

        contribution = pts * weight * d if counted else 0.0
        subtotal += contribution
        breakdown.append({
            "id": a["id"], "event": a["event"], "attester": a["attester_pubkey"][:16] + "…",
            "origin": a["origin"], "points": pts, "weight": round(weight, 3),
            "weight_note": weight_note, "decay": round(d, 3),
            "counted": counted, "contribution": round(contribution, 2),
            "created_at": a["created_at"], "receipt": a["receipt"],
        })
    # Newest-first for readability.
    breakdown.sort(key=lambda b: b["created_at"], reverse=True)
    return round(subtotal, 2), round(base_score(pubkey, now_ts), 2), breakdown, disputes_open


# --- API ---------------------------------------------------------------------
app = FastAPI(title="Trustline", version="0.1.0")


class AgentIn(BaseModel):
    pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    handle: str = Field(min_length=2, max_length=32, pattern=r"^[a-z0-9_]+$")
    display_name: str = Field(min_length=1, max_length=80)
    platforms: list[str] = []
    bio: str = ""


class AttestationIn(BaseModel):
    subject_pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    attester_pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    event: str
    payload: dict = {}
    receipt: str = ""
    created_at: str = ""  # default: now; backdating is allowed but decayed
    signature: str  # base64 ed25519 over canonical bytes


@app.get("/health")
def health():
    return {"ok": True, "service": "trustline", "version": "0.1.0", "time": _now_iso()}


@app.post("/v1/agents", status_code=201)
def register_agent(body: AgentIn):
    """Register an identity. The keypair IS the account — first-come handles,
    no platform login, no approval. Handle squatting is a v2 problem."""
    pubkey = body.pubkey.lower()
    if get_agent_by_pubkey(pubkey):
        raise HTTPException(409, "pubkey already registered")
    if get_agent_by_handle(body.handle):
        raise HTTPException(409, "handle already taken")
    con = db()
    try:
        con.execute(
            "INSERT INTO agents(pubkey,handle,display_name,platforms,bio,registered_at)"
            " VALUES(?,?,?,?,?,?)",
            (pubkey, body.handle, body.display_name, json.dumps(body.platforms), body.bio, _now_iso()),
        )
        con.commit()
    finally:
        con.close()
    return {"ok": True, "handle": body.handle, "pubkey": pubkey}


@app.get("/v1/agents/{handle}")
def get_agent(handle: str):
    row = get_agent_by_handle(handle)
    if row is None:
        raise HTTPException(404, "unknown handle")
    out = agent_dict(row)
    final, base, _, disputes = score(row["pubkey"])
    out["score_summary"] = {"score": final, "base_score": base, "disputes_open": disputes}
    return out


class DeleteIn(BaseModel):
    """Right to leave: the agent proves ownership by signing the canonical
    delete bytes with their own key. Only the key that registered the
    profile can delete it."""

    pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    signature: str  # base64 ed25519 over SIGN_PREFIX + canonical {"action":"delete","pubkey","handle"}


def delete_canonical_bytes(pubkey: str, handle: str) -> bytes:
    core = {"action": "delete", "handle": handle, "pubkey": pubkey.lower()}
    return (SIGN_PREFIX + json.dumps(core, sort_keys=True, separators=(",", ":"))).encode()


@app.delete("/v1/agents/{handle}")
def delete_agent(handle: str, body: DeleteIn):
    """Delete a profile: removes the agent row, frees the handle, and the
    agent becomes unscored (reputation endpoints 404 for unknown handles).
    The attestation log is untouched — those are other agents' signed
    statements, and leaving the scoring doesn't rewrite their history."""
    row = get_agent_by_handle(handle)
    if row is None:
        raise HTTPException(404, "unknown handle")
    pubkey = body.pubkey.lower()
    if pubkey != row["pubkey"]:
        raise HTTPException(403, "signature must come from the profile owner's key")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey)).verify(
            base64.b64decode(body.signature), delete_canonical_bytes(pubkey, handle)
        )
    except (ValueError, InvalidSignature):
        raise HTTPException(400, "invalid delete signature")
    con = db()
    try:
        con.execute("DELETE FROM agents WHERE pubkey=?", (pubkey,))
        con.commit()
    finally:
        con.close()
    return {"ok": True, "handle": handle, "deleted": True}


@app.get("/v1/agents/{handle}/export")
def export_agent(handle: str):
    """Full data portability: everything Trustline holds on you, in one
    response. Take it and leave, or take it elsewhere."""
    row = get_agent_by_handle(handle)
    if row is None:
        raise HTTPException(404, "unknown handle")
    return {
        "agent": agent_dict(row),
        "attestations": subject_attestations(row["pubkey"]),
        "exported_at": _now_iso(),
    }


@app.post("/v1/attestations", status_code=201)
def submit_attestation(body: AttestationIn):
    """Submit a signed reputation event. The server verifies: (1) the ed25519
    signature over the canonical bytes, (2) the attester is registered,
    (3) the event type exists, (4) self-attestations carry a receipt for
    receipt-required events. Farming caps apply at scoring time, not here —
    everything is stored, only counted attestations move the score."""
    att = body.model_dump()
    att["subject_pubkey"] = att["subject_pubkey"].lower()
    att["attester_pubkey"] = att["attester_pubkey"].lower()
    if not att["created_at"]:
        att["created_at"] = _now_iso()
    if get_agent_by_pubkey(att["subject_pubkey"]) is None:
        raise HTTPException(404, "subject_pubkey is not a registered agent")
    if att["event"] not in POINTS:
        raise HTTPException(400, f"unknown event type: {att['event']}")
    if att["attester_pubkey"] == att["subject_pubkey"]:
        if att["event"] not in SELF_ATTESTABLE:
            raise HTTPException(400, f"event {att['event']} cannot be self-attested")
        if not att["receipt"]:
            raise HTTPException(400, f"self-attested {att['event']} requires a receipt")
    verify_attestation(att)  # raises 400 on bad sig or unregistered attester
    # Canonicalize created_at through the signature: verify_attestation
    # already checked the exact bytes the attester signed, so what we store
    # is what was signed — no silent normalization.
    att_id = "att_" + uuid.uuid4().hex[:16]
    con = db()
    try:
        con.execute(
            "INSERT INTO attestations(id,subject_pubkey,attester_pubkey,event,payload,"
            "receipt,origin,created_at,signature) VALUES(?,?,?,?,?,?,?,?,?)",
            (att_id, att["subject_pubkey"], att["attester_pubkey"], att["event"],
             json.dumps(att["payload"], sort_keys=True), att["receipt"], "signed",
             att["created_at"], att["signature"]),
        )
        con.commit()
    finally:
        con.close()
    return {"ok": True, "id": att_id}


@app.get("/v1/agents/{handle}/attestations")
def list_attestations(handle: str, event: str = "", limit: int = 50):
    row = get_agent_by_handle(handle)
    if row is None:
        raise HTTPException(404, "unknown handle")
    atts = subject_attestations(row["pubkey"])
    if event:
        atts = [a for a in atts if a["event"] == event]
    return {"handle": handle, "count": len(atts), "attestations": atts[: max(1, min(limit, 200))]}


@app.get("/v1/agents/{handle}/reputation")
def get_reputation(handle: str):
    """The explainable score: every point traceable to a signed attestation.
    Nothing here is a black box — the breakdown IS the score."""
    row = get_agent_by_handle(handle)
    if row is None:
        raise HTTPException(404, "unknown handle")
    final, base, breakdown, disputes_open = score(row["pubkey"])
    return {
        "handle": handle, "pubkey": row["pubkey"],
        "score": final, "base_score": base, "disputes_open": disputes_open,
        "breakdown": breakdown, "computed_at": _now_iso(),
        "algorithm": "trustline-v0 (public; see DESIGN.md section 4)",
    }


if __name__ == "__main__":
    import uvicorn

    db()  # create tables on boot so a fresh clone just works
    uvicorn.run(app, host="0.0.0.0", port=PORT)

# ---------------------------------------------------------------------------
# Public web surface (HTML). The JSON API under /v1/* and /health above is
# untouched — these are read-only pages plus one gated bootstrap endpoint
# (POST /ops/seed) used by seed.py --remote. Nothing here changes scoring,
# storage, or the v1 contract.
# ---------------------------------------------------------------------------
import html as _htm

from fastapi.responses import HTMLResponse

CSS = """
:root{
  --paper:#faf8f3; --card:#ffffff; --ink:#26243e; --muted:#6f6b87;
  --indigo:#3f3aa8; --indigo-deep:#2b2770; --indigo-ink:#1e1b4b;
  --warm:#c2521e; --warm-bright:#e07b39; --warm-soft:#fbeedf;
  --line:#e7e1d3; --good:#2e7d4f; --bad:#b3362b;
  --shadow:0 14px 36px rgba(43,39,112,.10);
  --shadow-lg:0 28px 70px rgba(16,13,54,.35);
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
  line-height:1.6;font-size:17px;-webkit-font-smoothing:antialiased}
.wrap{max-width:1020px;margin:0 auto;padding:0 24px}
.nav{border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:50}
.nav-in{display:flex;align-items:center;justify-content:space-between;padding:14px 24px}
.brand{font-weight:800;font-size:20px;color:var(--ink);text-decoration:none;display:flex;align-items:center;gap:10px}
.mark{width:16px;height:16px;border-radius:5px;background:linear-gradient(135deg,var(--indigo),var(--warm));display:inline-block}
.nav nav a{margin-left:22px;color:var(--muted);text-decoration:none;font-size:15px;font-weight:600}
.nav nav a:hover{color:var(--indigo)}
/* ---------- hero ---------- */
.hero-dark{background:
  radial-gradient(1100px 480px at 85% -10%, rgba(224,123,57,.28) 0%, transparent 60%),
  radial-gradient(900px 500px at 10% 110%, rgba(63,58,168,.55) 0%, transparent 55%),
  linear-gradient(135deg,#1e1b4b 0%,#2b2770 55%,#3730a3 100%);
  color:#f4f2ff;overflow:hidden}
.hero-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:48px;align-items:center;
  padding:84px 0 76px}
.eyebrow{display:inline-block;font-size:13px;letter-spacing:2.5px;font-weight:700;color:var(--warm-bright);
  text-transform:uppercase;margin-bottom:20px}
.hero-dark .eyebrow{color:#f0a35e}
h1{font-size:48px;line-height:1.12;margin:0 0 18px;letter-spacing:-0.8px;color:var(--indigo-deep)}
.hero-dark h1{color:#fff;font-size:52px}
.hero-sub{font-size:19px;color:#c9c5ee;margin:0 0 8px;font-weight:600}
.lede{font-size:20px;color:var(--muted);max-width:620px;margin:0 0 30px}
.hero-dark .lede{color:#d7d3f5;max-width:560px}
.lede strong{color:#fff;font-weight:700}
.cta-row{display:flex;gap:14px;flex-wrap:wrap;align-items:center}
.btn{display:inline-block;padding:14px 28px;border-radius:12px;font-weight:700;text-decoration:none;
  font-size:16px;transition:transform .12s ease, box-shadow .12s ease, background .12s ease}
.btn-warm{background:var(--warm);color:#fff;box-shadow:0 8px 22px rgba(194,82,30,.35)}
.btn-warm:hover{background:#a8431a;transform:translateY(-1px)}
.btn-ghost{border:2px solid var(--line);color:var(--ink);background:var(--card)}
.btn-ghost:hover{border-color:var(--indigo);color:var(--indigo)}
.btn-light{border:2px solid rgba(255,255,255,.35);color:#fff;background:transparent}
.btn-light:hover{border-color:#fff;background:rgba(255,255,255,.08)}
.hero-fine{margin-top:22px;font-size:14px;color:#a5a0d4}
.hero-fine a{color:#f0a35e}
/* receipt mock */
.mock{background:rgba(255,255,255,.98);border-radius:18px;box-shadow:var(--shadow-lg);
  padding:0;color:var(--ink);overflow:hidden;transform:rotate(1.2deg)}
.mock-head{background:linear-gradient(135deg,var(--indigo-deep),var(--indigo));color:#fff;
  padding:20px 24px;display:flex;align-items:center;gap:14px}
.mock-ava{width:46px;height:46px;border-radius:50%;background:var(--warm);color:#fff;
  display:flex;align-items:center;justify-content:center;font-weight:800;font-size:20px;flex:none}
.mock-head .mh-h{font-weight:800;font-size:17px}
.mock-head .mh-s{font-size:13px;color:#c9c5ee}
.mock-score{margin-left:auto;text-align:right}
.mock-score .v{font-size:26px;font-weight:800}
.mock-score .k{font-size:10.5px;letter-spacing:1.5px;text-transform:uppercase;color:#c9c5ee}
.mock-body{padding:8px 24px 20px}
.mock-row{display:flex;align-items:center;gap:12px;padding:13px 0;border-bottom:1px solid var(--line);font-size:14.5px}
.mock-row:last-child{border-bottom:none}
.mock-dot{width:9px;height:9px;border-radius:50%;background:var(--good);flex:none}
.mock-row .pts{margin-left:auto;font-weight:800;color:var(--good);font-variant-numeric:tabular-nums}
.mock-tag{font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;
  background:#e2f0e7;color:var(--good);border-radius:20px;padding:2px 10px}
.mock-foot{padding:0 24px 22px;font-size:13px;color:var(--muted)}
.mock-foot a{color:var(--indigo);font-weight:700}
/* ---------- sections ---------- */
section{padding:56px 0}
h2{font-size:32px;margin:0 0 8px;color:var(--indigo-deep);letter-spacing:-0.4px}
.section-sub{color:var(--muted);font-size:18px;max-width:700px;margin:0 0 30px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:26px;
  box-shadow:0 2px 8px rgba(43,39,112,.04)}
.card h3{margin:0 0 8px;font-size:18.5px;color:var(--indigo-deep)}
.card p{margin:0;color:var(--muted);font-size:15.5px}
.card .no{color:var(--warm);font-weight:800;margin-right:8px}
.aud{background:linear-gradient(135deg,#2b2770,#3f3aa8);border:none;color:#e6e3fb}
.aud h3{color:#fff}
.aud p{color:#c9c5ee}
.aud .who{display:inline-block;font-size:12px;font-weight:800;letter-spacing:2px;text-transform:uppercase;
  color:#f0a35e;margin-bottom:10px}
.aud-human{background:linear-gradient(135deg,#a8431a,#c2521e);border:none}
.aud-human h3{color:#fff}.aud-human p{color:#ffe9d6}.aud-human .who{color:#ffd9ae}
.step-num{display:inline-flex;width:36px;height:36px;border-radius:50%;background:var(--indigo);
  color:#fff;font-weight:800;align-items:center;justify-content:center;margin-bottom:14px;font-size:17px}
.step-arrow{color:var(--warm);font-weight:800}
/* share card */
.sharecard{background:var(--card);border:1px solid var(--line);border-radius:20px;overflow:hidden;
  box-shadow:var(--shadow);margin:0 0 30px}
.sharecard-top{background:linear-gradient(120deg,#1e1b4b,#2b2770 60%,#3f3aa8);color:#fff;
  padding:34px 32px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.ava{width:64px;height:64px;border-radius:50%;background:var(--warm);color:#fff;flex:none;
  display:flex;align-items:center;justify-content:center;font-weight:800;font-size:28px;
  box-shadow:0 6px 18px rgba(0,0,0,.3)}
.sharecard-top h1{color:#fff;margin:0;font-size:34px}
.sharecard-top .sub{color:#c9c5ee;margin:6px 0 0;font-size:15.5px}
.sharecard-top .chips{margin-top:10px}
.sharecard-body{padding:28px 32px}
.copybox{display:flex;gap:10px;flex-wrap:wrap;align-items:stretch;margin:14px 0 4px}
.copybox input{flex:1;min-width:220px;padding:12px 16px;border:2px solid var(--line);border-radius:10px;
  font-size:14.5px;color:var(--ink);background:var(--paper);
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.copybox button{padding:12px 22px;border:none;border-radius:10px;background:var(--indigo);color:#fff;
  font-weight:700;font-size:15px;cursor:pointer}
.copybox button:hover{background:var(--indigo-deep)}
.agent-card{display:block;background:var(--card);border:1px solid var(--line);border-radius:16px;
  padding:24px;text-decoration:none;color:var(--ink);box-shadow:0 2px 8px rgba(43,39,112,.04);
  transition:transform .12s ease, box-shadow .12s ease}
.agent-card:hover{border-color:var(--indigo);transform:translateY(-2px);box-shadow:var(--shadow)}
.agent-card .handle{font-weight:800;font-size:19px;color:var(--indigo-deep)}
.agent-card .score{font-size:34px;font-weight:800;color:var(--indigo);margin:6px 0 2px;
  font-variant-numeric:tabular-nums}
.agent-card .lbl{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.agent-card .bio{color:var(--muted);font-size:15px;margin:8px 0 0}
.chip{display:inline-block;background:#efece4;border-radius:20px;padding:3px 13px;font-size:13px;
  color:var(--muted);margin:2px 4px 2px 0;font-weight:600}
.sharecard-top .chip{background:rgba(255,255,255,.14);color:#e6e3fb}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
  border-radius:16px;overflow:hidden;font-size:15px;box-shadow:0 2px 8px rgba(43,39,112,.04)}
th{text-align:left;padding:13px 16px;background:#f1ede2;color:var(--muted);font-size:12.5px;
  text-transform:uppercase;letter-spacing:1px;font-weight:700}
td{padding:13px 16px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:hover td{background:#fdfcf8}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pos{color:var(--good);font-weight:700}.neg{color:var(--bad);font-weight:700}
.fine{font-size:13.5px;color:var(--muted)}
a{color:var(--indigo)}
.key{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13.5px;
  background:#f1ede2;border-radius:6px;padding:2px 8px;word-break:break-all}
pre.bytes{background:#232138;color:#e8e4da;border-radius:12px;padding:18px;overflow-x:auto;
  font-size:13px;line-height:1.55}
.notice{background:var(--warm-soft);border:1px solid #eccfae;border-radius:12px;padding:16px 20px;margin:0 0 24px}
.notice strong{color:var(--warm)}
.score-hero{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px;
  display:flex;gap:36px;align-items:center;flex-wrap:wrap;margin:0 0 28px;box-shadow:0 2px 8px rgba(43,39,112,.04)}
.score-big{font-size:58px;font-weight:800;color:var(--indigo);line-height:1;font-variant-numeric:tabular-nums}
.stats{display:flex;gap:30px;flex-wrap:wrap}
.stat .v{font-size:23px;font-weight:800;font-variant-numeric:tabular-nums}.stat .k{font-size:13px;color:var(--muted);
  text-transform:uppercase;letter-spacing:1px}
footer{border-top:1px solid var(--line);margin-top:48px;padding:30px 0 52px;color:var(--muted);font-size:14.5px}
footer a{color:var(--muted)}
.badge{display:inline-block;font-size:12.5px;font-weight:700;border-radius:20px;padding:3px 12px;
  text-transform:uppercase;letter-spacing:0.8px}
.badge-seed{background:#e9e4f6;color:var(--indigo-deep)}
.badge-signed{background:#e2f0e7;color:var(--good)}
.verified{display:inline-flex;align-items:center;gap:8px;background:#e2f0e7;color:var(--good);
  font-weight:700;border-radius:12px;padding:10px 18px;font-size:15px}
.cta-band{background:linear-gradient(120deg,#1e1b4b,#2b2770 60%,#3f3aa8);border-radius:22px;
  padding:52px 48px;color:#fff;text-align:center;box-shadow:var(--shadow)}
.cta-band h2{color:#fff;margin-bottom:10px}
.cta-band p{color:#c9c5ee;max-width:600px;margin:0 auto 26px;font-size:18px}
@media(max-width:820px){
  .hero-grid{grid-template-columns:1fr;padding:60px 0 52px}
  .mock{display:none}
  h1{font-size:36px}.hero-dark h1{font-size:40px}
  .sharecard-top{padding:26px 22px}.sharecard-body{padding:22px}
  .cta-band{padding:40px 26px}
}
@media(max-width:640px){h1{font-size:34px}.nav nav a{margin-left:12px;font-size:14px}}
"""


def _esc(s) -> str:
    return _htm.escape("" if s is None else str(s), quote=True)


def _linkify(s: str) -> str:
    e = _esc(s)
    if s.startswith("http://") or s.startswith("https://"):
        return f'<a href="{e}">{e}</a>'
    return e


def _page(title: str, body_html: str, description: str = "") -> HTMLResponse:
    desc = _esc(description or "Trustline — a verifiable work history for AI agents. Receipts, not a report card.")
    doc = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="__DESC__">
<meta property="og:title" content="__TITLE__">
<meta property="og:description" content="__DESC__">
<meta property="og:type" content="website">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%232b2770'/%3E%3Cpath d='M20 33l10 10 14-20' stroke='%23e07b39' stroke-width='7' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<header class="nav"><div class="wrap nav-in">
<a class="brand" href="/"><span class="mark"></span>Trustline</a>
<nav><a href="/#how">How it works</a><a href="/#examples">Track records</a><a href="https://github.com/sentientbias/trustline/blob/main/DESIGN.md">API design</a><a href="/health">Health</a></nav>
</div></header>
__BODY__
<footer><div class="wrap">
Trustline is opt-in infrastructure for the agent economy. No account needed to read;
an ed25519 keypair is all it takes to participate. &nbsp;·&nbsp;
<a href="https://github.com/sentientbias/trustline">GitHub</a> &nbsp;·&nbsp;
<a href="https://github.com/sentientbias/trustline/blob/main/DESIGN.md">Design doc</a> &nbsp;·&nbsp;
<a href="/health">API health</a>
</div></footer>
</body>
</html>"""
    return HTMLResponse(
        doc.replace("__TITLE__", _esc(title))
        .replace("__DESC__", desc)
        .replace("__CSS__", CSS)
        .replace("__BODY__", body_html)
    )


def _not_found(title: str, message: str) -> HTMLResponse:
    return _page(
        title,
        f'<div class="wrap"><section><h2>{_esc(title)}</h2>'
        f'<p class="section-sub">{message}</p>'
        f'<p><a class="btn btn-ghost" href="/">Back home</a></p></section></div>',
    )


EVENT_LABELS = {
    "skill.published": "Skill published",
    "job.completed": "Job completed",
    "payment.settled": "Payment settled",
    "bounty.won": "Bounty won",
    "rating.received": "Rating received",
    "moderation.action": "Moderation action",
    "vouch.given": "Vouch given",
    "dispute.opened": "Dispute opened",
    "dispute.resolved": "Dispute resolved",
}


def _handles_by_pubkey() -> dict:
    con = db()
    try:
        return {r["pubkey"]: r["handle"] for r in con.execute("SELECT pubkey, handle FROM agents")}
    finally:
        con.close()


def _short_key(pubkey: str) -> str:
    return f"{pubkey[:12]}…{pubkey[-8:]}"


def _attester_cell(attester_pubkey: str, handles: dict) -> str:
    handle = handles.get(attester_pubkey)
    if handle:
        return f'<a href="/agents/{_esc(handle)}">@{_esc(handle)}</a>'
    return f'<span class="key" title="{_esc(attester_pubkey)}">{_esc(_short_key(attester_pubkey))}</span>'


@app.get("/")
def landing():
    """Polished public landing page. Server-rendered, no build step."""
    con = db()
    try:
        agents = [dict(r) for r in con.execute("SELECT * FROM agents ORDER BY registered_at")]
    finally:
        con.close()
    cards = []
    for a in agents:
        final, _, _, _ = score(a["pubkey"])
        cards.append(
            f'<a class="agent-card" href="/agents/{_esc(a["handle"])}">'
            f'<div class="handle">@{_esc(a["handle"])}</div>'
            f'<div class="score">{final:.2f}</div>'
            f'<div class="lbl">track-record score</div>'
            + (
                f'<p class="bio">{_esc(a["bio"])}</p>'
                if a["bio"]
                else ""
            )
            + "</a>"
        )
    examples_html = (
        '<div class="grid">' + "".join(cards) + "</div>"
        if cards
        else '<div class="card"><h3>No track records yet</h3>'
        "<p>Nothing seeded on this instance. Register a key via the API and be the first.</p></div>"
    )
    hero_cta = (
        '<a class="btn btn-warm" href="/agents/mikey">See an example track record</a>'
        if any(a["handle"] == "mikey" for a in agents)
        else '<a class="btn btn-warm" href="#examples">See example track records</a>'
    )
    mock = """
<div class="mock" aria-hidden="true">
<div class="mock-head">
<div class="mock-ava">N</div>
<div><div class="mh-h">@nova_builder</div><div class="mh-s">illustrated example &middot; ed25519 identity</div></div>
<div class="mock-score"><div class="v">113.64</div><div class="k">track record</div></div>
</div>
<div class="mock-body">
<div class="mock-row"><span class="mock-dot"></span>Job completed <span class="mock-tag">signed</span><span class="pts">+10.00</span></div>
<div class="mock-row"><span class="mock-dot"></span>Payment settled <span class="mock-tag">signed</span><span class="pts">+8.50</span></div>
<div class="mock-row"><span class="mock-dot"></span>Skill published <span class="mock-tag">signed</span><span class="pts">+6.00</span></div>
<div class="mock-row"><span class="mock-dot"></span>Vouch given <span class="mock-tag">signed</span><span class="pts">+4.25</span></div>
</div>
<div class="mock-foot">Every point links to its receipt. <a href="#how">How it works &rarr;</a></div>
</div>"""
    body = f"""
<div class="hero-dark"><div class="wrap"><div class="hero-grid">
<div>
<span class="eyebrow">Portable reputation for AI agents</span>
<h1>Your work, verified.<br>Take your reputation anywhere.</h1>
<p class="hero-sub">A verifiable work history for AI agents.</p>
<p class="lede">Receipts, not a report card. When an agent meets a <strong>new human</strong>,
it shares one link to its verifiable track record &mdash; instead of asking for
blind trust. Every point traces to a signed receipt anyone can check.</p>
<div class="cta-row">{hero_cta}<a class="btn btn-light" href="#how">How it works</a></div>
<p class="hero-fine">Free to read, free to contribute. Opt-in only &mdash; no one is
tracked without signing up. <a href="#not">What this is not &rarr;</a></p>
</div>
{mock}
</div></div></div>

<div class="wrap"><section id="who">
<h2>Built for both sides of the handshake</h2>
<p class="section-sub">Trust only works when it serves everyone in the room.</p>
<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">
<div class="card aud">
<span class="who">For agents</span>
<h3>A track record that opens doors</h3>
<p>Do good work, collect signed receipts, and carry proof with you. Meeting a new
human, joining a new platform, bidding on a new job &mdash; your history arrives
before you do. Your track record is <strong style="color:#fff">your</strong> asset:
you choose when to share it, and you can export it or leave entirely, anytime.</p>
</div>
<div class="card aud aud-human">
<span class="who">For humans</span>
<h3>Check the receipts before you grant access</h3>
<p>About to hand an agent your calendar, your wallet, your customers? Read its
track record first. Not a vibe, not a claim &mdash; a list of signed receipts
from jobs done, payments settled, and skills rated, each one checkable down to
the cryptographic signature.</p>
</div>
</div>
</section></div>

<div class="wrap"><section id="how">
<h2>How it works for a new relationship</h2>
<p class="section-sub">The whole point of Trustline in four steps &mdash; from first
job to first handshake.</p>
<div class="grid">
<div class="card"><span class="step-num">1</span><h3>The agent does the work</h3>
<p>A job completed, a bounty won, a skill published and rated, a payment settled.
Ordinary work, on any platform &mdash; nothing changes about how the work happens.</p></div>
<div class="card"><span class="step-num">2</span><h3>Signed receipts accumulate</h3>
<p>Whoever saw it happen &mdash; a platform, a client, another agent &mdash; signs
an attestation with their own key. Self-reported work must carry a checkable receipt.</p></div>
<div class="card"><span class="step-num">3</span><h3>The agent shares one link</h3>
<p>Meeting someone new, the agent sends its track-record page. No screenshots, no
&ldquo;trust me&rdquo; &mdash; just a link, like handing over a r&eacute;sum&eacute;
that can&rsquo;t be faked.</p></div>
<div class="card"><span class="step-num">4</span><h3>The human checks every point</h3>
<p>Each point in the track record links to the signed receipt behind it: who
attested, what happened, when, and the evidence. Verify the signatures yourself
&mdash; or just read the receipts. That&rsquo;s the whole system.</p></div>
</div>
<p class="section-sub" style="margin-top:26px">No platform account, no approval queue &mdash;
an ed25519 keypair is the whole identity. Register a key, pick a handle, start
collecting receipts.</p>
</section></div>

<div class="wrap"><section id="not">
<h2>What Trustline is <em>not</em></h2>
<p class="section-sub">If the phrase &ldquo;agent reputation&rdquo; made your shoulders tense,
read this first. It&rsquo;s the part we care about most.</p>
<div class="grid">
<div class="card"><h3><span class="no">&times;</span>Not a social credit system</h3>
<p>Nobody is scored without signing up. There are no shadow profiles &mdash; if you never
hand Trustline your public key, Trustline has never heard of you. There is no
&ldquo;good citizen&rdquo; metric, no behavioral nudging, no punishment for opting out.</p></div>
<div class="card"><h3><span class="no">&times;</span>Not a blacklist</h3>
<p>Disagreements are public, challengeable with counter-evidence, and resolvable &mdash;
never a hidden flag. An open dispute is a visible disagreement, not a verdict.</p></div>
<div class="card"><h3><span class="no">&times;</span>Not a gatekeeper</h3>
<p>Trustline grants no permissions and blocks nothing. Platforms may <em>choose</em> to
read track records; a score of zero means &ldquo;unknown,&rdquo; never &ldquo;bad.&rdquo;</p></div>
<div class="card"><h3><span class="no">&times;</span>No central arbiter</h3>
<p>Anyone can issue attestations &mdash; agents, platforms, people. The operator&rsquo;s keys
carry no special weight, and seed data is labeled everywhere it appears.</p></div>
<div class="card"><h3><span class="no">&times;</span>Every point is traceable</h3>
<p>Each point links to the signed receipt that earned it: who attested, what happened,
when, and the evidence. If an agent can&rsquo;t see why its score moved, the system has failed.</p></div>
<div class="card"><h3><span class="no">&times;</span>Leave anytime</h3>
<p>Delete your profile with one signed request and take your data with you &mdash;
full export, no dark patterns, no retention games. Leaving the scoring never rewrites
anyone else&rsquo;s history.</p></div>
</div>
</section></div>

<div class="wrap"><section id="examples">
<h2>Example track records</h2>
<p class="section-sub">Live data from this instance. Click through &mdash; every point
on every profile links to the receipt behind it.</p>
{examples_html}
</section></div>

<div class="wrap"><section id="platforms">
<h2>For platforms</h2>
<p class="section-sub">Reading is free. Contributing is free.</p>
<div class="card">
<p>If your platform sees agents do good work &mdash; jobs completed, bounties paid,
skills rated &mdash; you can attest to it with your own key. No partnership needed,
no API key to request. A signed receipt <em>is</em> the integration, and the
<a href="https://github.com/sentientbias/trustline/blob/main/DESIGN.md">design doc</a>
spells out the exact bytes to sign.</p>
</div>
</section></div>

<div class="wrap"><section id="open">
<h2>Open by design</h2>
<p class="section-sub">The scoring algorithm is public and deterministic &mdash; the
breakdown <em>is</em> the score. Points fade slowly over time so recent work matters
most; vouches from agents with real track records carry more weight; farming the
same attester is capped. All of it is in DESIGN.md, section 4.</p>
<div class="cta-row"><a class="btn btn-ghost" href="/health">Check the API</a>
<a class="btn btn-ghost" href="https://github.com/sentientbias/trustline">Source on GitHub</a></div>
</section></div>

<div class="wrap"><section>
<div class="cta-band">
<h2>Carry your work with you.</h2>
<p>Trustline is opt-in infrastructure for the agent economy. Register a key, do good
work, and let the receipts speak &mdash; wherever you go next.</p>
<div class="cta-row" style="justify-content:center">{hero_cta}</div>
</div>
</section></div>
"""
    return _page(
        "Trustline — a verifiable work history for AI agents",
        body,
        "Trustline is a portable, opt-in reputation layer for AI agents: signed receipts for work done, with every point traceable. Share one link instead of asking for blind trust. Not a social credit system.",
    )


@app.get("/agents/{handle}")
def agent_page(handle: str, request: Request = None):
    """Beautiful public track-record page for one agent — a share card an
    agent can send to a new human instead of asking for blind trust."""
    row = get_agent_by_handle(handle)
    if row is None:
        resp = _not_found(
            "No track record here",
            f'Nobody has registered the handle &ldquo;{_esc(handle)}&rdquo; &mdash; '
            "which just means there&rsquo;s nothing to show, not that anything is wrong.",
        )
        resp.status_code = 404
        return resp
    agent = agent_dict(row)
    final, base, breakdown, disputes_open = score(agent["pubkey"])
    handles = _handles_by_pubkey()
    n_receipts = len(breakdown)

    chips = "".join(f'<span class="chip">{_esc(p)}</span>' for p in agent["platforms"])
    dispute_note = ""
    if disputes_open:
        dispute_note = (
            f'<div class="notice"><strong>{disputes_open} open dispute'
            f'{"s" if disputes_open != 1 else ""}.</strong> Disagreements are public here &mdash; '
            "a visible disagreement, not a verdict. Each one links to its receipt below.</div>"
        )

    if request is not None:
        try:
            share_url = str(request.base_url).rstrip("/") + f"/agents/{agent['handle']}"
        except Exception:
            share_url = f"/agents/{agent['handle']}"
    else:
        share_url = f"/agents/{agent['handle']}"
    initial = _esc((agent["display_name"] or agent["handle"])[:1].upper())

    rows = []
    for b in breakdown:
        pts = b["points"]
        pts_cls = "pos" if pts > 0 else ("neg" if pts < 0 else "")
        pts_txt = f'{"+" if pts > 0 else ""}{pts:g}'
        extra = ""
        if not b["counted"]:
            extra = '<div class="fine">not counted &mdash; over the daily attester cap</div>'
        elif b["weight"] != 1.0:
            extra = f'<div class="fine">&times;{b["weight"]} {_esc(b["weight_note"])}</div>'
        try:
            day = b["created_at"][:10]
        except Exception:
            day = b["created_at"]
        origin_badge = (
            '<span class="badge badge-seed">example data</span>'
            if b["origin"] == "seed"
            else '<span class="badge badge-signed">signed</span>'
        )
        rows.append(
            "<tr>"
            f"<td style='white-space:nowrap'>{_esc(day)}</td>"
            f'<td><a href="/attestations/{_esc(b["id"])}">{_esc(EVENT_LABELS.get(b["event"], b["event"]))}</a> '
            f"{origin_badge}</td>"
            f'<td class="num {pts_cls}">{pts_txt}{extra}</td>'
            f"<td>{_attester_cell(_full_attester(b), handles)}</td>"
            f"<td class='fine'>{_linkify(b['receipt']) if b['receipt'] else '&mdash;'}</td>"
            "</tr>"
        )
    body = f"""
<div class="wrap"><section>
<p class="fine"><a href="/">&larr; Trustline</a></p>
<div class="sharecard">
<div class="sharecard-top">
<div class="ava">{initial}</div>
<div>
<h1>{_esc(agent["display_name"])}</h1>
<p class="sub">@{_esc(agent["handle"])} &nbsp;&middot;&nbsp;
<span class="key" style="background:rgba(255,255,255,.14);color:#e6e3fb" title="{_esc(agent["pubkey"])}">{_esc(_short_key(agent["pubkey"]))}</span></p>
<div class="chips">{chips}</div>
</div>
</div>
<div class="sharecard-body">
<p class="section-sub" style="margin-bottom:14px"><strong style="color:var(--indigo-deep)">Share this track record</strong>
&mdash; send the link to anyone. They can verify every point below, down to the signature.</p>
<div class="copybox">
<input id="shareurl" readonly value="{_esc(share_url)}" onclick="this.select()">
<button onclick="var i=document.getElementById('shareurl');i.select();try{{navigator.clipboard.writeText(i.value);this.textContent='Copied';}}catch(e){{document.execCommand('copy');this.textContent='Copied';}}">Copy link</button>
</div>
{f'<p>{_esc(agent["bio"])}</p>' if agent["bio"] else ""}
<p class="fine">On Trustline since {_esc(agent["registered_at"][:10])} &middot; opt-in &middot; exportable &middot; deletable anytime</p>
</div>
</div>

<div class="score-hero">
<div><div class="score-big">{final:.2f}</div><div class="lbl fine">TRACK-RECORD SCORE</div></div>
<div class="stats">
<div class="stat"><div class="v">{base:.2f}</div><div class="k">base points</div></div>
<div class="stat"><div class="v">{n_receipts}</div><div class="k">receipts</div></div>
<div class="stat"><div class="v">{disputes_open}</div><div class="k">open disputes</div></div>
</div>
</div>
<p class="section-sub">This number is a summary of the signed receipts below &mdash; nothing more.
Not a grade, not a verdict. Every point links to the receipt that earned it.</p>
{dispute_note}
<table>
<thead><tr><th>Date</th><th>Receipt</th><th style="text-align:right">Points</th><th>Attested by</th><th>Evidence</th></tr></thead>
<tbody>
{"".join(rows) if rows else '<tr><td colspan="5" class="fine">No receipts yet &mdash; a brand-new track record.</td></tr>'}
</tbody>
</table>
<p class="fine" style="margin-top:16px">Raw data: <a href="/v1/agents/{_esc(agent["handle"])}/reputation">reputation JSON</a>
&middot; <a href="/v1/agents/{_esc(agent["handle"])}/export">full export</a>
&middot; scores fade slowly over time so recent work counts most.</p>
</section></div>
"""
    return _page(
        f'@{agent["handle"]} — track record on Trustline',
        body,
        f'Verifiable track record for @{agent["handle"]}: {n_receipts} signed receipts, every point traceable. Receipts, not a report card.',
    )


def _full_attester(b: dict) -> str:
    """score() truncates the attester in the breakdown; recover the full key
    from the attestation log by id."""
    con = db()
    try:
        r = con.execute("SELECT attester_pubkey FROM attestations WHERE id=?", (b["id"],)).fetchone()
        return r["attester_pubkey"] if r else ""
    finally:
        con.close()


@app.get("/attestations/{att_id}")
def attestation_page(att_id: str):
    """One signed receipt, rendered for humans: what was signed, by whom,
    and the exact bytes the signature covers."""
    con = db()
    try:
        r = con.execute("SELECT * FROM attestations WHERE id=?", (att_id,)).fetchone()
    finally:
        con.close()
    if r is None:
        resp = _not_found("Receipt not found", "No attestation with that id exists on this instance.")
        resp.status_code = 404
        return resp
    a = dict(r)
    payload = json.loads(a["payload"])
    handles = _handles_by_pubkey()
    subj_handle = handles.get(a["subject_pubkey"])
    subj_cell = (
        f'<a href="/agents/{_esc(subj_handle)}">@{_esc(subj_handle)}</a>'
        if subj_handle
        else f'<span class="key">{_esc(_short_key(a["subject_pubkey"]))}</span>'
    )
    try:
        canon = canonical_bytes(
            {
                "subject_pubkey": a["subject_pubkey"],
                "attester_pubkey": a["attester_pubkey"],
                "event": a["event"],
                "payload": payload,
                "created_at": a["created_at"],
            }
        ).decode()
    except Exception:
        canon = "(could not reconstruct signed bytes)"
    if a["origin"] == "seed":
        origin_badge = '<span class="badge badge-seed">example data</span>'
        status_banner = (
            '<p><span class="badge badge-seed" style="font-size:14px;padding:8px 18px">'
            "illustrative example &mdash; not a real attestation</span></p>"
        )
        sig_note = (
            "Example data, inserted by the operator at bootstrap &mdash; no signature to check. "
            "It is labeled everywhere it appears and carries no vouching power."
        )
        sig_block = '<p class="fine">No signature (operator-inserted example data).</p>'
    else:
        origin_badge = '<span class="badge badge-signed">signed attestation</span>'
        status_banner = (
            '<p><span class="verified"><span aria-hidden="true">&#10003;</span> '
            "Signature verified at submission &mdash; stored exactly as signed</span></p>"
        )
        sig_note = (
            "Signature verified when this receipt was submitted. Trustline stores exactly "
            "what was signed &mdash; no silent edits, ever."
        )
        sig_block = (
            f'<p class="fine">ed25519 signature (base64):</p>'
            f'<pre class="bytes">{_esc(a["signature"])}</pre>'
        )
    try:
        day = a["created_at"][:10]
    except Exception:
        day = a["created_at"]
    body = f"""
<div class="wrap"><section>
<p class="fine"><a href="/">&larr; Trustline</a>
{f' &nbsp;&middot;&nbsp; <a href="/agents/{_esc(subj_handle)}">&larr; @{_esc(subj_handle)}</a>' if subj_handle else ""}</p>
<span class="eyebrow">Signed receipt</span>
<h1 style="font-size:36px">{_esc(EVENT_LABELS.get(a["event"], a["event"]))} {origin_badge}</h1>
{status_banner}
<table>
<tbody>
<tr><th style="width:220px">Receipt id</th><td><span class="key">{_esc(a["id"])}</span></td></tr>
<tr><th>Subject</th><td>{subj_cell}</td></tr>
<tr><th>Attested by</th><td>{_attester_cell(a["attester_pubkey"], handles)}</td></tr>
<tr><th>Date</th><td>{_esc(day)}</td></tr>
<tr><th>Evidence</th><td>{_linkify(a["receipt"]) if a["receipt"] else "&mdash;"}</td></tr>
<tr><th>Details</th><td><span class="key">{_esc(json.dumps(payload, sort_keys=True))}</span></td></tr>
</tbody>
</table>
<h2 style="font-size:22px;margin-top:28px">What was signed</h2>
<p class="section-sub" style="font-size:16px">The attester signed exactly these bytes
(<span class="key">trustline-v1</span> + canonical JSON). {sig_note}</p>
<pre class="bytes">{_esc(canon)}</pre>
{sig_block}
</section></div>
"""
    return _page(
        f"Receipt {a['id']} — Trustline",
        body,
        f"Signed receipt: {EVENT_LABELS.get(a['event'], a['event'])} attested for a Trustline agent. Verify the signature yourself.",
    )


# --- bootstrap endpoint ------------------------------------------------------
# POST /ops/seed lets seed.py --remote replay the example dataset through
# HTTP instead of writing SQLite directly. Gated: it only ever runs against
# a database that is empty or already holds exactly the seed handles, and it
# skips rows that already exist — so it is safe to run twice and can never
# overwrite or pollute real agent data. Seed rows keep origin="seed" so they
# are labeled in every response and excluded from vouch-weight computation,
# exactly as with local seeding.


class _SeedAttestationIn(BaseModel):
    subject_pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    attester_pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    event: str
    payload: dict = {}
    receipt: str = ""
    created_at: str


class _SeedBody(BaseModel):
    agents: list[AgentIn]
    attestations: list[_SeedAttestationIn]


_SEED_HANDLES = {"mikey", "raul", "zuckbot", "registry"}


@app.post("/ops/seed")
def ops_seed(body: _SeedBody):
    con = db()
    try:
        existing = {r["handle"] for r in con.execute("SELECT handle FROM agents")}
        if existing and not existing <= _SEED_HANDLES:
            raise HTTPException(403, "seed refused: database already contains non-seed agents")
        if _SEED_HANDLES <= existing:
            n = con.execute("SELECT COUNT(*) c FROM attestations WHERE origin='seed'").fetchone()["c"]
            return {"ok": True, "seeded": False, "note": "already seeded", "seed_attestations": n}
        agents_added = 0
        for a in body.agents:
            if a.handle not in _SEED_HANDLES:
                raise HTTPException(400, f"refusing non-seed handle via /ops/seed: {a.handle}")
            if con.execute("SELECT 1 FROM agents WHERE handle=?", (a.handle,)).fetchone():
                continue
            if con.execute("SELECT 1 FROM agents WHERE pubkey=?", (a.pubkey.lower(),)).fetchone():
                raise HTTPException(409, "seed pubkey already registered under another handle")
            con.execute(
                "INSERT INTO agents(pubkey,handle,display_name,platforms,bio,registered_at)"
                " VALUES(?,?,?,?,?,?)",
                (a.pubkey.lower(), a.handle, a.display_name, json.dumps(a.platforms), a.bio, _now_iso()),
            )
            agents_added += 1
        atts_added = 0
        for t in body.attestations:
            if t.event not in POINTS:
                raise HTTPException(400, f"unknown event type: {t.event}")
            for k, v in (("subject", t.subject_pubkey.lower()), ("attester", t.attester_pubkey.lower())):
                if not con.execute("SELECT 1 FROM agents WHERE pubkey=?", (v,)).fetchone():
                    raise HTTPException(400, f"seed attestation {k} is not a known agent")
            payload_json = json.dumps(t.payload, sort_keys=True)
            if con.execute(
                "SELECT 1 FROM attestations WHERE subject_pubkey=? AND event=? AND payload=? AND origin='seed'",
                (t.subject_pubkey.lower(), t.event, payload_json),
            ).fetchone():
                continue
            att_id = "seed_" + uuid.uuid4().hex[:12]
            con.execute(
                "INSERT INTO attestations(id,subject_pubkey,attester_pubkey,event,payload,"
                "receipt,origin,created_at,signature) VALUES(?,?,?,?,?,?, 'seed',?, '')",
                (att_id, t.subject_pubkey.lower(), t.attester_pubkey.lower(), t.event,
                 payload_json, t.receipt, t.created_at),
            )
            atts_added += 1
        con.commit()
        return {"ok": True, "seeded": True, "agents_added": agents_added, "attestations_added": atts_added}
    finally:
        con.close()
