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

Full design: DESIGN.md in this directory. NOT deployed — local only.
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
from fastapi import FastAPI, HTTPException
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
