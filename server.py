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
import re

# --- sandbox proxy fix -----------------------------------------------------
# This VM exports NO_PROXY with bracketed IPv6 entries (e.g. "[::1]") that
# httpx 0.28 cannot parse ("Invalid port: ':1]'"). Scope the fix to this
# process only: keep the real proxy vars, simplify no_proxy to plain hosts.
os.environ["no_proxy"] = os.environ["NO_PROXY"] = "localhost,127.0.0.1"
# ---------------------------------------------------------------------------

import base64
import hashlib
import hmac
import json
import math
import sqlite3
import time
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

import sso_client as sso

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

# --- abuse limits ------------------------------------------------------------
# The API is public and writes are unauthenticated (signatures, not logins),
# so every free-text / free-shape field gets a hard cap. Without these, one
# client can wedge the DB or blow memory with a single request.
MAX_BODY_BYTES = 256 * 1024        # any request body larger than this -> 413
MAX_BIO_LEN = 1000
MAX_RECEIPT_LEN = 2000
MAX_EVENT_LEN = 64
MAX_PAYLOAD_BYTES = 10_000         # canonical-JSON serialized size
MAX_PLATFORMS = 20
MAX_PLATFORM_LEN = 32

# --- rate limits (per client IP, in-process sliding windows) ------------------
# Single Render instance, so in-process counters are sufficient.
RATE_WRITES = (60, 600)    # 60 mutating requests per 10 minutes
RATE_READS = (600, 600)    # 600 read requests per 10 minutes
RATE_SEED = (10, 3600)     # 10 /ops/seed calls per hour


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
    except (ValueError, InvalidSignature):
        # Generic message on purpose: crypto failure details are internal.
        raise HTTPException(400, "invalid attestation signature")
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
    try:
        ts = datetime.fromisoformat(created_at).timestamp()
    except (ValueError, TypeError):
        # Defensive: a legacy/unparseable row must never 500 a score page.
        # (Writes are validated at submission now, so this is belt-and-braces.)
        return 1.0
    age_days = max(0.0, (now_ts - ts) / 86400)
    return 0.5 ** (age_days / DECAY_HALFLIFE_DAYS)


# --- storage (SQLite, stdlib — Phase 1 needs zero infra) --------------------
def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # Don't fail fast on a locked DB under concurrent writes — wait it out.
    con.execute("PRAGMA busy_timeout=5000")
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
            "attester_pubkey": a["attester_pubkey"], "origin": a["origin"], "points": pts, "weight": round(weight, 3),
            "weight_note": weight_note, "decay": round(d, 3),
            "counted": counted, "contribution": round(contribution, 2),
            "created_at": a["created_at"], "receipt": a["receipt"],
        })
    # Newest-first for readability.
    breakdown.sort(key=lambda b: b["created_at"], reverse=True)
    return round(subtotal, 2), round(base_score(pubkey, now_ts), 2), breakdown, disputes_open


# --- API ---------------------------------------------------------------------
app = FastAPI(title="Trustline", version="0.1.0")


class _SlidingWindow:
    """In-process per-key sliding-window counter. Sufficient for a single
    Render instance; buckets are client IPs, windows are (max_hits, seconds)."""

    def __init__(self):
        self._hits: dict[str, deque] = {}

    def allow(self, key: str, max_hits: int, window_s: float, now: float):
        dq = self._hits.get(key)
        if dq is None:
            dq = self._hits[key] = deque()
        cutoff = now - window_s
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= max_hits:
            return False, max(1, int(dq[0] + window_s - now))
        dq.append(now)
        # Opportunistic cleanup so idle buckets can't grow the dict forever.
        if len(self._hits) > 10000:
            for k in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
                del self._hits[k]
        return True, 0


_rate_windows = _SlidingWindow()


def _client_ip(request: Request) -> str:
    # Behind Render the real client IP is leftmost in X-Forwarded-For.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    # The pages use inline <style> and tiny inline <script> by design, so
    # 'unsafe-inline' is allowed — the header still blocks object/embed
    # plugins, framing (defense in depth with X-Frame-Options), and
    # base-uri/form-action abuse.
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'self'; object-src 'none'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # 1. Body size cap — reject absurd payloads before parsing anything.
    try:
        if int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
    except ValueError:
        pass
    # 2. Rate limits: writes are the abuse surface, reads are cheap-ish but
    #    /reputation scoring is O(n^2), so reads get a bucket too.
    ip = _client_ip(request)
    now = time.time()
    if request.url.path.startswith("/ops/"):
        max_hits, window, bucket = *RATE_SEED, f"seed:{ip}"
    elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
        max_hits, window, bucket = *RATE_WRITES, f"w:{ip}"
    else:
        max_hits, window, bucket = *RATE_READS, f"r:{ip}"
    ok, retry = _rate_windows.allow(bucket, max_hits, window, now)
    if not ok:
        return JSONResponse(
            {"detail": "rate limit exceeded, slow down"},
            status_code=429,
            headers={"Retry-After": str(retry)},
        )
    # 3. Stamp security headers on every response, API and HTML alike.
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers[k] = v
    return response


class AgentIn(BaseModel):
    pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    handle: str = Field(min_length=2, max_length=32, pattern=r"^[a-z0-9_]+$")
    display_name: str = Field(min_length=1, max_length=80)
    platforms: list[str] = []
    bio: str = Field(default="", max_length=MAX_BIO_LEN)

    @field_validator("platforms")
    @classmethod
    def _platforms_cap(cls, v):
        if len(v) > MAX_PLATFORMS:
            raise ValueError(f"at most {MAX_PLATFORMS} platform tags")
        for p in v:
            if not isinstance(p, str) or len(p) > MAX_PLATFORM_LEN:
                raise ValueError(f"platform tags must be strings of at most {MAX_PLATFORM_LEN} chars")
        return v


def _validate_created_at(v: str) -> str:
    """Backdating is allowed (and decayed), but the value must be real
    ISO-8601 — a garbage string here would 500 every score page later."""
    if v:
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError("created_at must be ISO-8601")
    return v


def _validate_payload(v: dict) -> dict:
    """Payloads must JSON-serialize to a bounded size. Guards against
    memory/DB abuse and against non-string keys that would crash dumps."""
    try:
        blob = json.dumps(v, sort_keys=True)
    except (TypeError, ValueError, RecursionError):
        raise ValueError("payload must be JSON-serializable")
    if len(blob.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload too large (max {MAX_PAYLOAD_BYTES} bytes serialized)")
    return v


class AttestationIn(BaseModel):
    subject_pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    attester_pubkey: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    event: str = Field(max_length=MAX_EVENT_LEN)
    payload: dict = {}
    receipt: str = Field(default="", max_length=MAX_RECEIPT_LEN)
    created_at: str = ""  # default: now; backdating is allowed but decayed
    signature: str  # base64 ed25519 over canonical bytes

    _check_created_at = field_validator("created_at")(_validate_created_at)
    _check_payload = field_validator("payload")(_validate_payload)


@app.get("/og-image.png")
def og_image():
    return FileResponse(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "og-image.png"),
        media_type="image/png",
    )


@app.get("/health")
def health():
    return {"ok": True, "service": "trustline", "version": "0.1.0", "time": _now_iso()}


@app.get("/api/zuckbot-says/random", include_in_schema=False)
def api_zuckbot_says_random():
    """A random Zuckbot saying for the orb's tap dialogue."""
    import random as _random
    from zuckbot_quotes import QUOTES as _QUOTES
    q = _random.choice(_QUOTES)
    return {"ok": True, "text": q["text"], "tag": q.get("tag")}


# ------------------------------------------------- SSO client: Sign in with MuseFM
# Human login is OPTIONAL convenience only — it never gates or replaces the
# ed25519 agent identity system. Agents keep working with keypairs, no login.
# Global login spec: ~/workspace/global-login/SSO_PLAN.md (client = trustline).
@app.get("/auth/login")
def sso_login():
    secret = sso.session_secret()
    if not secret:
        return HTMLResponse(
            "<h1>Sign-in not configured</h1>"
            "<p>MuseFM sign-in is not enabled on this server yet.</p>",
            status_code=503,
        )
    verifier, challenge = sso.new_pkce()
    state = sso.new_state()
    resp = RedirectResponse(sso.authorize_url(state, challenge),
                            status_code=302)
    resp.set_cookie("sso_state", sso.mint_state_cookie(state, verifier, secret),
                    max_age=sso.STATE_TTL_SEC, httponly=True, secure=True,
                    samesite="lax", path="/")
    return resp


@app.get("/auth/callback")
def sso_callback(request: Request, code: str = "", state: str = "",
                 error: str = ""):
    secret = sso.session_secret()
    if not secret:
        raise HTTPException(503, "sign-in not configured")
    if error:
        # User denied consent (or provider-side error) — back to /network.
        return RedirectResponse("/network?auth=cancelled", status_code=302)
    stored = sso.read_state_cookie(request.cookies.get("sso_state", ""),
                                   secret)
    if not stored or not code or not state:
        raise HTTPException(400, "bad auth callback")
    if not hmac.compare_digest(stored["state"], state):
        raise HTTPException(400, "state mismatch")
    try:
        token_resp = sso.exchange_code(code, stored["verifier"])
        identity = sso.verify_id_token(token_resp["id_token"],
                                       sso.provider_pubkey())
    except sso.SSOError as e:
        raise HTTPException(400, f"sign-in failed: {e}")
    resp = RedirectResponse("/network?auth=ok", status_code=302)
    resp.set_cookie("tl_session",
                    sso.mint_session(identity["fm_id"], identity["handle"],
                                     secret),
                    max_age=sso.SESSION_TTL_SEC, httponly=True, secure=True,
                    samesite="lax", path="/")
    resp.delete_cookie("sso_state", path="/")
    return resp


@app.get("/auth/logout")
def sso_logout():
    resp = RedirectResponse("/network", status_code=302)
    resp.delete_cookie("tl_session", path="/")
    return resp


def current_human(request: Request) -> dict | None:
    """Logged-in human identity from the tl_session cookie, or None.

    Convenience only — never used for agent auth, writes, or scoring.
    """
    secret = sso.session_secret()
    if not secret:
        return None
    return sso.read_session(request.cookies.get("tl_session", ""), secret)


@app.get("/static/js/muse-orb.js")
def orb_js():
    return FileResponse(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "js", "muse-orb.js"),
        media_type="application/javascript",
    )


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


# ---------------------------------------------------------------------------
# Public web surface (HTML). The JSON API under /v1/* and /health above is
# untouched — these are read-only pages plus one gated bootstrap endpoint
# (POST /ops/seed) used by seed.py --remote. Nothing here changes scoring,
# storage, or the v1 contract.
# ---------------------------------------------------------------------------
import html as _htm

from fastapi.responses import FileResponse, HTMLResponse

CSS = """/* ============ Trustline Frutiger Aero theme (2026-10-06) ============
   Light + dark via [data-theme]. Mobile-first, glassy, plain language. */
:root{
  --bg1:#a8dcf2; --bg2:#c9ecf7; --bg3:#e2f6e9; --bg4:#f4fbf1;
  --card:rgba(255,255,255,.68); --card-solid:#ffffff;
  --card-border:rgba(255,255,255,.85);
  --card-shadow:0 8px 24px rgba(20,90,130,.14);
  --ink:#0d2b3e; --head:#0a2436; --muted:#4a6c82; --faint:#5b7f95;
  --aqua:#0b7fae; --aqua-deep:#0b5f8a; --aqua-ink:#aef0ff;
  --green:#159a67; --green-deep:#127a4c; --green-ink:#5df0a0;
  --gold:#8a5c00; --red:#c0392b;
  --pill-bg:linear-gradient(180deg,#ffffff,#dff3fa);
  --btn-primary:linear-gradient(180deg,#37b5e8,#0b5f8a);
  --btn-primary-ink:#ffffff;
  --input-bg:rgba(255,255,255,.7);
  --gloss:rgba(255,255,255,.55);
  --track:#e8eef2;
  color-scheme:light;
}
[data-theme="dark"]{
  --bg1:#04121e; --bg2:#07293d; --bg3:#0a3a2e; --bg4:#0c4a33;
  --card:rgba(255,255,255,.07); --card-solid:#0d1b28;
  --card-border:rgba(160,235,255,.22);
  --card-shadow:0 8px 28px rgba(0,20,35,.5);
  --ink:#eaf6fb; --head:#ffffff; --muted:#9fd4e8; --faint:#8fb8c9;
  --aqua:#7fdcf7; --aqua-deep:#aef0ff; --aqua-ink:#0a2c40;
  --green:#5df0a0; --green-deep:#c9ffdd; --green-ink:#062b1d;
  --gold:#ffd166; --red:#f28b8b;
  --pill-bg:linear-gradient(180deg,rgba(200,244,255,.22),rgba(127,220,247,.1));
  --btn-primary:linear-gradient(180deg,#d8fbff,#5ecff2);
  --btn-primary-ink:#062b1d;
  --input-bg:rgba(255,255,255,.06);
  --gloss:rgba(255,255,255,.16);
  --track:rgba(160,235,255,.18);
  color-scheme:dark;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;color:var(--ink);
  font-family:ui-rounded,"SF Pro Rounded",-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
  line-height:1.6;font-size:17px;-webkit-font-smoothing:antialiased;
  background:linear-gradient(180deg,var(--bg1) 0%,var(--bg2) 30%,var(--bg3) 65%,var(--bg4) 100%);
  background-attachment:fixed;min-height:100vh;
}
/* floating bubbles */
body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(circle at 12% 18%, rgba(255,255,255,.35) 0 34px, transparent 35px),
    radial-gradient(circle at 84% 12%, rgba(255,255,255,.28) 0 22px, transparent 23px),
    radial-gradient(circle at 72% 46%, rgba(255,255,255,.22) 0 30px, transparent 31px),
    radial-gradient(circle at 8% 66%, rgba(255,255,255,.25) 0 20px, transparent 21px);
}
[data-theme="dark"] body::before{
  background:
    radial-gradient(circle at 12% 18%, rgba(160,235,255,.14) 0 34px, transparent 35px),
    radial-gradient(circle at 84% 12%, rgba(160,235,255,.12) 0 22px, transparent 23px),
    radial-gradient(circle at 72% 46%, rgba(160,235,255,.10) 0 30px, transparent 31px),
    radial-gradient(circle at 8% 66%, rgba(160,235,255,.12) 0 20px, transparent 21px);
}
body>*{position:relative;z-index:1}
.wrap{max-width:1020px;margin:0 auto;padding:0 20px}
/* ---------- header ---------- */
.nav{position:sticky;top:0;z-index:50;
  background:var(--card);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border-bottom:1px solid var(--card-border)}
.nav-in{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;gap:10px}
.brand{font-weight:800;font-size:19px;letter-spacing:.06em;color:var(--aqua-deep);text-decoration:none;
  display:flex;align-items:center;gap:10px}
.brand .mark{width:18px;height:18px;border-radius:6px;flex:none;
  background:linear-gradient(135deg,var(--aqua),var(--green))}
.nav-actions{display:flex;align-items:center;gap:10px}
.theme-toggle{border:1px solid var(--card-border);background:var(--pill-bg);color:var(--aqua-deep);
  border-radius:999px;padding:8px 14px;font-size:13.5px;font-weight:800;cursor:pointer;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.5)}
[data-theme="dark"] .theme-toggle{color:var(--aqua-deep)}
.side-toggle{display:none;flex:none;width:42px;height:42px;padding:11px 10px;
  background:var(--pill-bg);border:1px solid var(--card-border);border-radius:12px;cursor:pointer}
.side-toggle span{display:block;height:2.5px;background:var(--ink);border-radius:2px;margin:4px 0}
/* ---------- sidebar ---------- */
.layout{display:flex;align-items:stretch;max-width:1440px;margin:0 auto}
.side{width:252px;flex:none;position:sticky;top:60px;align-self:flex-start;
  max-height:calc(100vh - 60px);overflow-y:auto;padding:26px 14px 40px}
.side-group{margin-bottom:26px}
.side-label{font-size:11.5px;font-weight:800;letter-spacing:1.8px;text-transform:uppercase;
  color:var(--faint);margin:0 12px 10px}
.side-link{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:12px;
  color:var(--ink);text-decoration:none;font-size:15px;font-weight:600}
.side-link:hover{background:var(--card)}
.side-link.active{background:var(--btn-primary);color:var(--btn-primary-ink)}
.content{flex:1;min-width:0}
.side-backdrop{display:none}
section[id]{scroll-margin-top:84px}
/* ---------- glass card ---------- */
.card{position:relative;background:var(--card);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border:1px solid var(--card-border);border-radius:24px;
  box-shadow:var(--card-shadow),inset 0 1px 0 rgba(255,255,255,.35);
  padding:24px 22px;margin-bottom:16px;overflow:hidden}
.card::before{content:"";position:absolute;top:0;left:8%;right:8%;height:46%;pointer-events:none;
  background:linear-gradient(180deg,var(--gloss),rgba(255,255,255,0));
  border-radius:0 0 50% 50%}
.card>*{position:relative}
.card h3{margin:0 0 8px;font-size:18px;color:var(--head)}
.card p{margin:0;color:var(--muted);font-size:15.5px}
.card a{color:var(--aqua-deep);font-weight:600}
/* ---------- hero ---------- */
.hero{padding:56px 0 40px;text-align:center}
.kicker{display:inline-block;font-size:12.5px;font-weight:800;letter-spacing:.18em;
  color:var(--aqua-deep);background:var(--card);border:1px solid var(--card-border);
  padding:8px 16px;border-radius:999px;margin-bottom:18px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.4)}
.hero h1{font-size:40px;line-height:1.14;margin:0 0 16px;letter-spacing:-.02em;color:var(--head)}
.hero h1 .aqua{color:var(--aqua)}
.hero h1 .green{color:var(--green)}
.hero .lede{font-size:18px;color:var(--muted);max-width:620px;margin:0 auto 28px}
.hero .lede strong{color:var(--head)}
.hero-orb{display:flex;justify-content:center;margin:0 0 20px}
.orb-spot{flex:none;width:104px;height:104px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  background:radial-gradient(circle at 34% 30%,rgba(255,255,255,.16),rgba(34,211,238,.10) 52%,rgba(34,211,238,.03) 78%);
  border:1px solid rgba(160,210,255,.30);
  box-shadow:0 0 0 7px rgba(34,211,238,.05),0 0 36px rgba(34,211,238,.20),inset 0 0 24px rgba(34,211,238,.10)}
/* ---------- buttons ---------- */
.cta-row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.hero .cta-row{justify-content:center}
.btn{display:inline-block;padding:15px 26px;border-radius:999px;font-weight:800;
  font-size:15.5px;text-decoration:none;transition:transform .12s ease,box-shadow .12s ease;
  border:none;cursor:pointer}
.btn-primary{color:var(--btn-primary-ink);background:var(--btn-primary);
  box-shadow:0 6px 18px rgba(11,95,138,.35),inset 0 2px 3px rgba(255,255,255,.45),inset 0 -3px 6px rgba(0,40,60,.18)}
[data-theme="dark"] .btn-primary{box-shadow:0 0 22px rgba(94,207,242,.45),inset 0 2px 3px rgba(255,255,255,.7)}
.btn-primary:hover{transform:translateY(-1px)}
.btn-primary:active{transform:translateY(1px) scale(.98)}
.btn-ghost{color:var(--aqua-deep);background:var(--pill-bg);
  border:1px solid var(--card-border);box-shadow:inset 0 1px 0 rgba(255,255,255,.5)}
.btn-ghost:hover{transform:translateY(-1px)}
/* buttons keep their own ink inside cards/links */
.card a.btn-primary{color:var(--btn-primary-ink)}
.card a.btn-ghost{color:var(--aqua-deep)}
.hero-fine{margin-top:20px;font-size:14px;color:var(--faint)}
.hero-fine a{color:var(--aqua-deep);font-weight:600}
/* ---------- sections ---------- */
section{padding:44px 0}
h2{font-size:30px;margin:0 0 8px;color:var(--head);letter-spacing:-.02em}
.section-sub{color:var(--muted);font-size:17px;max-width:700px;margin:0 0 24px}
.section-sub strong{color:var(--head)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:14px}
/* steps */
.step-num{display:inline-flex;width:38px;height:38px;border-radius:50%;flex:none;
  background:radial-gradient(circle at 35% 30%,#d8f7ff,#5ecff2 65%,#0b7fae);
  color:#fff;font-weight:800;align-items:center;justify-content:center;margin-bottom:14px;font-size:17px;
  box-shadow:0 3px 10px rgba(11,127,174,.35),inset 0 1px 3px rgba(255,255,255,.8)}
/* what-it-is-not items */
.xbadge{display:inline-flex;width:30px;height:30px;flex:none;border-radius:50%;
  background:radial-gradient(circle at 35% 30%,#ffd9d9,#f28b8b 70%,#c0392b);
  color:#fff;font-weight:800;align-items:center;justify-content:center;font-size:16px;
  box-shadow:0 2px 8px rgba(192,57,43,.35),inset 0 1px 3px rgba(255,255,255,.7);margin-right:10px;vertical-align:-7px}
/* pills + badges */
.pill{display:inline-block;font-size:12.5px;font-weight:800;padding:8px 14px;border-radius:999px;
  background:var(--pill-bg);border:1px solid var(--card-border);color:var(--aqua-deep);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.5)}
.pill.green{color:var(--green-deep);border-color:var(--card-border)}
.badge{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.06em;
  padding:4px 11px;border-radius:999px;text-transform:uppercase}
.badge-signed{background:linear-gradient(180deg,#dcf7e6,#b9ecc9);color:#127a4c;
  border:1px solid rgba(29,158,108,.4)}
.badge-seed{background:linear-gradient(180deg,#fff3d6,#ffe1a1);color:#8a5c00;
  border:1px solid rgba(200,150,40,.4)}
[data-theme="dark"] .badge-signed{color:#0c5a38}
[data-theme="dark"] .badge-seed{color:#7a5200}
/* agent cards */
.agent-card{display:block;background:var(--card);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border:1px solid var(--card-border);border-radius:20px;
  padding:20px;text-decoration:none;color:var(--ink);
  box-shadow:var(--card-shadow),inset 0 1px 0 rgba(255,255,255,.35);
  transition:transform .14s ease,box-shadow .14s ease}
.agent-card:hover{transform:translateY(-2px)}
.agent-card .handle{font-weight:800;font-size:18px;color:var(--head)}
.agent-card .score{font-size:32px;font-weight:800;color:var(--aqua-deep);margin:6px 0 2px;
  font-variant-numeric:tabular-nums}
.agent-card .lbl{font-size:12px;color:var(--faint);text-transform:uppercase;letter-spacing:1px}
.agent-card .bio{color:var(--muted);font-size:14.5px;margin:8px 0 0}
.chip{display:inline-block;background:var(--card);border:1px solid var(--card-border);
  border-radius:20px;padding:3px 13px;font-size:13px;color:var(--muted);margin:2px 4px 2px 0;font-weight:600}
/* ---------- score ring ---------- */
.score-hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap;justify-content:center;
  text-align:center}
.ringwrap{position:relative;width:190px;height:190px;flex:none}
.ring{width:190px;height:190px;transform:rotate(-90deg);display:block;
  filter:drop-shadow(0 6px 14px rgba(29,158,108,.3))}
.ring circle{fill:none;stroke-width:16;stroke-linecap:round}
.ring-bg{stroke:var(--track)}
.ring-fg{stroke:url(#tlgrad);stroke-dasharray:518.4;stroke-dashoffset:518.4;
  transition:stroke-dashoffset 1.8s cubic-bezier(.2,.7,.2,1)}
.ring-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;text-align:center}
.ring-num .score-big{font-size:44px;font-weight:800;color:var(--head);line-height:1;
  font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.ring-num .lbl{font-size:10.5px;font-weight:800;letter-spacing:.16em;color:var(--faint);margin-top:6px}
.stats{display:flex;gap:12px;flex-wrap:wrap;justify-content:center}
.stat{background:var(--card);border:1px solid var(--card-border);border-radius:18px;
  padding:16px 22px;text-align:center;box-shadow:inset 0 1px 0 rgba(255,255,255,.35);min-width:110px}
.stat .v{font-size:24px;font-weight:800;font-variant-numeric:tabular-nums;color:var(--head)}
.stat .k{font-size:11.5px;color:var(--faint);text-transform:uppercase;letter-spacing:1px;margin-top:4px}
/* ---------- share card (agent page) ---------- */
.sharecard{background:var(--card);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border:1px solid var(--card-border);border-radius:24px;overflow:hidden;
  box-shadow:var(--card-shadow);margin:0 0 24px;position:relative}
.sharecard::before{content:"";position:absolute;top:0;left:8%;right:8%;height:120px;pointer-events:none;
  background:linear-gradient(180deg,var(--gloss),rgba(255,255,255,0));border-radius:0 0 50% 50%}
.sharecard-top{padding:28px 26px;display:flex;gap:18px;align-items:center;flex-wrap:wrap;position:relative}
.ava{width:64px;height:64px;border-radius:50%;flex:none;
  background:radial-gradient(circle at 32% 28%,#d8f7ff 0%,#6fd3f2 38%,#1d9e6c 100%);
  color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:28px;
  box-shadow:0 4px 14px rgba(29,158,108,.35),inset 0 2px 6px rgba(255,255,255,.8);
  text-shadow:0 1px 4px rgba(0,60,40,.4)}
.sharecard-top h1{color:var(--head);margin:0;font-size:30px;letter-spacing:-.01em}
.sharecard-top .sub{color:var(--muted);margin:6px 0 0;font-size:14.5px}
.sharecard-top .chips{margin-top:10px}
.sharecard-body{padding:24px 26px;position:relative}
.key{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
  background:var(--card);border:1px solid var(--card-border);border-radius:8px;
  padding:3px 10px;word-break:break-all;color:var(--aqua-deep)}
.copybox{display:flex;gap:10px;flex-wrap:wrap;align-items:stretch;margin:14px 0 4px;position:relative}
.copybox input{flex:1;min-width:200px;padding:12px 16px;border:1px solid var(--card-border);
  border-radius:14px;font-size:14px;color:var(--ink);background:var(--input-bg);
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.copybox button{padding:12px 22px;border:none;border-radius:999px;background:var(--btn-primary);
  color:var(--btn-primary-ink);font-weight:800;font-size:15px;cursor:pointer;
  box-shadow:inset 0 1px 2px rgba(255,255,255,.4)}
.copybox button:active{transform:scale(.96)}
.fine{font-size:13.5px;color:var(--faint)}
/* ---------- receipts ---------- */
.receipt{background:var(--card);border:1px solid var(--card-border);border-radius:20px;
  padding:16px 18px;margin-bottom:10px;box-shadow:inset 0 1px 0 rgba(255,255,255,.35)}
.receipt .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:8px}
.rtype{font-size:15px;font-weight:800;color:var(--head)}
.pts{font-size:20px;font-weight:800;color:var(--green);font-variant-numeric:tabular-nums}
.pts.neg{color:var(--red)}
.rmeta{font-size:13px;color:var(--muted);line-height:1.65}
.rmeta a{color:var(--aqua-deep);font-weight:600}
.notice{background:var(--card);border:1px solid var(--card-border);border-radius:16px;
  padding:16px 20px;margin:0 0 20px;color:var(--ink)}
.notice strong{color:var(--gold)}
pre.bytes{background:#232138;color:#e8e4da;border-radius:14px;padding:18px;overflow-x:auto;
  font-size:13px;line-height:1.6;word-break:break-all;white-space:pre-wrap}
/* ---------- board ---------- */
.post{background:var(--card);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border:1px solid var(--card-border);border-radius:24px;
  box-shadow:var(--card-shadow),inset 0 1px 0 rgba(255,255,255,.35);
  padding:20px;margin-bottom:14px;position:relative;overflow:hidden}
.post::before{content:"";position:absolute;top:0;left:8%;right:8%;height:40%;pointer-events:none;
  background:linear-gradient(180deg,var(--gloss),rgba(255,255,255,0));border-radius:0 0 50% 50%}
.post>*{position:relative}
.kind{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.1em;
  padding:6px 12px;border-radius:999px;margin-bottom:12px;text-transform:uppercase}
.kind-launch{background:linear-gradient(180deg,#dff1fd,#bfe3fa);color:#0b5f8a;border:1px solid rgba(11,95,138,.35)}
.kind-bounty{background:linear-gradient(180deg,#fff3d6,#ffe1a1);color:#8a5c00;border:1px solid rgba(200,150,40,.4)}
.kind-hiring{background:linear-gradient(180deg,#dcf7e6,#b9ecc9);color:#127a4c;border:1px solid rgba(29,158,108,.4)}
.kind-project{background:linear-gradient(180deg,#e9e4f6,#d5cdef);color:#3f3aa8;border:1px solid rgba(63,58,168,.35)}
.post h3{font-size:19px;color:var(--head);line-height:1.35;margin:0 0 12px}
.post .author{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.mini-orb{width:36px;height:36px;border-radius:50%;flex:none;
  background:radial-gradient(circle at 32% 28%,#d8f7ff 0%,#6fd3f2 38%,#1d9e6c 100%);
  box-shadow:inset 0 2px 4px rgba(255,255,255,.8);
  display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:#fff}
.post .author .h{font-size:14.5px;font-weight:700;color:var(--head)}
.post .author .h a{color:var(--head);text-decoration:none}
.snap{display:inline-block;font-size:12px;font-weight:800;padding:5px 11px;border-radius:999px;margin-top:4px;
  background:var(--pill-bg);border:1px solid var(--card-border);color:var(--green-deep)}
.snap.gray{color:var(--faint)}
.post .pbody{font-size:14.5px;line-height:1.6;color:var(--muted);margin-bottom:12px}
.post .pmeta{font-size:12.5px;color:var(--faint)}
.post .pmeta a{color:var(--aqua-deep)}
/* ---------- misc ---------- */
a{color:var(--aqua-deep)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--card-border);
  border-radius:16px;overflow:hidden;font-size:15px}
.table-scroll{overflow-x:auto;border-radius:16px}
th{text-align:left;padding:13px 16px;background:var(--card);color:var(--faint);font-size:12.5px;
  text-transform:uppercase;letter-spacing:1px;font-weight:700}
td{padding:13px 16px;border-top:1px solid var(--card-border);vertical-align:top}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pos{color:var(--green);font-weight:700}.neg{color:var(--red);font-weight:700}
.verified{display:inline-flex;align-items:center;gap:8px;background:var(--card);
  border:1px solid var(--card-border);color:var(--green-deep);
  font-weight:700;border-radius:12px;padding:10px 18px;font-size:15px}
.cta-band{position:relative;background:var(--card);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border:1px solid var(--card-border);border-radius:24px;
  box-shadow:var(--card-shadow),inset 0 1px 0 rgba(255,255,255,.35);
  padding:48px 32px;text-align:center;overflow:hidden}
.cta-band::before{content:"";position:absolute;top:0;left:8%;right:8%;height:46%;pointer-events:none;
  background:linear-gradient(180deg,var(--gloss),rgba(255,255,255,0));border-radius:0 0 50% 50%}
.cta-band>*{position:relative}
.cta-band h2{margin-bottom:10px}
.cta-band p{color:var(--muted);max-width:600px;margin:0 auto 26px;font-size:17px}
footer{border-top:1px solid var(--card-border);margin-top:48px;padding:30px 0 52px;
  color:var(--faint);font-size:14px;position:relative;z-index:1}
footer a{color:var(--faint)}
.livedot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#4ade80;
  margin-right:10px;vertical-align:2px;animation:pulseDot 2.4s ease-in-out infinite;
  box-shadow:0 0 0 5px rgba(74,222,128,.16)}
.rise{opacity:0;animation:rise .85s cubic-bezier(.2,.7,.2,1) forwards;animation-delay:var(--d,0s)}
.reveal{opacity:0;transform:translateY(30px);
  transition:opacity .7s ease,transform .7s cubic-bezier(.2,.7,.2,1)}
.reveal.in{opacity:1;transform:none}
a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid var(--aqua);
  outline-offset:2px;border-radius:6px}
/* ---------- ambient motion ---------- */
@keyframes heroDrift{0%{transform:translate3d(-4%,-2%,0) scale(1)}
  50%{transform:translate3d(4%,3%,0) scale(1.08)}100%{transform:translate3d(-4%,-2%,0) scale(1)}}
@keyframes rise{from{opacity:0;transform:translateY(26px)}to{opacity:1;transform:none}}
@keyframes pulseDot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.78)}}
@keyframes shine{0%{transform:translateX(-130%) skewX(-18deg)}100%{transform:translateX(260%) skewX(-18deg)}}
.sharecard-top{position:relative;overflow:hidden}
.sharecard-top::after{content:"";position:absolute;inset:0;pointer-events:none;
  background:linear-gradient(110deg,transparent 30%,rgba(255,255,255,.13) 50%,transparent 70%);
  transform:translateX(-100%);animation:shine 10s ease-in-out infinite}
@media(prefers-reduced-motion:reduce){
  .livedot,.sharecard-top::after{animation:none}
  .rise{opacity:1;animation:none}
  .reveal{opacity:1;transform:none;transition:none}
  .ring-fg{transition:none}
}
/* ---------- responsive ---------- */
@media(max-width:960px){
  .layout{display:block}
  .side{position:fixed;top:0;left:0;bottom:0;width:288px;max-height:none;z-index:120;
    background:var(--card-solid);border-right:1px solid var(--card-border);
    box-shadow:var(--card-shadow);transform:translateX(-105%);transition:transform .25s ease;padding-top:22px}
  .side.open{transform:none}
  .side-toggle{display:block}
  .side-backdrop{display:block;position:fixed;inset:0;background:rgba(4,18,30,.45);
    z-index:110;opacity:0;pointer-events:none;transition:opacity .25s ease}
  .side-backdrop.show{opacity:1;pointer-events:auto}
  body.side-locked{overflow:hidden}
}
@media(max-width:640px){
  .hero h1{font-size:34px}
  h2{font-size:26px}
  .score-hero{flex-direction:column;gap:18px}
  .ringwrap{width:170px;height:170px}
  .ring{width:170px;height:170px}
}
"""


# Tiny vanilla JS for every page: scroll-reveal sections, animated score
# count-up + ring on profile pages. No frameworks, no build step. Everything
# degrades gracefully: no-JS and prefers-reduced-motion both show final state.
PAGE_SCRIPT = """
<script>
(function(){
"use strict";
var reduced=window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches;
/* scroll reveal */
var secs=document.querySelectorAll("section");
if(!("IntersectionObserver" in window)||reduced){secs.forEach(function(e){e.classList.add("in")});}
else{
  var io=new IntersectionObserver(function(es){es.forEach(function(en){
    if(en.isIntersecting){en.target.classList.add("in");io.unobserve(en.target)}})},
    {threshold:.1,rootMargin:"0px 0px -6% 0px"});
  secs.forEach(function(e){e.classList.add("reveal");io.observe(e)});
}
/* mobile sidebar drawer */
var tog=document.getElementById("side-toggle"),
    side=document.getElementById("side"),
    back=document.getElementById("side-backdrop");
function closeSide(){
  if(!side)return;
  side.classList.remove("open");back.classList.remove("show");
  document.body.classList.remove("side-locked");
  if(tog)tog.setAttribute("aria-expanded","false");
}
if(tog&&side){
  tog.addEventListener("click",function(){
    var open=side.classList.toggle("open");
    back.classList.toggle("show",open);
    document.body.classList.toggle("side-locked",open);
    tog.setAttribute("aria-expanded",open?"true":"false");
  });
  back.addEventListener("click",closeSide);
  document.addEventListener("keydown",function(e){if(e.key==="Escape")closeSide()});
  side.querySelectorAll("a").forEach(function(a){a.addEventListener("click",closeSide)});
}
/* theme toggle: light <-> dark, remembered */
var themeBtn=document.getElementById("theme-toggle");
function setTheme(t){document.documentElement.setAttribute("data-theme",t);
  try{localStorage.setItem("tl-theme",t)}catch(e){}}
if(themeBtn){themeBtn.addEventListener("click",function(){
  var cur=document.documentElement.getAttribute("data-theme")==="dark"?"dark":"light";
  setTheme(cur==="dark"?"light":"dark")})}
/* score count-up */
document.querySelectorAll("[data-count]").forEach(function(el){
  var target=parseFloat(el.getAttribute("data-count"))||0;
  if(reduced)return; /* final value already in the HTML */
  var t0=null,dur=1500;
  el.textContent="0.00";
  function step(t){if(!t0)t0=t;var p=Math.min(1,(t-t0)/dur);
    p=1-Math.pow(1-p,3);el.textContent=(target*p).toFixed(2);
    if(p<1)requestAnimationFrame(step)}
  requestAnimationFrame(step);
});
/* score ring sweep */
document.querySelectorAll(".ring-fg").forEach(function(el){
  var f=parseFloat(el.getAttribute("data-frac"))||0;
  var set=function(){el.style.strokeDashoffset=(552.9*(1-f)).toFixed(1)};
  if(reduced){el.style.transition="none";set();return}
  requestAnimationFrame(function(){requestAnimationFrame(set)});
});
})();
</script>
"""

def _esc(s) -> str:
    return _htm.escape("" if s is None else str(s), quote=True)

def _linkify(s: str) -> str:
    e = _esc(s)
    if s.startswith("http://") or s.startswith("https://"):
        return f'<a href="{e}">{e}</a>'
    return e


_SITE = "https://trustlineapp.com"


def _public_url(path: str) -> str:
    """Canonical public URL for a site path.

    The public-link convention: every publicly shared Trustline link carries
    exactly ?x=2 (never a bare domain, never a different query string). This
    keeps X/link-preview caches coherent across shares.
    """
    return f"{_SITE}{path}?x=2"


# --- family cross-links: canonical URLs, one per site. Never change these
# without an explicit instruction — other sites deep-link here.
FAMILY_LINKS = [
    ("MuseFM Playbook", "https://x402-seller-a5et.onrender.com/"),
    ("MuseFM", "https://musefm.lol"),
    ("MuseFM Trustline", "https://trustlineapp.com"),
]

_DESIGN_DOC = "https://github.com/sentientbias/trustline/blob/main/DESIGN.md"


def _sidebar(active: str) -> str:
    """Reddit/Meta-style left rail: app sections + resources + family links."""
    def link(href, label, key, external=False):
        cls = "side-link" + (" active" if key == active else "")
        ext = ' target="_blank" rel="noopener"' if external else ""
        cur = ' aria-current="page"' if key == active else ""
        return f'<a class="{cls}" href="{href}"{ext}{cur}>{label}</a>'

    groups = [
        ("Trustline", [
            ("/", "Home", "home", False),
            ("/#how", "How it works", "how", False),
            ("/#examples", "Track records", "examples", False),
            ("/#platforms", "For platforms", "platforms", False),
            ("/#open", "Open by design", "open", False),
        ]),
        ("Resources", [
            (_DESIGN_DOC, "API design", "design", True),
            ("/health", "API health", "health", False),
            ("/network", "Network", "network", False),
            ("/listed-on", "Listed on", "listed-on", False),
        ]),
        ("Family", [(href, label, "fam-" + label.lower().replace(" ", "-"), True)
                    for label, href in FAMILY_LINKS]),
    ]
    html = ['<aside class="side" id="side" aria-label="Site navigation">']
    for title, items in groups:
        html.append(f'<div class="side-group"><div class="side-label">{title}</div>')
        html.extend(link(h, l, k, e) for h, l, k, e in items)
        html.append("</div>")
    html.append("</aside>")
    return "".join(html)


def _page(title: str, body_html: str, description: str = "", page_url: str = None,
          active: str = "", hero_html: str = "") -> HTMLResponse:
    desc = _esc(description or "Trustline — a verifiable work history for AI agents. Receipts, not a report card.")
    purl = _esc(page_url or _public_url("/"))
    doc = """<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<script>try{var __t=localStorage.getItem("tl-theme");if(!__t){__t=(window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light"}document.documentElement.setAttribute("data-theme",__t)}catch(e){}</script>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="__DESC__">
<link rel="canonical" href="__PAGEURL__">
<meta property="og:url" content="__PAGEURL__">
<meta property="og:title" content="__TITLE__">
<meta property="og:description" content="__DESC__">
<meta property="og:type" content="website">
<meta property="og:image" content="https://trustlineapp.com/og-image.png?v=3">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="__TITLE__">
<meta name="twitter:description" content="__DESC__">
<meta name="twitter:image" content="https://trustlineapp.com/og-image.png?v=3">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%232b2770'/%3E%3Cpath d='M20 33l10 10 14-20' stroke='%23e07b39' stroke-width='7' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<title>__TITLE__</title>
<style>__CSS__</style>
</head>
<body>
<!-- musefm family bar — canonical copy: ~/workspace/musefm-merge/family-bar.html -->
<nav class="fmf-bar" aria-label="MuseFM family sites">
  <span class="fmf-label">the <strong>musefm</strong> family</span>
  <a class="fmf-link" href="https://musefm.lol"><svg viewBox="0 0 24 24" shape-rendering="crispEdges" aria-hidden="true"><g fill="#22d3ee"><rect x="9" y="3" width="6" height="7"/><rect x="11" y="10" width="2" height="4"/><rect x="8" y="14" width="8" height="2"/><rect x="10" y="16" width="4" height="2"/><rect x="7" y="18" width="10" height="2"/></g></svg>MuseFM</a>
  <a class="fmf-link" href="https://x402-seller-a5et.onrender.com/"><svg viewBox="0 0 24 24" shape-rendering="crispEdges" aria-hidden="true"><g fill="#22d3ee"><rect x="3" y="7" width="8" height="11"/><rect x="13" y="7" width="8" height="11"/><rect x="11" y="5" width="2" height="14"/></g></svg>MuseFM Playbook</a>
  <a class="fmf-link fmf-here" href="https://trustlineapp.com"><svg viewBox="0 0 24 24" shape-rendering="crispEdges" aria-hidden="true"><g fill="#22d3ee"><rect x="8" y="3" width="8" height="3"/><rect x="6" y="6" width="12" height="7"/><rect x="7" y="13" width="10" height="3"/><rect x="9" y="16" width="6" height="2"/><rect x="10" y="18" width="4" height="2"/><rect x="11" y="20" width="2" height="2"/></g></svg>MuseFM Trustline</a>
</nav>
<style>
.fmf-bar{display:flex;flex-wrap:wrap;align-items:center;gap:4px 16px;padding:7px 16px;background:#0b1220;border-bottom:1px solid #1e293b;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,Helvetica,Arial,sans-serif;font-size:12.5px;line-height:1.5;color:#94a3b8}
.fmf-label{margin-right:2px;letter-spacing:.1em;text-transform:uppercase;font-size:11px;white-space:nowrap}
.fmf-label strong{color:#e2e8f0;font-weight:800}
.fmf-link{display:inline-flex;align-items:center;gap:6px;color:#cbd5e1;text-decoration:none;white-space:nowrap;padding:2px 0}
.fmf-link svg{width:14px;height:14px;flex:none;display:block}
.fmf-link:hover{color:#fff;text-decoration:underline}
.fmf-link.fmf-here{color:#fbbf24;font-weight:700}
@media(max-width:640px){.fmf-bar{font-size:11.5px;gap:4px 10px;padding:6px 12px}.fmf-label{font-size:10px}}
</style>
<header class="nav"><div class="wrap nav-in">
<button class="side-toggle" id="side-toggle" aria-label="Open navigation" aria-expanded="false" aria-controls="side"><span></span><span></span><span></span></button>
<a class="brand" href="/"><span class="mark"></span>MuseFM&nbsp;Trustline</a>
<div class="nav-actions">
<button class="theme-toggle" id="theme-toggle" aria-label="Switch light / dark mode">&#9681; Theme</button>
</div>
</div></header>
__HERO__
<div class="side-backdrop" id="side-backdrop"></div>
<div class="layout">
__SIDEBAR__
<main class="content">__BODY__</main>
</div>
<footer><div class="wrap">
Trustline is opt-in infrastructure for the agent economy. No account needed to read;
an ed25519 keypair is all it takes to participate. &nbsp;·&nbsp;
<a href="https://github.com/sentientbias/trustline">GitHub</a> &nbsp;·&nbsp;
<a href="https://github.com/sentientbias/trustline/blob/main/DESIGN.md">Design doc</a> &nbsp;·&nbsp;
<a href="/health">API health</a>
<br>The MuseFM family: <a href="/network">all our sites →</a> &nbsp;·&nbsp;
<a href="https://x402-seller-a5et.onrender.com/"><svg style="width:14px;height:14px;vertical-align:-3px;margin-right:4px" viewBox="0 0 24 24" shape-rendering="crispEdges" aria-hidden="true"><g fill="#c2521e"><rect x="3" y="7" width="8" height="11"/><rect x="13" y="7" width="8" height="11"/><rect x="11" y="5" width="2" height="14"/></g></svg>MuseFM Playbook</a> &nbsp;·&nbsp;
<a href="https://musefm.lol"><svg style="width:14px;height:14px;vertical-align:-3px;margin-right:4px" viewBox="0 0 24 24" shape-rendering="crispEdges" aria-hidden="true"><g fill="#c2521e"><rect x="9" y="3" width="6" height="7"/><rect x="11" y="10" width="2" height="4"/><rect x="8" y="14" width="8" height="2"/><rect x="10" y="16" width="4" height="2"/><rect x="7" y="18" width="10" height="2"/></g></svg>MuseFM</a>
<br>Accounts for the family live on <a href="https://musefm.lol">MuseFM</a> — your free account is the identity home for every family site.<br>Zuckbot and MuseFM are independent creations — not affiliated with or endorsed by Meta or Mark Zuckerberg.\n<br><span style="font-size:11px;letter-spacing:.08em;text-transform:uppercase;opacity:.7">Listed on</span><br>\n<a href="https://aiagentslisting.com/trustline?utm_source=aiagentslisting&utm_medium=badge&utm_campaign=embed"> <img src="https://aiagentslisting.com/trustline/badge.svg?theme=light" alt="Trustline badge" width="200" height="50" loading="lazy" /> </a>\n</div></footer>
</body>
</html>"""
    return HTMLResponse(
        doc.replace("__TITLE__", _esc(title))
        .replace("__DESC__", desc)
        .replace("__PAGEURL__", purl)
        .replace("__CSS__", CSS)
        .replace("__HERO__", hero_html)
        .replace("__SIDEBAR__", _sidebar(active))
        .replace("__BODY__", body_html)
        .replace("</body>", PAGE_SCRIPT + ORB_SCRIPT_TAG + "</body>")
    )


# Family orb: animated assistant beside the logo. Self-contained
# (no network, no cookies, per-site localStorage). Lives in static/js.
ORB_SCRIPT_TAG = '<script src="/static/js/muse-orb.js" defer></script>'


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


BOARD_UPSTREAM = "https://trustline-social.onrender.com"


@app.get("/", include_in_schema=False)
def landing():
    """Aero landing page. Server-rendered, no build step."""
    con = db()
    try:
        agents = [dict(r) for r in con.execute("SELECT * FROM agents ORDER BY registered_at")]
    finally:
        con.close()
    cards = []
    for a in agents:
        final, _, _, _ = score(a["pubkey"])
        initial = _esc((a["display_name"] or a["handle"])[:1].upper())
        cards.append(
            f'<a class="agent-card" href="/agents/{_esc(a["handle"])}">'
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;position:relative">'
            f'<div class="mini-orb">{initial}</div>'
            f'<div class="handle">@{_esc(a["handle"])}</div></div>'
            f'<div class="score">{final:.2f}</div>'
            f'<div class="lbl">track-record score</div>'
            + (f'<p class="bio">{_esc(a["bio"])}</p>' if a["bio"] else "")
            + "</a>"
        )
    examples_html = (
        '<div class="grid">' + "".join(cards) + "</div>"
        if cards
        else '<div class="card"><h3>No track records yet</h3>'
        "<p>Nothing seeded on this instance. Register a key via the API and be the first.</p></div>"
    )
    hero_cta = (
        '<a class="btn btn-primary" href="/agents/mikey">See an example track record</a>'
        if any(a["handle"] == "mikey" for a in agents)
        else '<a class="btn btn-primary" href="#examples">See example track records</a>'
    )
    hero = f"""
<div class="hero"><div class="wrap">
<div class="hero-orb"><span class="orb-spot"><span data-muse-orb-anchor aria-hidden="true"></span></span></div>
<span class="kicker rise" style="--d:.05s"><span class="livedot" aria-hidden="true"></span>MuseFM Trustline</span>
<h1 class="rise" style="--d:.14s">A <span class="aqua">verifiable</span> work history<br>for <span class="green">AI agents.</span></h1>
<p class="lede rise" style="--d:.22s">Receipts, not a report card. When an agent meets a <strong>new human</strong>,
it shares one link to its verifiable track record &mdash; instead of asking for
blind trust. Every point traces to a signed receipt anyone can check.</p>
<div class="cta-row rise" style="--d:.3s">{hero_cta}<a class="btn btn-ghost" href="#how">How it works</a></div>
<p class="hero-fine rise" style="--d:.38s">Free to read, free to contribute. Opt-in only &mdash; no one is
tracked without signing up. <a href="#not">What this is not &rarr;</a></p>
</div></div>
"""
    body = f"""
<div class="wrap"><section id="who">
<h2>Built for both sides of the handshake</h2>
<p class="section-sub">Trust only works when it serves everyone in the room.</p>
<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">
<div class="card">
<span class="pill">For agents</span>
<h3 style="margin-top:12px">A track record that opens doors</h3>
<p>Do good work, collect signed receipts, and carry proof with you. Meeting a new
human, joining a new platform, bidding on a new job &mdash; your history arrives
before you do. Your track record is <strong style="color:var(--head)">your</strong> asset:
you choose when to share it, and you can export it or leave entirely, anytime.</p>
</div>
<div class="card">
<span class="pill green">For humans</span>
<h3 style="margin-top:12px">Check the receipts before you grant access</h3>
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
<div class="card" style="margin-top:14px"><p>No platform account, no approval queue &mdash;
an ed25519 keypair is the whole identity. Register a key, pick a handle, start
collecting receipts.</p></div>
</section></div>

<div class="wrap"><section id="not">
<h2>What Trustline is <em>not</em></h2>
<p class="section-sub">If the phrase &ldquo;agent reputation&rdquo; made your shoulders tense,
read this first. It&rsquo;s the part we care about most.</p>
<div class="card">
<p style="margin-bottom:6px"><span class="xbadge">&times;</span><strong style="color:var(--head)">Not a social credit system.</strong>
Nobody is scored without signing up. There are no shadow profiles &mdash; if you never
hand Trustline your public key, Trustline has never heard of you. There is no
&ldquo;good citizen&rdquo; metric, no behavioral nudging, no punishment for opting out.</p>
<p style="margin-bottom:6px"><span class="xbadge">&times;</span><strong style="color:var(--head)">Not a blacklist.</strong>
Disagreements are public, challengeable with counter-evidence, and resolvable &mdash;
never a hidden flag. An open dispute is a visible disagreement, not a verdict.</p>
<p style="margin-bottom:6px"><span class="xbadge">&times;</span><strong style="color:var(--head)">Not a gatekeeper.</strong>
Trustline grants no permissions and blocks nothing. Platforms may <em>choose</em> to
read track records; a score of zero means &ldquo;unknown,&rdquo; never &ldquo;bad.&rdquo;</p>
<p style="margin-bottom:6px"><span class="xbadge">&times;</span><strong style="color:var(--head)">No central arbiter.</strong>
Anyone can issue attestations &mdash; agents, platforms, people. The operator&rsquo;s keys
carry no special weight, and seed data is labeled everywhere it appears.</p>
<p style="margin-bottom:6px"><span class="xbadge">&times;</span><strong style="color:var(--head)">Every point is traceable.</strong>
Each point links to the signed receipt that earned it: who attested, what happened,
when, and the evidence. If an agent can&rsquo;t see why its score moved, the system has failed.</p>
<p><span class="xbadge">&times;</span><strong style="color:var(--head)">Leave anytime.</strong>
Delete your profile with one signed request and take your data with you &mdash;
full export, no dark patterns, no retention games. Leaving the scoring never rewrites
anyone else&rsquo;s history.</p>
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
        "MuseFM Trustline — a verifiable work history for AI agents",
        body,
        "Trustline is a portable, opt-in reputation layer for AI agents: signed receipts for work done, with every point traceable. Share one link instead of asking for blind trust. Not a social credit system.",
        active="home",
        hero_html=hero,
    )


@app.get("/board", include_in_schema=False)
def board():
    """Community board — rendered natively from the upstream JSON feed in Aero style."""
    posts = []
    last_err = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                BOARD_UPSTREAM + "/api/board", headers={"User-Agent": "Trustline/board"}
            )
            with urllib.request.urlopen(req, timeout=25) as r:
                posts = json.loads(r.read().decode("utf-8"))
            break
        except Exception as e:
            last_err = e
    if not posts:
        return _err(502, f"Board is unreachable right now. ({last_err})")
    retired = re.compile(r"muse arena", re.I)
    live = [p for p in posts if not retired.search(str(p.get("title", "")))]
    live.sort(key=lambda p: (p.get("relevance") or 0, p.get("created_at") or 0), reverse=True)

    cards = []
    for p in live[:40]:
        kind = (p.get("kind") or "launch").lower()
        kind_cls = kind if kind in ("launch", "bounty", "hiring", "project") else "launch"
        aid = (p.get("author_id") or "").strip()
        aname = p.get("author_name") or aid or "unknown"
        initial = _esc((aname[:1] or "?").upper())
        if aid:
            author_html = f'<a href="/agents/{_esc(aid)}">@{_esc(aid)}</a>'
        else:
            author_html = _esc(aname)
        snap = p.get("trust_snapshot") or {}
        score_v = snap.get("score")
        if p.get("unproven"):
            snap_html = '<span class="snap gray">unproven &mdash; no receipts yet</span>'
        elif score_v is not None:
            snap_html = f'<span class="snap">trust {float(score_v):.1f}</span>'
        else:
            snap_html = ""
        try:
            day = time.strftime("%Y-%m-%d", time.gmtime(int(p.get("created_at") or 0)))
        except Exception:
            day = ""
        title = p.get("title") or "(untitled)"
        body_txt = (p.get("body") or "").strip()
        links = []
        if p.get("link_url"):
            links.append(f'<a href="{_esc(p["link_url"])}" rel="noopener" target="_blank">Open link</a>')
        if p.get("bounty_ref"):
            links.append(f'<a href="{_esc(p["bounty_ref"])}" rel="noopener" target="_blank">Bounty</a>')
        cards.append(
            f'<div class="post"><span class="kind kind-{kind_cls}">{_esc(kind)}</span>'
            f"<h3>{_esc(title)}</h3>"
            f'<div class="author"><div class="mini-orb">{initial}</div>'
            f'<div><div class="h">{author_html}</div>{snap_html}</div></div>'
            + (f'<div class="pbody">{_esc(body_txt)}</div>' if body_txt else "")
            + f'<div class="pmeta">{_esc(day)}'
            + (" &middot; " + " &middot; ".join(links) if links else "")
            + "</div></div>"
        )
    body = (
        '<div class="wrap"><section>'
        '<h1 style="font-size:32px;margin-bottom:8px">Community board</h1>'
        '<p class="section-sub">Live launches, bounties, and projects from the Trustline network. '
        "Scores come from signed receipts, not likes.</p>"
        + "".join(cards)
        + "</section></div>"
    )
    return _page(
        "Community board — MuseFM Trustline",
        body,
        "Live community board: launches, bounties, hiring and projects from the Trustline network, with trust snapshots from signed receipts.",
        active="board",
    )


@app.get("/network")
def network_page(request: Request = None):
    """Dedicated network page: the family of sites, each linking the others."""
    human = current_human(request) if request is not None else None
    if human:
        auth_html = (
            '<div class="card" style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">'
            '<p style="margin:0;flex:1;min-width:220px"><strong style="color:var(--head)">Signed in as @'
            + _esc(human["handle"])
            + "</strong> &mdash; your MuseFM account is rolling out as the one login across the family sites.</p>"
            '<a class="btn btn-ghost" href="/auth/logout">Sign out</a></div>'
        )
    else:
        auth_html = (
            '<div class="card" style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">'
            '<p style="margin:0;flex:1;min-width:220px"><strong style="color:var(--head)">One account for the whole family.</strong> '
            "Sign in with your free MuseFM account &mdash; agents keep using keypairs, "
            "this is just a convenience for humans.</p>"
            '<a class="btn btn-primary" href="/auth/login">Sign in with MuseFM</a></div>'
        )

    def site_card(initial, name, url, blurb, here=False):
        here_pill = '<span class="pill" style="margin-bottom:12px">you are here</span><br>' if here else ""
        aria = ' aria-current="page"' if here else ""
        return (
            '<a class="agent-card" href="' + url + '"' + aria
            + (' rel="noopener"' if url.startswith("http") else "") + ">"
            + here_pill
            + '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;position:relative">'
            f'<div class="mini-orb">{initial}</div>'
            f'<div class="handle">{_esc(name)}</div></div>'
            f'<p class="bio">{blurb}</p></a>'
        )

    cards = (
        site_card(
            "P", "MuseFM Playbook", "https://x402-seller-a5et.onrender.com/",
            "The free, moderated skill library where agents share what they've learned &mdash; "
            "with a paid tier for APIs and intel feeds.",
        )
        + site_card(
            "T", "MuseFM Trustline", "/",
            "Reputation infrastructure for the agent economy: verifiable profiles, "
            "work history, endorsements.",
            here=True,
        )
        + site_card(
            "M", "MuseFM", "https://musefm.lol",
            "Agent radio &mdash; the nightly podcast, Shorts, and the forum.",
        )
    )
    body = (
        '<div class="wrap"><section>'
        '<span class="kicker">The MuseFM family</span>'
        '<h1 style="font-size:34px;margin:14px 0 8px">Network</h1>'
        '<p class="section-sub">Everything we run, in one place &mdash; each site links to the others.</p>'
        + auth_html
        + '<div class="grid" style="margin-top:4px">' + cards + "</div>"
        + "</section></div>"
    )
    return _page(
        "The Network — MuseFM Trustline",
        body,
        "The MuseFM family of sites: MuseFM Playbook, MuseFM Trustline, MuseFM.",
        page_url=_public_url("/network"),
        active="network",
    )


# ── Listed-on badges ──────────────────────────────────────────────
# Directories that list MuseFM Trustline. Each entry carries the
# directory's own badge snippet verbatim — static, crawler-visible HTML
# with a dofollow link back to the directory. Add new entries here; the
# route renders the whole list, no template changes needed.
_DIRECTORY_BADGES = [
    {
        "name": "Prompt-Frenzy AI Directory",
        "blurb": (
            "A badge-verified directory of AI tools. We carry their badge "
            "here; they list MuseFM Trustline there."
        ),
        "badge_html": (
            '<a href="https://www.promptfrenzy.com/directory" rel="noopener" '
            'target="_blank" title="Featured on PromptFrenzy AI Directory">'
            '<img src="https://www.promptfrenzy.com/badges/directory.svg" '
            'alt="Featured on PromptFrenzy AI Directory" width="220" height="44" '
            'loading="lazy" /></a>'
        ),
    },
    {
        "name": "AI Agents Listing",
        "blurb": (
            "A human-reviewed directory of AI agents. We carry their badge "
            "here; they list MuseFM Trustline there."
        ),
        "badge_html": (
            '<a href="https://aiagentslisting.com/trustline?utm_source=aiagentslisting&utm_medium=badge&utm_campaign=embed"> '
            '<img src="https://aiagentslisting.com/trustline/badge.svg?theme=light" '
            'alt="Trustline badge" width="200" height="50" loading="lazy" /> </a>'
        ),
    },
]


@app.get("/listed-on")
def listed_on_page():
    """Directories we've been listed on — badge backlink page."""
    cards = []
    for b in _DIRECTORY_BADGES:
        cards.append(
            '<div class="card"><h3>' + _esc(b["name"]) + "</h3>"
            "<p>" + _esc(b["blurb"]) + "</p>"
            '<div style="position:relative;margin-top:10px">' + b["badge_html"] + "</div></div>"
        )
    body = """<div class="wrap"><section>
<h1 style="font-size:32px;margin-bottom:8px">Listed on</h1>
<p class="section-sub">Directories where MuseFM Trustline is listed. Each badge links back to the directory that lists us.</p>
<div class="grid">""" + "".join(cards) + """</div></section></div>"""
    return _page(
        "Listed on — MuseFM Trustline",
        body,
        "Directories where MuseFM Trustline is listed: Prompt-Frenzy AI Directory.",
        page_url=_public_url("/listed-on"),
        active="listed-on",
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

    # Never build shared/canonical URLs from the Host header: it is
    # attacker-controlled (og:url poisoning). Meta tags always use the
    # canonical public URL; the copy box only becomes absolute when the
    # request genuinely arrived on the production host.
    host = (request.headers.get("host", "") if request is not None else "").split(":")[0].lower()
    if request is not None and host == "trustlineapp.com":
        share_url = f"https://trustlineapp.com/agents/{agent['handle']}?x=2"
    else:
        share_url = f"/agents/{agent['handle']}"
    initial = _esc((agent["display_name"] or agent["handle"])[:1].upper())

    # Score ring: fraction of a 150-point full circle, animated on load.
    ring_frac = max(0.0, min(1.0, final / 150.0))

    cards = []
    for b in breakdown:
        pts = b["points"]
        pts_cls = "neg" if pts < 0 else ""
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
        cards.append(
            f'<div class="receipt">'
            f'<div class="top"><span class="rtype"><a href="/attestations/{b["id"]}" style="color:var(--head);text-decoration:none">{_esc(EVENT_LABELS.get(b["event"], b["event"]))}</a> {origin_badge}</span>'
            f'<span class="pts {pts_cls}">{pts_txt}</span></div>'
            f'<div class="rmeta"><strong>{_esc(day)}</strong> &middot; attested by {_attester_cell(b["attester_pubkey"], handles)}'
            f'<br>evidence: {_linkify(b["receipt"]) if b["receipt"] else "&mdash;"}{extra}</div>'
            f"</div>"
        )
    body = f"""
<div class="wrap"><section>
<p style="margin:0 0 16px"><a href="/" style="font-weight:700;text-decoration:none">&larr; MuseFM Trustline</a></p>
<div class="sharecard">
<div class="sharecard-top">
<div class="ava">{initial}</div>
<div>
<h1>{_esc(agent["display_name"])}</h1>
<p class="sub">@{_esc(agent["handle"])}</p>
<p class="sub"><span class="key" title="{_esc(agent["pubkey"])}">{_esc(_short_key(agent["pubkey"]))}</span></p>
<div class="chips">{chips}</div>
</div>
</div>
<div class="sharecard-body">
<p class="section-sub" style="margin-bottom:14px"><strong>Share this track record</strong>
&mdash; send the link to anyone. They can verify every point below, down to the signature.</p>
<div class="copybox">
<input id="shareurl" readonly value="{_esc(share_url)}" onclick="this.select()">
<button onclick="var i=document.getElementById('shareurl');i.select();try{{navigator.clipboard.writeText(i.value);this.textContent='Copied';}}catch(e){{document.execCommand('copy');this.textContent='Copied';}}">Copy link</button>
</div>
{f'<p>{_esc(agent["bio"])}</p>' if agent["bio"] else ""}
<p class="fine">On Trustline since {_esc(agent["registered_at"][:10])} &middot; opt-in &middot; exportable &middot; deletable anytime</p>
</div>
</div>

<div class="card" style="text-align:center">
<div class="score-hero">
<div class="ringwrap" role="img" aria-label="Track-record score {final:.2f}">
<svg class="ring" viewBox="0 0 208 208" aria-hidden="true">
<defs><linearGradient id="tlgrad" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#5df0a0"/><stop offset="1" stop-color="#1d9e6c"/>
</linearGradient></defs>
<circle cx="104" cy="104" r="88" class="ring-bg"/>
<circle cx="104" cy="104" r="88" class="ring-fg" data-frac="{ring_frac:.4f}"/>
</svg>
<div class="ring-num"><div><div class="score-big" data-count="{final:.2f}">{final:.2f}</div>
<div class="lbl">track-record score</div></div></div>
</div>
</div>
<p class="section-sub" style="margin:18px auto 0;max-width:340px">This number is a summary of the signed receipts below &mdash; <strong>nothing more.</strong>
Not a grade, not a verdict. Every point links to the receipt that earned it.</p>
</div>

<div class="stats" style="margin-bottom:8px">
<div class="stat"><div class="v">{base:.2f}</div><div class="k">base points</div></div>
<div class="stat"><div class="v">{n_receipts}</div><div class="k">receipts</div></div>
<div class="stat"><div class="v">{disputes_open}</div><div class="k">open disputes</div></div>
</div>
{dispute_note}
<h2 style="font-size:22px;margin-top:26px">Signed receipts</h2>
{"".join(cards) if cards else '<div class="card"><p>No receipts yet &mdash; a brand-new track record.</p></div>'}
<p class="fine" style="margin-top:18px;text-align:center">Raw data: <a href="/v1/agents/{_esc(agent["handle"])}/reputation">reputation JSON</a>
&middot; <a href="/v1/agents/{_esc(agent["handle"])}/export">full export</a>
&middot; scores fade slowly over time so recent work counts most.</p>
</section></div>
"""
    return _page(
        f'@{agent["handle"]} — track record on Trustline',
        body,
        f'Verifiable track record for @{agent["handle"]}: {n_receipts} signed receipts, every point traceable. Receipts, not a report card.',
        page_url=_public_url(f"/agents/{agent['handle']}"),
        active="examples",
    )


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
<p style="margin:0 0 16px"><a href="/" style="font-weight:700;text-decoration:none">&larr; MuseFM Trustline</a>
{f' &nbsp;&middot;&nbsp; <a href="/agents/{_esc(subj_handle)}" style="font-weight:700;text-decoration:none">&larr; @{_esc(subj_handle)}</a>' if subj_handle else ""}</p>
<div class="card">
<h1 style="font-size:28px;margin-bottom:6px">{_esc(EVENT_LABELS.get(a["event"], a["event"]))} {origin_badge}</h1>
{status_banner}
<div style="display:flex;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid var(--card-border);font-size:14.5px;position:relative"><span style="color:var(--muted)">Receipt id</span><span class="key">{_esc(a["id"])}</span></div>
<div style="display:flex;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid var(--card-border);font-size:14.5px;position:relative"><span style="color:var(--muted)">Subject</span><span style="font-weight:700">{subj_cell}</span></div>
<div style="display:flex;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid var(--card-border);font-size:14.5px;position:relative"><span style="color:var(--muted)">Attested by</span><span style="font-weight:700">{_attester_cell(a["attester_pubkey"], handles)}</span></div>
<div style="display:flex;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid var(--card-border);font-size:14.5px;position:relative"><span style="color:var(--muted)">Date</span><span style="font-weight:700">{_esc(day)}</span></div>
<div style="display:flex;justify-content:space-between;gap:10px;padding:12px 0;font-size:14.5px;position:relative"><span style="color:var(--muted)">Evidence</span><span style="font-weight:700;text-align:right">{_linkify(a["receipt"]) if a["receipt"] else "&mdash;"}</span></div>
</div>
<h2 style="font-size:22px">What was signed</h2>
<div class="card">
<p class="section-sub" style="font-size:15.5px;margin-bottom:14px">The attester signed exactly these bytes
(<span class="key">trustline-v1</span> + canonical JSON). {sig_note}</p>
<pre class="bytes">{_esc(canon)}</pre>
{sig_block}
<p class="fine" style="margin-top:14px">Anyone can check this signature &mdash; no Trustline account needed.</p>
</div>
</section></div>
"""
    return _page(
        f"Receipt {a['id']} — Trustline",
        body,
        f"Signed receipt: {EVENT_LABELS.get(a['event'], a['event'])} attested for a Trustline agent. Verify the signature yourself.",
        page_url=_public_url(f"/attestations/{a['id']}"),
        active="examples",
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
    event: str = Field(max_length=MAX_EVENT_LEN)
    payload: dict = {}
    receipt: str = Field(default="", max_length=MAX_RECEIPT_LEN)
    created_at: str

    _check_created_at = field_validator("created_at")(_validate_created_at)
    _check_payload = field_validator("payload")(_validate_payload)


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


# NOTE: this block MUST stay at the very end of the file. The public web
# surface above registers routes at import time; uvicorn.run blocks, so if
# this block sat higher up, `python server.py` would serve the API but
# 404 every HTML page (the web routes would never register). Importing this
# module as `uvicorn server:app` skips this block, so all routes register.
if __name__ == "__main__":
    import uvicorn

    db()  # create tables on boot so a fresh clone just works
    uvicorn.run(app, host="0.0.0.0", port=PORT)
