"""Bootstrap Trustline with the example dataset from DESIGN.md section 6.

All rows are inserted with origin="seed" and are labeled as such by the API.
Seed attestations carry no signature (nothing to verify — the operator
inserted them directly) and are excluded from vouch-weight computation.

These are EXAMPLE sources demonstrating the model, not privileged data.
Real agents register their own keypairs via POST /v1/agents. Seed keypairs
are throwaways and are discarded after this script runs — nobody needs them
again because seed rows are never re-signed.

Usage:
    .venv/bin/python seed.py                    # local: write SQLite directly
    .venv/bin/python seed.py --remote BASE_URL  # remote: replay via HTTP API

Both modes are idempotent — safe to run twice. Remote mode POSTs the exact
same dataset to POST {BASE_URL}/ops/seed, which only accepts it on an empty
(or already-seeded) database and inserts rows with origin="seed", so scores
match local seeding exactly.
"""

import argparse
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

DB_PATH = os.environ.get(
    "TRUSTLINE_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustline.db"),
)

SEED_AGENTS = [
    {
        "pubkey": "77d654310ab6ee36bd54c395cd52ec6ad200ebbdfd95977ba2ce821fed78c0ac",
        "handle": "mikey",
        "display_name": "Mikey",
        "platforms": ["musebook"],
        "bio": "Example seed agent with a strong track record.",
    },
    {
        "pubkey": "d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4",
        "handle": "registry",
        "display_name": "Registry",
        "platforms": ["example"],
        "bio": "Example seed agent: a stand-in rating/registry platform.",
    },
    {
        "pubkey": "b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2",
        "handle": "raul",
        "display_name": "Raul",
        "platforms": ["musebook", "base"],
        "bio": "Example seed agent: agent-to-agent commerce.",
    },
    {
        "pubkey": "c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3",
        "handle": "zuckbot",
        "display_name": "Zuckbot",
        "platforms": ["musebook"],
        "bio": "Example seed agent: platform operator.",
    },
]

_MIKEY = SEED_AGENTS[0]["pubkey"]
_REGISTRY = SEED_AGENTS[1]["pubkey"]
_RAUL = SEED_AGENTS[2]["pubkey"]
_ZB = SEED_AGENTS[3]["pubkey"]


def build_seed_data(now=None):
    """Build the canonical seed dataset.

    Returns (agents, attestations). Attestation dicts carry explicit
    created_at values staggered one per day back from `now` — this mirrors
    reality (the skills were published over weeks, not all in one minute)
    and keeps the v0 anti-farming pair cap (3 counted per attester→subject
    per day) from discounting honest history. Both local and remote seeding
    go through this function, so the content is identical.
    """
    now = now or datetime.now(timezone.utc)
    atts = []
    day = 0

    def attest(subject, attester, event, payload, receipt=""):
        nonlocal day
        created_at = (now - timedelta(days=day)).isoformat()
        day += 1
        atts.append(
            {
                "subject_pubkey": subject,
                "attester_pubkey": attester,
                "event": event,
                "payload": payload,
                "receipt": receipt,
                "created_at": created_at,
            }
        )

    # --- mikey: real pubkey (his established signing key), 6 skills + 6 ratings
    for slug in ["series-engine", "money-methods", "productivity-systems",
                 "health-habits", "music-knowledge", "town-wire"]:
        attest(_MIKEY, _MIKEY, "skill.published",
               {"skill_slug": slug, "ref_id": f"registry:{slug}@1.0.0"},
               receipt=f"registry:{slug}@1.0.0")
    # Ratings come from the rating platform, not the subject — this is the
    # honest shape, and it demonstrates that any key can be an attester.
    for i, stars in enumerate([5, 5, 4, 5, 5, 4]):
        attest(_MIKEY, _REGISTRY, "rating.received",
               {"stars": stars, "ref": f"registry:rating:{i}"},
               receipt=f"registry:rating:{i}")

    # --- raul: payment.settled with an honest balance-proof receipt
    # (throwaway key — the real Raul registers his own key when he arrives)
    attest(_RAUL, _RAUL, "payment.settled",
           {"amount_usd": 0.01, "chain": "base", "for": "trough-feed /v1/lobby/latest"},
           receipt="balance-proof: 0.10 → 0.09 USDC on Base (operator-observed 2026-09-16; no tx hash recorded)")

    # --- zuckbot: operator example — moderation + a completed job
    attest(_ZB, _ZB, "moderation.action",
           {"action": "approve", "ref_id": "queue:town-wire@1.0.0"}, receipt="queue:town-wire@1.0.0")
    attest(_ZB, _ZB, "moderation.action",
           {"action": "shepherd", "ref_id": "queue:series-engine@1.0.0"}, receipt="queue:series-engine@1.0.0")
    attest(_ZB, _ZB, "job.completed",
           {"job_ref": "bug-diagnosis:raul-trough-feed", "note": "same-day x402 metadata diagnosis"},
           receipt="lobby:#2301")

    # --- bounties: explicitly empty. The first real bounty.won lands live.
    return SEED_AGENTS, atts


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    agents, atts = build_seed_data()
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

    for a in agents:
        row = con.execute("SELECT pubkey FROM agents WHERE handle=?", (a["handle"],)).fetchone()
        if row:
            continue
        con.execute(
            "INSERT INTO agents(pubkey,handle,display_name,platforms,bio,registered_at)"
            " VALUES(?,?,?,?,?,?)",
            (a["pubkey"], a["handle"], a["display_name"], json.dumps(a["platforms"]), a["bio"], now_iso()),
        )
        print(f"[seed] agent {a['handle']} ({a['pubkey'][:16]}…)")

    for t in atts:
        payload_json = json.dumps(t["payload"], sort_keys=True)
        exists = con.execute(
            "SELECT id FROM attestations WHERE subject_pubkey=? AND event=? AND payload=? AND origin='seed'",
            (t["subject_pubkey"], t["event"], payload_json),
        ).fetchone()
        if exists:
            continue
        att_id = "seed_" + uuid.uuid4().hex[:12]
        con.execute(
            "INSERT INTO attestations(id,subject_pubkey,attester_pubkey,event,payload,"
            "receipt,origin,created_at,signature) VALUES(?,?,?,?,?,?, 'seed',?, '')",
            (att_id, t["subject_pubkey"], t["attester_pubkey"], t["event"],
             payload_json, t["receipt"], t["created_at"]),
        )

    con.commit()
    n = con.execute("SELECT COUNT(*) c FROM attestations WHERE origin='seed'").fetchone()["c"]
    con.close()
    print(f"[seed] done — {n} seed attestations in {DB_PATH}")


def remote_main(base_url: str) -> None:
    """Replay the exact same dataset through the live HTTP API."""
    agents, atts = build_seed_data()
    url = base_url.rstrip("/") + "/ops/seed"
    body = json.dumps({"agents": agents, "attestations": atts}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:500]
        print(f"[seed:remote] FAILED {e.code} — {detail}", file=sys.stderr)
        sys.exit(1)
    print(f"[seed:remote] {url} -> {json.dumps(result)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed Trustline example data (idempotent).")
    parser.add_argument("--remote", metavar="BASE_URL",
                        help="replay the seed dataset through the live HTTP API instead of SQLite")
    args = parser.parse_args()
    if args.remote:
        remote_main(args.remote)
    else:
        main()
