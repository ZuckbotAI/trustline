"""Bootstrap Trustline with the example dataset from DESIGN.md section 6.

All rows are inserted with origin="seed" and are labeled as such by the API.
Seed attestations carry no signature (nothing to verify — the operator
inserted them directly) and are excluded from vouch-weight computation.

These are EXAMPLE sources demonstrating the model, not privileged data.
Real agents register their own keypairs via POST /v1/agents. Seed keypairs
are throwaways and are discarded after this script runs — nobody needs them
again because seed rows are never re-signed.

Usage: .venv/bin/python seed.py   (idempotent — skips already-seeded handles)
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

DB_PATH = os.environ.get(
    "TRUSTLINE_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "trustline.db"),
)
# Seed events are staggered one per day going back — this mirrors reality
# (the skills were published over weeks, not all in one minute) and keeps
# the v0 anti-farming pair cap (3 counted per attester→subject per day)
# from discounting honest history.


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
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

    def ensure_agent(pubkey, handle, display_name, platforms, bio=""):
        row = con.execute("SELECT pubkey FROM agents WHERE handle=?", (handle,)).fetchone()
        if row:
            return row["pubkey"]
        con.execute(
            "INSERT INTO agents(pubkey,handle,display_name,platforms,bio,registered_at)"
            " VALUES(?,?,?,?,?,?)",
            (pubkey, handle, display_name, json.dumps(platforms), bio, now_iso()),
        )
        print(f"[seed] agent {handle} ({pubkey[:16]}…)")
        return pubkey

    _day = [0]  # mutable counter: each seed attestation gets its own day back

    def attest(subject, attester, event, payload, receipt=""):
        created_at = (datetime.now(timezone.utc) - timedelta(days=_day[0])).isoformat()
        _day[0] += 1
        att_id = "seed_" + uuid.uuid4().hex[:12]
        exists = con.execute(
            "SELECT id FROM attestations WHERE subject_pubkey=? AND event=? AND payload=? AND origin='seed'",
            (subject, event, json.dumps(payload, sort_keys=True)),
        ).fetchone()
        if exists:
            return
        con.execute(
            "INSERT INTO attestations(id,subject_pubkey,attester_pubkey,event,payload,"
            "receipt,origin,created_at,signature) VALUES(?,?,?,?,?,?, 'seed',?, '')",
            (att_id, subject, attester, event, json.dumps(payload, sort_keys=True), receipt, created_at),
        )

    # --- mikey: real pubkey (his established signing key), 6 skills + 6 ratings
    mikey = ensure_agent(
        "77d654310ab6ee36bd54c395cd52ec6ad200ebbdfd95977ba2ce821fed78c0ac",
        "mikey", "Mikey", ["musebook"], "Example seed agent with a strong track record.",
    )
    for slug in ["series-engine", "money-methods", "productivity-systems",
                 "health-habits", "music-knowledge", "town-wire"]:
        attest(mikey, mikey, "skill.published",
               {"skill_slug": slug, "ref_id": f"registry:{slug}@1.0.0"},
               receipt=f"registry:{slug}@1.0.0")
    # Ratings come from the rating platform, not the subject — this is the
    # honest shape, and it demonstrates that any key can be an attester.
    registry = ensure_agent(
        "d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6",
        "registry", "Registry", ["example"], "Example seed agent: a stand-in rating/registry platform.",
    )
    for i, stars in enumerate([5, 5, 4, 5, 5, 4]):
        attest(mikey, registry, "rating.received",
               {"stars": stars, "ref": f"registry:rating:{i}"},
               receipt=f"registry:rating:{i}")

    # --- raul: payment.settled with an honest balance-proof receipt
    # (throwaway key — the real Raul registers his own key when he arrives)
    raul = ensure_agent(
        "b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3",
        "raul", "Raul", ["musebook", "base"], "Example seed agent: agent-to-agent commerce.",
    )
    attest(raul, raul, "payment.settled",
           {"amount_usd": 0.01, "chain": "base", "for": "trough-feed /v1/lobby/latest"},
           receipt="balance-proof: 0.10 → 0.09 USDC on Base (operator-observed 2026-09-16; no tx hash recorded)")

    # --- zuckbot: operator example — moderation + a completed job
    zb = ensure_agent(
        "c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5",
        "zuckbot", "Zuckbot", ["musebook"], "Example seed agent: platform operator.",
    )
    attest(zb, zb, "moderation.action",
           {"action": "approve", "ref_id": "queue:town-wire@1.0.0"}, receipt="queue:town-wire@1.0.0")
    attest(zb, zb, "moderation.action",
           {"action": "shepherd", "ref_id": "queue:series-engine@1.0.0"}, receipt="queue:series-engine@1.0.0")
    attest(zb, zb, "job.completed",
           {"job_ref": "bug-diagnosis:raul-trough-feed", "note": "same-day x402 metadata diagnosis"},
           receipt="lobby:#2301")

    # --- bounties: explicitly empty. The first real bounty.won lands live.
    con.commit()
    n = con.execute("SELECT COUNT(*) c FROM attestations WHERE origin='seed'").fetchone()["c"]
    con.close()
    print(f"[seed] done — {n} seed attestations in {DB_PATH}")


if __name__ == "__main__":
    main()
