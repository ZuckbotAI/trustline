"""Trustline smoke tests — stdlib only (no httpx/pytest in the venv).

Covers the v1 JSON API contract, the v0 scorer, the new HTML pages, and the
/ops/seed bootstrap gate. Run: .venv/bin/python smoke_test.py
Exits 0 only if every check passes.
"""

import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="trustline-smoke-")
os.environ["TRUSTLINE_DB"] = os.path.join(TMP, "smoke.db")
sys.path.insert(0, HERE)

import server  # noqa: E402
from server import (  # noqa: E402
    AgentIn,
    AttestationIn,
    DeleteIn,
    _SeedBody,
    _SeedAttestationIn,
    agent_page,
    attestation_page,
    delete_canonical_bytes,
    export_agent,
    get_agent,
    get_reputation,
    health,
    landing,
    list_attestations,
    ops_seed,
    register_agent,
    submit_attestation,
    delete_agent,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from fastapi import HTTPException  # noqa: E402
from pydantic import ValidationError  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


def expect_http(fn, code, name):
    try:
        fn()
        check(name, False, f"expected HTTP {code}, got success")
    except HTTPException as e:
        check(name, e.status_code == code, f"expected {code}, got {e.status_code}")


def fresh_key():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    return priv, pub


def sign_att(priv, subject_pubkey, attester_pubkey, event, payload, created_at):
    core = {
        "subject_pubkey": subject_pubkey,
        "attester_pubkey": attester_pubkey,
        "event": event,
        "payload": payload,
        "created_at": created_at,
    }
    return base64.b64encode(priv.sign(server.canonical_bytes(core))).decode()


TS = "2026-09-01T12:00:00+00:00"

# 1 — health
h = health()
check("01 health ok", h["ok"] is True and h["service"] == "trustline")

# 2 — register
_, k_alice = fresh_key()
r = register_agent(AgentIn(pubkey=k_alice, handle="alice", display_name="Alice"))
check("02 register 201", r["ok"] is True and r["handle"] == "alice")

# 3 — duplicate pubkey
expect_http(
    lambda: register_agent(AgentIn(pubkey=k_alice, handle="alice2", display_name="A2")),
    409, "03 duplicate pubkey -> 409",
)

# 4 — duplicate handle
_, k_bob = fresh_key()
expect_http(
    lambda: register_agent(AgentIn(pubkey=k_bob, handle="alice", display_name="B")),
    409, "04 duplicate handle -> 409",
)

# 5 — handle pattern enforced by pydantic
try:
    AgentIn(pubkey=k_bob, handle="Bad-Handle!", display_name="B")
    check("05 bad handle rejected", False, "no ValidationError")
except ValidationError:
    check("05 bad handle rejected", True)

# attester + subject for signature tests
priv_e, k_eve = fresh_key()
_, k_subj = fresh_key()
register_agent(AgentIn(pubkey=k_eve, handle="eve", display_name="Eve"))
register_agent(AgentIn(pubkey=k_subj, handle="subj", display_name="Subj"))


def att_in(priv, subj, att, event, payload, created_at=TS, receipt="r"):
    sig = sign_att(priv, subj.lower(), att.lower(), event, payload, created_at)
    return AttestationIn(
        subject_pubkey=subj, attester_pubkey=att, event=event,
        payload=payload, receipt=receipt, created_at=created_at, signature=sig,
    )


# 6 — valid signed attestation
r = submit_attestation(att_in(priv_e, k_subj, k_eve, "job.completed", {"job": "1"}))
check("06 valid attestation -> 201", r["ok"] is True and r["id"].startswith("att_"))

# 7 — tampered signature
bad = att_in(priv_e, k_subj, k_eve, "job.completed", {"job": "2"})
bad.signature = base64.b64encode(b"0" * 64).decode()
expect_http(lambda: submit_attestation(bad), 400, "07 bad signature -> 400")

# 8 — unregistered attester (valid sig, unknown key)
priv_x, k_x = fresh_key()
expect_http(
    lambda: submit_attestation(att_in(priv_x, k_subj, k_x, "job.completed", {"job": "3"})),
    400, "08 unregistered attester -> 400",
)

# 9 — unknown event
priv_e2, _ = fresh_key()
sig9 = sign_att(priv_e, k_subj.lower(), k_eve.lower(), "nope.event", {}, TS)
expect_http(
    lambda: submit_attestation(AttestationIn(
        subject_pubkey=k_subj, attester_pubkey=k_eve, event="nope.event",
        payload={}, created_at=TS, signature=sig9)),
    400, "09 unknown event -> 400",
)

# 10 — self-attestation rules
priv_s, k_self = fresh_key()
register_agent(AgentIn(pubkey=k_self, handle="selfie", display_name="Selfie"))
expect_http(
    lambda: submit_attestation(att_in(priv_s, k_self, k_self, "job.completed", {}, receipt="x")),
    400, "10a self job.completed -> 400",
)
expect_http(
    lambda: submit_attestation(att_in(priv_s, k_self, k_self, "payment.settled", {"usd": 1}, receipt="")),
    400, "10b self payment.settled w/o receipt -> 400",
)
r = submit_attestation(att_in(priv_s, k_self, k_self, "payment.settled", {"usd": 1}, receipt="tx:1"))
check("10c self payment.settled w/ receipt -> 201", r["ok"] is True)

# 11 — reputation breakdown shape + contributions sum to score
rep = get_reputation("subj")
need = {"handle", "pubkey", "score", "base_score", "disputes_open", "breakdown", "computed_at", "algorithm"}
bkeys = {"id", "event", "attester", "origin", "points", "weight", "weight_note",
         "decay", "counted", "contribution", "created_at", "receipt"}
ok = need <= set(rep.keys()) and all(bkeys <= set(b.keys()) for b in rep["breakdown"])
s = sum(b["contribution"] for b in rep["breakdown"])
check("11 breakdown shape + sums to score", ok and abs(s - rep["score"]) < 0.01, f"sum={s} score={rep['score']}")

# 12 — vouch weight 0.1 for zero-base-score attester
w = [b["weight"] for b in rep["breakdown"] if b["event"] == "job.completed"][0]
check("12 zero-score attester weight 0.1", w == 0.1, f"weight={w}")

# 13 — pair daily cap (4 same-day attestations -> 4th not counted)
priv_c, k_cap_a = fresh_key()
_, k_cap_s = fresh_key()
register_agent(AgentIn(pubkey=k_cap_a, handle="capper", display_name="Capper"))
register_agent(AgentIn(pubkey=k_cap_s, handle="capped", display_name="Capped"))
for i in range(4):
    submit_attestation(att_in(
        priv_c, k_cap_s, k_cap_a, "vouch.given", {"n": i},
        created_at=f"2026-03-01T1{i}:00:00+00:00"))
rep_c = get_reputation("capped")
counted = [b["counted"] for b in sorted(rep_c["breakdown"], key=lambda b: b["created_at"])]
check("13 pair daily cap", counted == [True, True, True, False], f"{counted}")

# 14 — rating dedup per (rater, ref)
priv_r, k_rater = fresh_key()
_, k_rated = fresh_key()
register_agent(AgentIn(pubkey=k_rater, handle="rater", display_name="Rater"))
register_agent(AgentIn(pubkey=k_rated, handle="rated", display_name="Rated"))
submit_attestation(att_in(priv_r, k_rated, k_rater, "rating.received",
                          {"stars": 5, "ref": "skill:x"}, created_at="2026-04-01T10:00:00+00:00"))
submit_attestation(att_in(priv_r, k_rated, k_rater, "rating.received",
                          {"stars": 5, "ref": "skill:x"}, created_at="2026-04-02T10:00:00+00:00"))
rep_r = get_reputation("rated")
rc = [b["counted"] for b in rep_r["breakdown"]]
check("14 rating dedup", rc == [True, False] or rc == [False, True], f"{rc}")

# 15/16/17 — delete flow
priv_d, k_del = fresh_key()
register_agent(AgentIn(pubkey=k_del, handle="leaver", display_name="Leaver"))
_, k_other = fresh_key()
register_agent(AgentIn(pubkey=k_other, handle="other", display_name="Other"))
sig_other = base64.b64encode(priv_d.sign(delete_canonical_bytes(k_del, "leaver"))).decode()
expect_http(lambda: delete_agent("leaver", DeleteIn(pubkey=k_other, signature=sig_other)),
            403, "15 delete with wrong key -> 403")
expect_http(lambda: delete_agent("leaver", DeleteIn(pubkey=k_del, signature=base64.b64encode(b"1" * 64).decode())),
            400, "16 delete with bad sig -> 400")
sig_ok = base64.b64encode(priv_d.sign(delete_canonical_bytes(k_del, "leaver"))).decode()
r = delete_agent("leaver", DeleteIn(pubkey=k_del, signature=sig_ok))
expect_http(lambda: get_agent("leaver"), 404, "17b profile gone after delete")
check("17a delete success", r["ok"] is True and r["deleted"] is True)

# 18 — export
x = export_agent("subj")
check("18 export", set(x.keys()) == {"agent", "attestations", "exported_at"}
      and x["agent"]["handle"] == "subj" and len(x["attestations"]) >= 1)

# 19/20 — HTML pages need seeded data: seed a second DB via ops/seed
DB2 = os.path.join(TMP, "seed.db")
os.environ["TRUSTLINE_DB"] = DB2
server.DB_PATH = DB2  # module constant read at import; rebind for this process
sys.path.insert(0, HERE)
import seed as seedmod  # noqa: E402

agents, atts = seedmod.build_seed_data()
sb = _SeedBody(
    agents=[AgentIn(**a) for a in agents],
    attestations=[_SeedAttestationIn(**t) for t in atts],
)
r = ops_seed(sb)
check("21a ops/seed fresh db", r["ok"] and r["seeded"] and r["attestations_added"] == 16,
      f"{r}")
rep_m = get_reputation("mikey")
check("21b mikey score == 113.64", rep_m["score"] == 113.64, f"score={rep_m['score']}")
r = ops_seed(sb)
check("21c ops/seed rerun idempotent", r["ok"] and not r["seeded"], f"{r}")
register_agent(AgentIn(pubkey=k_alice, handle="realperson", display_name="Real"))
try:
    ops_seed(sb)
    check("21d ops/seed refuses polluted db", False, "no HTTPException")
except HTTPException as e:
    check("21d ops/seed refuses polluted db", e.status_code == 403, f"{e.status_code}")

# 19 — landing page
lp = landing()
b = lp.body.decode()
check("19 landing page", lp.status_code == 200
      and "A verifiable work history for AI agents." in b
      and "Not a social credit system" in b
      and 'href="/agents/mikey"' in b
      and "receipts, not a report card" in b.lower())

# 20 — profile page
pp = agent_page("mikey")
pb = pp.body.decode()
seed_id = [x["id"] for x in list_attestations("mikey")["attestations"]][0]
check("20 profile page", pp.status_code == 200
      and "113.64" in pb
      and f"/attestations/{seed_id}" in pb
      and "track-record score" in pb.lower()
      and "@mikey" in pb)
p404 = agent_page("nosuchhandle")
check("20b profile 404", p404.status_code == 404)

# receipt page
rp = attestation_page(seed_id)
rb = rp.body.decode()
check("20c receipt page", rp.status_code == 200 and "Signed receipt" in rb and "trustline-v1" in rb)
r404 = attestation_page("att_nope")
check("20d receipt 404", r404.status_code == 404)

# 22 — v1 reputation JSON key set (contract stability)
rep = get_reputation("mikey")
check("22 v1 reputation keys", set(rep.keys()) == need, f"{sorted(rep.keys())}")

# ---- remote parity: boot a real server, seed via --remote, compare score ----
RDB = os.path.join(TMP, "remote.db")
env = dict(os.environ, TRUSTLINE_DB=RDB, PORT="18741")
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", "18741"],
    cwd=HERE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
try:
    base = "http://127.0.0.1:18741"
    for _ in range(60):
        try:
            with urllib.request.urlopen(base + "/health", timeout=2) as rh:
                if rh.status == 200:
                    break
        except Exception:
            time.sleep(0.5)
    else:
        check("R1 server boot", False, "never healthy")
        raise SystemExit(1)
    # landing works over HTTP too
    with urllib.request.urlopen(base + "/", timeout=5) as rh:
        html = rh.read().decode()
    check("R1 landing over HTTP", rh.status == 200 and "verifiable work history" in html)
    # remote seed
    pr = subprocess.run([sys.executable, os.path.join(HERE, "seed.py"),
                         "--remote", base], capture_output=True, text=True, timeout=60)
    check("R2 seed.py --remote ok", pr.returncode == 0, pr.stderr[:200])
    with urllib.request.urlopen(base + "/v1/agents/mikey/reputation", timeout=5) as rh:
        rep = json.loads(rh.read().decode())
    check("R3 remote mikey == 113.64", rep["score"] == 113.64, f"score={rep['score']}")
    # idempotent rerun
    pr = subprocess.run([sys.executable, os.path.join(HERE, "seed.py"),
                         "--remote", base], capture_output=True, text=True, timeout=60)
    with urllib.request.urlopen(base + "/v1/agents/mikey/reputation", timeout=5) as rh:
        rep2 = json.loads(rh.read().decode())
    check("R4 remote rerun idempotent", pr.returncode == 0 and rep2["score"] == 113.64
          and rep2["breakdown"] and len(rep2["breakdown"]) == len(rep["breakdown"]))
finally:
    proc.terminate()

n = len(results)
passed = sum(1 for x in results if x)
print(f"\n{passed}/{n} checks passed")
sys.exit(0 if passed == n else 1)
