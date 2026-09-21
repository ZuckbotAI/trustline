#!/usr/bin/env python3
"""Trustline SSO client tests (2026-09-21) — stdlib only, no httpx/pytest.

Covers: /auth/login redirect + state cookie, /auth/callback happy path
(against a stubbed provider with REAL Ed25519 tokens we sign ourselves),
state mismatch, tampered token, wrong aud/iss, expired token, consent
deny, logout, /network sign-in affordance, orb embed, and — critically —
agent keypair auth working exactly as before with no human login.

Run: .venv/bin/python test_sso_client_2026_09_21.py
Exits 0 only if every check passes.
"""
import base64
import json
import os
import sys
import tempfile
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="trustline-sso-")
os.environ["TRUSTLINE_DB"] = os.path.join(TMP, "sso.db")
os.environ["TRUSTLINE_SESSION_SECRET"] = "test-secret-not-real-123"
sys.path.insert(0, HERE)

import server  # noqa: E402
import sso_client as sso  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from fastapi import HTTPException  # noqa: E402
from starlette.requests import Request  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name +
          (f"  [{detail}]" if detail and not cond else ""))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_req(path="/", cookies="", query=b""):
    headers = [(b"host", b"trustlineapp.com")]
    if cookies:
        headers.append((b"cookie", cookies.encode()))
    return Request({"type": "http", "method": "GET", "path": path,
                    "query_string": query, "headers": headers})


def set_cookies(resp):
    return resp.headers.getlist("set-cookie")


def cookie_val(set_cookie_headers, name):
    for h in set_cookie_headers:
        if h.startswith(name + "="):
            return h.split(";", 1)[0][len(name) + 1:]
    return None


# --- stub provider: real Ed25519 tokens, our own key --------------------------
PROV_PRIV = Ed25519PrivateKey.generate()
PROV_PUB = PROV_PRIV.public_key()
OTHER_PRIV = Ed25519PrivateKey.generate()  # attacker key

_orig_exchange = sso.exchange_code
_orig_pubkey = sso.provider_pubkey


def make_token(priv, **over):
    header = b64u(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": "sso-v1"},
                             separators=(",", ":")).encode())
    now = int(time.time())
    claims = {"iss": "https://musefm.lol", "aud": "trustline",
              "sub": "fm_test123", "handle": "testhuman",
              "iat": now, "exp": now + 600}
    claims.update(over)
    payload = b64u(json.dumps(claims, separators=(",", ":"),
                              sort_keys=True).encode())
    sig = b64u(priv.sign((header + "." + payload).encode()))
    return header + "." + payload + "." + sig


seen_verifiers = []


def stub_exchange(token):
    def _ex(code, verifier):
        seen_verifiers.append(verifier)
        return {"ok": True, "id_token": token,
                "fm_id": "fm_test123", "handle": "testhuman"}
    return _ex


def fresh_login_state():
    """Run /auth/login, return (state, verifier_cookie_value, redirect)."""
    resp = server.sso_login()
    loc = resp.headers["location"]
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    sc = cookie_val(set_cookies(resp), "sso_state")
    stored = sso.read_state_cookie(sc, os.environ["TRUSTLINE_SESSION_SECRET"])
    return q["state"][0], sc, stored["verifier"], loc


# 1 — login redirect ---------------------------------------------------------
resp = server.sso_login()
loc = resp.headers["location"]
check("01 login -> 302", resp.status_code == 302)
q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
check("02 login targets provider authorize",
      loc.startswith("https://musefm.lol/auth/authorize?"), loc[:60])
check("03 login params (client, redirect, S256, state)",
      q.get("client_id") == ["trustline"]
      and q.get("redirect_uri") == ["https://trustlineapp.com/auth/callback"]
      and q.get("code_challenge_method") == ["S256"]
      and len(q.get("code_challenge", [""])[0]) >= 43
      and len(q.get("state", [""])[0]) >= 32)
sc = cookie_val(set_cookies(resp), "sso_state")
check("04 sso_state cookie set", bool(sc))
hdr = [h for h in set_cookies(resp) if h.startswith("sso_state=")][0].lower()
check("05 sso_state flags (httponly/secure/lax)",
      "httponly" in hdr and "secure" in hdr and "samesite=lax" in hdr, hdr)
stored = sso.read_state_cookie(sc, os.environ["TRUSTLINE_SESSION_SECRET"])
check("06 sso_state is signed + carries verifier",
      stored is not None and stored["state"] == q["state"][0]
      and len(stored["verifier"]) >= 43)

# 2 — happy path --------------------------------------------------------------
state, state_cookie, verifier, _ = fresh_login_state()
server.sso.exchange_code = stub_exchange(make_token(PROV_PRIV))
server.sso.provider_pubkey = lambda: PROV_PUB
req = make_req("/auth/callback", cookies=f"sso_state={state_cookie}",
               query=f"code=authcode123&state={state}".encode())
resp = server.sso_callback(req, code="authcode123", state=state)
check("07 callback happy path -> 302 /network?auth=ok",
      resp.status_code == 302
      and resp.headers["location"] == "/network?auth=ok",
      resp.headers.get("location"))
check("07b server sent the PKCE verifier from the state cookie",
      seen_verifiers and seen_verifiers[-1] == verifier)
sess = cookie_val(set_cookies(resp), "tl_session")
check("08 tl_session cookie set", bool(sess))
hdr = [h for h in set_cookies(resp) if h.startswith("tl_session=")][0].lower()
check("09 tl_session flags (httponly/secure/lax)",
      "httponly" in hdr and "secure" in hdr and "samesite=lax" in hdr, hdr)
ident = sso.read_session(sess, os.environ["TRUSTLINE_SESSION_SECRET"])
check("10 session round-trips fm_id + handle",
      ident and ident["fm_id"] == "fm_test123"
      and ident["handle"] == "testhuman")
check("11 sso_state cleared after use",
      any(h.startswith("sso_state=") and "max-age=0" in h.lower()
          for h in set_cookies(resp)))

# 3 — /network affordance -----------------------------------------------------
page = server.network_page(make_req(cookies=f"tl_session={sess}"))
html = page.body.decode()
check("12 /network shows signed-in handle",
      "Signed in as @testhuman" in html and "/auth/logout" in html)
page2 = server.network_page(make_req())
html2 = page2.body.decode()
check("13 /network logged-out shows sign-in CTA",
      "Sign in with MuseFM" in html2 and "/auth/login" in html2)

# 4 — failure modes -----------------------------------------------------------
def expect_400(name, fn):
    try:
        fn()
        check(name, False, "expected 400, got success")
    except HTTPException as e:
        check(name, e.status_code == 400, f"got {e.status_code}")
    except Exception as e:
        check(name, False, f"wrong exception: {type(e).__name__}: {e}")

# 4a state mismatch
state, sc_bad, _, _ = fresh_login_state()
req = make_req(cookies=f"sso_state={sc_bad}",
               query=b"code=x&state=wrong-state-value")
expect_400("14 state mismatch -> 400",
           lambda: server.sso_callback(req, code="x",
                                       state="wrong-state-value"))
# 4b tampered state cookie
req = make_req(cookies="sso_state=tampered.value",
               query=f"code=x&state={state}".encode())
expect_400("15 tampered state cookie -> 400",
           lambda: server.sso_callback(req, code="x", state=state))
# 4c missing code
state, sc2, _, _ = fresh_login_state()
req = make_req(cookies=f"sso_state={sc2}",
               query=f"code=&state={state}".encode())
expect_400("16 missing code -> 400",
           lambda: server.sso_callback(req, code="", state=state))
# 4d tampered id_token (attacker key)
state, sc3, _, _ = fresh_login_state()
server.sso.exchange_code = stub_exchange(make_token(OTHER_PRIV))
req = make_req(cookies=f"sso_state={sc3}",
               query=f"code=x&state={state}".encode())
expect_400("17 token signed by wrong key -> 400",
           lambda: server.sso_callback(req, code="x", state=state))
# 4e wrong audience
server.sso.exchange_code = stub_exchange(make_token(PROV_PRIV, aud="arena"))
req = make_req(cookies=f"sso_state={sc3}",
               query=f"code=x&state={state}".encode())
expect_400("18 wrong aud -> 400",
           lambda: server.sso_callback(req, code="x", state=state))
# 4f wrong issuer
server.sso.exchange_code = stub_exchange(
    make_token(PROV_PRIV, iss="https://evil.example.com"))
expect_400("19 wrong iss -> 400",
           lambda: server.sso_callback(req, code="x", state=state))
# 4g expired token
past = int(time.time()) - 700
server.sso.exchange_code = stub_exchange(
    make_token(PROV_PRIV, iat=past - 600, exp=past))
expect_400("20 expired token -> 400",
           lambda: server.sso_callback(req, code="x", state=state))
# 4h consent denied at provider
req = make_req(query=b"error=access_denied&state=whatever")
resp = server.sso_callback(req, code="", state="", error="access_denied")
check("21 consent deny -> 302 /network?auth=cancelled",
      resp.status_code == 302
      and resp.headers["location"] == "/network?auth=cancelled")

server.sso.exchange_code = _orig_exchange
server.sso.provider_pubkey = _orig_pubkey

# 5 — logout ------------------------------------------------------------------
resp = server.sso_logout()
check("22 logout -> 302", resp.status_code == 302)
check("23 logout clears tl_session",
      any(h.startswith("tl_session=") and "max-age=0" in h.lower()
          for h in set_cookies(resp)))

# 6 — no secret configured ----------------------------------------------------
del os.environ["TRUSTLINE_SESSION_SECRET"]
resp = server.sso_login()
check("24 login without secret -> 503, no redirect",
      resp.status_code == 503)
os.environ["TRUSTLINE_SESSION_SECRET"] = "test-secret-not-real-123"

# 7 — agent keypair auth untouched, no login -----------------------------------
priv_a = Ed25519PrivateKey.generate()
pub_a = priv_a.public_key().public_bytes_raw().hex()
priv_b = Ed25519PrivateKey.generate()
pub_b = priv_b.public_key().public_bytes_raw().hex()
r = server.register_agent(server.AgentIn(
    pubkey=pub_a, handle="ssoagent", display_name="SSO Agent"))
check("25 agent register works without login", r["ok"] is True)
r = server.register_agent(server.AgentIn(
    pubkey=pub_b, handle="ssoattester", display_name="SSO Attester"))
check("25b second agent registers", r["ok"] is True)


def sign_att(priv, core):
    return base64.b64encode(
        priv.sign(server.canonical_bytes(core))).decode()


# B vouches for A — the classic agent-to-agent flow, no human login anywhere
core = {"subject_pubkey": pub_a, "attester_pubkey": pub_b,
        "event": "vouch.given", "payload": {"note": "solid work"},
        "created_at": "2026-09-01T12:00:00+00:00"}
r = server.submit_attestation(server.AttestationIn(
    subject_pubkey=pub_a, attester_pubkey=pub_b, event="vouch.given",
    payload={"note": "solid work"}, created_at="2026-09-01T12:00:00+00:00",
    signature=sign_att(priv_b, core)))
check("26 signed attestation accepted without login", r["ok"] is True)
rep = server.get_reputation("ssoagent")
check("27 reputation readable without login",
      rep["handle"] == "ssoagent" and rep["score"] > 0)
del_core = {"pubkey": pub_a, "handle": "ssoagent"}
del_sig = base64.b64encode(priv_a.sign(
    server.delete_canonical_bytes(pub_a, "ssoagent"))).decode()
r = server.delete_agent("ssoagent", server.DeleteIn(
    pubkey=pub_a, handle="ssoagent", signature=del_sig))
check("28 owner-signed delete works without login", r["ok"] is True)

# 8 — orb embed ----------------------------------------------------------------
page = server.landing()
html = page.body.decode()
check("29 orb anchor on brand link", "data-muse-orb-anchor" in html)
check("30 orb script included (defer, same-origin)",
      '<script src="/static/js/muse-orb.js" defer></script>' in html)
orb_path = os.path.join(HERE, "static", "js", "muse-orb.js")
check("31 orb js served from repo", os.path.exists(orb_path)
      and os.path.getsize(orb_path) > 20000)
resp = server.orb_js()
check("32 /static/js/muse-orb.js route -> js file",
      resp.media_type == "application/javascript"
      and resp.path == orb_path)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
