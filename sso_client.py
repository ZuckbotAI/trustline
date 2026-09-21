"""Trustline SSO client — "Sign in with MuseFM" (global login, 2026-09-21).

Trustline is a *client* of the MuseFM identity provider (musefm.lol).
Flow: /auth/login -> provider consent -> /auth/callback -> local session.

Human login is OPTIONAL convenience only. Agent identity stays
ed25519-keypair based; nothing here touches the v1 agent API, the
attestation signatures, or the scorer. No passwords, no user table.

Session cookie: "tl_session" — HMAC-signed (server secret from
TRUSTLINE_SESSION_SECRET), HttpOnly + Secure + SameSite=Lax, 30 days.
State cookie: "sso_state" — HMAC-signed JSON {state, verifier, exp},
HttpOnly + Secure + SameSite=Lax, 10 minutes.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SSO_CLIENT_ID = "trustline"
SSO_PROVIDER = "https://musefm.lol"
SSO_ISSUER = "https://musefm.lol"
SSO_REDIRECT_URI = "https://trustlineapp.com/auth/callback"
SSO_AUTHORIZE_PATH = "/auth/authorize"
SSO_TOKEN_PATH = "/auth/token"
SSO_PUBKEY_PATH = "/auth/pubkey"

STATE_TTL_SEC = 10 * 60
SESSION_TTL_SEC = 30 * 24 * 3600
HTTP_TIMEOUT_SEC = 10


class SSOError(Exception):
    """Anything wrong with the SSO exchange — always fail closed."""


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def session_secret() -> str | None:
    """Server secret for HMAC-signing cookies. None = SSO not configured."""
    return os.environ.get("TRUSTLINE_SESSION_SECRET") or None


# --- PKCE + authorize URL ----------------------------------------------------
def new_pkce() -> tuple[str, str]:
    """(code_verifier, code_challenge_S256)."""
    verifier = secrets.token_urlsafe(64)
    challenge = b64u_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def new_state() -> str:
    return secrets.token_urlsafe(32)


def authorize_url(state: str, challenge: str) -> str:
    q = urllib.parse.urlencode({
        "client_id": SSO_CLIENT_ID,
        "redirect_uri": SSO_REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    return SSO_PROVIDER + SSO_AUTHORIZE_PATH + "?" + q


# --- signed cookies ----------------------------------------------------------
def _sign(value: str, secret: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), value.encode("ascii"),
                   hashlib.sha256).digest()
    return value + "." + b64u_encode(sig)


def _unsign(signed: str, secret: str) -> str | None:
    if "." not in signed:
        return None
    value, _, sig_b64 = signed.rpartition(".")
    try:
        sig = b64u_decode(sig_b64)
    except Exception:
        return None
    expected = hmac.new(secret.encode("utf-8"), value.encode("ascii"),
                        hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    return value


def _pack(payload: dict, secret: str) -> str:
    body = b64u_encode(json.dumps(payload, separators=(",", ":"),
                                  sort_keys=True).encode("utf-8"))
    return _sign(body, secret)


def _unpack(signed: str, secret: str) -> dict | None:
    body = _unsign(signed, secret)
    if body is None:
        return None
    try:
        return json.loads(b64u_decode(body))
    except Exception:
        return None


def mint_state_cookie(state: str, verifier: str, secret: str) -> str:
    return _pack({"state": state, "verifier": verifier,
                  "exp": int(time.time()) + STATE_TTL_SEC}, secret)


def read_state_cookie(value: str, secret: str) -> dict | None:
    d = _unpack(value, secret)
    if not d or not isinstance(d.get("exp"), int):
        return None
    if d["exp"] < int(time.time()):
        return None
    if not d.get("state") or not d.get("verifier"):
        return None
    return d


def mint_session(fm_id: str, handle: str, secret: str) -> str:
    return _pack({"fm_id": fm_id, "handle": handle,
                  "exp": int(time.time()) + SESSION_TTL_SEC}, secret)


def read_session(value: str, secret: str) -> dict | None:
    d = _unpack(value, secret)
    if not d or not isinstance(d.get("exp"), int):
        return None
    if d["exp"] < int(time.time()):
        return None
    if not d.get("fm_id") or not d.get("handle"):
        return None
    return d


# --- provider calls ----------------------------------------------------------
def _http_json(method: str, url: str, payload: dict | None = None) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        raise SSOError(f"provider request failed: {e}") from e


def exchange_code(code: str, verifier: str) -> dict:
    """POST the auth code + PKCE verifier; returns the token response dict."""
    body = _http_json("POST", SSO_PROVIDER + SSO_TOKEN_PATH, {
        "client_id": SSO_CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": SSO_REDIRECT_URI,
    })
    if not isinstance(body, dict) or not body.get("ok"):
        raise SSOError("token exchange rejected: %r"
                       % (body.get("error") if isinstance(body, dict)
                          else body))
    return body


_pubkey_cache: tuple[float, Ed25519PublicKey] | None = None


def provider_pubkey() -> Ed25519PublicKey:
    """Fetch + cache the provider's Ed25519 ID-token key (1h)."""
    global _pubkey_cache
    now = time.time()
    if _pubkey_cache and _pubkey_cache[0] > now - 3600:
        return _pubkey_cache[1]
    body = _http_json("GET", SSO_PROVIDER + SSO_PUBKEY_PATH)
    try:
        raw = b64u_decode(body["public_key"])
        pub = Ed25519PublicKey.from_public_bytes(raw)
    except Exception as e:
        raise SSOError(f"bad provider pubkey: {e}") from e
    _pubkey_cache = (now, pub)
    return pub


def verify_id_token(token: str, pub: Ed25519PublicKey) -> dict:
    """Verify signature + iss/aud/exp. Returns {fm_id, handle} or raises."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        signed = (h_b64 + "." + p_b64).encode("ascii")
        pub.verify(b64u_decode(s_b64), signed)
        claims = json.loads(b64u_decode(p_b64))
    except InvalidSignature as e:
        raise SSOError("bad id_token signature") from e
    except Exception as e:
        raise SSOError(f"malformed id_token: {e}") from e
    now = int(time.time())
    if claims.get("iss") != SSO_ISSUER:
        raise SSOError("id_token wrong issuer")
    if claims.get("aud") != SSO_CLIENT_ID:
        raise SSOError("id_token wrong audience")
    exp = claims.get("exp")
    if not isinstance(exp, int) or exp <= now:
        raise SSOError("id_token expired")
    iat = claims.get("iat")
    if isinstance(iat, int) and iat > now + 300:
        raise SSOError("id_token issued in the future")
    fm_id = claims.get("sub")
    handle = claims.get("handle")
    if not fm_id or not handle or not isinstance(fm_id, str) \
            or not isinstance(handle, str):
        raise SSOError("id_token missing sub/handle")
    return {"fm_id": fm_id, "handle": handle}
