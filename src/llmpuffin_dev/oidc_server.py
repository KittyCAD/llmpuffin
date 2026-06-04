"""Minimal OIDC provider for local development.

Run via: uv run llmpuffin-oidc
Serves on http://localhost:9090

Hardcoded users:
  admin / admin    → groups: ["llmpuffin-admin"]
  auditor / auditor → groups: ["llmpuffin-auditor"]
  viewer / viewer   → groups: []

Discovery: http://localhost:9090/.well-known/openid-configuration
"""

from __future__ import annotations

import time
import uuid
from urllib.parse import urlencode

import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from joserfc import jwt
from joserfc.jwk import RSAKey

PORT = 9090
ISSUER = f"http://localhost:{PORT}"

# Generate an RSA key pair at startup for signing JWTs.
_rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_rsa_key = RSAKey.import_key(_rsa_private)
_kid = "dev-key-1"

# Hardcoded users: username → {password, claims}
USERS = {
    "admin": {
        "password": "admin",
        "sub": "1",
        "name": "Admin User",
        "email": "admin@localhost",
        "groups": ["llmpuffin-admin"],
    },
    "auditor": {
        "password": "auditor",
        "sub": "2",
        "name": "Auditor User",
        "email": "auditor@localhost",
        "groups": ["llmpuffin-auditor"],
    },
    "viewer": {
        "password": "viewer",
        "sub": "3",
        "name": "Viewer",
        "email": "viewer@localhost",
        "groups": [],
    },
}

# In-memory stores for codes and tokens.
_codes: dict[str, dict] = {}  # code → {user, client_id, redirect_uri, nonce}
_tokens: dict[str, dict] = {}  # access_token → user claims


def _make_id_token(claims: dict) -> str:
    """Create an RS256-signed JWT."""
    header = {"alg": "RS256", "kid": _kid}
    return jwt.encode(header, claims, _rsa_key)


app = FastAPI(title="llmpuffin dev OIDC")


@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": ["sub", "name", "email", "groups"],
    }


@app.get("/jwks")
def jwks():
    pub = _rsa_key.as_dict(is_private=False)
    pub["kid"] = _kid
    pub["use"] = "sig"
    pub["alg"] = "RS256"
    return {"keys": [pub]}


@app.get("/authorize", response_class=HTMLResponse)
def authorize(request: Request):
    """Show a simple login form."""
    params = dict(request.query_params)
    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{v}">' for k, v in params.items()
    )
    return f"""<!DOCTYPE html>
<html><head><title>Dev OIDC Login</title>
<style>
  body {{ font-family: system-ui; max-width: 24rem; margin: 4rem auto; }}
  input, button {{ display: block; width: 100%; padding: 0.5rem; margin: 0.5rem 0; box-sizing: border-box; }}
  button {{ background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; padding: 0.75rem; }}
  .hint {{ color: #666; font-size: 0.85em; }}
</style>
</head><body>
<h2>Dev OIDC Login</h2>
<form method="post" action="/authorize">
  {hidden}
  <label>Username</label>
  <input type="text" name="username" required autofocus>
  <label>Password</label>
  <input type="password" name="password" required>
  <button type="submit">Sign in</button>
</form>
<p class="hint">Users: admin/admin, auditor/auditor, viewer/viewer</p>
</body></html>"""


@app.post("/authorize")
def authorize_post(
    request: Request,
    username: str = Form(),
    password: str = Form(),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    response_type: str = Form("code"),
    scope: str = Form("openid"),
    state: str = Form(""),
    nonce: str = Form(""),
):
    user = USERS.get(username)
    if not user or user["password"] != password:
        return HTMLResponse(
            "<h2>Invalid credentials</h2><p><a href='javascript:history.back()'>Back</a></p>",
            status_code=401,
        )

    code = uuid.uuid4().hex
    _codes[code] = {
        "username": username,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "nonce": nonce,
    }

    params = {"code": code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


@app.post("/token")
async def token(request: Request):
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

    code = data.get("code", "")
    code_data = _codes.pop(code, None)
    if not code_data:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    username = code_data["username"]
    user = USERS[username]
    now = int(time.time())

    claims = {
        "iss": ISSUER,
        "sub": user["sub"],
        "aud": code_data["client_id"],
        "exp": now + 3600,
        "iat": now,
        "name": user["name"],
        "email": user["email"],
        "groups": user["groups"],
    }
    if code_data.get("nonce"):
        claims["nonce"] = code_data["nonce"]

    id_token = _make_id_token(claims)
    access_token = uuid.uuid4().hex

    _tokens[access_token] = {
        "sub": user["sub"],
        "name": user["name"],
        "email": user["email"],
        "groups": user["groups"],
    }

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "scope": "openid profile email",
    }


@app.get("/userinfo")
def userinfo(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    tok = auth[7:]
    user_claims = _tokens.get(tok)
    if not user_claims:
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    return user_claims


def main():
    print(f"Dev OIDC server on http://localhost:{PORT}")
    print(f"Discovery: http://localhost:{PORT}/.well-known/openid-configuration")
    print("Users: admin/admin, auditor/auditor, viewer/viewer")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
