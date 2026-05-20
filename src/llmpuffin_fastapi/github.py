"""GitHub App integration for creating issues via installation tokens."""

from __future__ import annotations

import json
import logging
import time
from urllib.request import Request, urlopen

import jwt

log = logging.getLogger("llmpuffin")


def _generate_jwt(app_id: str, private_key: str) -> str:
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + (10 * 60), "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


def _get_installation_token(app_id: str, private_key: str, installation_id: str) -> str:
    token = _generate_jwt(app_id, private_key)
    req = Request(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urlopen(req) as resp:
        data = json.loads(resp.read())
    return data["token"]


def create_issue(
    repo: str,
    title: str,
    body: str,
    app_id: str,
    private_key: str,
    installation_id: str,
    labels: list[str] | None = None,
) -> str:
    token = _get_installation_token(app_id, private_key, installation_id)
    payload: dict = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels

    req = Request(
        f"https://api.github.com/repos/{repo}/issues",
        method="POST",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    with urlopen(req) as resp:
        data = json.loads(resp.read())
    return data["html_url"]


def update_issue(
    repo: str,
    issue_number: int,
    title: str,
    body: str,
    app_id: str,
    private_key: str,
    installation_id: str,
) -> str:
    token = _get_installation_token(app_id, private_key, installation_id)
    payload = {"title": title, "body": body}
    req = Request(
        f"https://api.github.com/repos/{repo}/issues/{issue_number}",
        method="PATCH",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    with urlopen(req) as resp:
        data = json.loads(resp.read())
    return data["html_url"]
