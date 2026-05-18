"""GitHub App integration for creating issues via installation tokens."""

from __future__ import annotations

import json
import logging
import time
from urllib.request import Request, urlopen

import jwt

log = logging.getLogger("llmpuffin")


def _generate_jwt(app_id: str, private_key: str) -> str:
    """Generate a JWT for GitHub App authentication."""
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def _get_installation_token(app_id: str, private_key: str, installation_id: str) -> str:
    """Exchange a JWT for an installation access token."""
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
    """Create a GitHub issue and return the issue URL.

    Args:
        repo: Repository in "owner/repo" format.
        title: Issue title.
        body: Issue body (markdown).
        app_id: GitHub App ID.
        private_key: PEM private key content.
        installation_id: GitHub App installation ID.
        labels: Optional list of label names.

    Returns:
        The URL of the created issue.
    """
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
