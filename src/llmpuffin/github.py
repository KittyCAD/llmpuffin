"""GitHub App integration using PyGithub.

Provides a GitHubClient that caches the App config and exposes methods
for issues, PRs, and commits.

Usage:
    from llmpuffin.github import client_from_config

    gh = client_from_config()  # reads config from llmpuffin.toml
    gh.create_issue("owner/repo", "title", "body")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.request import Request, urlopen

from github import Auth, Github, GithubIntegration

log = logging.getLogger("llmpuffin")


@dataclass
class PullRequestInfo:
    """Structured result from fetching a GitHub PR."""

    number: int
    title: str
    body: str
    state: str
    diff: str
    comments: list[str] = field(default_factory=list)

    def format(self) -> str:
        lines = [
            f"# PR #{self.number}: {self.title}",
            f"State: {self.state}",
            "",
            "## Description",
            self.body or "(no description)",
            "",
        ]
        if self.comments:
            lines.append("## Comments")
            for i, c in enumerate(self.comments, 1):
                lines.append(f"### Comment {i}")
                lines.append(c)
                lines.append("")
        lines.append("## Diff")
        if len(self.diff) > 50_000:
            lines.append(self.diff[:50_000])
            lines.append(f"\n... (truncated, {len(self.diff)} chars total)")
        else:
            lines.append(self.diff)
        return "\n".join(lines)


@dataclass
class CommitInfo:
    """Structured result from fetching a GitHub commit."""

    sha: str
    message: str
    author: str
    date: str
    diff: str
    files: list[str] = field(default_factory=list)

    def format(self) -> str:
        lines = [
            f"# Commit {self.sha[:12]}",
            f"Author: {self.author}",
            f"Date: {self.date}",
            "",
            "## Message",
            self.message,
            "",
            f"## Files changed ({len(self.files)})",
        ]
        for f in self.files:
            lines.append(f"  - {f}")
        lines.append("")
        lines.append("## Diff")
        if len(self.diff) > 50_000:
            lines.append(self.diff[:50_000])
            lines.append(f"\n... (truncated, {len(self.diff)} chars total)")
        else:
            lines.append(self.diff)
        return "\n".join(lines)


class GitHubClient:
    """GitHub App client that stores credentials and exposes API methods."""

    def __init__(self, app_id: str, private_key: str, installation_id: str):
        self.app_id = app_id
        self.private_key = private_key
        self.installation_id = installation_id

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.private_key and self.installation_id)

    def _gh(self) -> Github:
        """Return an authenticated PyGithub client (new token each call)."""
        auth = Auth.AppAuth(int(self.app_id), self.private_key)
        gi = GithubIntegration(auth=auth)
        token = gi.get_access_token(int(self.installation_id))
        return Github(auth=Auth.Token(token.token))

    def _install_token(self) -> str:
        auth = Auth.AppAuth(int(self.app_id), self.private_key)
        gi = GithubIntegration(auth=auth)
        return gi.get_access_token(int(self.installation_id)).token

    def _fetch_diff(self, url: str) -> str:
        """Fetch a diff URL using the installation token."""
        req = Request(
            url,
            headers={
                "Authorization": f"token {self._install_token()}",
                "Accept": "application/vnd.github.v3.diff",
            },
        )
        with urlopen(req) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def check_repo_access(self, repo: str) -> dict | None:
        """Return repo metadata if accessible, else None."""
        try:
            r = self._gh().get_repo(repo)
            return {"private": r.private, "full_name": r.full_name}
        except Exception:
            return None

    def create_issue(
        self, repo: str, title: str, body: str, labels: list[str] | None = None
    ) -> str:
        """Create a GitHub issue and return its HTML URL."""
        r = self._gh().get_repo(repo)
        issue = r.create_issue(title=title, body=body, labels=labels or [])
        return issue.html_url

    def create_draft_advisory(
        self,
        repo: str,
        summary: str,
        description: str,
        severity: str = "medium",
        cwe_ids: list[str] | None = None,
    ) -> str:
        """Create a draft security advisory and return its HTML URL.

        Uses the REST API directly since PyGithub doesn't support advisories.
        """
        import json

        token = self._install_token()
        # Map our severity to GHSA severity (critical/high/medium/low)
        ghsa_severity = severity.lower()
        if ghsa_severity not in ("critical", "high", "medium", "low"):
            ghsa_severity = "medium"

        payload: dict = {
            "summary": summary,
            "description": description,
            "severity": ghsa_severity,
            "vulnerabilities": [],
        }
        if cwe_ids:
            payload["cwe_ids"] = cwe_ids

        req = Request(
            f"https://api.github.com/repos/{repo}/security-advisories",
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

    def update_issue(self, repo: str, issue_number: int, title: str, body: str) -> str:
        """Update a GitHub issue and return its HTML URL."""
        r = self._gh().get_repo(repo)
        issue = r.get_issue(issue_number)
        issue.edit(title=title, body=body)
        return issue.html_url

    def fetch_pull_request(self, repo: str, number: int) -> PullRequestInfo:
        """Fetch a PR's title, description, comments, and diff."""
        r = self._gh().get_repo(repo)
        pr = r.get_pull(number)

        comments = []
        for c in pr.get_issue_comments():
            comments.append(f"**{c.user.login}** ({c.created_at}):\n{c.body}")
        for c in pr.get_comments():
            path = f" (`{c.path}:{c.position}`)" if c.path else ""
            comments.append(f"**{c.user.login}**{path} ({c.created_at}):\n{c.body}")

        diff = self._fetch_diff(pr.diff_url)

        return PullRequestInfo(
            number=pr.number,
            title=pr.title,
            body=pr.body or "",
            state=pr.state,
            diff=diff,
            comments=comments,
        )

    def fetch_commit(self, repo: str, sha: str) -> CommitInfo:
        """Fetch a commit's message, files, and diff."""
        r = self._gh().get_repo(repo)
        commit = r.get_commit(sha)
        files = [f.filename for f in commit.files]
        diff = self._fetch_diff(commit.html_url + ".diff")

        return CommitInfo(
            sha=commit.sha,
            message=commit.commit.message,
            author=commit.commit.author.name,
            date=str(commit.commit.author.date),
            diff=diff,
            files=files,
        )


def client_from_config() -> GitHubClient:
    """Create a GitHubClient from llmpuffin.toml config."""
    from llmpuffin.config import Config

    gh = Config.load().github
    return GitHubClient(
        app_id=gh.app_id,
        private_key=gh.private_key,
        installation_id=gh.installation_id,
    )
