"""Pull-request approvals from the GitHub REST API, for reviewer obligations.

Team membership needs a token that can read organisation members; the default GITHUB_TOKEN cannot,
so without GOV_GITHUB_TOKEN only individual approvers are matched.
https://docs.github.com/en/rest/pulls/reviews#list-reviews-for-a-pull-request
https://docs.github.com/en/rest/teams/members#list-team-members
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class GitHubError(Exception):
    pass


def _get(path: str, token: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    url: str | None = f"{API}{path}{'&' if '?' in path else '?'}per_page=100"
    while url:
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                items.extend(json.loads(response.read()))
                url = _next_link(response.headers.get("Link", ""))
        except urllib.error.HTTPError as exc:
            raise GitHubError(f"GET {path}: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"GET {path}: {exc.reason}") from exc
    return items


def _next_link(header: str) -> str | None:
    for part in header.split(","):
        if 'rel="next"' in part:
            return part[part.index("<") + 1 : part.index(">")]
    return None


def pr_approvals(
    repository: str, pr: int, token: str, teams: set[str], head_sha: str | None = None, team_token: str | None = None
) -> set[str]:
    """`@user` for each approver whose latest review is APPROVED (on head_sha when given), plus `@org/team`
    for each referenced team with an approving member."""
    latest: dict[str, dict[str, Any]] = {}
    for review in _get(f"/repos/{repository}/pulls/{pr}/reviews", token):
        user = (review.get("user") or {}).get("login")
        if user and review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[user.lower()] = review
    approvers = {
        u
        for u, r in latest.items()
        if r["state"] == "APPROVED" and (head_sha is None or r.get("commit_id") == head_sha)
    }
    result = {f"@{u}" for u in approvers}
    if team_token:
        for team in sorted(teams):
            org, _, slug = team.lstrip("@").partition("/")
            if not slug:
                continue
            members = {m["login"].lower() for m in _get(f"/orgs/{org}/teams/{slug}/members", team_token)}
            if members & approvers:
                result.add(team.lower())
    return result
