"""
Fetch repository security advisories and the processed list from the latest summary, and lay out
the agent's input directory:

    <in_dir>/advisories/<GHSA>.json   every advisory, any state
    <in_dir>/manifest.json            which advisories are new or changed since the last summary
    <in_dir>/processed.txt            the processed list to embed in this run's summary

Runs outside the sandbox with a GitHub App token. Prints nothing: advisory data is confidential
and workflow logs are public.
"""

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com"
TITLE_PREFIX = "Advisory summary"
PROCESSED_RE = re.compile(r"<!-- processed\n(.*?)\n-->", re.DOTALL)
# Advisories still awaiting a decision. Closed and published ones are only compared against.
OPEN_STATES = {"triage", "draft"}


def request(url: str, token: str, body: dict[str, Any] | None = None) -> tuple[Any, str | None]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        link = resp.headers.get("Link") or ""
        next_url = next(
            (m.group(1) for m in re.finditer(r'<([^>]+)>;\s*rel="next"', link)),
            None,
        )
        return json.load(resp), next_url


def graphql(token: str, query: str, **variables: object) -> dict[str, Any]:
    data = request(f"{API}/graphql", token, {"query": query, "variables": variables})[0]
    if data.get("errors"):
        raise RuntimeError("GraphQL request failed")
    result: dict[str, Any] = data["data"]
    return result


def fetch_advisories(token: str, repo: str) -> list[dict[str, Any]]:
    advisories: list[dict[str, Any]] = []
    url: str | None = f"{API}/repos/{repo}/security-advisories?per_page=100"
    while url:
        response = request(url, token)
        advisories.extend(response[0])
        url = response[1]
    return advisories


def fetch_latest_summary(token: str, org: str, number: int) -> tuple[str, str] | None:
    query = """
    query($org: String!, $number: Int!, $cursor: String) {
      organization(login: $org) {
        projectV2(number: $number) {
          items(first: 100, after: $cursor) {
            pageInfo { hasNextPage endCursor }
            nodes { content { ... on DraftIssue { title body createdAt } } }
          }
        }
      }
    }
    """
    latest = None
    cursor = None
    while True:
        items = graphql(token, query, org=org, number=number, cursor=cursor)["organization"][
            "projectV2"
        ]["items"]
        for node in items["nodes"]:
            content = node.get("content") or {}
            if not content.get("title", "").startswith(TITLE_PREFIX):
                continue
            if PROCESSED_RE.search(content.get("body", "")) is None:
                continue
            if latest is None or content["createdAt"] > latest["createdAt"]:
                latest = content
        if not items["pageInfo"]["hasNextPage"]:
            break
        cursor = items["pageInfo"]["endCursor"]
    return (latest["createdAt"], latest["body"]) if latest else None


def fingerprint(advisory: dict[str, Any]) -> str:
    return f"{advisory['updated_at']} {advisory.get('comments') or 0}"


def parse_processed(body: str) -> dict[str, str]:
    match = PROCESSED_RE.search(body)
    entries = {}
    for line in match.group(1).splitlines() if match else []:
        ghsa, _, rest = line.partition(" ")
        entries[ghsa] = rest
    return entries


def main() -> None:
    token = os.environ["GH_TOKEN"]
    in_dir = Path(sys.argv[1])
    advisories = fetch_advisories(token, os.environ["REPO"])
    latest = fetch_latest_summary(token, os.environ["ORG"], int(os.environ["PROJECT_NUMBER"]))
    previous = parse_processed(latest[1]) if latest else {}

    (in_dir / "advisories").mkdir(parents=True, exist_ok=True)
    new: list[str] = []
    changed: list[dict[str, Any]] = []
    for advisory in advisories:
        ghsa = advisory["ghsa_id"]
        (in_dir / "advisories" / f"{ghsa}.json").write_text(json.dumps(advisory, indent=2))
        if advisory["state"] not in OPEN_STATES:
            continue
        if ghsa not in previous:
            new.append(ghsa)
        elif previous[ghsa] != fingerprint(advisory):
            updated_at, _, comments = previous[ghsa].partition(" ")
            changed.append({
                "ghsa_id": ghsa,
                "previous_updated_at": updated_at,
                "previous_comments": int(comments),
            })

    manifest = {
        "previous_summary_at": latest[0] if latest else None,
        "new": sorted(new),
        "changed": sorted(changed, key=lambda c: c["ghsa_id"]),
        "total": len(advisories),
    }
    (in_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (in_dir / "processed.txt").write_text(
        "".join(
            f"{a['ghsa_id']} {fingerprint(a)}\n"
            for a in sorted(advisories, key=lambda a: a["ghsa_id"])
            if a["state"] in OPEN_STATES
        )
    )
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a") as f:
            f.write(f"pending={len(new) + len(changed)}\n")


if __name__ == "__main__":
    main()
