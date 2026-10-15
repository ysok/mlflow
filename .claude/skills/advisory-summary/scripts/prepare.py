"""
Fetch repository security advisories and the processed list from the latest summary, and lay out
the agent's input directory:

    <in_dir>/advisories/<GHSA>.json   every advisory, any state
    <in_dir>/manifest.json            which advisories are new or changed since the last summary
    <in_dir>/processed.txt            the processed list to embed in this run's summary

Runs outside the sandbox with a GitHub App token. Prints nothing: advisory data is confidential
and workflow logs are public.
"""

import argparse
import json
import os
import re
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
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("in_dir", type=Path)
    parser.add_argument("--repo", default="mlflow/mlflow")
    parser.add_argument(
        "--project",
        type=int,
        help="Org project number holding past summaries. Without it, all open advisories are new.",
    )
    parser.add_argument(
        "--limit", type=int, help="Cover at most this many of the newest advisories."
    )
    args = parser.parse_args()

    token = os.environ["GH_TOKEN"]
    in_dir: Path = args.in_dir
    advisories = fetch_advisories(token, args.repo)
    org = args.repo.split("/")[0]
    latest = fetch_latest_summary(token, org, args.project) if args.project else None
    previous = parse_processed(latest[1]) if latest else {}

    (in_dir / "advisories").mkdir(parents=True, exist_ok=True)
    open_advisories = []
    for advisory in advisories:
        (in_dir / "advisories" / f"{advisory['ghsa_id']}.json").write_text(
            json.dumps(advisory, indent=2)
        )
        if advisory["state"] in OPEN_STATES:
            open_advisories.append(advisory)

    pending = [a for a in open_advisories if previous.get(a["ghsa_id"]) != fingerprint(a)]
    pending.sort(key=lambda a: a["updated_at"], reverse=True)
    covered = {a["ghsa_id"] for a in pending[: args.limit]}
    new = []
    changed = []
    for advisory in pending:
        ghsa = advisory["ghsa_id"]
        if ghsa not in covered:
            continue
        if ghsa not in previous:
            new.append(ghsa)
        else:
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
    # Advisories left out by --limit keep their previous entry, so the next run still covers them.
    processed = {a["ghsa_id"]: fingerprint(a) for a in open_advisories}
    for advisory in pending:
        ghsa = advisory["ghsa_id"]
        if ghsa in covered:
            continue
        if ghsa in previous:
            processed[ghsa] = previous[ghsa]
        else:
            del processed[ghsa]
    (in_dir / "processed.txt").write_text(
        "".join(f"{ghsa} {fp}\n" for ghsa, fp in sorted(processed.items()))
    )
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a") as f:
            f.write(f"pending={len(new) + len(changed)}\n")


if __name__ == "__main__":
    main()
