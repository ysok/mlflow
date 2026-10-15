"""
Publish the agent's summary as a draft item in the private project, with the processed list from
prepare.py embedded so the next run can tell what it already covered.

The summary was written by an agent that read reporter-controlled text, so it is sanitized before
publishing: HTML, images, links, and bare URLs are removed (an image or link to an outside host
could leak advisory content when the item is viewed), @-mentions are defused so nobody is
notified, and GHSA IDs that exist in the repository are linked to their advisories.

Runs outside the sandbox with a GitHub App token. Prints nothing.
"""

import datetime
import os
import re
import sys
from pathlib import Path

from prepare import TITLE_PREFIX, graphql

MAX_SUMMARY_CHARS = 30_000
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b")


def sanitize(text: str, known: set[str], repo: str) -> str:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>\n]*>", "", text)
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"^\s*\[[^\]]+\]:\s*\S+.*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"\b(?:https?|ftp)://\S+|\bwww\.\S+", "", text)
    text = re.sub(r"@(?=[A-Za-z0-9])", "@​", text)
    if len(text) > MAX_SUMMARY_CHARS:
        text = text[:MAX_SUMMARY_CHARS] + "\n\n_Summary truncated._\n"
    return GHSA_RE.sub(
        lambda m: (
            f"[{m[0]}](https://github.com/{repo}/security/advisories/{m[0]})"
            if m[0] in known
            else m[0]
        ),
        text,
    )


def main() -> None:
    token = os.environ["GH_TOKEN"]
    repo = os.environ["REPO"]
    in_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    known = {p.stem for p in (in_dir / "advisories").glob("GHSA-*.json")}
    summary = sanitize((out_dir / "summary.md").read_text(), known, repo)
    processed = (in_dir / "processed.txt").read_text()
    body = f"{summary.rstrip()}\n\n<!-- processed\n{processed.rstrip()}\n-->\n"

    project_id = graphql(
        token,
        "query($org: String!, $number: Int!) "
        "{ organization(login: $org) { projectV2(number: $number) { id } } }",
        org=os.environ["ORG"],
        number=int(os.environ["PROJECT_NUMBER"]),
    )["organization"]["projectV2"]["id"]
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    graphql(
        token,
        "mutation($project: ID!, $title: String!, $body: String!) "
        "{ addProjectV2DraftIssue(input: { projectId: $project, title: $title, body: $body }) "
        "{ projectItem { id } } }",
        project=project_id,
        title=f"{TITLE_PREFIX} · {today}",
        body=body,
    )


if __name__ == "__main__":
    main()
