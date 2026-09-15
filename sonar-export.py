#!/usr/bin/env python3
"""Export SonarQube/SonarCloud issues + security hotspots to a DefectDojo
Generic Findings Import JSON file.

Pulls from the SonarQube web API (works for SonarCloud too) so nothing needs to
be installed in the app being scanned — SonarCloud already analysed it in CI.
By default it reads the project's main branch (SONAR_BRANCH, e.g. develop);
set SONAR_PR to pull a pull request's findings instead (handy for testing).

Env: SONAR_URL SONAR_TOKEN SONAR_PROJECT_KEY [SONAR_ORG] [SONAR_BRANCH|SONAR_PR]
     OUTPUT_FILE (default /reports/sonarqube.json)
"""
import base64
import json
import os
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("SONAR_URL", "https://sonarcloud.io").rstrip("/")
TOKEN = os.environ["SONAR_TOKEN"]
PROJECT = os.environ["SONAR_PROJECT_KEY"]
ORG = os.environ.get("SONAR_ORG", "")
BRANCH = os.environ.get("SONAR_BRANCH", "")
PR = os.environ.get("SONAR_PR", "")
OUT = os.environ.get("OUTPUT_FILE", "/reports/sonarqube.json")

# SonarQube severity (legacy) -> DefectDojo severity
SEV = {"BLOCKER": "Critical", "CRITICAL": "High", "MAJOR": "Medium",
       "MINOR": "Low", "INFO": "Info"}
# Security hotspot review priority -> DefectDojo severity
HOTSPOT_SEV = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
# Sonar issue type -> title label; also emitted (lower-kebab) as a DefectDojo tag
TYPE_LABEL = {"VULNERABILITY": "Vulnerability", "BUG": "Bug",
              "CODE_SMELL": "Code Smell", "SECURITY_HOTSPOT": "Hotspot"}

# SonarQube token authenticates as HTTP basic user with an empty password.
AUTH = "Basic " + base64.b64encode(f"{TOKEN}:".encode()).decode()


def api(path, **params):
    if ORG:
        params.setdefault("organization", ORG)
    if BRANCH:
        params.setdefault("branch", BRANCH)
    if PR:
        params.setdefault("pullRequest", PR)
    url = f"{BASE}/api/{path}?" + urllib.parse.urlencode(
        {k: v for k, v in params.items() if v not in (None, "")})
    req = urllib.request.Request(url, headers={"Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


# Sonar search endpoints refuse to page past 10,000 results, and facets list at
# most 100 values.
SEARCH_LIMIT = 10000
FACET_LIMIT = 100


def total_of(data):
    return data.get("paging", {}).get("total", data.get("total", 0))


def paged(path, list_key, **params):
    page, size = 1, 500
    while True:
        data = api(path, p=page, ps=size, **params)
        items = data.get(list_key, [])
        yield from items
        if page * size >= min(total_of(data), SEARCH_LIMIT) or not items:
            break
        page += 1


def facet_values(facet, **params):
    data = api("issues/search", ps=1, facets=facet, **params)
    values = next((f["values"] for f in data.get("facets", [])
                   if f["property"] == facet), [])
    return [v["val"] for v in values if v["count"]]


# Single-valued issue attributes, coarsest first. Splitting on one of them
# yields disjoint slices that together cover the parent query.
SPLIT_FACETS = ("severities", "types", "cleanCodeAttributeCategories", "scopes", "rules")


def split(params):
    """Partition an oversized issue query into disjoint narrower ones."""
    for facet in SPLIT_FACETS:
        if facet in params:
            continue
        values = facet_values(facet, **params)
        if len(values) < FACET_LIMIT:  # a truncated facet would drop issues
            return [{**params, facet: v} for v in values]
    return []


def issues(**params):
    total = total_of(api("issues/search", p=1, ps=1, **params))
    if not total:
        return
    subs = split(params) if total > SEARCH_LIMIT else []
    if not subs:
        if total > SEARCH_LIMIT:
            print(f"sonar-export: WARNING {total} issues in slice {params}, "
                  f"only the first {SEARCH_LIMIT} are exported", file=sys.stderr)
        yield from paged("issues/search", "issues", **params)
        return
    for sub in subs:
        yield from issues(**sub)


def slug(text):
    # "Code Smell" / "CODE_SMELL" -> "code-smell"
    return text.lower().replace("_", "-").replace(" ", "-")


def strip_component(component):
    # "projectKey:path/to/file.cs" -> "path/to/file.cs"
    return component.split(":", 1)[1] if ":" in component else component


def main():
    findings = []

    expected = total_of(api("issues/search", p=1, ps=1,
                            componentKeys=PROJECT, resolved="false"))
    seen = set()
    for i in issues(componentKeys=PROJECT, resolved="false"):
        if i.get("key") in seen:
            continue
        seen.add(i.get("key"))
        rng = i.get("textRange", {})
        rule = i.get("rule", "")
        kind = i.get("type", "")
        label = TYPE_LABEL.get(kind, kind.replace("_", " ").title())
        # MQR-mode impacts, e.g. MAINTAINABILITY:LOW, RELIABILITY:HIGH
        impacts = i.get("impacts", [])
        findings.append({
            "title": f"[Sonar {label}] {rule}: {i.get('message', '')}"[:511],
            "description": (
                f"{i.get('message', '')}\n\n"
                f"Rule: {rule}\nType: {kind}\n"
                f"Effort: {i.get('effort', i.get('debt', 'n/a'))}"),
            "severity": SEV.get(i.get("severity", "INFO"), "Info"),
            "severity_justification": "Sonar severity: {}{}".format(
                i.get("severity", ""),
                "".join(f"\n{m['softwareQuality'].title()} impact: {m['severity']}"
                        for m in impacts)),
            "tags": ["sonar", slug(label)] + sorted(
                {slug(m["softwareQuality"]) for m in impacts}),
            "file_path": strip_component(i.get("component", "")),
            "line": i.get("line") or rng.get("startLine"),
            "vuln_id_from_tool": rule,
            "unique_id_from_tool": i.get("key"),
            "references": f"{BASE}/project/issues?id={PROJECT}&open={i.get('key')}",
            "static_finding": True,
            "dynamic_finding": False,
        })
    if len(seen) != expected:
        print(f"sonar-export: WARNING exported {len(seen)} of {expected} open issues",
              file=sys.stderr)

    for h in paged("hotspots/search", "hotspots", projectKey=PROJECT):
        rng = h.get("textRange", {})
        findings.append({
            "title": f"[Sonar Hotspot] {h.get('message', '')}"[:511],
            "description": (
                f"{h.get('message', '')}\n\n"
                f"Security category: {h.get('securityCategory', '')}\n"
                f"Vulnerability probability: {h.get('vulnerabilityProbability', '')}"),
            "severity": HOTSPOT_SEV.get(h.get("vulnerabilityProbability", "LOW"), "Info"),
            "tags": ["sonar", "security-hotspot", "security"],
            "file_path": strip_component(h.get("component", "")),
            "line": h.get("line") or rng.get("startLine"),
            "unique_id_from_tool": h.get("key"),
            "references": f"{BASE}/security_hotspots?id={PROJECT}&hotspots={h.get('key')}",
            "static_finding": True,
            "dynamic_finding": False,
        })

    with open(OUT, "w") as f:
        json.dump({"findings": findings}, f, indent=2)

    scope = f"PR #{PR}" if PR else (f"branch {BRANCH}" if BRANCH else "main branch")
    print(f"sonar-export: {len(findings)} findings from {PROJECT} ({scope}) -> {OUT}")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        print(f"sonar-export: HTTP {e.code} {e.reason}: {e.read().decode()[:300]}",
              file=sys.stderr)
        sys.exit(1)
