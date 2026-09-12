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


def paged(path, list_key, **params):
    page, size = 1, 500
    while True:
        data = api(path, p=page, ps=size, **params)
        items = data.get(list_key, [])
        yield from items
        got = data.get("paging", {}).get("total", data.get("total", 0))
        if page * size >= got or not items:
            break
        page += 1


def strip_component(component):
    # "projectKey:path/to/file.cs" -> "path/to/file.cs"
    return component.split(":", 1)[1] if ":" in component else component


def main():
    findings = []

    for i in paged("issues/search", "issues",
                   componentKeys=PROJECT, resolved="false"):
        rng = i.get("textRange", {})
        rule = i.get("rule", "")
        findings.append({
            "title": f"[Sonar] {rule}: {i.get('message', '')}"[:511],
            "description": (
                f"{i.get('message', '')}\n\n"
                f"Rule: {rule}\nType: {i.get('type', '')}\n"
                f"Effort: {i.get('effort', i.get('debt', 'n/a'))}"),
            "severity": SEV.get(i.get("severity", "INFO"), "Info"),
            "file_path": strip_component(i.get("component", "")),
            "line": i.get("line") or rng.get("startLine"),
            "vuln_id_from_tool": rule,
            "unique_id_from_tool": i.get("key"),
            "references": f"{BASE}/project/issues?id={PROJECT}&open={i.get('key')}",
            "static_finding": True,
            "dynamic_finding": False,
        })

    for h in paged("hotspots/search", "hotspots", projectKey=PROJECT):
        rng = h.get("textRange", {})
        findings.append({
            "title": f"[Sonar Hotspot] {h.get('message', '')}"[:511],
            "description": (
                f"{h.get('message', '')}\n\n"
                f"Security category: {h.get('securityCategory', '')}\n"
                f"Vulnerability probability: {h.get('vulnerabilityProbability', '')}"),
            "severity": HOTSPOT_SEV.get(h.get("vulnerabilityProbability", "LOW"), "Info"),
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
