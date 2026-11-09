"""counts.py <report-dir>: print the release-notes tables for security-report.sh's output.

Exits 1 when the report must block: a CRITICAL/HIGH vulnerability with a fix,
any secret (gitleaks, Trivy) or verified credential (trufflehog), or an
error-level CodeQL result. Stdlib only.
"""
import json
import pathlib
import sys

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def load(path):
    return json.loads(path.read_text() or "null") if path.exists() else None


def row(name, kind, items):
    counts = {s: 0 for s in SEV}
    for it in items:
        counts[it.get("Severity", "UNKNOWN") if it.get("Severity") in SEV else "UNKNOWN"] += 1
    return f"| {name} | {kind} | " + " | ".join(str(counts[s]) for s in SEV) + " |", counts


def main(d):
    d = pathlib.Path(d)
    lines = ["| Report | Kind | " + " | ".join(SEV) + " |", "|---|---|" + "---|" * len(SEV)]
    blocked = []

    sbom = load(d / "trivy-sbom.json") or {}
    vulns = [v for r in sbom.get("Results") or [] for v in r.get("Vulnerabilities") or []]
    lines.append(row("trivy-sbom", "all vulnerabilities", vulns)[0])
    text, fixable = row("trivy-sbom", "with a fix available", [v for v in vulns if v.get("FixedVersion")])
    lines.append(text)
    if fixable["CRITICAL"] or fixable["HIGH"]:
        blocked.append(f"{fixable['CRITICAL'] + fixable['HIGH']} CRITICAL or HIGH vulnerabilities with a fix available.")

    mis = load(d / "trivy-misconfig.json") or {}
    failed = [m for r in mis.get("Results") or [] for m in r.get("Misconfigurations") or [] if m.get("Status") == "FAIL"]
    lines.append(row("trivy-misconfig", "failed checks", failed)[0])

    trivy_secrets = [s for r in (load(d / "trivy-secret.json") or {}).get("Results") or [] for s in r.get("Secrets") or []]
    gitleaks = load(d / "gitleaks.json") or []
    hog = [json.loads(l) for l in (d / "trufflehog.json").read_text().splitlines() if l.strip()] if (d / "trufflehog.json").exists() else []
    verified = [h for h in hog if h.get("Verified")]
    lines += ["", "| Secret scan | Findings |", "|---|---|",
              f"| gitleaks, every commit | {len(gitleaks)} |",
              f"| trivy-secret, committed tree | {len(trivy_secrets)} |",
              f"| trufflehog, verified live | {len(verified)} |",
              f"| trufflehog, could not verify (advisory) | {len(hog) - len(verified)} |"]
    if gitleaks or trivy_secrets:
        blocked.append(f"{len(gitleaks) + len(trivy_secrets)} secrets found.")
    if verified:
        blocked.append(f"INCIDENT: {len(verified)} verified live credentials. Rotate them.")

    sarifs = sorted(d.glob("codeql-*.sarif"))
    if sarifs:
        lines += ["", "| CodeQL | error | warning | note |", "|---|---|---|---|"]
        errors = 0
        for f in sarifs:
            res = [r for run in json.loads(f.read_text())["runs"] for r in run.get("results", [])]
            c = {k: sum(1 for r in res if r.get("level", "warning") == k) for k in ("error", "warning", "note")}
            errors += c["error"]
            lines.append(f"| {f.stem.removeprefix('codeql-')} | {c['error']} | {c['warning']} | {c['note']} |")
        if errors:
            blocked.append(f"{errors} error-level CodeQL results.")

    lines.append("")
    if blocked:
        lines += [f"**Blocked:** {b}" for b in blocked]
    else:
        lines += ["No CRITICAL or HIGH vulnerability with a fix available.", "No secret found.", "No error-level CodeQL result."]
    print("\n".join(lines))
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
