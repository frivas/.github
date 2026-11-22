# GitHub defaults

Shared issue forms, pull request guidance, and contribution notes for my public repositories.

The goal is simple: give changes enough context to review, connect work to the problem it solves, and keep documentation current.


## Shared workflows

Two reusable workflows every repository calls, so the security gate and the release shape are the same everywhere. Pin callers to the major tag (`@v2`).

- **`security.yml`** scans the committed tree and the full history, then blocks on any CRITICAL/HIGH vulnerability with a fix, any secret, a verified credential, or an error-level CodeQL result. It runs Trivy (CycloneDX SBOM, vulnerabilities, secrets, misconfigurations), gitleaks, trufflehog and CodeQL, each installed from its own release and checked against its published SHA-256. The tables go to the job summary, and every file is uploaded as the `security-report` artifact.
- **`release.yml`** runs that gate on a tag, then publishes the GitHub release. Its notes have five sections: What this is, Gate, Security, SBOM and Merged pull requests. Every report file is attached, including `sbom.cdx.json`.

Copy the callers from [`templates/`](templates): `security.yml` (PRs, `main`, weekly), `release.yml` (on a `v*` tag) and `dependabot.yml`.

### Keeping Actions minutes low

- Superseded runs cancel themselves (`concurrency` with `cancel-in-progress`), and every job has a timeout.
- The Trivy vulnerability database is cached, so it downloads once per repository per day.
- Public repositories use no minutes on standard runners. In private ones, run the gate on pull requests and weekly, not again on the merge to `main`, and keep macOS runners (billed at 10×) for pull requests only.

Scanner versions live in [`scripts/tools.env`](scripts/tools.env).
