#!/usr/bin/env bash
# security-report.sh <outdir>
#
# Scans the committed tree (git archive HEAD, so untracked files never count)
# and the full git history, then writes, for people and for the release:
#   sbom.cdx.json                       CycloneDX SBOM of the dependency tree
#   trivy-sbom.json/.txt                vulnerabilities in that SBOM
#   trivy-secret.json/.txt              secrets in the tree
#   trivy-misconfig.json/.txt           Dockerfile/IaC/workflow misconfigurations (advisory)
#   gitleaks.json                       secrets in every commit
#   trufflehog.json                     verified or unverifiable credentials in every commit
#   codeql-<language>.sarif             CodeQL default code-scanning suite
#   counts.md                           the tables that go into the release notes
# Exits 1 on any CRITICAL/HIGH vulnerability with a fix, any secret, a verified
# credential, or an error-level CodeQL result. Unfixed vulns and misconfigs never block.
#
# Env: CODEQL_LANGUAGES  JSON array, e.g. '["go","actions"]' (default '["actions"]')
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)
langs=$(jq -r '.[]' <<<"${CODEQL_LANGUAGES:-[\"actions\"]}")
tree=$(mktemp -d)
git archive HEAD | tar -x -C "$tree"

trivy fs --quiet --format cyclonedx --output "$out/sbom.cdx.json" "$tree"
trivy sbom --quiet --format json --output "$out/trivy-sbom.json" "$out/sbom.cdx.json"
trivy fs --quiet --scanners secret --format json --output "$out/trivy-secret.json" "$tree"
trivy fs --quiet --scanners misconfig --format json --output "$out/trivy-misconfig.json" "$tree"
for r in trivy-sbom trivy-secret trivy-misconfig; do
  trivy convert --quiet --format table --output "$out/$r.txt" "$out/$r.json"
  [ -s "$out/$r.txt" ] || echo "No findings." > "$out/$r.txt"   # GitHub refuses empty assets
done

gl=(git . --redact --no-banner --log-level warn --report-format json --exit-code 0
    --report-path "$out/gitleaks.json" --log-opts=--all)
[ -f .gitleaks.toml ] && gl+=(--config .gitleaks.toml)
[ -f gitleaks-baseline.json ] && gl+=(--baseline-path gitleaks-baseline.json)
gitleaks "${gl[@]}"

trufflehog git "file://$PWD" --results=verified,unknown --json --no-update --log-level=-1 > "$out/trufflehog.json"

for lang in $langs; do
  mode=none; [ "$lang" = go ] && mode=autobuild
  db=$(mktemp -d)
  codeql database create "$db/db" --language="$lang" --build-mode="$mode" --source-root=. --quiet
  codeql database analyze "$db/db" --format=sarif-latest --output="$out/codeql-$lang.sarif" \
    --sarif-category="$lang" --quiet
done

rc=0
{
  echo "Commit \`$(git rev-parse --short=8 HEAD)\` · trivy $(trivy --version | awk 'NR==1{print $2}'), DB $(trivy version --format json | jq -r '.VulnerabilityDB.UpdatedAt[:10]') · gitleaks $(gitleaks version) · trufflehog $(trufflehog --version 2>&1 | awk '{print $2}') · CodeQL $(codeql version --format=terse) · full history, $(git rev-list --count HEAD) commits"
  echo
  python3 "$here/counts.py" "$out" || rc=$?
} > "$out/counts.md"
cat "$out/counts.md"
exit "$rc"
