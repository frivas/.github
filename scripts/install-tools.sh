#!/usr/bin/env bash
# Installs the pinned scanners from their GitHub releases, each checked against
# the SHA-256 the project publishes, into $1 (default $RUNNER_TEMP/tools).
# No third-party action ever runs with the caller's token.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tools.env
. "$here/tools.env"
dest=${1:-$RUNNER_TEMP/tools}
mkdir -p "$dest"; cd "$dest"

fetch() { # url-base file checksums-file
  curl -fsSLO "$1/$2"
  curl -fsSL "$1/$3" | grep " $2\$" | sha256sum -c -
}
fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION" \
  "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt"
tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy
fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION" \
  "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt"
tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks
fetch "https://github.com/trufflesecurity/trufflehog/releases/download/v$TRUFFLEHOG_VERSION" \
  "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" "trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt"
tar -xzf "trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" trufflehog
fetch "https://github.com/github/codeql-action/releases/download/codeql-bundle-v$CODEQL_VERSION" \
  codeql-bundle-linux64.tar.zst codeql-bundle-linux64.tar.zst.checksum.txt
tar --zstd -xf codeql-bundle-linux64.tar.zst
rm -f ./*.tar.gz ./*.tar.zst
[ -n "${GITHUB_PATH:-}" ] && { echo "$dest" >> "$GITHUB_PATH"; echo "$dest/codeql" >> "$GITHUB_PATH"; }
"$dest/trivy" --version | head -1
