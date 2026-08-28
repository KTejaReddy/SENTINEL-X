#!/usr/bin/env bash
# Provision the real security tool binaries used by the SENTINEL X adapters.
# The platform degrades gracefully (NOT_AVAILABLE health) when a tool is
# missing, but real scanning requires the tools.
#
# Usage:  ./scripts/provision-tools.sh [--with-zap]
# Target: Linux (apt) / macOS (brew) / Windows (winget, via Git Bash).
set -uo pipefail
cd "$(dirname "$0")/.."

TOOLS=(nmap nuclei semgrep gitleaks trivy)
OPT_INSTALL_ZAP=0
[ "${1:-}" = "--with-zap" ] && OPT_INSTALL_ZAP=1

have() { command -v "$1" >/dev/null 2>&1; }

install_apt() {
  sudo apt-get update -qq
  sudo apt-get install -y -qq nmap
  curl -fsSL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | bash
  sudo apt-get install -y -qq semgrep gitleaks
  sudo apt-get install -y -qq trivy || {
    curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
  }
  [ "$OPT_INSTALL_ZAP" = "1" ] && {
    echo "ZAP requires a GUI/desktop install — see https://www.zaproxy.org/download/"
    return 0
  }
}

install_brew() {
  brew install nmap gitleaks trivy
  brew install --cask zap
  brew install semgrep
  curl -fsSL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | bash
}

install_winget() {
  winget install -e --id Insecure.Nmap --accept-source-agreements --accept-package-agreements || true
  winget install -e --id ProjectDiscovery.Nuclei --accept-source-agreements --accept-package-agreements || true
  winget install -e --id Semgrep.Semgrep --accept-source-agreements --accept-package-agreements || true
  winget install -e --id zricethezav.gitleaks --accept-source-agreements --accept-package-agreements || true
  winget install -e --id AquaSecurity.Trivy --accept-source-agreements --accept-package-agreements || true
}

echo "SENTINEL X — security tool provisioning"
if have apt-get; then install_apt
elif have brew; then install_brew
elif have winget; then install_winget
else echo "No supported package manager found (apt/brew/winget). Install tools manually and set *_PATH env vars."; fi

echo "--- Tool health ---"
for t in "${TOOLS[@]}"; do
  if have "$t"; then echo "$t: READY ($(command -v "$t"))"; else echo "$t: NOT_AVAILABLE"; fi
done
echo "Restart the API and refresh /api/tools to see the new health status."
