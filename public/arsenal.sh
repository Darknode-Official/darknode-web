#!/usr/bin/env bash
# ============================================================
#  Sentinel Arsenal — turn a Debian/Ubuntu/Kali box into a full
#  hacking workstation (the practical "custom hacking Linux" layer:
#  the combined Kali + BlackArch-style toolset, installed on top of
#  your existing OS). Idempotent — skips anything already present.
#
#  Usage:
#    ./sentinel-arsenal.sh              # install everything
#    ./sentinel-arsenal.sh recon web    # only those categories
#    ./sentinel-arsenal.sh --list       # show categories
#
#  Use only on systems you own or are authorized to test.
# ============================================================
set -uo pipefail

C=$'\e[36m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; Z=$'\e[0m'
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# category -> apt packages
declare -A APT=(
  [recon]="nmap masscan dnsutils whois dnsrecon amass theharvester enum4linux netdiscover arp-scan"
  [web]="nikto gobuster ffuf dirb wfuzz sqlmap whatweb wafw00f wpscan skipfish"
  [passwords]="hydra john hashcat medusa hashid crunch cewl ncrack"
  [exploit]="metasploit-framework exploitdb set"
  [wireless]="aircrack-ng reaver wifite kismet hcxtools hcxdumptool"
  [forensics]="binwalk foremost testdisk sleuthkit steghide exiftool bulk-extractor autopsy"
  [reversing]="gdb radare2 ltrace strace ghidra apktool"
  [network]="wireshark tcpdump tshark netcat-openbsd socat proxychains4 tor mitmproxy"
  [passwordstore]="seclists wordlists"
)
# category -> pipx packages
declare -A PIPX=(
  [recon]="dnstwist"
  [web]="dirsearch arjun"
  [exploit]="pacu"
  [cloud]="prowler scoutsuite"
)
# category -> "go install" specs
declare -A GO=(
  [recon]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest github.com/projectdiscovery/httpx/cmd/httpx@latest github.com/owasp-amass/amass/v4/...@master"
  [web]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest github.com/ffuf/ffuf/v2@latest github.com/OJ/gobuster/v3@latest"
)
ORDER=(recon web passwords exploit wireless forensics reversing network cloud passwordstore)

[ "${1:-}" = "--list" ] && { echo "categories: ${ORDER[*]}"; exit 0; }
WANT=("$@"); [ ${#WANT[@]} -eq 0 ] && WANT=("${ORDER[@]}")

echo "${B}${C}>_ Sentinel Arsenal${Z} — installing the hacking toolset"
echo "${Y}categories:${Z} ${WANT[*]}"; echo

have(){ command -v "$1" >/dev/null 2>&1; }
if ! have pipx; then $SUDO apt-get install -y pipx >/dev/null 2>&1 || true; fi

$SUDO apt-get update -y >/dev/null 2>&1 || echo "${Y}apt update skipped${Z}"

for cat in "${WANT[@]}"; do
  echo "${B}${C}== ${cat} ==${Z}"
  for pkg in ${APT[$cat]:-}; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then echo "  ${G}ok${Z} $pkg"; else
      echo "  ${Y}installing${Z} $pkg"; $SUDO apt-get install -y "$pkg" >/dev/null 2>&1 && echo "  ${G}done${Z} $pkg" || echo "  ${R}skip${Z} $pkg (not in this repo)"; fi
  done
  for pp in ${PIPX[$cat]:-}; do
    if pipx list 2>/dev/null | grep -qi "$pp"; then echo "  ${G}ok${Z} $pp (pipx)"; else
      echo "  ${Y}installing${Z} $pp (pipx)"; pipx install "$pp" >/dev/null 2>&1 && echo "  ${G}done${Z} $pp" || echo "  ${R}skip${Z} $pp"; fi
  done
  if have go; then for gs in ${GO[$cat]:-}; do
      bin="${gs##*/}"; bin="${bin%%@*}"
      if have "$bin"; then echo "  ${G}ok${Z} $bin (go)"; else echo "  ${Y}installing${Z} $bin (go)"; go install "$gs" >/dev/null 2>&1 && echo "  ${G}done${Z} $bin" || echo "  ${R}skip${Z} $bin"; fi
    done; fi
done

echo; echo "${B}${G}Arsenal ready.${Z} Go tools are in ~/go/bin, pipx tools in ~/.local/bin — ensure both are on your PATH."
echo "${Y}Tip:${Z} for a true bootable distro, use Kali (kali.org) or BlackArch (blackarch.org) directly; this script gives you their toolset on your current OS."
