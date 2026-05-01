#!/usr/bin/env bash
# recon.sh — domain recon pipeline
# Usage: ./recon.sh <domain> [output_dir]
# Example: ./recon.sh context7.com ./results

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
err()     { echo -e "${RED}[-]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Args ──────────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <domain> [output_dir]"
    echo "Example: $0 context7.com ./results"
    exit 1
fi

DOMAIN=$(echo "$1" | tr '[:upper:]' '[:lower:]')   # lowercase (macOS zsh compat)
OUTDIR="${2:-./recon-${DOMAIN}}"
mkdir -p "$OUTDIR"

# ── Dependency check ──────────────────────────────────────────────────────────
section "Checking dependencies"
MISSING=()
for tool in subfinder dnsx curl jq dig; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool found"
    else
        err "$tool NOT found"
        MISSING+=("$tool")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Installing missing tools via brew: ${MISSING[*]}"
    brew install "${MISSING[@]}" 2>/dev/null || {
        err "brew install failed. Install manually: ${MISSING[*]}"
        exit 1
    }
fi

# ── Helper: append unique lines ───────────────────────────────────────────────
append_unique() {
    local src="$1" dst="$2"
    [[ -s "$src" ]] && sort -u "$src" "$dst" 2>/dev/null > "${dst}.tmp" && mv "${dst}.tmp" "$dst" || true
}

RAW="$OUTDIR/all_raw.txt"
touch "$RAW"

# ── 1. subfinder ──────────────────────────────────────────────────────────────
section "subfinder (passive)"
info "Running subfinder on $DOMAIN ..."
TMP_SF=$(mktemp)
if subfinder -d "$DOMAIN" -silent -o "$TMP_SF" 2>/dev/null; then
    COUNT=$(wc -l < "$TMP_SF")
    ok "subfinder: $COUNT domains"
    cp "$TMP_SF" "$OUTDIR/subfinder.txt"
    append_unique "$TMP_SF" "$RAW"
else
    warn "subfinder returned no results"
fi
rm -f "$TMP_SF"

# ── 2. crt.sh ─────────────────────────────────────────────────────────────────
section "crt.sh (Certificate Transparency)"
info "Querying crt.sh for %.$DOMAIN ..."
TMP_CRT=$(mktemp)
RESP=$(curl -s --max-time 15 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null || true)
if echo "$RESP" | jq -e '.[0]' &>/dev/null; then
    echo "$RESP" \
        | jq -r '.[].name_value' 2>/dev/null \
        | tr ',' '\n' \
        | sed 's/^\*\.//' \
        | grep -v '^\*' \
        | grep -F "$DOMAIN" \
        | sort -u > "$TMP_CRT"
    COUNT=$(wc -l < "$TMP_CRT")
    ok "crt.sh: $COUNT domains"
    cp "$TMP_CRT" "$OUTDIR/crtsh.txt"
    append_unique "$TMP_CRT" "$RAW"
else
    warn "crt.sh unavailable or returned no JSON (may be down)"
    touch "$OUTDIR/crtsh.txt"
fi
rm -f "$TMP_CRT"

# ── 3. Certspotter ────────────────────────────────────────────────────────────
section "Certspotter API"
info "Querying certspotter.com for $DOMAIN ..."
TMP_CS=$(mktemp)
curl -s --max-time 15 \
    "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" \
    | jq -r '.[].dns_names[]' 2>/dev/null \
    | grep -F "$DOMAIN" \
    | sed 's/^\*\.//' \
    | grep -v '^\*' \
    | sort -u > "$TMP_CS" || true
COUNT=$(wc -l < "$TMP_CS")
ok "certspotter: $COUNT domains"
cp "$TMP_CS" "$OUTDIR/certspotter.txt"
append_unique "$TMP_CS" "$RAW"
rm -f "$TMP_CS"

# ── 4. HackerTarget ───────────────────────────────────────────────────────────
section "HackerTarget API"
info "Querying hackertarget.com for $DOMAIN ..."
TMP_HT=$(mktemp)
curl -s --max-time 15 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" \
    | cut -d',' -f1 \
    | grep -F "$DOMAIN" \
    | sort -u > "$TMP_HT" || true
COUNT=$(wc -l < "$TMP_HT")
ok "hackertarget: $COUNT domains"
cp "$TMP_HT" "$OUTDIR/hackertarget.txt"
append_unique "$TMP_HT" "$RAW"
rm -f "$TMP_HT"

# ── 5. URLScan.io ─────────────────────────────────────────────────────────────
section "URLScan.io"
info "Querying urlscan.io for $DOMAIN ..."
TMP_US=$(mktemp)
curl -s --max-time 15 \
    "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=100" \
    | jq -r '.results[].task.domain' 2>/dev/null \
    | grep -F "$DOMAIN" \
    | sort -u > "$TMP_US" || true
COUNT=$(wc -l < "$TMP_US")
ok "urlscan: $COUNT domains"
cp "$TMP_US" "$OUTDIR/urlscan.txt"
append_unique "$TMP_US" "$RAW"
rm -f "$TMP_US"

# ── 6. Wayback Machine ────────────────────────────────────────────────────────
section "Wayback Machine (web.archive.org)"
info "Querying Wayback CDX API for *.$DOMAIN ..."
TMP_WB=$(mktemp)
curl -s --max-time 20 \
    "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=5000" \
    | grep -oE "[a-z0-9._-]+\.${DOMAIN//./\\.}" \
    | sort -u > "$TMP_WB" || true
COUNT=$(wc -l < "$TMP_WB")
ok "wayback: $COUNT domains"
cp "$TMP_WB" "$OUTDIR/wayback.txt"
append_unique "$TMP_WB" "$RAW"
rm -f "$TMP_WB"

# ── 7. AlienVault OTX ────────────────────────────────────────────────────────
section "AlienVault OTX"
info "Querying AlienVault OTX for $DOMAIN ..."
TMP_AV=$(mktemp)
curl -s --max-time 15 \
    "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" \
    | jq -r '.passive_dns[].hostname' 2>/dev/null \
    | grep -F "$DOMAIN" \
    | sort -u > "$TMP_AV" || true
COUNT=$(wc -l < "$TMP_AV")
ok "alienvault: $COUNT domains"
cp "$TMP_AV" "$OUTDIR/alienvault.txt"
append_unique "$TMP_AV" "$RAW"
rm -f "$TMP_AV"

# ── 8. DNS records (MX, NS, TXT — дополнительные зацепки) ────────────────────
section "DNS records"
info "Checking DNS records for $DOMAIN ..."
TMP_DNS=$(mktemp)
{
    dig +short "$DOMAIN" A
    dig +short "$DOMAIN" MX | awk '{print $2}' | sed 's/\.$//'
    dig +short "$DOMAIN" NS | sed 's/\.$//'
    dig +short "$DOMAIN" TXT
} 2>/dev/null | grep -F "$DOMAIN" | sort -u > "$TMP_DNS" || true
if [[ -s "$TMP_DNS" ]]; then
    ok "dns records found additional entries"
    append_unique "$TMP_DNS" "$RAW"
fi
rm -f "$TMP_DNS"

# ── 9. Deduplicate raw list ───────────────────────────────────────────────────
section "Deduplication"
sort -u "$RAW" -o "$RAW"
TOTAL=$(wc -l < "$RAW")
ok "Total unique candidates: $TOTAL"

# ── 10. DNS validation via dnsx ───────────────────────────────────────────────
section "DNS validation (dnsx)"
info "Validating $TOTAL candidates ..."

dnsx -l "$RAW" -silent -resp 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | sort -u \
    > "$OUTDIR/all_domains_with_ip.txt"

dnsx -l "$RAW" -silent 2>/dev/null \
    | sort -u \
    > "$OUTDIR/all_domains.txt"

ALIVE=$(wc -l < "$OUTDIR/all_domains.txt")
DEAD=$((TOTAL - ALIVE))

ok "Alive: $ALIVE  |  Dead (no DNS): $DEAD"

# ── 11. Summary ───────────────────────────────────────────────────────────────
section "Summary"
echo ""
echo -e "${BOLD}Target:${RESET}     $DOMAIN"
echo -e "${BOLD}Output:${RESET}     $OUTDIR/"
echo ""
echo -e "${BOLD}Files:${RESET}"
echo "  all_domains.txt          — $ALIVE live domains (use this in Podkop)"
echo "  all_domains_with_ip.txt  — live domains with resolved IPs"
echo "  all_raw.txt              — $TOTAL all candidates before validation"
echo "  subfinder.txt            — subfinder raw output"
echo "  crtsh.txt                — crt.sh raw output"
echo "  certspotter.txt          — certspotter raw output"
echo "  hackertarget.txt         — hackertarget raw output"
echo "  urlscan.txt              — urlscan raw output"
echo "  wayback.txt              — wayback machine raw output"
echo "  alienvault.txt           — alienvault otx raw output"
echo ""
echo -e "${BOLD}Live domains:${RESET}"
cat "$OUTDIR/all_domains.txt"
echo ""
ok "Done. Use ${BOLD}${OUTDIR}/all_domains.txt${RESET} for Podkop."
