#!/usr/bin/env bash
# recon.sh — domain recon pipeline
# Usage: ./recon.sh <domain> [output_dir] [--diff] [--force]
# Example: ./recon.sh context7.com ./results
# Example: ./recon.sh context7.com ./results --diff
#
# Exit codes: 0 = ok, 2 = new domains found (--diff), 3 = run refused
# (no candidates collected, or DNS validation collapsed — see RECON_MIN_RETAIN).

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
err()     { echo -e "${RED}[-]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── curl with retry/backoff ───────────────────────────────────────────────────
# curl_retry <max_time_seconds> <max_attempts> <url> <outfile> [header ...]
# Succeeds only on HTTP 2xx + non-empty body. Backoff doubles from 1s.
# A 4xx is never retried: it means auth is required (certspotter, OTX) or we
# are already being throttled, and neither changes within a run — retrying a
# 429 only deepens the throttle while burning the wall-clock budget.
curl_retry() {
    local max_time="$1" max_attempts="$2" url="$3" outfile="$4"
    shift 4
    local hdr_args=() h
    for h in "$@"; do hdr_args+=(-H "$h"); done
    local attempt delay=1 code
    for (( attempt = 1; attempt <= max_attempts; attempt++ )); do
        # No --compressed: certspotter's body is always cut off mid-stream, and
        # a truncated gzip stream decompresses to nothing at all, while a
        # truncated plain body still parses into usable partial results.
        code=$(curl -s --max-time "$max_time" \
                    "${hdr_args[@]+"${hdr_args[@]}"}" \
                    -o "$outfile" -w '%{http_code}' "$url" 2>/dev/null || echo "000")
        if [[ "$code" =~ ^2 ]] && [[ -s "$outfile" ]]; then
            return 0
        fi
        if [[ "$code" =~ ^4 ]]; then
            warn "  http $code — not retrying"
            return 1
        fi
        if [[ $attempt -lt $max_attempts ]]; then
            warn "  retry $attempt/$max_attempts (http $code) in ${delay}s ..."
            sleep "$delay"
            delay=$((delay * 2))
        fi
    done
    return 1
}

# ── Domain validation ─────────────────────────────────────────────────────────
validate_domain() {
    local d="$1"
    if [[ "$d" =~ [[:space:]] ]]; then
        err "Domain must not contain whitespace: $d"
        exit 1
    fi
    if [[ "$d" == *"/"* || "$d" == *":"* ]]; then
        err "Domain must not contain a scheme or path: $d"
        exit 1
    fi
    if [[ ! "$d" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]; then
        err "Invalid domain format: $d"
        exit 1
    fi
    if [[ ${#d} -gt 253 ]]; then
        err "Domain too long: $d"
        exit 1
    fi
}

# ── Helper: append unique lines ───────────────────────────────────────────────
append_unique() {
    local src="$1" dst="$2"
    [[ -s "$src" ]] && sort -u "$src" "$dst" 2>/dev/null > "${dst}.tmp" && mv "${dst}.tmp" "$dst" || true
}

# ── Args ──────────────────────────────────────────────────────────────────────
DIFF_MODE=false
FORCE=false
ARGS=()
for arg in "$@"; do
    if [[ "$arg" == "--diff" ]]; then
        DIFF_MODE=true
    elif [[ "$arg" == "--force" ]]; then
        FORCE=true
    else
        ARGS+=("$arg")
    fi
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <domain> [output_dir] [--diff] [--force]"
    echo "Example: $0 context7.com ./results --diff"
    exit 1
fi

DOMAIN=$(echo "$1" | tr '[:upper:]' '[:lower:]')   # lowercase (macOS zsh compat)
validate_domain "$DOMAIN"
OUTDIR="${2:-./recon-${DOMAIN}}"
mkdir -p "$OUTDIR"

# ── Dependency check ──────────────────────────────────────────────────────────
if [[ "${RECON_SKIP_DEPCHECK:-0}" != "1" ]]; then
    section "Checking dependencies"
    GO_TOOLS=(subfinder dnsx)
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
        detect_pkg_manager() {
            case "$(uname -s)" in
                Darwin) echo "brew" ;;
                Linux)
                    if command -v apt-get &>/dev/null; then echo "apt"
                    elif command -v pacman &>/dev/null; then echo "pacman"
                    elif command -v dnf &>/dev/null; then echo "dnf"
                    elif command -v brew &>/dev/null; then echo "brew"
                    else echo "none"
                    fi ;;
                *) echo "none" ;;
            esac
        }
        PM=$(detect_pkg_manager)
        MISSING_GO=(); MISSING_SYS=()
        for t in "${MISSING[@]}"; do
            if [[ " ${GO_TOOLS[*]} " == *" $t "* ]]; then
                MISSING_GO+=("$t")
            else
                MISSING_SYS+=("$t")
            fi
        done

        case "$PM" in
            brew)
                warn "Installing missing tools via brew: ${MISSING[*]}"
                brew install "${MISSING[@]}" 2>/dev/null || {
                    err "brew install failed. Install manually: ${MISSING[*]}"
                    exit 1
                }
                ;;
            apt|pacman|dnf)
                if [[ ${#MISSING_SYS[@]} -gt 0 ]]; then
                    warn "Installing via $PM: ${MISSING_SYS[*]}"
                    case "$PM" in
                        apt)    sudo apt-get update && sudo apt-get install -y jq curl dnsutils ;;
                        pacman) sudo pacman -Sy --noconfirm jq curl bind ;;
                        dnf)    sudo dnf install -y jq curl bind-utils ;;
                    esac
                fi
                if [[ ${#MISSING_GO[@]} -gt 0 ]]; then
                    err "No package for ${MISSING_GO[*]} on $PM. Install manually, e.g.:"
                    err "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
                    err "  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
                    err "  (requires Go, and \$GOPATH/bin or \$HOME/go/bin in PATH)"
                    exit 1
                fi
                ;;
            none)
                err "No supported package manager detected. Install manually: ${MISSING[*]}"
                exit 1
                ;;
        esac
    fi
fi

RAW="$OUTDIR/all_raw.txt"
: > "$RAW"   # truncate/create fresh so reruns don't accumulate stale candidates

# ── Sources (each writes its own $OUTDIR/<name>.txt, run in parallel below) ───

run_subfinder() {
    section "subfinder (passive)"
    info "Running subfinder on $DOMAIN ..."
    local tmp; tmp=$(mktemp)
    if subfinder -d "$DOMAIN" -silent -o "$tmp" 2>/dev/null; then
        ok "subfinder: $(wc -l < "$tmp") domains"
        cp "$tmp" "$OUTDIR/subfinder.txt"
    else
        warn "subfinder returned no results"
        touch "$OUTDIR/subfinder.txt"
    fi
    rm -f "$tmp"
}

run_crtsh() {
    section "crt.sh (Certificate Transparency)"
    info "Querying crt.sh for %.$DOMAIN ..."
    local tmp; tmp=$(mktemp)
    if curl_retry 12 2 "https://crt.sh/?q=%25.${DOMAIN}&output=json" "$tmp"; then
        if jq -e '.[0]' "$tmp" &>/dev/null; then
            jq -r '.[].name_value' "$tmp" 2>/dev/null \
                | tr ',' '\n' \
                | sed 's/^\*\.//' \
                | grep -v '^\*' \
                | grep -F "$DOMAIN" \
                | sort -u > "$OUTDIR/crtsh.txt" || true
            ok "crt.sh: $(wc -l < "$OUTDIR/crtsh.txt") domains"
        else
            warn "crt.sh returned no JSON results"
            touch "$OUTDIR/crtsh.txt"
        fi
    else
        warn "crt.sh unavailable (all retries failed)"
        touch "$OUTDIR/crtsh.txt"
    fi
    rm -f "$tmp"
}

run_certspotter() {
    section "Certspotter API"
    local tmp; tmp=$(mktemp)
    local hdr=()
    if [[ -n "${CERTSPOTTER_API_KEY:-}" ]]; then
        info "Querying certspotter.com for $DOMAIN (authenticated) ..."
        hdr=("Authorization: Bearer ${CERTSPOTTER_API_KEY}")
    else
        # Unauthenticated the endpoint trickles the body out and never finishes
        # (measured: 20 KB in 120 s, then a truncated-JSON parse error). One
        # bounded attempt; whatever arrives is still usable candidates.
        info "Querying certspotter.com for $DOMAIN (no CERTSPOTTER_API_KEY — partial results) ..."
    fi
    if curl_retry 20 1 "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" "$tmp" "${hdr[@]+"${hdr[@]}"}"; then
        jq -r '.[].dns_names[]' "$tmp" 2>/dev/null \
            | grep -F "$DOMAIN" \
            | sed 's/^\*\.//' \
            | grep -v '^\*' \
            | sort -u > "$OUTDIR/certspotter.txt" || true
        ok "certspotter: $(wc -l < "$OUTDIR/certspotter.txt") domains"
    else
        warn "certspotter: request failed"
        touch "$OUTDIR/certspotter.txt"
    fi
    rm -f "$tmp"
}

run_hackertarget() {
    section "HackerTarget API"
    info "Querying hackertarget.com for $DOMAIN ..."
    local tmp; tmp=$(mktemp)
    if curl_retry 15 3 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" "$tmp"; then
        cut -d',' -f1 "$tmp" \
            | grep -F "$DOMAIN" \
            | sort -u > "$OUTDIR/hackertarget.txt" || true
        ok "hackertarget: $(wc -l < "$OUTDIR/hackertarget.txt") domains"
    else
        warn "hackertarget: all retries failed"
        touch "$OUTDIR/hackertarget.txt"
    fi
    rm -f "$tmp"
}

run_urlscan() {
    section "URLScan.io"
    info "Querying urlscan.io for $DOMAIN ..."
    local tmp; tmp=$(mktemp)
    if curl_retry 15 3 "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=100" "$tmp"; then
        jq -r '.results[].task.domain' "$tmp" 2>/dev/null \
            | grep -F "$DOMAIN" \
            | sort -u > "$OUTDIR/urlscan.txt" || true
        ok "urlscan: $(wc -l < "$OUTDIR/urlscan.txt") domains"
    else
        warn "urlscan: all retries failed"
        touch "$OUTDIR/urlscan.txt"
    fi
    rm -f "$tmp"
}

run_wayback() {
    section "Wayback Machine (web.archive.org)"
    info "Querying Wayback CDX API for *.$DOMAIN ..."
    local tmp; tmp=$(mktemp)
    if curl_retry 20 2 "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=5000" "$tmp"; then
        grep -oE "[a-z0-9._-]+\.${DOMAIN//./\\.}" "$tmp" \
            | sort -u > "$OUTDIR/wayback.txt" || true
        ok "wayback: $(wc -l < "$OUTDIR/wayback.txt") domains"
    else
        warn "wayback: all retries failed"
        touch "$OUTDIR/wayback.txt"
    fi
    rm -f "$tmp"
}

run_alienvault() {
    section "AlienVault OTX"
    # Anonymous access to this endpoint now returns 429 unconditionally
    # ("Please authenticate"), so without a key it is pure wasted wall-clock.
    if [[ -z "${OTX_API_KEY:-}" ]]; then
        info "Skipping AlienVault OTX (set OTX_API_KEY to enable — anonymous access is refused)"
        touch "$OUTDIR/alienvault.txt"
        return 0
    fi
    info "Querying AlienVault OTX for $DOMAIN ..."
    local tmp; tmp=$(mktemp)
    if curl_retry 15 2 "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" "$tmp" "X-OTX-API-KEY: ${OTX_API_KEY}"; then
        jq -r '.passive_dns[].hostname' "$tmp" 2>/dev/null \
            | grep -F "$DOMAIN" \
            | sort -u > "$OUTDIR/alienvault.txt" || true
        ok "alienvault: $(wc -l < "$OUTDIR/alienvault.txt") domains"
    else
        warn "alienvault: all retries failed"
        touch "$OUTDIR/alienvault.txt"
    fi
    rm -f "$tmp"
}

run_rapiddns() {
    section "RapidDNS.io"
    info "Querying rapiddns.io for $DOMAIN ..."
    local tmp; tmp=$(mktemp)
    if curl_retry 20 3 "https://rapiddns.io/subdomain/${DOMAIN}?full=1" "$tmp"; then
        grep -oE "[a-zA-Z0-9._-]+\.${DOMAIN//./\\.}" "$tmp" \
            | sort -u > "$OUTDIR/rapiddns.txt" || true
        ok "rapiddns: $(wc -l < "$OUTDIR/rapiddns.txt") domains"
    else
        warn "rapiddns.io: all retries failed (or page format changed)"
        touch "$OUTDIR/rapiddns.txt"
    fi
    rm -f "$tmp"
}

run_dnsrecords() {
    section "DNS records"
    info "Checking DNS records for $DOMAIN ..."
    {
        dig +short "$DOMAIN" A
        dig +short "$DOMAIN" MX | awk '{print $2}' | sed 's/\.$//'
        dig +short "$DOMAIN" NS | sed 's/\.$//'
        dig +short "$DOMAIN" TXT
    } 2>/dev/null | grep -F "$DOMAIN" | sort -u > "$OUTDIR/.dnsrecords.candidates" || true
    if [[ -s "$OUTDIR/.dnsrecords.candidates" ]]; then
        ok "dns records found additional entries"
    else
        info "no additional DNS record entries"
    fi
}

# ── Run all sources in parallel, print their logs back in fixed order ────────
mkdir -p "$OUTDIR/.logs"
SOURCES=(subfinder crtsh certspotter hackertarget urlscan wayback alienvault rapiddns)

PIDS=()
for s in "${SOURCES[@]}"; do
    "run_${s}" > "$OUTDIR/.logs/${s}.log" 2>&1 &
    PIDS+=("$!")
done
run_dnsrecords > "$OUTDIR/.logs/dnsrecords.log" 2>&1 &
PIDS+=("$!")

info "Waiting for ${#PIDS[@]} background sources ..."
for pid in "${PIDS[@]}"; do
    wait "$pid" || warn "a background source (pid $pid) exited non-zero"
done

for s in "${SOURCES[@]}"; do
    cat "$OUTDIR/.logs/${s}.log"
done
cat "$OUTDIR/.logs/dnsrecords.log"

for s in "${SOURCES[@]}"; do
    [[ -s "$OUTDIR/${s}.txt" ]] && append_unique "$OUTDIR/${s}.txt" "$RAW"
done
[[ -s "$OUTDIR/.dnsrecords.candidates" ]] && append_unique "$OUTDIR/.dnsrecords.candidates" "$RAW"
rm -rf "$OUTDIR/.logs" "$OUTDIR/.dnsrecords.candidates"

# ── Deduplicate raw list ───────────────────────────────────────────────────────
section "Deduplication"
sort -u "$RAW" -o "$RAW"
TOTAL=$(wc -l < "$RAW" | tr -d ' ')
ok "Total unique candidates: $TOTAL"

# ── DNS validation via dnsx ────────────────────────────────────────────────────
section "DNS validation (dnsx)"

# Every source failing leaves an empty candidate pool. Validating it would
# "succeed" with zero results and wipe the deliverable, so stop here instead.
if [[ "$TOTAL" -eq 0 ]]; then
    err "No candidates collected — every source failed. Existing results left untouched."
    exit 3
fi

DNSX_THREADS="${RECON_DNSX_THREADS:-100}"
DNSX_RETRY="${RECON_DNSX_RETRY:-3}"
DNSX_ARGS=(-l "$RAW" -silent -resp -t "$DNSX_THREADS" -retry "$DNSX_RETRY")
[[ -n "${RECON_DNSX_RESOLVERS:-}" ]] && DNSX_ARGS+=(-r "$RECON_DNSX_RESOLVERS")
[[ -n "${RECON_DNSX_RATELIMIT:-}" ]] && DNSX_ARGS+=(-rl "$RECON_DNSX_RATELIMIT")

info "Validating $TOTAL candidates (threads=$DNSX_THREADS, retry=$DNSX_RETRY) ..."

# One pass, not two. all_domains.txt is derived from the -resp output rather
# than from a second dnsx run, so the two files cannot disagree, and the
# resolver sees half the query volume — the doubled volume is what got us
# throttled into producing an empty list before.
TMP_IPS="$OUTDIR/.all_domains_with_ip.new"
TMP_DOMAINS="$OUTDIR/.all_domains.new"
dnsx "${DNSX_ARGS[@]}" 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | sort -u \
    > "$TMP_IPS"
awk '{print $1}' "$TMP_IPS" | sort -u > "$TMP_DOMAINS"

ALIVE=$(wc -l < "$TMP_DOMAINS" | tr -d ' ')
DEAD=$((TOTAL - ALIVE))

# ── Retention guard ───────────────────────────────────────────────────────────
# dnsx exits 0 even when it resolves nothing, so `set -e` never fires and a
# throttled resolver would silently replace a good Podkop list with an empty
# one. Refuse the write unless the new list keeps at least RECON_MIN_RETAIN
# percent of the previous one.
MIN_RETAIN="${RECON_MIN_RETAIN:-50}"
PREV_ALIVE=0
[[ -f "$OUTDIR/all_domains.txt" ]] && PREV_ALIVE=$(wc -l < "$OUTDIR/all_domains.txt" | tr -d ' ')

if [[ "$FORCE" != true && "$PREV_ALIVE" -gt 0 && $(( ALIVE * 100 )) -lt $(( PREV_ALIVE * MIN_RETAIN )) ]]; then
    mv "$TMP_DOMAINS" "$OUTDIR/all_domains.rejected.txt"
    rm -f "$TMP_IPS"
    err "DNS validation collapsed: $ALIVE alive vs $PREV_ALIVE previously (below ${MIN_RETAIN}%)."
    err "Existing results left untouched. Suspect output: $OUTDIR/all_domains.rejected.txt"
    err "This is almost always a throttled resolver, not real domain death — re-run later."
    err "Override with --force, or lower the bar with RECON_MIN_RETAIN=<percent>."
    exit 3
fi
rm -f "$OUTDIR/all_domains.rejected.txt"

# Snapshot the previous result only now that the new one has passed the guard,
# so a rejected run can never clobber the last known-good list.
HAVE_PREV=false
if [[ -f "$OUTDIR/all_domains.txt" ]]; then
    cp "$OUTDIR/all_domains.txt" "$OUTDIR/all_domains.prev.txt"
    HAVE_PREV=true
fi
mv "$TMP_IPS" "$OUTDIR/all_domains_with_ip.txt"
mv "$TMP_DOMAINS" "$OUTDIR/all_domains.txt"

ok "Alive: $ALIVE  |  Dead (no DNS): $DEAD"

# ── Diff vs previous run ───────────────────────────────────────────────────────
NEW_COUNT=0
GONE_COUNT=0
if [[ "$DIFF_MODE" == true ]]; then
    section "Diff vs previous run"
    if [[ "$HAVE_PREV" == true ]]; then
        comm -13 <(sort -u "$OUTDIR/all_domains.prev.txt") <(sort -u "$OUTDIR/all_domains.txt") > "$OUTDIR/all_domains.new.txt"
        comm -23 <(sort -u "$OUTDIR/all_domains.prev.txt") <(sort -u "$OUTDIR/all_domains.txt") > "$OUTDIR/all_domains.gone.txt"
        NEW_COUNT=$(wc -l < "$OUTDIR/all_domains.new.txt" | tr -d ' ')
        GONE_COUNT=$(wc -l < "$OUTDIR/all_domains.gone.txt" | tr -d ' ')
        if [[ "$NEW_COUNT" -gt 0 ]]; then
            ok "New domains since last run ($NEW_COUNT):"
            cat "$OUTDIR/all_domains.new.txt"
        else
            info "No new domains since last run."
        fi
        # A net loss is a signal too: the exit code only ever reported gains,
        # so a run that shed thousands of domains and gained none looked
        # identical to a clean no-op.
        if [[ "$GONE_COUNT" -gt 0 ]]; then
            warn "Domains gone since last run ($GONE_COUNT) — see all_domains.gone.txt"
        fi
    else
        info "No previous run found — nothing to diff."
        touch "$OUTDIR/all_domains.new.txt"
    fi
fi

# ── Summary ────────────────────────────────────────────────────────────────────
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
echo "  alienvault.txt           — alienvault otx raw output (needs OTX_API_KEY)"
echo "  rapiddns.txt             — rapiddns.io raw output"
if [[ "$DIFF_MODE" == true ]]; then
    echo "  all_domains.new.txt      — $NEW_COUNT domains new since previous run"
    [[ "$HAVE_PREV" == true ]] && echo "  all_domains.gone.txt     — $GONE_COUNT domains gone since previous run"
fi
echo ""
# Dumping the whole list flooded the terminal (atlassian.net alone is ~34k
# lines of wildcard DNS); the file is right there if you want all of it.
echo -e "${BOLD}Live domains (first 50 of $ALIVE):${RESET}"
head -n 50 "$OUTDIR/all_domains.txt"
[[ "$ALIVE" -gt 50 ]] && echo "  ... $((ALIVE - 50)) more in $OUTDIR/all_domains.txt"
echo ""
ok "Done. Use ${BOLD}${OUTDIR}/all_domains.txt${RESET} for Podkop."

EXIT_CODE=0
if [[ "$DIFF_MODE" == true && "$NEW_COUNT" -gt 0 ]]; then
    EXIT_CODE=2
fi
exit "$EXIT_CODE"
