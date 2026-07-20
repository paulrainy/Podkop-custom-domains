#!/usr/bin/env bash
# update-all.sh — re-run recon.sh against every target listed in targets.conf
# Usage: ./update-all.sh [--dry-run]
#
# Reruns recon (with --diff) for every folder mapped in targets.conf and
# reports which targets picked up new domains. Multi-root targets (e.g.
# brawlstars-recon) run recon.sh once per root domain and merge results using
# the domain-suffixed file convention already used in that folder.
#
# Note: this burns shared daily rate limits (e.g. HackerTarget: 50 req/day
# total) across all targets in one run — don't run more than once a day.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
err()     { echo -e "${RED}[-]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAPFILE="$SCRIPT_DIR/targets.conf"
RECON="$SCRIPT_DIR/recon.sh"

DRY_RUN=false
for arg in "$@"; do
    [[ "$arg" == "--dry-run" ]] && DRY_RUN=true
done

if [[ ! -f "$MAPFILE" ]]; then
    err "targets.conf not found at $MAPFILE"
    exit 1
fi

CHANGED=()

while read -r folder rest; do
    [[ -z "$folder" || "$folder" == \#* ]] && continue
    read -ra domains <<< "$rest"

    if [[ ${#domains[@]} -eq 1 ]]; then
        section "Updating $folder (${domains[0]})"
        if [[ "$DRY_RUN" == true ]]; then
            info "Would run: $RECON ${domains[0]} $SCRIPT_DIR/$folder --diff"
            continue
        fi
        set +e
        RECON_SKIP_DEPCHECK=1 "$RECON" "${domains[0]}" "$SCRIPT_DIR/$folder" --diff
        rc=$?
        set -e
        if [[ $rc -eq 2 ]]; then
            CHANGED+=("$folder")
        elif [[ $rc -ne 0 ]]; then
            warn "$folder: recon.sh exited with code $rc"
        fi
    else
        section "Updating $folder (multi-root: ${domains[*]})"
        if [[ "$DRY_RUN" == true ]]; then
            for d in "${domains[@]}"; do
                info "Would run: $RECON $d <scratch-dir>, merge into $SCRIPT_DIR/$folder as *_${d%%.*}.txt"
            done
            continue
        fi

        target_dir="$SCRIPT_DIR/$folder"
        mkdir -p "$target_dir"
        raw_new="$target_dir/all_raw.txt.new"
        domains_new="$target_dir/all_domains.txt.new"
        ips_new="$target_dir/all_domains_with_ip.txt.new"
        : > "$raw_new"; : > "$domains_new"; : > "$ips_new"

        for d in "${domains[@]}"; do
            tmp=$(mktemp -d)
            RECON_SKIP_DEPCHECK=1 "$RECON" "$d" "$tmp" || warn "$d: recon.sh exited non-zero"
            suffix="${d%%.*}"
            for f in subfinder crtsh certspotter hackertarget urlscan wayback alienvault rapiddns; do
                [[ -f "$tmp/$f.txt" ]] && cp "$tmp/$f.txt" "$target_dir/${f}_${suffix}.txt"
            done
            [[ -f "$tmp/all_raw.txt" ]] && cat "$tmp/all_raw.txt" >> "$raw_new"
            [[ -f "$tmp/all_domains.txt" ]] && cat "$tmp/all_domains.txt" >> "$domains_new"
            [[ -f "$tmp/all_domains_with_ip.txt" ]] && cat "$tmp/all_domains_with_ip.txt" >> "$ips_new"
            rm -rf "$tmp"
            sleep 2
        done

        have_prev=false
        if [[ -f "$target_dir/all_domains.txt" ]]; then
            cp "$target_dir/all_domains.txt" "$target_dir/all_domains.prev.txt"
            have_prev=true
        fi

        sort -u -o "$raw_new" "$raw_new"
        sort -u -o "$domains_new" "$domains_new"
        sort -u -o "$ips_new" "$ips_new"
        mv "$raw_new" "$target_dir/all_raw.txt"
        mv "$domains_new" "$target_dir/all_domains.txt"
        mv "$ips_new" "$target_dir/all_domains_with_ip.txt"

        if [[ "$have_prev" == true ]]; then
            new_count=$(comm -13 "$target_dir/all_domains.prev.txt" "$target_dir/all_domains.txt" | tee "$target_dir/all_domains.new.txt" | wc -l)
            comm -23 "$target_dir/all_domains.prev.txt" "$target_dir/all_domains.txt" > "$target_dir/all_domains.gone.txt"
            [[ "$new_count" -gt 0 ]] && CHANGED+=("$folder")
        fi
    fi

    sleep 5   # be polite to shared rate limits between targets
done < "$MAPFILE"

section "Summary"
if [[ "$DRY_RUN" == true ]]; then
    info "Dry run complete — no network requests made."
elif [[ ${#CHANGED[@]} -gt 0 ]]; then
    ok "Targets with new domains: ${CHANGED[*]}"
else
    info "No targets had new domains this run."
fi
