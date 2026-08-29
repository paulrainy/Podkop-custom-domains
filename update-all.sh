#!/usr/bin/env bash
# update-all.sh — re-run recon.sh against every target listed in targets.conf
# Usage: ./update-all.sh [--dry-run] [-j N]
#
# Reruns recon (with --diff) for every folder mapped in targets.conf and
# reports which targets picked up new domains, lost domains, or had their
# results refused by recon.sh's retention guard. Multi-root targets (e.g.
# brawlstars-recon) run recon.sh once per root domain and merge results using
# the domain-suffixed file convention already used in that folder.
#
#   -j N   run N targets concurrently (default 3, or $UPDATE_JOBS).
#          -j 1 restores the old strictly-serial behaviour.
#
# Note: this burns shared daily rate limits (e.g. HackerTarget: 50 req/day
# total) across all targets in one run — don't run more than once a day.
# Raising -j does not change how many requests are made, only how fast; keep
# it low enough that per-minute limits (urlscan, rapiddns) aren't tripped.
#
# Exit codes: 0 = all targets ok, 1 = at least one target failed or was refused.

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
JOBS="${UPDATE_JOBS:-3}"
MIN_RETAIN="${RECON_MIN_RETAIN:-50}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        -j|--jobs) JOBS="${2:-}"; shift 2 ;;
        -j*)       JOBS="${1#-j}"; shift ;;
        *)         err "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    err "-j expects a positive integer, got: $JOBS"
    exit 1
fi

if [[ ! -f "$MAPFILE" ]]; then
    err "targets.conf not found at $MAPFILE"
    exit 1
fi

# ── Retention guard for the merged multi-root list ────────────────────────────
# Mirrors the guard in recon.sh. recon.sh applies it per scratch run, but a
# multi-root target's real list is only assembled here, so it needs its own.
# retain_ok <new_list> <current_list>
retain_ok() {
    local new_f="$1" cur_f="$2" new_n cur_n
    [[ -f "$cur_f" ]] || return 0
    cur_n=$(wc -l < "$cur_f" | tr -d ' ')
    [[ "$cur_n" -eq 0 ]] && return 0
    new_n=$(wc -l < "$new_f" | tr -d ' ')
    [[ $(( new_n * 100 )) -ge $(( cur_n * MIN_RETAIN )) ]]
}

count_lines() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

# ── One target, start to finish. Writes "<status> <new> <gone>" to $2. ────────
# status: ok | new | refused | failed
# Echoes one per-source file suffix per domain, in the order given.
#
# The root's first label is enough for supercell.com + brawlstarsgame.com, but
# not for playstation.com + playstation.net — both claim "playstation", and the
# second root would silently overwrite the first one's files. A colliding label
# falls back to the whole domain with dots turned into dashes.
root_suffixes() {
    local d j lbl collide
    for d in "$@"; do
        lbl="${d%%.*}"
        collide=false
        for j in "$@"; do
            [[ "$j" != "$d" && "${j%%.*}" == "$lbl" ]] && collide=true
        done
        if [[ "$collide" == true ]]; then printf '%s\n' "${d//./-}"; else printf '%s\n' "$lbl"; fi
    done
}

update_target() {
    local folder="$1" status_file="$2"; shift 2
    local domains=("$@")
    local target_dir="$SCRIPT_DIR/$folder"

    if [[ ${#domains[@]} -eq 1 ]]; then
        section "Updating $folder (${domains[0]})"
        local rc=0
        # </dev/null so recon.sh (and its subfinder/dnsx/curl children) cannot
        # read from this script's stdin, which used to be targets.conf itself:
        # any child that read stdin silently ate the remaining targets.
        RECON_SKIP_DEPCHECK=1 "$RECON" "${domains[0]}" "$target_dir" --diff </dev/null || rc=$?
        local gone; gone=$(count_lines "$target_dir/all_domains.gone.txt")
        case "$rc" in
            0) echo "ok $(count_lines "$target_dir/all_domains.new.txt") $gone" > "$status_file" ;;
            2) echo "new $(count_lines "$target_dir/all_domains.new.txt") $gone" > "$status_file" ;;
            3) warn "$folder: recon.sh refused the result (retention guard)"
               echo "refused 0 0" > "$status_file" ;;
            *) warn "$folder: recon.sh exited with code $rc"
               echo "failed 0 0" > "$status_file" ;;
        esac
        return 0
    fi

    section "Updating $folder (multi-root: ${domains[*]})"
    mkdir -p "$target_dir"
    local raw_new="$target_dir/all_raw.txt.new"
    local domains_new="$target_dir/all_domains.txt.new"
    local ips_new="$target_dir/all_domains_with_ip.txt.new"
    : > "$raw_new"; : > "$domains_new"; : > "$ips_new"

    local d rc any_failed=false tmp suffix f i
    local sfx=()
    while IFS= read -r suffix; do sfx+=("$suffix"); done < <(root_suffixes "${domains[@]}")
    for i in $(seq 0 $(( ${#domains[@]} - 1 ))); do
        d="${domains[$i]}"
        tmp=$(mktemp -d)
        rc=0
        RECON_SKIP_DEPCHECK=1 "$RECON" "$d" "$tmp" </dev/null || rc=$?
        # A failed root used to be downgraded to a warning, then its (empty)
        # output was merged and moved over the folder's real files anyway.
        if [[ "$rc" -ne 0 && "$rc" -ne 2 ]]; then
            warn "$folder/$d: recon.sh exited with code $rc"
            any_failed=true
        fi
        suffix="${sfx[$i]}"
        for f in subfinder crtsh certspotter hackertarget urlscan wayback alienvault rapiddns; do
            [[ -s "$tmp/$f.txt" ]] && cp "$tmp/$f.txt" "$target_dir/${f}_${suffix}.txt"
        done
        [[ -f "$tmp/all_raw.txt" ]] && cat "$tmp/all_raw.txt" >> "$raw_new"
        [[ -f "$tmp/all_domains.txt" ]] && cat "$tmp/all_domains.txt" >> "$domains_new"
        [[ -f "$tmp/all_domains_with_ip.txt" ]] && cat "$tmp/all_domains_with_ip.txt" >> "$ips_new"
        rm -rf "$tmp"
        sleep 2
    done

    sort -u -o "$raw_new" "$raw_new"
    sort -u -o "$domains_new" "$domains_new"
    sort -u -o "$ips_new" "$ips_new"

    if [[ "$any_failed" == true ]]; then
        err "$folder: at least one root domain failed — not overwriting existing results"
        rm -f "$raw_new" "$domains_new" "$ips_new"
        echo "failed 0 0" > "$status_file"
        return 0
    fi
    if ! retain_ok "$domains_new" "$target_dir/all_domains.txt"; then
        err "$folder: merged list collapsed to $(count_lines "$domains_new") from $(count_lines "$target_dir/all_domains.txt") (below ${MIN_RETAIN}%) — not overwriting"
        mv "$domains_new" "$target_dir/all_domains.rejected.txt"
        rm -f "$raw_new" "$ips_new"
        echo "refused 0 0" > "$status_file"
        return 0
    fi
    rm -f "$target_dir/all_domains.rejected.txt"

    local have_prev=false
    if [[ -f "$target_dir/all_domains.txt" ]]; then
        cp "$target_dir/all_domains.txt" "$target_dir/all_domains.prev.txt"
        have_prev=true
    fi

    mv "$raw_new" "$target_dir/all_raw.txt"
    mv "$domains_new" "$target_dir/all_domains.txt"
    mv "$ips_new" "$target_dir/all_domains_with_ip.txt"

    local new_count=0 gone_count=0
    if [[ "$have_prev" == true ]]; then
        # sort -u both sides, as recon.sh does: these legacy folders' lists are
        # partly hand-maintained, and comm on unsorted input silently lies.
        comm -13 <(sort -u "$target_dir/all_domains.prev.txt") <(sort -u "$target_dir/all_domains.txt") \
            > "$target_dir/all_domains.new.txt"
        comm -23 <(sort -u "$target_dir/all_domains.prev.txt") <(sort -u "$target_dir/all_domains.txt") \
            > "$target_dir/all_domains.gone.txt"
        new_count=$(count_lines "$target_dir/all_domains.new.txt")
        gone_count=$(count_lines "$target_dir/all_domains.gone.txt")
    fi
    if [[ "$new_count" -gt 0 ]]; then
        echo "new $new_count $gone_count" > "$status_file"
    else
        echo "ok $new_count $gone_count" > "$status_file"
    fi
}

# ── Read targets.conf up front so no child process can consume it ────────────
FOLDERS=(); DOMAINSETS=()
while read -r folder rest || [[ -n "$folder" ]]; do
    [[ -z "$folder" || "$folder" == \#* ]] && continue
    FOLDERS+=("$folder")
    DOMAINSETS+=("$rest")
done < "$MAPFILE"

if [[ ${#FOLDERS[@]} -eq 0 ]]; then
    err "No targets found in $MAPFILE"
    exit 1
fi

LAST=$(( ${#FOLDERS[@]} - 1 ))

if [[ "$DRY_RUN" == true ]]; then
    info "Dry run — ${#FOLDERS[@]} targets, $JOBS at a time"
    for i in $(seq 0 "$LAST"); do
        read -ra domains <<< "${DOMAINSETS[$i]}"
        section "${FOLDERS[$i]}"
        if [[ ${#domains[@]} -eq 1 ]]; then
            info "Would run: $RECON ${domains[0]} $SCRIPT_DIR/${FOLDERS[$i]} --diff"
        else
            sfx=()
            while IFS= read -r s; do sfx+=("$s"); done < <(root_suffixes "${domains[@]}")
            for k in $(seq 0 $(( ${#domains[@]} - 1 ))); do
                info "Would run: $RECON ${domains[$k]} <scratch-dir>, merge into $SCRIPT_DIR/${FOLDERS[$i]} as *_${sfx[$k]}.txt"
            done
        fi
    done
    section "Summary"
    info "Dry run complete — no network requests made."
    exit 0
fi

# ── Dispatch, at most $JOBS at a time ─────────────────────────────────────────
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

info "Updating ${#FOLDERS[@]} targets, $JOBS at a time ..."

for i in $(seq 0 "$LAST"); do
    # bash 3.2 (what macOS ships) has no `wait -n`, so poll the job count.
    while [[ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$JOBS" ]]; do
        sleep 1
    done
    read -ra domains <<< "${DOMAINSETS[$i]}"
    update_target "${FOLDERS[$i]}" "$WORKDIR/${FOLDERS[$i]}.status" "${domains[@]}" \
        > "$WORKDIR/${FOLDERS[$i]}.log" 2>&1 &
    if [[ "$JOBS" -eq 1 ]]; then
        sleep 5   # be polite to shared rate limits between targets
    fi
done
wait

# ── Replay per-target output in targets.conf order ────────────────────────────
for i in $(seq 0 "$LAST"); do
    [[ -f "$WORKDIR/${FOLDERS[$i]}.log" ]] && cat "$WORKDIR/${FOLDERS[$i]}.log"
done

# ── Summary ───────────────────────────────────────────────────────────────────
CHANGED=(); LOST=(); REFUSED=(); FAILED=()
for i in $(seq 0 "$LAST"); do
    folder="${FOLDERS[$i]}"
    sf="$WORKDIR/$folder.status"
    if [[ ! -f "$sf" ]]; then
        FAILED+=("$folder")
        continue
    fi
    read -r status new_count gone_count < "$sf"
    case "$status" in
        new)     CHANGED+=("$folder(+$new_count)") ;;
        refused) REFUSED+=("$folder") ;;
        failed)  FAILED+=("$folder") ;;
    esac
    if [[ "${gone_count:-0}" -gt 0 ]]; then
        LOST+=("$folder(-$gone_count)")
    fi
done

section "Summary"
if [[ ${#CHANGED[@]} -gt 0 ]]; then
    ok "Targets with new domains: ${CHANGED[*]}"
else
    info "No targets had new domains this run."
fi
[[ ${#LOST[@]} -gt 0 ]]    && warn "Targets that lost domains: ${LOST[*]}"
[[ ${#REFUSED[@]} -gt 0 ]] && err "Refused by the retention guard (results left untouched): ${REFUSED[*]}"
[[ ${#FAILED[@]} -gt 0 ]]  && err "Failed: ${FAILED[*]}"

if [[ ${#REFUSED[@]} -gt 0 || ${#FAILED[@]} -gt 0 ]]; then
    exit 1
fi
exit 0
