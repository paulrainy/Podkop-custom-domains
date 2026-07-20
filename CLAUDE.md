# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

This is not a software application — it's a single passive-recon shell script (`recon.sh`) plus its accumulated output data. The repo's purpose is to generate domain/subdomain lists for [Podkop](https://github.com/itdoginfo/podkop), a domain-based routing tool. There is no build, lint, or test tooling, no package manifest, and no CI.

The typical unit of work in this repo is: run `recon.sh` against a new target service and commit the resulting `<target>-recon/` output folder. Git history literally reads "figma added", "atlassian and xbox added" — adding a new recon target is the normal PR.

## Running recon.sh

```bash
chmod +x recon.sh
./recon.sh <domain> [output_dir] [--diff]

# Examples
./recon.sh context7.com                          # writes to ./recon-context7.com/
./recon.sh xda-developers.com ./xda-recon
./recon.sh context7.com ./recon-context7.com --diff   # compare against the previous run in that dir
```

Required tools: `subfinder`, `dnsx`, `curl`, `jq`, `dig`. The script checks for each on startup and auto-installs anything missing: `brew install` on macOS; on Linux it uses `apt`/`pacman`/`dnf` for the system tools (`curl`, `jq`, `dig`) and prints a `go install` instruction for `subfinder`/`dnsx` (no distro package exists for those). Set `RECON_SKIP_DEPCHECK=1` to skip this check entirely (used by `update-all.sh` to avoid repeating it per target).

There is no way to run "just one source" or "just the DNS validation step" — re-running the script re-queries every source, though `all_raw.txt` is truncated at the start of each run so stale candidates from a previous run don't silently accumulate.

Note the rate-limit caveats from the README: all sources are free/keyless but throttled (HackerTarget caps at 50 req/day; crt.sh is frequently down and handled as a soft failure). Don't re-run against the same domain repeatedly in a short window — this applies per-invocation of `recon.sh` and cumulatively across a single `update-all.sh` run (which hits every mapped target back to back).

## Architecture of recon.sh

The script runs over a single target domain, writing intermediate results into `$OUTDIR` (default `./recon-<domain>/`) and a running `all_raw.txt` candidate pool:

1. **Dependency check** — verifies/installs `subfinder`, `dnsx`, `curl`, `jq`, `dig` (skippable via `RECON_SKIP_DEPCHECK=1`).
2. **Collection, in parallel** — subfinder, crt.sh, certspotter, hackertarget, urlscan.io, wayback machine, alienvault OTX, rapiddns.io, and `dig` MX/NS/TXT each run as a backgrounded `run_<source>` function, output buffered to a per-source log file so console output stays in the original fixed order despite running concurrently. curl-based sources go through a shared `curl_retry()` helper (3 attempts, exponential backoff, requires HTTP 2xx + non-empty body). After `wait`-ing on every background pid individually (not the multi-pid form, which under `set -e` would only surface the last job's exit code), each source's `<name>.txt` is merged into `all_raw.txt` sequentially in the main process via `append_unique()` — merging never happens concurrently from the background jobs themselves. A failing source (e.g. crt.sh down) only kills its own background job, not the whole run.
3. **Dedup** — `all_raw.txt` is sorted/uniq'd in place.
4. **DNS validation** — the deduped candidate list is piped through `dnsx` twice: once for `all_domains.txt` (bare live hostnames) and once with `-resp` for `all_domains_with_ip.txt` (hostname + resolved IP). Only domains with a live A record survive into these two files — `all_domains.txt` is the deliverable meant for Podkop. Before this overwrites `all_domains.txt`, the previous run's copy is snapshotted to `all_domains.prev.txt` for diffing.
5. **Diff (optional, `--diff`)** — `comm` against `all_domains.prev.txt` produces `all_domains.new.txt`/`all_domains.gone.txt`; exits with code `2` if any domain is new (used by `update-all.sh` to detect change), `0` otherwise.
6. **Summary** — prints counts and the live domain list to stdout.

## Output folder convention

Every `<target>-recon/` directory at the repo root is generated data, not source code. The current schema (produced by today's `recon.sh`) is 11 files, plus 2–3 more when run with `--diff`:

```
<target>-recon/
├── all_domains.txt          # deliverable: live, DNS-validated domains → feed to Podkop
├── all_domains_with_ip.txt  # same, as "host [A] [ip]"
├── all_raw.txt              # all candidates pre-validation
├── subfinder.txt / crtsh.txt / certspotter.txt / hackertarget.txt / urlscan.txt / wayback.txt / alienvault.txt / rapiddns.txt
├── all_domains.prev.txt     # (--diff only) snapshot of the previous run
├── all_domains.new.txt      # (--diff only) domains new since the previous run
└── all_domains.gone.txt     # (--diff only, if a previous run existed) domains no longer resolving
```

Folders matching the base (non-diff) schema (`figma-recon`, `xbox-recon`, `apple-music-recon`, `apple-itunes-recon`, `jetmail-recon`) are current-format runs. `context7-recon`, `brawlstars-recon`, and `xda-recon` predate the unified script and have divergent, per-source-suffixed filenames plus a hand-curated `existing.txt` — treat these as legacy, not a pattern to replicate.

When adding a new target, let `recon.sh` generate the folder rather than hand-authoring these files, so the output stays consistent with the current schema. Register it in `targets.conf` (`folder domain [domain2 ...]`) if it should be picked up by `update-all.sh`.

## update-all.sh

Re-runs `recon.sh --diff` (`RECON_SKIP_DEPCHECK=1`) against every folder mapped in `targets.conf`, sleeping between targets to stay polite to shared rate limits, and reports which folders had new domains. Multi-root targets (currently only `brawlstars-recon`, mapped to `supercell.com` + `brawlstarsgame.com`) run once per root domain into a scratch dir and merge per-source files into the target folder using its existing domain-suffixed naming convention (e.g. `subfinder_supercell.txt`) rather than the single-domain schema above. Use `./update-all.sh --dry-run` to see the resolved folder→domain(s) mapping and planned invocations without making any network requests — this is the cheap way to sanity-check `targets.conf` after editing it.

The folder→domain mapping in `targets.conf` is not mechanically derivable from folder names (e.g. `atlassian-recon` → `atlassian.net`, `jetmail-recon` → `jetmail.atlassian.net`) — always check `targets.conf` rather than guessing a domain from a folder name.
