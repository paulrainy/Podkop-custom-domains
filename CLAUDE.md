# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

This is not a software application — it's a passive-recon pipeline (`recon.sh` plus an equivalent `recon.py`) and its accumulated output data. The repo's purpose is to generate domain/subdomain lists for [Podkop](https://github.com/itdoginfo/podkop), a domain-based routing tool. There is no build, lint, or test tooling, no package manifest, and no CI.

The typical unit of work in this repo is: run `recon.sh` against a new target service and commit the resulting `<target>-recon/` output folder. Git history literally reads "figma added", "atlassian and xbox added" — adding a new recon target is the normal PR.

## Two implementations, one pipeline

`recon.sh` + `update-all.sh` (bash) and `recon.py` (Python 3.14, run via `uv`) are interchangeable. Same sources, same output filenames, same exit codes, same env vars, same retention guard; they can be run against the same folders in any mix. On `context7.com` both produce a byte-identical `all_domains.txt` — that equivalence is the acceptance test when changing either one.

**Change both, or say why not.** A fix to a source parser, a budget, or the guard in one script belongs in the other.

`recon.py` is a single PEP 723 script (inline `# /// script` metadata, one dependency: `httpx`). There is no venv, no requirements file, no package manifest — `uv` resolves the header. Invoke it as `uv run recon.py ...` or `./recon.py ...` (its shebang is `#!/usr/bin/env -S uv run --script`). `--all` replaces `update-all.sh`; there is no separate `update_all.py`.

Where `recon.py` is genuinely better, and why those differences exist:
- Truncated certspotter JSON falls back to a regex scrape instead of vanishing. In bash, `jq ... 2>/dev/null` on a malformed body silently yields nothing — that is how the truncation went unnoticed for so long.
- The wayback CDX body is percent-decoded before scraping, so `%2Fwww.xbox.com` yields `www.xbox.com` rather than the junk candidate `2fwww.xbox.com` that is still present in the bash-generated data.
- HackerTarget's quota response (`200 OK` with `API count exceeded` in the body) is detected rather than counted as a successful fetch.
- Target concurrency is an `asyncio.Semaphore` rather than polling `jobs -rp` in a sleep loop — the bash version cannot use `wait -n` because macOS ships bash 3.2.

## Running recon.sh

```bash
chmod +x recon.sh
./recon.sh <domain> [output_dir] [--diff] [--force]

# Examples
./recon.sh context7.com                          # writes to ./recon-context7.com/
./recon.sh xda-developers.com ./xda-recon
./recon.sh context7.com ./recon-context7.com --diff   # compare against the previous run in that dir
```

Required tools: `subfinder`, `dnsx`, `curl`, `jq`, `dig`. The script checks for each on startup and auto-installs anything missing: `brew install` on macOS; on Linux it uses `apt`/`pacman`/`dnf` for the system tools (`curl`, `jq`, `dig`) and prints a `go install` instruction for `subfinder`/`dnsx` (no distro package exists for those). Set `RECON_SKIP_DEPCHECK=1` to skip this check entirely (used by `update-all.sh` to avoid repeating it per target).

There is no way to run "just one source" or "just the DNS validation step" — re-running the script re-queries every source, though `all_raw.txt` is truncated at the start of each run so stale candidates from a previous run don't silently accumulate.

Exit codes: `0` ok, `2` new domains found (`--diff`), `3` **run refused** — either no source returned a single candidate, or the retention guard rejected the DNS result (see below). On `3` no output file is modified.

Tunables (all optional env vars): `RECON_MIN_RETAIN` (default `50`), `RECON_DNSX_THREADS` (`100`), `RECON_DNSX_RETRY` (`3`), `RECON_DNSX_RESOLVERS`, `RECON_DNSX_RATELIMIT`, `RECON_SKIP_DEPCHECK`, plus `OTX_API_KEY` and `CERTSPOTTER_API_KEY` for the two sources that now require auth.

Note the rate-limit caveats from the README: all sources are free/keyless but throttled (HackerTarget caps at 50 req/day; crt.sh is frequently down and handled as a soft failure). Don't re-run against the same domain repeatedly in a short window — this applies per-invocation of `recon.sh` and cumulatively across a single `update-all.sh` run (which hits every mapped target back to back).

## Architecture of recon.sh

The script runs over a single target domain, writing intermediate results into `$OUTDIR` (default `./recon-<domain>/`) and a running `all_raw.txt` candidate pool:

1. **Dependency check** — verifies/installs `subfinder`, `dnsx`, `curl`, `jq`, `dig` (skippable via `RECON_SKIP_DEPCHECK=1`).
2. **Collection, in parallel** — subfinder, crt.sh, certspotter, hackertarget, urlscan.io, wayback machine, alienvault OTX, rapiddns.io, and `dig` MX/NS/TXT each run as a backgrounded `run_<source>` function, output buffered to a per-source log file so console output stays in the original fixed order despite running concurrently. curl-based sources go through a shared `curl_retry() <max_time> <max_attempts> <url> <outfile> [header ...]` helper: exponential backoff, requires HTTP 2xx + non-empty body, and **never retries a 4xx** (it means auth is required or we are already throttled — neither changes within a run). Attempt budgets are per-source and were tuned against measured behaviour: crt.sh gets 2×12s (it is either a fast 502 or a hard timeout, so a third attempt only adds dead wall-clock), certspotter gets a single 20s shot. After `wait`-ing on every background pid individually (not the multi-pid form, which under `set -e` would only surface the last job's exit code), each source's `<name>.txt` is merged into `all_raw.txt` sequentially in the main process via `append_unique()` — merging never happens concurrently from the background jobs themselves. A failing source (e.g. crt.sh down) only kills its own background job, not the whole run.

   Two sources are effectively dead without a key and are handled accordingly: **AlienVault OTX** returns `429 "Please authenticate"` to anonymous callers and is *skipped entirely* unless `OTX_API_KEY` is set; **Certspotter** unauthenticated trickles its body out and never completes (measured: 20 KB in 120 s, then a truncated-JSON parse error), so it takes one bounded attempt and whatever partial body arrives is still used as candidates.
3. **Dedup** — `all_raw.txt` is sorted/uniq'd in place.
4. **DNS validation** — an empty candidate pool aborts with exit `3` before anything is touched. Otherwise the deduped list goes through `dnsx` **exactly once**, with `-resp`; `all_domains.txt` is derived from that output with `awk '{print $1}'` rather than from a second `dnsx` run, so the two files cannot disagree and the resolver sees half the query volume. Only domains with a live A record survive — `all_domains.txt` is the deliverable meant for Podkop.

   Do not raise `RECON_DNSX_THREADS` to "speed this up". Measured on atlassian.net's 34,963 candidates: `-t 100` against the system resolver took 3m07s and found 34,337 domains; `-t 300` against six public resolvers took 49s but found only 14,227 — the resolvers silently drop queries under load, and `dnsx` reports no error for the ones it lost. Throughput here is bought with recall.

5. **Retention guard** — `dnsx` exits `0` even when it resolves nothing, so `set -e` never fires and a throttled resolver would silently replace a 45,885-domain Podkop list with an empty file (this actually happened). The new list is written to a temp file, and unless it retains at least `RECON_MIN_RETAIN` percent (default 50) of the current `all_domains.txt`, the write is refused: existing files stay untouched, the suspect result goes to `all_domains.rejected.txt`, and the script exits `3`. `--force` (or `RECON_MIN_RETAIN=0`) overrides it for a genuine drop. Only *after* the guard passes is the previous list snapshotted to `all_domains.prev.txt` — so a rejected run can never clobber the last known-good list.
6. **Diff (optional, `--diff`)** — `comm` against `all_domains.prev.txt` produces `all_domains.new.txt`/`all_domains.gone.txt`; exits with code `2` if any domain is new (used by `update-all.sh` to detect change), `0` otherwise. Losses are reported too — the old exit code only ever signalled gains, so a run that shed 47,000 domains and gained none was indistinguishable from a clean no-op.
7. **Summary** — prints counts and the first 50 live domains (the full list is in the file; atlassian.net alone is ~34k lines of wildcard DNS).

## Output folder convention

Both implementations write this identical layout. Every `<target>-recon/` directory at the repo root is generated data, not source code. The current schema (produced by today's `recon.sh`) is 11 files, plus 2–3 more when run with `--diff`:

```
<target>-recon/
├── all_domains.txt          # deliverable: live, DNS-validated domains → feed to Podkop
├── all_domains_with_ip.txt  # same, as "host [A] [ip]"
├── all_raw.txt              # all candidates pre-validation
├── subfinder.txt / crtsh.txt / certspotter.txt / hackertarget.txt / urlscan.txt / wayback.txt / alienvault.txt / rapiddns.txt
├── all_domains.rejected.txt # (only if the retention guard refused a run)
├── all_domains.prev.txt     # (--diff only) snapshot of the previous run
├── all_domains.new.txt      # (--diff only) domains new since the previous run
└── all_domains.gone.txt     # (--diff only, if a previous run existed) domains no longer resolving
```

Folders matching the base (non-diff) schema (`figma-recon`, `xbox-recon`, `apple-music-recon`, `apple-itunes-recon`, `jetmail-recon`) are current-format runs. `context7-recon`, `brawlstars-recon`, and `xda-recon` predate the unified script and have divergent, per-source-suffixed filenames plus a hand-curated `existing.txt` — treat these as legacy, not a pattern to replicate.

When adding a new target, let `recon.sh` generate the folder rather than hand-authoring these files, so the output stays consistent with the current schema. Register it in `targets.conf` (`folder domain [domain2 ...]`) if it should be picked up by `update-all.sh`.

## update-all.sh

Re-runs `recon.sh --diff` (`RECON_SKIP_DEPCHECK=1`) against every folder mapped in `targets.conf` and reports which folders gained domains, which *lost* domains, and which had their result refused. Use `./update-all.sh --dry-run` to see the resolved folder→domain(s) mapping and planned invocations without making any network requests — this is the cheap way to sanity-check `targets.conf` after editing it.

`-j N` runs N targets concurrently (default 3, or `$UPDATE_JOBS`); `-j 1` restores the old strictly-serial behaviour with a 5s pause between targets. Concurrency does not change how many requests are made, only how fast — the daily caps still apply per run. Job dispatch polls `jobs -rp` rather than using `wait -n`, because macOS ships bash 3.2 (the whole repo targets it — note the `${arr[@]+"${arr[@]}"}` empty-array workarounds).

Concurrent `dnsx` runs across targets were checked and do *not* contend measurably: figma's 223-candidate list returns the same 85 live domains at `-t 10`, `-t 25` and `-t 100`, and atlassian's count was unchanged between a `-j 3` run and a run with DNS validation serialised. Don't add a cross-process DNS lock — it costs ~2 minutes of wall clock and buys nothing.

`targets.conf` is read into arrays up front, and every `recon.sh` invocation gets `</dev/null`. Previously the loop was `while read ... done < "$MAPFILE"`, which handed the remaining config lines to every child as stdin; anything that read stdin would have silently eaten targets.

Multi-root targets (`brawlstars-recon` = `supercell.com` + `brawlstarsgame.com`, `github-recon` = `github.com` + `githubusercontent.com` + `githubcopilot.com`, `playstation-recon` = `playstation.com` + `playstation.net` + `sonyentertainmentnetwork.com` + `account.sony.com`) run once per root domain into a scratch dir and merge per-source files into the target folder using a domain-suffixed naming convention (e.g. `subfinder_supercell.txt`) rather than the single-domain schema above. The suffix is the root's first label, unless two roots in the same target share it — `playstation.com` and `playstation.net` both yield `playstation`, and the second root would silently overwrite the first one's files — in which case both fall back to the full domain with dots turned into dashes (`subfinder_playstation-net.txt`). `root_suffixes()` implements this in both scripts and must stay in sync; brawlstars' existing filenames are unaffected because its labels do not collide. That merged list is only assembled here, so `update-all.sh` carries its own copy of the retention guard (`retain_ok`) and refuses the `mv` if any root failed or the merge collapsed. The script exits `1` if any target failed or was refused.

The folder→domain mapping in `targets.conf` is not mechanically derivable from folder names (e.g. `atlassian-recon` → `atlassian.net`, `jetmail-recon` → `jetmail.atlassian.net`) — always check `targets.conf` rather than guessing a domain from a folder name.
