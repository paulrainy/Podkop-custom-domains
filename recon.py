#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = ["httpx>=0.28"]
# ///
"""Passive domain recon — Python port of recon.sh, run via uv.

    uv run recon.py <domain> [output_dir] [--diff] [--force]
    uv run recon.py --all [-j N] [--dry-run]

The two scripts are interchangeable: same sources, same output filenames, same
exit codes, same env vars. Run whichever you prefer against the same folders.

Exit codes
    0   ok
    2   new domains found (--diff)
    3   run refused: no candidates collected, or the retention guard rejected
        the DNS result. No output file is modified.
    1   (--all only) at least one target failed or was refused.

System tools required: subfinder, dnsx, dig. curl and jq are not — httpx and
the json module replace them, which is the point: a truncated or malformed
response raises here instead of being swallowed by `jq ... 2>/dev/null`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import httpx

# ── Console ───────────────────────────────────────────────────────────────────

_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def info(msg: str) -> None:
    print(f"{_c('0;36', '[*]')} {msg}")


def ok(msg: str) -> None:
    print(f"{_c('0;32', '[+]')} {msg}")


def warn(msg: str) -> None:
    print(f"{_c('1;33', '[!]')} {msg}")


def err(msg: str) -> None:
    print(f"{_c('0;31', '[-]')} {msg}")


def section(msg: str) -> None:
    print(f"\n{_c('1;36', f'══ {msg} ══')}")


# ── Config ────────────────────────────────────────────────────────────────────

SOURCE_NAMES = (
    "subfinder",
    "crtsh",
    "certspotter",
    "hackertarget",
    "urlscan",
    "wayback",
    "alienvault",
    "rapiddns",
)

DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        warn(f"{name}={raw!r} is not an integer — using {default}")
        return default


@dataclass(frozen=True, slots=True)
class Settings:
    min_retain: int = field(default_factory=lambda: env_int("RECON_MIN_RETAIN", 50))
    dnsx_threads: int = field(default_factory=lambda: env_int("RECON_DNSX_THREADS", 100))
    dnsx_retry: int = field(default_factory=lambda: env_int("RECON_DNSX_RETRY", 3))
    dnsx_resolvers: str = field(default_factory=lambda: os.environ.get("RECON_DNSX_RESOLVERS", ""))
    dnsx_ratelimit: str = field(default_factory=lambda: os.environ.get("RECON_DNSX_RATELIMIT", ""))
    otx_key: str = field(default_factory=lambda: os.environ.get("OTX_API_KEY", ""))
    certspotter_key: str = field(default_factory=lambda: os.environ.get("CERTSPOTTER_API_KEY", ""))


def validate_domain(d: str) -> str:
    d = d.strip().lower()
    if not d:
        raise SystemExit("Domain must not be empty")
    if any(ch.isspace() for ch in d):
        raise SystemExit(f"Domain must not contain whitespace: {d}")
    if "/" in d or ":" in d:
        raise SystemExit(f"Domain must not contain a scheme or path: {d}")
    if len(d) > 253:
        raise SystemExit(f"Domain too long: {d}")
    if not DOMAIN_RE.match(d):
        raise SystemExit(f"Invalid domain format: {d}")
    return d


# ── HTTP ──────────────────────────────────────────────────────────────────────


async def fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float,
    attempts: int,
    headers: dict[str, str] | None = None,
    log: list[str],
) -> str | None:
    """GET with backoff. Returns the body, or None if every attempt failed.

    A 4xx is never retried: it means auth is required (certspotter, OTX) or we
    are already being throttled, and neither changes within a run — retrying a
    429 only deepens the throttle while burning the wall-clock budget.

    A read timeout mid-body still returns what arrived. certspotter
    unauthenticated never finishes its response, and a partial body there is
    still worth parsing, so this deliberately keeps it rather than discarding.
    No compression is requested for the same reason: a cut-off gzip stream
    decodes to nothing at all, while a cut-off plain body is still usable.
    """
    delay = 1.0
    for attempt in range(1, attempts + 1):
        body: str | None = None
        status: int | str = "000"
        try:
            async with client.stream(
                "GET", url, timeout=timeout, headers=headers or {}
            ) as resp:
                status = resp.status_code
                chunks: list[bytes] = []
                try:
                    async for chunk in resp.aiter_bytes():
                        chunks.append(chunk)
                except (httpx.ReadTimeout, httpx.ReadError):
                    log.append(f"  truncated after {sum(map(len, chunks))} bytes")
                body = b"".join(chunks).decode("utf-8", errors="replace")
        except httpx.HTTPError as exc:
            status = type(exc).__name__

        if isinstance(status, int) and 200 <= status < 300 and body:
            return body
        if isinstance(status, int) and 400 <= status < 500:
            log.append(f"  http {status} — not retrying")
            return None
        if attempt < attempts:
            log.append(f"  retry {attempt}/{attempts} (http {status}) in {delay:.0f}s ...")
            await asyncio.sleep(delay)
            delay *= 2
    return None


def scrape_domains(text: str, domain: str) -> set[str]:
    """Every hostname under `domain` appearing anywhere in `text`.

    Used both as the primary extractor for the HTML/text sources and as the
    fallback when a JSON body is truncated — which is how certspotter's
    always-cut-off response still yields candidates instead of nothing.
    """
    pattern = re.compile(
        rf"(?<![a-zA-Z0-9.-])((?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?\.)*{re.escape(domain)})"
        r"(?![a-zA-Z0-9-])"
    )
    return {m.group(1).lower().lstrip("*.") for m in pattern.finditer(text)}


def clean(names: object, domain: str) -> set[str]:
    """Normalise an iterable of raw names down to hostnames under `domain`."""
    out: set[str] = set()
    if not isinstance(names, (list, tuple, set)):
        return out
    for raw in names:
        if not isinstance(raw, str):
            continue
        for part in raw.replace(",", "\n").split("\n"):
            host = part.strip().lower().removeprefix("*.")
            if not host or "*" in host:
                continue
            if host == domain or host.endswith("." + domain):
                out.add(host)
    return out


# ── Sources ───────────────────────────────────────────────────────────────────
#
# Each returns (set_of_domains, log_lines). Log lines are buffered rather than
# printed so that concurrent sources still report in a fixed, readable order.


async def src_subfinder(domain: str, st: Settings) -> tuple[set[str], list[str]]:
    log = [f"Running subfinder on {domain} ..."]
    proc = await asyncio.create_subprocess_exec(
        "subfinder", "-d", domain, "-silent",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await proc.communicate()
    found = clean(out.decode(errors="replace").splitlines(), domain)
    if not found:
        log.append("subfinder returned no results")
    return found, log


async def src_crtsh(client: httpx.AsyncClient, domain: str, st: Settings) -> tuple[set[str], list[str]]:
    log = [f"Querying crt.sh for %.{domain} ..."]
    # crt.sh is either a fast 502 or a hard timeout; a third attempt only ever
    # adds dead wall-clock to a phase that is already the long pole.
    body = await fetch(
        client, f"https://crt.sh/?q=%25.{domain}&output=json",
        timeout=12, attempts=2, log=log,
    )
    if body is None:
        log.append("crt.sh unavailable (all retries failed)")
        return set(), log
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        log.append("crt.sh returned malformed JSON — falling back to a text scrape")
        return scrape_domains(body, domain), log
    found: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict):
            found |= clean([row.get("name_value", "")], domain)
    return found, log


async def src_certspotter(client: httpx.AsyncClient, domain: str, st: Settings) -> tuple[set[str], list[str]]:
    headers = {}
    if st.certspotter_key:
        log = [f"Querying certspotter.com for {domain} (authenticated) ..."]
        headers["Authorization"] = f"Bearer {st.certspotter_key}"
    else:
        # Unauthenticated the endpoint trickles its body out and never
        # completes (measured: 20 KB in 120 s). One bounded attempt, and the
        # partial body is parsed for what it does contain.
        log = [f"Querying certspotter.com for {domain} (no CERTSPOTTER_API_KEY — partial results) ..."]
    body = await fetch(
        client,
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        "&include_subdomains=true&expand=dns_names",
        timeout=20, attempts=1, headers=headers, log=log,
    )
    if body is None:
        log.append("certspotter: request failed")
        return set(), log
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        log.append("certspotter: body truncated — scraping the partial response")
        return scrape_domains(body, domain), log
    found: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict):
            found |= clean(row.get("dns_names"), domain)
    return found, log


async def src_hackertarget(client: httpx.AsyncClient, domain: str, st: Settings) -> tuple[set[str], list[str]]:
    log = [f"Querying hackertarget.com for {domain} ..."]
    body = await fetch(
        client, f"https://api.hackertarget.com/hostsearch/?q={domain}",
        timeout=15, attempts=3, log=log,
    )
    if body is None:
        log.append("hackertarget: all retries failed")
        return set(), log
    if "API count exceeded" in body:
        # 200 OK with an error sentence in the body — the daily 50-request cap.
        log.append("hackertarget: daily quota exhausted")
        return set(), log
    return clean([line.split(",")[0] for line in body.splitlines()], domain), log


async def src_urlscan(client: httpx.AsyncClient, domain: str, st: Settings) -> tuple[set[str], list[str]]:
    log = [f"Querying urlscan.io for {domain} ..."]
    body = await fetch(
        client, f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
        timeout=15, attempts=3, log=log,
    )
    if body is None:
        log.append("urlscan: all retries failed")
        return set(), log
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        log.append("urlscan: malformed JSON — falling back to a text scrape")
        return scrape_domains(body, domain), log
    results = data.get("results", []) if isinstance(data, dict) else []
    names = [
        r["task"]["domain"]
        for r in results
        if isinstance(r, dict) and isinstance(r.get("task"), dict) and r["task"].get("domain")
    ]
    return clean(names, domain), log


async def src_wayback(client: httpx.AsyncClient, domain: str, st: Settings) -> tuple[set[str], list[str]]:
    log = [f"Querying Wayback CDX API for *.{domain} ..."]
    body = await fetch(
        client,
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        "&output=text&fl=original&collapse=urlkey&limit=5000",
        timeout=20, attempts=2, log=log,
    )
    if body is None:
        log.append("wayback: all retries failed")
        return set(), log
    # Percent-decode first: the bash version scraped raw CDX lines and leaked
    # names like "2fwww.xbox.com" out of encoded "%2Fwww.xbox.com" paths.
    decoded = re.sub(
        r"%([0-9a-fA-F]{2})",
        lambda m: chr(int(m.group(1), 16)),
        body,
    )
    return scrape_domains(decoded, domain), log


async def src_alienvault(client: httpx.AsyncClient, domain: str, st: Settings) -> tuple[set[str], list[str]]:
    # Anonymous access to this endpoint returns 429 unconditionally
    # ("Please authenticate"), so without a key it is pure wasted wall-clock.
    if not st.otx_key:
        return set(), ["Skipping AlienVault OTX (set OTX_API_KEY to enable — anonymous access is refused)"]
    log = [f"Querying AlienVault OTX for {domain} ..."]
    body = await fetch(
        client,
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=15, attempts=2, headers={"X-OTX-API-KEY": st.otx_key}, log=log,
    )
    if body is None:
        log.append("alienvault: all retries failed")
        return set(), log
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        log.append("alienvault: malformed JSON — falling back to a text scrape")
        return scrape_domains(body, domain), log
    entries = data.get("passive_dns", []) if isinstance(data, dict) else []
    return clean([e.get("hostname") for e in entries if isinstance(e, dict)], domain), log


async def src_rapiddns(client: httpx.AsyncClient, domain: str, st: Settings) -> tuple[set[str], list[str]]:
    log = [f"Querying rapiddns.io for {domain} ..."]
    body = await fetch(
        client, f"https://rapiddns.io/subdomain/{domain}?full=1",
        timeout=20, attempts=3, log=log,
    )
    if body is None:
        log.append("rapiddns.io: all retries failed (or page format changed)")
        return set(), log
    return scrape_domains(body, domain), log


async def dns_records(domain: str) -> tuple[set[str], list[str]]:
    """A/MX/NS/TXT of the apex, for hostnames the passive sources missed."""
    log = [f"Checking DNS records for {domain} ..."]
    found: set[str] = set()
    for rtype in ("A", "MX", "NS", "TXT"):
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", domain, rtype,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        for line in out.decode(errors="replace").splitlines():
            token = line.split()[-1].rstrip(".") if line.split() else ""
            found |= clean([token], domain)
    log.append(
        "dns records found additional entries" if found else "no additional DNS record entries"
    )
    return found, log


SECTION_TITLES = {
    "subfinder": "subfinder (passive)",
    "crtsh": "crt.sh (Certificate Transparency)",
    "certspotter": "Certspotter API",
    "hackertarget": "HackerTarget API",
    "urlscan": "URLScan.io",
    "wayback": "Wayback Machine (web.archive.org)",
    "alienvault": "AlienVault OTX",
    "rapiddns": "RapidDNS.io",
}


async def collect(domain: str, st: Settings) -> tuple[dict[str, set[str]], set[str], list[tuple[str, list[str]]]]:
    """Run every source concurrently. Returns per-source results, dig extras, logs."""
    limits = httpx.Limits(max_connections=16)
    async with httpx.AsyncClient(follow_redirects=True, limits=limits) as client:
        async with asyncio.TaskGroup() as tg:
            tasks = {
                "subfinder": tg.create_task(src_subfinder(domain, st)),
                "crtsh": tg.create_task(src_crtsh(client, domain, st)),
                "certspotter": tg.create_task(src_certspotter(client, domain, st)),
                "hackertarget": tg.create_task(src_hackertarget(client, domain, st)),
                "urlscan": tg.create_task(src_urlscan(client, domain, st)),
                "wayback": tg.create_task(src_wayback(client, domain, st)),
                "alienvault": tg.create_task(src_alienvault(client, domain, st)),
                "rapiddns": tg.create_task(src_rapiddns(client, domain, st)),
                "dnsrecords": tg.create_task(dns_records(domain)),
            }

    results: dict[str, set[str]] = {}
    logs: list[tuple[str, list[str]]] = []
    for name in SOURCE_NAMES:
        found, log = tasks[name].result()
        results[name] = found
        logs.append((SECTION_TITLES[name], log + [f"{name}: {len(found)} domains"]))
    extra, dig_log = tasks["dnsrecords"].result()
    logs.append(("DNS records", dig_log))
    return results, extra, logs


# ── DNS validation ────────────────────────────────────────────────────────────


async def run_dnsx(raw_file: Path, st: Settings) -> list[str]:
    """One dnsx pass with -resp. Returns 'host [A] [ip]' lines, sorted-unique.

    One pass, not two: all_domains.txt is derived from this output rather than
    from a second dnsx run, so the two files cannot disagree and the resolver
    sees half the query volume.
    """
    args = [
        "dnsx", "-l", str(raw_file), "-silent", "-resp",
        "-t", str(st.dnsx_threads), "-retry", str(st.dnsx_retry),
    ]
    if st.dnsx_resolvers:
        args += ["-r", st.dnsx_resolvers]
    if st.dnsx_ratelimit:
        args += ["-rl", st.dnsx_ratelimit]
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    out, _ = await proc.communicate()
    lines = {ANSI_RE.sub("", ln).strip() for ln in out.decode(errors="replace").splitlines()}
    return sorted(ln for ln in lines if ln)


# ── Files ─────────────────────────────────────────────────────────────────────


def write_lines(path: Path, lines: object) -> None:
    body = "\n".join(sorted(lines)) if not isinstance(lines, str) else lines
    path.write_text(body + "\n" if body else "", encoding="utf-8")


def read_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()}


def count(path: Path) -> int:
    return len(read_lines(path))


# ── One target ────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class Outcome:
    status: str              # ok | new | refused | failed
    new_count: int = 0
    gone_count: int = 0
    exit_code: int = 0


async def recon(domain: str, outdir: Path, *, diff: bool, force: bool, st: Settings) -> Outcome:
    outdir.mkdir(parents=True, exist_ok=True)
    raw_file = outdir / "all_raw.txt"

    results, extra, logs = await collect(domain, st)
    for title, lines in logs:
        section(title)
        for i, line in enumerate(lines):
            (ok if i == len(lines) - 1 and "domains" in line else info)(line)

    for name in SOURCE_NAMES:
        write_lines(outdir / f"{name}.txt", results[name])

    candidates: set[str] = set(extra)
    for found in results.values():
        candidates |= found
    write_lines(raw_file, candidates)

    section("Deduplication")
    total = len(candidates)
    ok(f"Total unique candidates: {total}")

    section("DNS validation (dnsx)")
    # An empty candidate pool would "validate" to zero results and wipe the
    # deliverable, so stop before anything is touched.
    if total == 0:
        err("No candidates collected — every source failed. Existing results left untouched.")
        return Outcome("refused", exit_code=3)

    info(f"Validating {total} candidates (threads={st.dnsx_threads}, retry={st.dnsx_retry}) ...")
    resp_lines = await run_dnsx(raw_file, st)
    alive_hosts = sorted({ln.split()[0] for ln in resp_lines if ln.split()})
    alive, dead = len(alive_hosts), total - len(alive_hosts)

    # ── Retention guard ──────────────────────────────────────────────────────
    # dnsx exits 0 even when it resolves nothing, so a throttled resolver would
    # otherwise silently replace a good Podkop list with an empty one.
    domains_file = outdir / "all_domains.txt"
    prev_alive = count(domains_file)
    rejected_file = outdir / "all_domains.rejected.txt"

    if not force and prev_alive > 0 and alive * 100 < prev_alive * st.min_retain:
        write_lines(rejected_file, alive_hosts)
        err(f"DNS validation collapsed: {alive} alive vs {prev_alive} previously "
            f"(below {st.min_retain}%).")
        err(f"Existing results left untouched. Suspect output: {rejected_file}")
        err("This is almost always a throttled resolver, not real domain death — re-run later.")
        err("Override with --force, or lower the bar with RECON_MIN_RETAIN=<percent>.")
        return Outcome("refused", exit_code=3)
    rejected_file.unlink(missing_ok=True)

    # Snapshot the previous list only now that the new one has passed the
    # guard, so a rejected run can never clobber the last known-good list.
    prev_file = outdir / "all_domains.prev.txt"
    have_prev = domains_file.exists()
    if have_prev:
        prev_file.write_bytes(domains_file.read_bytes())
    write_lines(outdir / "all_domains_with_ip.txt", resp_lines)
    write_lines(domains_file, alive_hosts)
    ok(f"Alive: {alive}  |  Dead (no DNS): {dead}")

    new_count = gone_count = 0
    if diff:
        section("Diff vs previous run")
        if have_prev:
            prev_set = read_lines(prev_file)
            cur_set = set(alive_hosts)
            new_domains = sorted(cur_set - prev_set)
            gone_domains = sorted(prev_set - cur_set)
            write_lines(outdir / "all_domains.new.txt", new_domains)
            write_lines(outdir / "all_domains.gone.txt", gone_domains)
            new_count, gone_count = len(new_domains), len(gone_domains)
            if new_count:
                ok(f"New domains since last run ({new_count}):")
                print("\n".join(new_domains))
            else:
                info("No new domains since last run.")
            # Losses matter too: an exit code that only ever signalled gains
            # made a run that shed thousands of domains look like a no-op.
            if gone_count:
                warn(f"Domains gone since last run ({gone_count}) — see all_domains.gone.txt")
        else:
            info("No previous run found — nothing to diff.")
            write_lines(outdir / "all_domains.new.txt", [])

    section("Summary")
    print(f"\n{_c('1', 'Target:')}     {domain}")
    print(f"{_c('1', 'Output:')}     {outdir}/\n")
    print(f"{_c('1', 'Live domains (first 50 of ' + str(alive) + '):')}")
    print("\n".join(alive_hosts[:50]))
    if alive > 50:
        print(f"  ... {alive - 50} more in {domains_file}")
    print()
    ok(f"Done. Use {_c('1', str(domains_file))} for Podkop.")

    status = "new" if (diff and new_count) else "ok"
    return Outcome(status, new_count, gone_count, exit_code=2 if status == "new" else 0)


# ── --all mode ────────────────────────────────────────────────────────────────


def read_targets(mapfile: Path) -> list[tuple[str, list[str]]]:
    targets: list[tuple[str, list[str]]] = []
    for line in mapfile.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        folder, *domains = line.split()
        if domains:
            targets.append((folder, domains))
    return targets


def root_suffixes(domains: list[str]) -> list[str]:
    """Per-source file suffixes for a multi-root target, in the order given.

    The root's first label is enough for supercell.com + brawlstarsgame.com,
    but not for playstation.com + playstation.net — both claim "playstation",
    and the second root would silently overwrite the first one's files. A
    colliding label falls back to the whole domain with dots turned into dashes.
    """
    labels = [d.split(".")[0] for d in domains]
    return [lab if labels.count(lab) == 1 else d.replace(".", "-")
            for d, lab in zip(domains, labels, strict=True)]


async def update_multiroot(folder: str, domains: list[str], root: Path, st: Settings) -> Outcome:
    """Multi-root target: one recon per root domain, merged into one folder.

    The merged list only exists here, so the retention guard has to be applied
    here too — and a failed root must not be allowed to overwrite the real
    files, which is how brawlstars-recon lost its whole list.
    """
    target_dir = root / folder
    target_dir.mkdir(parents=True, exist_ok=True)
    merged_raw: set[str] = set()
    merged_domains: set[str] = set()
    merged_ips: set[str] = set()
    any_failed = False

    import tempfile

    for d, suffix in zip(domains, root_suffixes(domains), strict=True):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            try:
                outcome = await recon(d, scratch, diff=False, force=False, st=st)
            except Exception as exc:  # noqa: BLE001 - one root must not kill the rest
                warn(f"{folder}/{d}: {type(exc).__name__}: {exc}")
                any_failed = True
                continue
            if outcome.exit_code not in (0, 2):
                warn(f"{folder}/{d}: recon exited with code {outcome.exit_code}")
                any_failed = True
            for name in SOURCE_NAMES:
                src = scratch / f"{name}.txt"
                if src.exists() and src.stat().st_size:
                    (target_dir / f"{name}_{suffix}.txt").write_bytes(src.read_bytes())
            merged_raw |= read_lines(scratch / "all_raw.txt")
            merged_domains |= read_lines(scratch / "all_domains.txt")
            merged_ips |= read_lines(scratch / "all_domains_with_ip.txt")
        await asyncio.sleep(2)

    domains_file = target_dir / "all_domains.txt"
    if any_failed:
        err(f"{folder}: at least one root domain failed — not overwriting existing results")
        return Outcome("failed", exit_code=1)

    prev_alive = count(domains_file)
    if prev_alive > 0 and len(merged_domains) * 100 < prev_alive * st.min_retain:
        write_lines(target_dir / "all_domains.rejected.txt", merged_domains)
        err(f"{folder}: merged list collapsed to {len(merged_domains)} from {prev_alive} "
            f"(below {st.min_retain}%) — not overwriting")
        return Outcome("refused", exit_code=3)
    (target_dir / "all_domains.rejected.txt").unlink(missing_ok=True)

    prev_file = target_dir / "all_domains.prev.txt"
    have_prev = domains_file.exists()
    if have_prev:
        prev_file.write_bytes(domains_file.read_bytes())
    write_lines(target_dir / "all_raw.txt", merged_raw)
    write_lines(target_dir / "all_domains_with_ip.txt", merged_ips)
    write_lines(domains_file, merged_domains)

    new_count = gone_count = 0
    if have_prev:
        prev_set = read_lines(prev_file)
        new_count = len(merged_domains - prev_set)
        gone_count = len(prev_set - merged_domains)
        write_lines(target_dir / "all_domains.new.txt", merged_domains - prev_set)
        write_lines(target_dir / "all_domains.gone.txt", prev_set - merged_domains)
    return Outcome("new" if new_count else "ok", new_count, gone_count)


async def update_all(root: Path, jobs: int, dry_run: bool, st: Settings) -> int:
    mapfile = root / "targets.conf"
    if not mapfile.exists():
        err(f"targets.conf not found at {mapfile}")
        return 1
    targets = read_targets(mapfile)
    if not targets:
        err(f"No targets found in {mapfile}")
        return 1

    if dry_run:
        info(f"Dry run — {len(targets)} targets, {jobs} at a time")
        for folder, domains in targets:
            section(folder)
            if len(domains) == 1:
                info(f"Would run: recon {domains[0]} -> {root / folder} --diff")
            else:
                for d in domains:
                    info(f"Would run: recon {d} -> <scratch>, merge into {root / folder} as *_{d.split('.')[0]}.txt")
        section("Summary")
        info("Dry run complete — no network requests made.")
        return 0

    sem = asyncio.Semaphore(jobs)
    buffers: dict[str, list[str]] = {}

    async def one(folder: str, domains: list[str]) -> Outcome:
        async with sem:
            # Buffer this target's stdout so concurrent targets don't interleave.
            import contextlib, io

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                if len(domains) == 1:
                    section(f"Updating {folder} ({domains[0]})")
                    try:
                        outcome = await recon(domains[0], root / folder, diff=True, force=False, st=st)
                    except Exception as exc:  # noqa: BLE001
                        err(f"{folder}: {type(exc).__name__}: {exc}")
                        outcome = Outcome("failed", exit_code=1)
                else:
                    section(f"Updating {folder} (multi-root: {' '.join(domains)})")
                    outcome = await update_multiroot(folder, domains, root, st)
            buffers[folder] = [buf.getvalue()]
            return outcome

    info(f"Updating {len(targets)} targets, {jobs} at a time ...")
    async with asyncio.TaskGroup() as tg:
        tasks = [(folder, tg.create_task(one(folder, domains))) for folder, domains in targets]

    for folder, _ in tasks:
        sys.stdout.write("".join(buffers.get(folder, [])))

    changed, lost, refused, failed = [], [], [], []
    for folder, task in tasks:
        outcome = task.result()
        match outcome.status:
            case "new":
                changed.append(f"{folder}(+{outcome.new_count})")
            case "refused":
                refused.append(folder)
            case "failed":
                failed.append(folder)
        if outcome.gone_count:
            lost.append(f"{folder}(-{outcome.gone_count})")

    section("Summary")
    if changed:
        ok(f"Targets with new domains: {' '.join(changed)}")
    else:
        info("No targets had new domains this run.")
    if lost:
        warn(f"Targets that lost domains: {' '.join(lost)}")
    if refused:
        err(f"Refused by the retention guard (results left untouched): {' '.join(refused)}")
    if failed:
        err(f"Failed: {' '.join(failed)}")
    return 1 if (refused or failed) else 0


# ── Entry point ───────────────────────────────────────────────────────────────


def check_deps(need_dnsx: bool = True) -> None:
    if os.environ.get("RECON_SKIP_DEPCHECK") == "1":
        return
    tools = ["subfinder", "dig"] + (["dnsx"] if need_dnsx else [])
    missing = [t for t in tools if shutil.which(t) is None]
    if not missing:
        return
    err(f"Missing required tools: {', '.join(missing)}")
    err("  macOS:  brew install subfinder dnsx")
    err("  Linux:  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    err("          go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
    err("  dig comes from bind-utils / dnsutils / bind.")
    raise SystemExit(3)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="Passive domain recon for Podkop (Python port of recon.sh).",
    )
    parser.add_argument("domain", nargs="?", help="target domain, e.g. figma.com")
    parser.add_argument("outdir", nargs="?", help="output directory (default ./recon-<domain>)")
    parser.add_argument("--diff", action="store_true", help="compare against the previous run")
    parser.add_argument("--force", action="store_true", help="bypass the retention guard")
    parser.add_argument("--all", action="store_true", help="run every target in targets.conf")
    parser.add_argument("-j", "--jobs", type=int, default=3, metavar="N",
                        help="with --all: targets to run concurrently (default 3)")
    parser.add_argument("--dry-run", action="store_true", help="with --all: resolve the plan only")
    args = parser.parse_args()

    st = Settings()

    if args.all:
        if args.domain:
            parser.error("--all takes no domain argument")
        if args.jobs < 1:
            parser.error("-j expects a positive integer")
        if not args.dry_run:
            check_deps()
        return asyncio.run(update_all(Path(__file__).resolve().parent, args.jobs, args.dry_run, st))

    if not args.domain:
        parser.error("a domain is required (or use --all)")
    domain = validate_domain(args.domain)
    check_deps()
    outdir = Path(args.outdir) if args.outdir else Path(f"./recon-{domain}")
    outcome = asyncio.run(recon(domain, outdir, diff=args.diff, force=args.force, st=st))
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
