# Getting Started with Threat-X

This walks through getting the pipeline running on your machine, from nothing to
a live dashboard. It's split into two paths: **fixture mode** (works right away,
no Docker/scanner installs needed) and **live mode** (real scans against real
targets). Do fixture mode first — it proves the whole pipeline works before you
deal with scanner installs.

## 1. Prerequisites

Already required, no extra install:
- Python 3.12+ (check with `python3 --version`)
- Internet access (the enrichment phase calls NVD/CISA KEV/FIRST EPSS live)

Only required for **live mode** (scanning a real target instead of fixtures):
- Docker, with the daemon running (`docker info` should succeed) — needed for the ZAP scan
- `nuclei` on PATH ([install docs](https://docs.projectdiscovery.io/tools/nuclei/install))
- `nmap` on PATH (`apt install nmap` / `brew install nmap`)

You don't need to check these yourself — `pipeline.py run --target-url ...`
checks all three up front and fails immediately with a clear list of what's
missing, rather than dying partway through a scan.

Optional, nice-to-have:
- `searchsploit` (`apt install exploitdb`) — without it, Exploit-DB availability
  just always reports `False` instead of erroring; everything else still works.
- `GEMINI_API_KEY` — unlocks AI-assisted semantic dedup and per-finding
  summaries (see `README.md`'s environment variables table). Free tier is
  fairly rate-limited (a handful of requests/minute); if you hit `429`s, the
  pipeline retries automatically and otherwise just logs a warning and moves
  on rather than failing the run.

## 2. Install

```bash
cd /home/vishal/Threat-X
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Leave `.env` mostly empty for now — every credential in it is optional and the
pipeline degrades gracefully without them (details in section 4).

## 3. Run it — fixture mode (start here)

This uses committed sample scanner output (`tests/fixtures/`) instead of live
scans, so it works immediately with nothing but Python installed:

```bash
python pipeline.py run --scan-id demo --use-fixtures
python scripts/verify_key_criteria.py demo
```

You should see all 4 criteria pass:

```
[x] Key Criterion #1: >=2 scanner outputs merged into one normalized dataset
[x] Key Criterion #2: measurable noise reduction (dedup % + FPs removed)
[x] Key Criterion #3: scoring driven by real threat intel, not raw CVSS alone
[x] Key Criterion #4: explainable, ticket-ready ranking with owners/SLAs
```

Then launch the dashboard:

```bash
streamlit run dashboard/app.py
```

Open http://localhost:8501 and pick `demo` from the sidebar.

Or do all of the above in one command: `./scripts/demo.sh demo`

## 4. Run it — live mode (real scans)

Once fixture mode works, point it at a real target — **one command**:

```bash
python pipeline.py run --scan-id myapp --target-url https://your-app.example.com --fast
```

That's it. It checks for Nuclei/Nmap/Docker up front, figures out the hostname
for Nmap automatically, runs all three scanners, and chains straight into
dedup → enrich → score → ticket. **Only scan a target you own or have
explicit written authorization to test.** If you don't have your own
infrastructure handy, [scanme.nmap.org](https://scanme.nmap.org) is the Nmap
project's own test target, explicitly put up for exactly this.

A few flags worth knowing:
- **`--fast`** — trims each scanner's scope for a much quicker (if less
  thorough) run: Nuclei only checks higher-severity/relevant template
  categories, Nmap drops its slowest script and limits itself to the top 100
  ports, ZAP's crawl is capped at 2 minutes. Drop it for a full, slower,
  more thorough scan.
- **`--nmap-target <host-or-ip>`** (repeatable) — override what Nmap scans;
  defaults to `--target-url`'s hostname.
- The `ingest` subcommand alone also accepts `--target-url`/`--fast` if you
  just want that one phase without chaining into the rest.

Then, same as fixture mode:
```bash
python scripts/verify_key_criteria.py myapp
streamlit run dashboard/app.py     # pick 'myapp' from the sidebar
```

### Alternative: your own disposable target (Juice Shop + Metasploitable2)

If you'd rather stand up a known-vulnerable target locally instead of scanning
something on the internet:

```bash
./scripts/setup_target.sh        # brings up Juice Shop + Metasploitable2 on an isolated Docker network
source data/.target_env          # sets $JUICE_IP / $META_IP for this shell
python pipeline.py run --scan-id live1 --target-url http://localhost:3000 \
  --nmap-target "$JUICE_IP" --nmap-target "$META_IP"
```

`scripts/setup_target.sh` explains in its comments why Metasploitable2 is there
(Juice Shop alone only exposes one port, so Nmap needs a second target to find
anything). Never expose Metasploitable2's ports outside that isolated network —
it's deliberately unpatched.

## 5. Assigning tickets

Tickets get created automatically by the `ticket` phase (score ≥70), but
*who* they're assigned to on GitHub is separate from that, and works two ways:

**Before a ticket exists — per host, via config.** `config/assets.yaml` has a
`github_username` field per asset, independent of the `owner`/`team` fields
(those are just free-text display labels, never validated against a real
account):

```yaml
juice-shop:
  github_username: "Vishal-V2"    # must be a real GitHub login with repo access
```

Any *new* ticket created for that host picks this up automatically — it
doesn't touch tickets already on GitHub.

**After a ticket already exists — the `assign` command:**

```bash
python pipeline.py assign 5 -u Vishal-V2              # by issue number
python pipeline.py assign <issue-url> -u alice -u bob  # or paste the full URL; multiple assignees
python pipeline.py assign 5                            # no -u at all = unassign everyone
```

One thing to know: `-u` **replaces** the entire assignee list, it doesn't
add to it — to keep an existing assignee while adding another, list both.

## 6. Verify everything

```bash
pytest tests/ -q
```

34 tests, covering the parsers, dedup logic, enrichment cache/fallback/resilience
(all four sources: NVD/KEV/EPSS/Exploit-DB), scoring formula, live-scan
invocation (Nmap script selection, ZAP's permission/exit-code handling — both
mocked, no Docker/nmap needed), CVE-ID normalization, ticket owner/assignee
config lookups, and a full acceptance test that re-runs the pipeline and
re-checks all 4 Key Criteria. This makes live network calls to NVD/EPSS/KEV
(cached after the first run) but needs no Docker/scanners/API keys.

## 7. Troubleshooting

- **`streamlit run` hangs / asks for an email in the terminal**: first-run
  telemetry prompt, only happens with a truly blank terminal session. Add
  `--server.headless true` to the command, or just press Enter.
- **`docker info` fails**: the daemon isn't running — start Docker Desktop (or
  `sudo systemctl start docker` on Linux) before a live scan.
- **ZAP's spider fails with "Network is unreachable"**: seen specifically when
  Docker is running in **rootless mode** — its userspace network stack can
  block a container's outbound access on a custom bridge network. Normal
  (non-rootless) Docker doesn't have this issue; if you're intentionally on
  rootless Docker, this is a known limitation to work around on your own
  network setup, not a Threat-X bug.
- **NVD enrichment is slow, or you see an occasional `[warn] NVD lookup
  failed`**: the unauthenticated rate limit is tight (5 req/30s), and NVD's
  API is occasionally flaky even within that limit. A free `NVD_API_KEY`
  raises it to 50 req/30s and mostly clears this up. Either way, a single
  failed CVE lookup logs a warning and falls back to a severity-based score
  instead of failing the whole run — results are cached in
  `data/cache/enrichment_cache.db` regardless, so repeated runs against the
  same CVEs are instant.
- **`[warn] AI summary failed ... 429 RESOURCE_EXHAUSTED`**: Gemini's free
  tier rate/quota limit — expected under heavy use, not a bug. The pipeline
  retries automatically (using the API's own suggested wait time when given)
  and otherwise just skips that finding's summary rather than failing the run.
- **Ticketing says "skipping"**: expected until you set `GITHUB_TOKEN` +
  `GITHUB_REPO` — see next section. If it instead prints a `403` about
  insufficient permissions, your token needs the `repo` scope (classic PAT) or
  `Issues: Read and write` (fine-grained PAT).
- **Just ran `assign` (or created a ticket) and the GitHub UI/API still shows
  the old state**: GitHub's own read-after-write consistency lag — we saw this
  twice in testing, where a `GET` immediately after a successful `PATCH`
  briefly returned stale data. Wait a couple seconds and check again; it's not
  a bug in the `assign` command or the token.

## What's next

See the next section of this conversation (or `README.md`'s "Environment
variables" table) for exactly which API keys unlock which features, and where
to get each one.
