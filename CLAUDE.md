# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this project is

`cvss-bt` enriches NVD CVSS **Base** scores into **CVSS-BT** (Base + Threat/Temporal)
scores by deriving the Exploit Code Maturity/Exploitability (`E`) metric from public
exploit-intelligence sources, then publishes the result as `cvss-bt.csv` once a day.

It is a **data-publishing pipeline**, not an application or a library. There is no
server, no API, and nothing to deploy. The deliverable is the CSV.

## Layout

```
code/enrich_nvd.py      # threat-intel sources, E-metric logic, CVSS-BT computation
code/process_nvd.py     # entry point: parse NVD JSON -> enrich -> write cvss-bt.csv
code/requirements.txt   # cvss, pandas, requests, ijson
code/last_run.txt       # UTC timestamp of last successful run (workflow guard)
.github/workflows/      # epss.yml (trigger) -> cvss-bt.yml (enrich + publish)
test.sh                 # local end-to-end dry run (NOT a unit test suite)
cvss-bt.csv             # published output, ~86 MB / ~382k rows, bot-committed daily
```

## Running it

Always run from the **repository root** — every path in the code is relative to the
CWD, and `process_nvd.py` imports `enrich_nvd` as a sibling module off `sys.path[0]`:

```bash
pip install -r code/requirements.txt
python -u code/process_nvd.py     # expects NVD *.json already unzipped in the root
```

`test.sh` does the full local loop (EPSS availability check, fetch the NVD bundle,
run the pipeline). It needs `VULNCHECK_API_KEY` in the environment plus `curl`,
`jq`, and `unzip`.

`VULNCHECK_API_KEY` is required for anything that touches VulnCheck (the NVD bundle
download and the VulnCheck KEV feed). Without it the run still completes, but
`vulncheck_kev` silently comes back empty and scores will be wrong — never treat a
green run without the key as a valid result.

There is **no test suite and no linter config**. Validate changes by running the
pipeline and diffing the output distribution, not by looking for tests to run.

## Pipeline shape

1. `epss.yml` runs hourly 11:00–15:00 UTC. It exits non-zero — deliberately — if the
   enrichment already ran today (`code/last_run.txt`) or if today's EPSS file is not
   yet published. **A failed `epss.yml` run is normal control flow, not a bug.**
2. On success it triggers `cvss-bt.yml` via `workflow_run`.
3. `cvss-bt.yml` pulls the NVD bundle from VulnCheck's mirror, runs the pipeline,
   commits `cvss-bt.csv` + `code/last_run.txt` straight to `main`, tags
   `vYYYY.MM.DD`, and attaches the CSV to a GitHub release.

## Data sources

| Source | Fetched from | Feeds column |
|---|---|---|
| NVD (via VulnCheck mirror) | `api.vulncheck.com/v3/backup/nist-nvd` | base score/vector |
| EPSS | `epss.empiricalsecurity.com/epss_scores-<date>.csv.gz` | `epss` |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | `cisa_kev` |
| VulnCheck KEV | `api.vulncheck.com/v3/index/vulncheck-kev` (paginated) | `vulncheck_kev` |
| ExploitDB | `gitlab.com/exploit-database/exploitdb` `files_exploits.csv` | `exploitdb` |
| Metasploit | `modules_metadata_base.json` on `master` | `metasploit` |
| Nuclei | `nuclei-templates` `cves.json` on `main` | `nuclei` |
| PoC-in-GitHub | `nomi-sec/PoC-in-GitHub` `README.md`, regex-scraped | `poc_github` |

All are unpinned upstream fetches over the network. A schema change upstream breaks
the run — if the pipeline suddenly fails or a column goes all-`False`, suspect an
upstream format change before suspecting the code.

## E-metric rules (`update_temporal_score`, `code/enrich_nvd.py`)

Threshold: `EPSS_THRESHOLD = 0.36` in `code/enrich_nvd.py:17`. This is the single
source of truth — the README's `.36` is documentation of it, not a second copy.

The mapping is **not uniform across CVSS versions**. Get this wrong and scores shift
silently across hundreds of thousands of rows:

- **CVSS 4.0**: `E:A` for CISA KEV / VulnCheck KEV / EPSS ≥ threshold / **Metasploit**;
  `E:P` for Nuclei / ExploitDB / PoC-in-GitHub. There is no `E:F` in v4.0.
- **CVSS 3.x**: `E:H` for KEV / EPSS ≥ threshold (Metasploit does *not* reach `E:H`);
  `E:F` for Metasploit / Nuclei; `E:P` for ExploitDB / PoC-in-GitHub.
- **CVSS 2.0**: same as 3.x except the PoC value is spelled **`E:POC`**, not `E:P`.
- Default is `E:U`; `E:X` is never emitted.

Scoring also differs by version in `compute_cvss`: v4.0 reads `CVSS4.base_score`
(the v4 class folds threat metrics into that score), while v3.x/v2.0 read
`temporal_score`. Failures per-row degrade to `UNKNOWN`/`UNKNOWN` rather than
aborting the run — so check the output for `UNKNOWN` counts after any change here.

## Gotchas

- `EPSS_CSV` at `code/enrich_nvd.py:8` (`'data/epss/epss_scores.csv'`) is **dead** —
  the real EPSS URL is `EPSS_CSV` in `code/process_nvd.py:7`, and the dataframe is
  passed into `enrich()`. Don't "fix" the wrong one.
- Date skew: `process_nvd.py` builds the EPSS URL from `date.today()` (runner-local /
  UTC) while `epss.yml` and `test.sh` check availability with `TZ=America/New_York`.
  Around the UTC day boundary these can disagree.
- CVSS 4.0 arrives as `impact.metricV40` — a **VulnCheck extension** to the NVD 1.1
  JSON schema, not standard NVD. Code reading it will not work against NVD's own feed.
- Rejected CVEs are filtered by description starting with `**` (i.e. `** REJECT **`).
- VulnCheck KEV entries carry a *list* of CVEs, joined with `', '` into one string
  before the merge. Multi-CVE entries therefore never match a single CVE and are
  effectively dropped.
- Nuclei parsing hard-drops the `Info` and `file_path` columns; a schema change there
  raises rather than degrades.
- `.gitignore` ignores `*.json`, so any downloaded NVD bundle stays untracked — and
  a JSON file you *do* want tracked needs `git add -f`.
- `epss.yml` triggers on pushes to a `dev` branch that no longer exists.
- The workflows use archived/deprecated actions (`checkout@v2`, `setup-python@v2`,
  `create-release@v1`, `upload-release-asset@v1`) and `::set-output`. Known stale;
  leave alone unless the task is specifically to modernize CI.

## Working conventions

- **Never hand-edit or regenerate `cvss-bt.csv` in a feature branch.** It is 86 MB
  and owned by the daily bot commit; a regenerated copy makes the diff unreviewable
  and will conflict. Change the code, let the workflow republish.
- Recent history is entirely `Updated CVSS-BT data <date>` bot commits — do not take
  that as the commit-message convention for code changes.
- If the E-metric mapping or the EPSS threshold changes, update the README's mapping
  table and Caveats section in the same change; they document that logic directly.
- Keep credentials in `VULNCHECK_API_KEY` only. No other secrets are used.

## Related repositories (same owner, no code dependency)

Adjacent vulnerability-scoring work — useful background, but nothing here imports
from or is imported by them:

- `t0sche/exploit_hazard_model` — Bayesian local exploit-hazard model, research
  artifact for arXiv:2607.24618. Consumes EPSS/CVSS/KEV directly, not this CSV.
- `t0sche/exploit_hazard`, `t0sche/epss_weibull_hazard_k` — private, same problem space.
- `FIRSTdotorg/epss-vendors` — a Markdown list of EPSS-supporting vendors.
