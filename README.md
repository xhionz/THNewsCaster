# THNewsCaster

**Threat-Hunting focused News Platform.** Ingests security news, vendor
research and social-media RSS, decides which stories matter for a threat
hunter, and emits a structured *hunt package* with hypotheses and
CTF-style disproof objectives for each relevant article.

THNewsCaster runs end-to-end on the Python standard library (no
runtime dependencies), so it works in air-gapped or restricted
environments — and ships with a bundled sample feed so the pipeline
always has something to chew on.

---

## What it produces

For every article that clears the relevance threshold the platform
emits a **briefing** containing:

1. **Article metadata** — title, source, link, published date, summary.
2. **Extracted signals** — CVEs, IPs, domains, hashes (MD5/SHA1/SHA256),
   malware families, threat actors, MITRE ATT&CK techniques, initial
   access vectors, products, sectors, impact actions.
3. **Relevance score** — 0–100 with an itemised rationale.
4. **At least 3 hypotheses** (typically 3–4) drawn from these
   archetypes:
   - `initial_access_cve` — exploitation of the reported CVE
   - `malware_execution` — payload landing & persistence on endpoints
   - `c2_beacon` — outbound C2 / RMM beaconing to reported IOCs
   - `lateral_movement` — post-foothold pivoting via RDP/SMB/Kerberos
   - `exfiltration` — staging and bulk data egress
   - `identity_compromise` — phishing / MFA fatigue / OAuth abuse
5. **3 to 5 CTF-style objectives per hypothesis.** Each objective is a
   *falsification test* — find evidence whose absence would disprove
   the hypothesis — with a difficulty (`easy` / `medium` / `hard`), a
   point value, a falsification criterion, suggested data sources, a
   sample SIEM-agnostic query, and mapped ATT&CK technique IDs.

The whole package is written as both `hunt_package.json` (machine-
readable) and `hunt_package.md` (analyst-readable briefing).

---

## Install / run

```bash
# from a checkout
python -m pip install -e .

# or just run it in-place
PYTHONPATH=src python -m thnewscaster --offline --out-dir out/
```

### Common invocations

```bash
# Live pull from the default feed list (Bleeping, THN, Krebs, CISA, Talos, Unit42, /r/netsec, …)
python -m thnewscaster --out-dir out/

# Air-gapped: use the bundled sample feed (also used if no live feed is reachable)
python -m thnewscaster --offline --out-dir out/

# Ingest your own RSS/Atom XML files
python -m thnewscaster --feed-file feeds/cisa.xml --feed-file feeds/talos.xml --out-dir out/

# Lower the relevance threshold (default 30) to keep more articles
python -m thnewscaster --threshold 20 --out-dir out/

# Stream Markdown to stdout
python -m thnewscaster --offline --print
```

### Outputs

```
out/
├── hunt_package.json   # full structured package
└── hunt_package.md     # analyst-ready briefing
```

A pre-rendered example is in [`examples/hunt_package.md`](examples/hunt_package.md).

---

## Hosting on GitHub Pages

The repo includes `.github/workflows/pages.yml`, which:

1. Runs the test suite.
2. Rebuilds the package (live feeds first, with an offline fallback).
3. Renders `site/index.html` + `site/hunt_package.json` via `--html`.
4. Publishes the `site/` directory to GitHub Pages using the official
   `actions/upload-pages-artifact` + `actions/deploy-pages` actions.

It triggers on push to `main`, on a 6-hourly cron, and via
`workflow_dispatch`. Enable Pages in **Settings → Pages → Build and
deployment → Source: GitHub Actions** once, then the URL surfaces in
the workflow's deploy job (typically
`https://<user>.github.io/<repo>/`).

A pre-rendered copy of the site lives under `docs/` so reviewers can
browse it without running the workflow:

```bash
python -m http.server -d docs 8000
# open http://localhost:8000
```

To render the site locally yourself:

```bash
PYTHONPATH=src python -m thnewscaster --offline --html --out-dir site/
python -m http.server -d site 8000
```

## Architecture

```
feeds.py        ── stdlib RSS/Atom fetch + parse
   │
   ▼
extraction.py   ── regex IOCs + alias lookup vs intel.py
   │
   ▼
relevance.py    ── weighted score; hunt-worthy if >= threshold
   │
   ▼
hypotheses.py   ── pick 3–4 archetypes that fit the signals
   │
   ▼
objectives.py   ── for each archetype emit 3–5 CTF disproof objectives
   │
   ▼
package.py      ── assemble HuntPackage; render JSON + Markdown
```

All components are in `src/thnewscaster/`. The intel knowledge base
(malware families, threat actors, MITRE technique aliases, etc.) lives
in `intel.py` and is intentionally a curated dictionary so it can be
edited or pull-requested as the landscape changes.

---

## Adding a new feed

Edit `src/thnewscaster/sources.py` and append a `(name, url, kind)`
tuple. `kind` is one of `"advisory"`, `"vendor"`, `"news"`, `"social"`
and feeds into the source-weight component of the relevance score.

## Adding a new hypothesis archetype

1. Add a builder function `_my_archetype(ext: Extraction)` in
   `objectives.py` returning a list of `ObjectiveSpec` tuples (3–5).
2. Register it in the `ARCHETYPES` dict at the bottom of that file.
3. Add a branch to `_statement_and_rationale` and `_select_archetypes`
   in `hypotheses.py` so it can be picked.

## Tests

```bash
python -m pytest -q
```

The test suite uses only the bundled offline sample, so it is
deterministic and network-free.

---

## Design notes

* **Zero runtime dependencies.** Parsing uses
  `xml.etree.ElementTree`, fetching uses `urllib`, so the package is
  trivial to drop into restricted environments.
* **Falsification, not confirmation.** Hunts that look for "evidence
  it happened" are biased; CTF-style disproof objectives force the
  hunter to enumerate finite searches whose null results are
  meaningful.
* **Source-aware scoring.** CISA advisories are weighted higher than
  social-media chatter so a single Reddit post can't crowd out a
  vendor advisory in the top of the package.
* **Curated, not crawled, intel KB.** Auto-extraction of threat-actor
  aliases from prose is noisy; the alias dictionary in `intel.py` is
  easier to review and audit.
