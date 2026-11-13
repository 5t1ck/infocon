# 5t1ck InfoCon

An automated Internet threat level: GREEN / YELLOW / ORANGE / RED, recomputed
from free public feeds every 30 minutes, with the reasons shown.

[![5t1ck InfoCon status](https://5t1ck.github.io/infocon/status.svg)](https://5t1ck.github.io/infocon/)

**Live dashboard: https://5t1ck.github.io/infocon/**

The SANS ISC InfoCon is set by hand, was designed around worm-era events, and
sits on green almost permanently. This one is computed. It measures how unusual
today is compared with each feed's own recent history, and it watches the
status pages of the services everyone depends on, so it moves when something
actually changes (a Microsoft 365 outage is YELLOW within one run) and says
what moved it.

## Use the data

Everything is a plain file at a fixed URL. No key, no account, no rate limit of
its own, and CORS is open (`Access-Control-Allow-Origin: *`), so it works from
scripts and from a browser page alike.

| URL | What you get |
|---|---|
| [`/status.json`](https://5t1ck.github.io/infocon/status.json) | The full record: level, score, reasons, every signal, feed health |
| [`/history.json`](https://5t1ck.github.io/infocon/history.json) | Score over time, for charts |
| [`/status.txt`](https://5t1ck.github.io/infocon/status.txt) | One line, `YELLOW 49`, for scripts and status bars |
| [`/status.svg`](https://5t1ck.github.io/infocon/status.svg) | Status card image: level, score and the main reason |
| [`/badge.svg`](https://5t1ck.github.io/infocon/badge.svg) | Small badge: level and score |

All under `https://5t1ck.github.io/infocon`. Files refresh every 30 minutes and
are cached for 10; `generated` in the JSON says exactly how fresh they are.

### Quick examples

Level and score:

```bash
curl -s https://5t1ck.github.io/infocon/status.txt
```

Level, score and the main reason:

```bash
curl -s https://5t1ck.github.io/infocon/status.json | jq -r '"\(.level) \(.score): \(.drivers[0].short // .summary)"'
```

Fail a script when the level is ORANGE or worse:

```bash
curl -s https://5t1ck.github.io/infocon/status.txt | grep -qE '^(ORANGE|RED)' && echo "heads up"
```

PowerShell:

```powershell
(Invoke-RestMethod https://5t1ck.github.io/infocon/status.json) | Select-Object level, score, summary
```

Python:

```python
import json, urllib.request
s = json.load(urllib.request.urlopen("https://5t1ck.github.io/infocon/status.json"))
print(s["level"], s["score"], [d["short"] for d in s["drivers"]])
```

### `status.json`

```json
{
  "schema": 1,
  "generated": "2026-11-13T22:39:40+00:00",
  "level": "YELLOW",
  "level_since": "2026-11-13T22:15:51+00:00",
  "score": 49.0,
  "summary": "Elevated outages and new critical vulns.",
  "drivers": [
    {
      "component": "infrastructure",
      "label": "Big-service incidents",
      "short": "Microsoft 365 major incident",
      "text": "Microsoft 365 (Consumer): Users may be unable to access ... (major, ongoing), plus incidents at 9 other services",
      "score": 74.5
    }
  ],
  "components": [
    { "id": "scanning", "label": "Attack traffic", "weight": 0.2, "score": 39.6, "signals": [ ... ], "sources": ["isc"] }
  ],
  "coverage": 1.0,
  "degraded": false,
  "sources": [
    { "id": "isc", "name": "SANS ISC / DShield", "ok": true, "note": null, "seconds": 1.0 }
  ]
}
```

| Field | Meaning |
|---|---|
| `level` | `GREEN`, `YELLOW`, `ORANGE` or `RED` |
| `score` | 0-100 composite (`null` if nothing could be computed) |
| `level_since` | When the current level began |
| `summary` | One sentence on why |
| `drivers` | Signals that are elevated, most important first. `short` is a few words, `text` the full sentence, `score` that signal's 0-100. Empty on a quiet day. |
| `components` | The six areas with their weight, score and `signals` (each with `value`, `typical`, `score`, `text`) |
| `coverage` | Share of the feeds, by weight, that answered (0-1) |
| `degraded` | `true` when too few feeds answered and the level is being held |
| `sources` | Health of each feed on this run |
| `highlights` | The detail behind the dashboard cards: `incidents`, `stories`, `kev_recent`, `weaponised`, `ransomware`, `ports`, `outages`, `trending` |
| `raw_level`, `easing_since` | The level before the hold rule, and when the score first dropped below the current level |
| `sans_infocon` | What the SANS InfoCon says right now, for comparison |
| `method` | The level floors, weights and hold settings used |

`schema` goes up if a field is ever renamed or removed.

### `history.json`

A list, oldest first. Every run for the last two weeks, one point per day
before that.

```json
{ "t": "2026-11-13T22:39:40+00:00", "score": 49.0, "level": "YELLOW", "coverage": 1.0,
  "c": { "scanning": 39.6, "exploitation": 38.2, "vulnerabilities": 42.8, "ransomware": 14.6, "infrastructure": 68.0, "chatter": 24.7 } }
```

`c` holds the six component scores. Points with `"bf": 1` were reconstructed
after the fact rather than measured live.

### Embed the status card

`status.svg` is the equivalent of the SANS `status.gif`, with the reason
included: the level, the score and, in a few words, the top indicator driving
it. Hovering shows when it was computed.

```html
<a href="https://5t1ck.github.io/infocon/"><img alt="5t1ck InfoCon status" src="https://5t1ck.github.io/infocon/status.svg"></a>
```

Markdown:

```markdown
[![5t1ck InfoCon status](https://5t1ck.github.io/infocon/status.svg)](https://5t1ck.github.io/infocon/)
```

### Grafana

- **Status card:** a **Text** panel in HTML mode with the `<a><img>` snippet
  above (360 x 80 px; it scales).
- **Numbers and charts:** the Infinity data source (or any JSON data source)
  pointed at `status.json` for a Stat panel (`score`, `level`,
  `drivers[0].short`) or at `history.json` for a time series (`t` as time,
  `score` or `c.*` as values).

## What it measures

| Component | Weight | Feeds | Signals |
|---|---|---|---|
| Attack traffic | 20% | [SANS ISC / DShield](https://isc.sans.edu/api/) | Distinct attacking IPs, reports per sensor, surge on any top port vs that port's 3-week norm |
| Active exploitation | 20% | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs newly confirmed exploited in 7 days (ransomware-linked count 1.5x) vs 180 rolling weeks |
| New critical vulns | 15% | [NVD](https://nvd.nist.gov/developers/vulnerabilities), [FIRST EPSS](https://www.first.org/epss/api) | Critical CVEs published in 7 days; fresh criticals EPSS already rates 10%+ likely exploited |
| Ransomware | 10% | [ransomware.live](https://www.ransomware.live/apidocs) | Victims posted to leak sites in 72 h |
| Outages | 20% | Status pages of 23 big services (below), [Hacker News](https://hn.algolia.com/api), [IODA](https://ioda.inetintel.cc.gatech.edu/) | Incidents at big services weighted by severity and size; points of outage stories on the HN front page; country-level outages seen by two independent measurement methods |
| Security buzz | 15% | [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/), [Hacker News](https://hn.algolia.com/api) | Daily CVE sightings across social media, news, advisories and exploit feeds; points of breach / exploit / malware stories on the HN front page |

### Big-service outages

"Outlook is down for everyone" should move the needle, so the status pages of
the services people notice are read on every run:

- **Tier 2** (half the Internet notices): [Microsoft 365](https://status.cloud.microsoft/),
  Azure, AWS, Google Cloud, Google Workspace, Apple, Cloudflare.
- **Tier 1**: Akamai, GitHub, DigitalOcean, Slack, Zoom, Discord, OpenAI, Claude,
  Atlassian, Dropbox, Reddit, npm, Vercel, Netlify, Shopify, Twitch.

An incident is worth its severity (minor 1, major 3, critical 6) times its
tier (0.75 or 2). The worst service leads and the next two add a quarter each.
A few minor incidents, which is every day, land around 3 points. **One major
outage at a tier-2 service is 6 points, which is YELLOW by itself**; a critical
one with front-page chatter reaches ORANGE. An incident keeps counting for a
while after it is fixed (90% for 6 h, fading to nothing at 24 h), and one left
open for days fades too.

Add or re-tier services in `STATUSPAGES` in [infocon/sources.py](infocon/sources.py)
(anything on statuspage.io works: it only needs `/api/v2/incidents.json`).

## How the level is computed

1. **Signal.** Each reading is compared with its own trailing baseline using a
   robust z-score (median and MAD, on a log scale for heavy-tailed counts) and
   mapped to 0-100. An ordinary day scores about 20. Signals with no meaningful
   baseline (port surge, EPSS-weaponised criticals, big-service incidents,
   Hacker News points) use fixed curves instead.
2. **Component.** 70% the loudest signal, 30% the average of all of them.
3. **Composite.** A weighted power mean (p=4) of the components. One alarming
   area lifts the level, but no single component can reach RED alone: that
   needs several agreeing.
4. **Level.** GREEN from 0, YELLOW from 35, ORANGE from 55, RED from 75.
   Escalation is immediate. De-escalation waits until the score has stayed 3
   points under the floor for 6 hours, so the level does not flap.
5. **Blind spots.** If feeds carrying less than half the weight answer, the
   level is held and marked degraded rather than recomputed from scraps.

Replayed over the 75 days to 12 Nov 2026 this gives GREEN on 49 days, YELLOW on
26, ORANGE and RED on none (median score 31, 90th percentile 45, peak 53). The
live run on 13 Nov, during a global Microsoft 365 outage, read YELLOW 49.

Every knob is in [infocon/config.py](infocon/config.py): weights, level floors,
curves, hold time. Re-run `backfill` after changing them to see the effect on
past days.

## Limits

- **ORANGE and RED are untested against a real major incident.** Nothing of
  that size happened in the replay window, so those floors are reasoned, not
  validated. Expect to tune them after the first real event.
- **Active exploitation rests on one feed** (CISA KEV), which lags real-world
  exploitation by days and reflects US federal priorities.
- **Reconstructed history is conservative.** Backfilled days lack port surges,
  EPSS and the status pages that publish no history (Microsoft 365, Azure), so
  they read slightly lower than a live run would have. Those two only show
  what is open right now: an outage that starts and ends between runs is
  missed, so run it at least every 30 minutes.
- **Status pages are self-reported.** A provider that plays an outage down as
  "minor", or is slow to post, scores low until Hacker News notices.
- **Hacker News is a crowd.** Story matching is by title keywords, so an
  off-topic story with "outage" or "breach" in the title can add a few points.
- **It measures the Internet, not your network.** A quiet day globally says
  nothing about your own exposure.
- It depends on free services staying free and reachable. Each failure is shown
  under feed health on the dashboard.

## Run your own

You do not need to: the URLs above are public. Run your own copy if you want
different weights, different services, or no dependency on this one.

It is Python standard library only. No dependencies, no API keys, no accounts.
A feed that is down is left out and reported; it never breaks the run.

### GitHub Pages (free, nothing to host)

This is how the live site runs.

1. Fork or copy this repository.
2. Repo Settings -> Pages -> Source: **GitHub Actions**.
3. Actions tab -> **infocon** -> Run workflow (after that it runs itself at
   :07 and :37 every hour).

[.github/workflows/infocon.yml](.github/workflows/infocon.yml) computes the
level, keeps its state in the Actions cache and publishes to
`https://<you>.github.io/<repo>/`. GitHub may start scheduled runs late when it
is busy, and pauses schedules on repositories with no activity for 60 days.

### Container

```bash
docker compose up -d --build
```

Then open `http://<host>:8377/`. One small container (Python slim image, no
packages installed) refetches the feeds every 30 minutes and serves the
dashboard and every file listed above.

- **First start** shows a "collecting" page for about a minute, then the live
  level; the 75-day history chart fills in a few minutes later.
- **State** (feed cache, score history, published site) lives in the
  `infocon-data` volume, so restarts and image rebuilds keep the history.
- **Settings** are environment variables in [compose.yaml](compose.yaml):
  `INFOCON_INTERVAL` (minutes), `INFOCON_BACKFILL_DAYS`, `INFOCON_PORT`,
  `INFOCON_USER_AGENT`.
- It runs as an unprivileged user on a read-only root filesystem with all
  capabilities dropped, and needs outbound HTTPS only.
- It has no login. Put it behind your reverse proxy if it should not be public.

```bash
docker compose logs -f
```

One line per refresh: time, level, score, summary.

```bash
docker compose down
```

Stops it and keeps the data (`docker compose down -v` also deletes the volume).

Without compose:

```bash
docker build -t infocon-auto . && docker run -d --name infocon --restart unless-stopped -p 8377:8377 -v infocon-data:/data infocon-auto
```

### Plain Python

```bash
python -m infocon backfill --days 75
```

Optional, once: reconstructs past days so the history chart is not empty
(takes a few minutes; later runs are cached).

```bash
python -m infocon run
```

Collects, scores and writes everything to `site/`. About 50 s cold, 15 s cached.
Exit code 2 means too few feeds answered and the level was held.

```bash
python -m infocon serve
```

Serves the dashboard at http://127.0.0.1:8377/ and recomputes every 30 minutes
(`--interval`, `--port`, `--host`, `--backfill` to change).

```bash
python -m infocon status
```

Prints the last result without fetching anything (`--json` for the full record).

With cron instead of `serve`:
`*/30 * * * * cd /path/to/infocon && python3 -m infocon run -q`, and serve
`site/` with any web server.

Developed and tested on Python 3.14. Nothing newer than 3.9 is knowingly used,
but older versions are untested.

Outputs go to `site/` and state to `data/` (feed cache, score history,
hysteresis state). Both folders are generated; delete them to start over.
`INFOCON_DATA_DIR` and `INFOCON_SITE_DIR` relocate them.

### Being a good API citizen

Requests are cached per day, rate-limited where the provider asks (NVD, ISC),
and sent with a generic User-Agent. SANS ISC asks API users to include contact
details; set `INFOCON_USER_AGENT` to do so:

```bash
INFOCON_USER_AGENT="infocon-auto/1.0 (you@example.org)" python -m infocon run
```

### Tests

```bash
python -m unittest discover -s tests -v
```

### Layout

```
infocon/
  config.py       weights, floors, curves
  net.py          HTTP with retries
  sources.py      one fetcher per feed, day-granular cache
  scoring.py      signals -> components -> composite -> level (pure functions)
  engine.py       run / backfill orchestration, history, highlights
  render.py       writes site/
  dashboard.html  the page (copied to site/index.html on every run)
tests/            scoring behaviour
Dockerfile        the container image
compose.yaml      how to run it
```
