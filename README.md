# infocon-auto

An automated Internet threat level: GREEN / YELLOW / ORANGE / RED, recomputed
from free public feeds every time it runs, with the reasons shown.

The SANS ISC InfoCon is set by hand, was designed around worm-era events, and
sits on green almost permanently. This one is computed. It measures how unusual
today is compared with each feed's own recent history, and it watches the
status pages of the services everyone depends on, so it moves when something
actually changes (a Microsoft 365 outage is YELLOW within one run) and says
what moved it.

- Python standard library only. No dependencies, no API keys, no accounts.
- Outputs a dashboard, a JSON API, a badge and a one-line text file.
- A feed that is down is left out and reported; it never breaks the run.

## Deploy it (container)

```bash
docker compose up -d --build
```

Then open `http://<host>:8377/`. That is the whole deployment: one small
container (Python slim image, no packages installed) that refetches the feeds
every 30 minutes and serves the dashboard, `status.json`, `badge.svg` and
`status.txt`.

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

## Run it without a container

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
(`--interval`, `--port`, `--host` to change).

```bash
python -m infocon status
```

Prints the last result without fetching anything (`--json` for the full record).

Developed and tested on Python 3.14. Nothing newer than 3.9 is knowingly used,
but older versions are untested.

## Other ways to keep it running

| Where | How |
|---|---|
| Container | `docker compose up -d --build` (above; the intended way) |
| Any machine with Python | `python -m infocon serve --host 0.0.0.0 --backfill 75` |
| cron | `*/30 * * * * cd /path/to/infocon && python3 -m infocon run -q`, and serve `site/` with any web server |
| GitHub | `.github/workflows/infocon.yml` runs every 30 min and publishes `site/` to GitHub Pages. The folder must be the root of its own repository, with Pages set to "GitHub Actions". |

## Outputs (`site/`)

| File | Use |
|---|---|
| `index.html` | Dashboard. Works over HTTP or opened straight from disk. |
| `status.json` | Level, score, drivers, every signal with its value and baseline, highlights, feed health. |
| `history.json` | Score history (full resolution for two weeks, daily before that). |
| `badge.svg` | Embeddable badge. |
| `status.txt` | `YELLOW 36` for scripts, prompts and status bars. |

State lives in `data/` (feed cache, score history, hysteresis state). Both
folders are generated; delete them to start over. `INFOCON_DATA_DIR` and
`INFOCON_SITE_DIR` relocate them.

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

## Being a good API citizen

Requests are cached per day, rate-limited where the provider asks (NVD, ISC),
and sent with a generic User-Agent. SANS ISC asks API users to include contact
details; set `INFOCON_USER_AGENT` to do so:

```bash
INFOCON_USER_AGENT="infocon-auto/1.0 (you@example.org)" python -m infocon run
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Layout

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
