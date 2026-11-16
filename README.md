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

All under `https://5t1ck.github.io/infocon`. The job is scheduled every 30
minutes, but GitHub starts scheduled jobs late (hours late on a quiet day), and
files are cached for 10 minutes; `generated` in the JSON says exactly how fresh
they are.

Embed the status card:

```html
<a href="https://5t1ck.github.io/infocon/"><img alt="5t1ck InfoCon status" src="https://5t1ck.github.io/infocon/status.svg"></a>
```

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

- **Tier 3** (half the Internet notices): [Microsoft 365](https://status.cloud.microsoft/),
  Azure, AWS, Google Cloud, Google Workspace, Apple, Cloudflare.
- **Tier 2** (most organisations use it every day): GitHub, Slack, Zoom, Akamai.
- **Tier 1**: DigitalOcean, Discord, OpenAI, Claude, Atlassian, Dropbox, Reddit,
  npm, Vercel, Netlify, Shopify, Twitch.

An incident is worth its severity (minor 1, major 3, critical 6) times the
weight of its tier. The worst service leads and the next two add a quarter
each. A few minor incidents, which is every day, land around 3 points; 6 points
is YELLOW by itself.

| Tier | Weight | YELLOW by itself |
|---|---|---|
| 3 | 2 | A major outage, at once |
| 2 | 0.5, rising to 2 between 1 h and 4 h | A critical outage lasting 2 h, or a major one lasting 4 h |
| 1 | 0.5, rising to 1 between 1 h and 4 h | A critical outage lasting 4 h |

The wait is there because status pages cry wolf: GitHub labelled 12 incidents
"critical" in 75 days, 9 of them under 2 hours. Minor incidents never earn the
higher weight. A critical tier-3 outage with front-page chatter reaches ORANGE.
An incident counts in full for 6 hours after it is fixed, so a run that comes
late still reports it, and one left open for days fades.

Outage stories on Hacker News count in full only when a status page or IODA is
elevated as well. Alone they count at half, so a headline about last week's
outage does not raise the level.

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
4. **Level.** GREEN from 0, YELLOW from 35, ORANGE from 55, RED from 75. The
   level is always the band the score is in.
5. **Blind spots.** If feeds carrying less than half the weight answer, the
   level is held and marked degraded rather than recomputed from scraps.

Replayed over the 75 days to 15 Nov 2026 this gives GREEN on about 56 days, YELLOW
on about 19, ORANGE and RED on none (median score 28, 90th percentile 47, peak 51). The
live run on 13 Nov, during a global Microsoft 365 outage, read YELLOW 49.

Every knob is in [infocon/config.py](infocon/config.py): weights, level floors,
curves, tiers. Re-run `backfill` after changing them to see the effect on
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
  Outage stories no status page confirms are halved for that reason.
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
`https://<you>.github.io/<repo>/`. GitHub starts scheduled runs late, sometimes
by hours, and pauses schedules on repositories with no activity for 60 days. If
you need the 30 minutes to be exact, have any external cron call the workflow's
`workflow_dispatch` endpoint, or use the container.

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

Outputs go to `site/` and state to `data/` (feed cache, score history, last
level). Both folders are generated; delete them to start over.
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
