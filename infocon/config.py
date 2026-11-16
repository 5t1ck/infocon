"""Tunable knobs. Everything that decides the level lives here, in one place."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("INFOCON_DATA_DIR", ROOT / "data"))
SITE_DIR = Path(os.environ.get("INFOCON_SITE_DIR", ROOT / "site"))

# Sent with every request. Some providers (ISC) ask for contact details here;
# set INFOCON_USER_AGENT if you want to give them one.
USER_AGENT = (
    os.environ.get("INFOCON_USER_AGENT") or "infocon-auto/1.0 (automated threat-level aggregator)"
)

# Level floors on the 0-100 composite score.
LEVELS = [("GREEN", 0), ("YELLOW", 35), ("ORANGE", 55), ("RED", 75)]

# Component weights (renormalised over whatever is available on a given run).
WEIGHTS = {
    "scanning": 0.20,
    "exploitation": 0.20,
    "vulnerabilities": 0.15,
    "ransomware": 0.10,
    "infrastructure": 0.20,
    "chatter": 0.15,
}

LABELS = {
    "scanning": "Attack traffic",
    "exploitation": "Active exploitation",
    "vulnerabilities": "New critical vulns",
    "ransomware": "Ransomware",
    "infrastructure": "Outages",
    "chatter": "Security buzz",
}

# Composite = weighted power mean of component scores. p=1 is a plain average
# (one screaming component gets averaged away); large p approaches max().
POWER = 4

# Robust z-score -> 0-100. A normal day (z=0) scores 20.
Z_CURVE = [(-3, 5), (0, 20), (1, 30), (2, 42), (3, 55), (4, 67), (5, 77), (6, 85), (8, 95), (10, 100)]

# Below this share of total weight we refuse to change the level.
MIN_COVERAGE = 0.5

# Big-service incidents. One incident is worth severity points (minor 1,
# major 3, critical 6) x its provider's tier weight. A provider is worth its
# worst incident plus a little for the others; the worst provider leads and the
# next two add a share. Routine noise (a few minor incidents) lands near 3, and
# 6 points is enough for YELLOW on its own.
#
# Tier weight is (at first, once sustained), rising between SUSTAINED_HOURS:
#   3  half the Internet (Microsoft 365, AWS, Google, Cloudflare, Apple): a
#      major outage is 6 points straight away.
#   2  what most organisations use every day (GitHub, Slack, Zoom, Akamai,
#      OpenAI, Claude, Atlassian):
#      6 points once a critical outage has lasted 2 h or a major one 4 h.
#   1  everything else: only a critical outage lasting 4 h gets there.
# The wait is there because status pages cry wolf: GitHub labelled 12 incidents
# "critical" in 75 days, 9 of them under 2 hours.
TIER_WEIGHT = {1: (0.5, 1.0), 2: (0.5, 2.0), 3: (2.0, 2.0)}
SUSTAINED_HOURS = (1, 4)
SUSTAINED_MIN_POINTS = 3     # minor incidents never earn the sustained weight
SUSTAINED_MIN_PARTS = 2      # nor one confined to a single component of the service (where the page says)
SERVICE_CURVE = [(0, 8), (2, 18), (3, 24), (4, 32), (5, 48), (6, 68), (8, 74), (12, 84), (18, 93), (26, 100)]
SAME_PROVIDER = 0.15      # share of a provider's further incidents (capped at 1.5x its worst)
OTHER_PROVIDERS = 0.25    # share of the second- and third-worst providers
# An outage that has ended still counts for a while: (hours since it ended, weight).
# Full weight for 6 h, so a run that comes hours late still reports it.
RESOLVED_DECAY = [(6, 1.0), (12, 0.5)]
# An incident left open for days stops being news: (hours open, weight).
OPEN_DECAY = [(24, 1.0), (72, 0.7), (168, 0.4), (720, 0.2)]
OPEN_STALE = 0.1

# Hacker News: summed points of front-page stories from the last 24 h.
HN_OUTAGE_CURVE = [(0, 10), (100, 22), (200, 35), (400, 52), (700, 66), (1000, 75), (1500, 85), (2500, 95), (4000, 100)]
# Outage stories count at this share unless a status page or IODA is elevated
# too: a headline about last week's outage is not an outage.
HN_UNCONFIRMED = 0.5
# Security stories are on the front page every day (median 220 points, 90th
# percentile 1,400 over 75 days), so an ordinary day sits near 20 on this curve.
HN_SECURITY_CURVE = [(0, 10), (250, 20), (700, 28), (1500, 38), (2500, 50), (4000, 65), (6000, 80), (9000, 100)]

# Fresh critical CVEs (<=30 days old) that EPSS already rates >=10% likely exploited.
WEAPONISED_CURVE = [(0, 12), (1, 20), (2, 30), (4, 47), (6, 58), (10, 72), (16, 85), (25, 100)]
EPSS_WEAPONISED = 0.10

# IODA: minimum outage score for a country to count, and the number of
# countries one measurement source may flag at once before we call it a glitch.
IODA_MIN_SCORE = 3_000
IODA_GLITCH = 60

HISTORY_KEEP_DAYS = 180
