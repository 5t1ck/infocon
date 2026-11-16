"""Fetchers for every upstream feed. All are free and need no API key.

Each fetcher returns plain dicts/lists. Day-granular history that never changes
once a day is over (CIRCL counts, IODA counts, DShield port history, ransomware
daily totals) is kept in the on-disk cache so normal runs stay light on the
providers.
"""
import collections
import datetime as dt
import re
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime

from . import config
from .net import FetchError, fetch_json, fetch_text

UTC = dt.timezone.utc
DAY = dt.timedelta(days=1)

ISC = "https://isc.sans.edu/api"
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS = "https://api.first.org/data/v1/epss"
RL = "https://api.ransomware.live/v2"
CIRCL = "https://vulnerability.circl.lu/api"
IODA = "https://api.ioda.inetintel.cc.gatech.edu/v2"
HN = "https://hn.algolia.com/api/v1"

# Status pages in the statuspage.io format: name -> (base URL, tier).
# Tier 2 = half the Internet notices when it breaks; tier 1 = widely used.
STATUSPAGES = {
    "Cloudflare": ("https://www.cloudflarestatus.com", 2),
    "Akamai": ("https://www.akamaistatus.com", 1),
    "GitHub": ("https://www.githubstatus.com", 1),
    "DigitalOcean": ("https://status.digitalocean.com", 1),
    "Zoom": ("https://www.zoomstatus.com", 1),
    "Discord": ("https://discordstatus.com", 1),
    "OpenAI": ("https://status.openai.com", 1),
    "Claude": ("https://status.claude.com", 1),
    "Atlassian": ("https://status.atlassian.com", 1),
    "Dropbox": ("https://status.dropbox.com", 1),
    "Reddit": ("https://www.redditstatus.com", 1),
    "npm": ("https://status.npmjs.org", 1),
    "Vercel": ("https://www.vercel-status.com", 1),
    "Netlify": ("https://www.netlifystatus.com", 1),
    "Shopify": ("https://status.shopify.com", 1),
    "Twitch": ("https://status.twitch.tv", 1),
}
# Severity points for one incident, before the tier multiplier.
IMPACT_POINTS = {"none": 0.3, "minor": 1, "major": 3, "critical": 6}

# Hacker News front-page titles that mean "something big is down" / "security news".
HN_OUTAGE = re.compile(
    r"\b(outages?|is down|are down|was down|went down|goes down|going down|downtime|"
    r"global disruption|service disruption|degraded (availability|performance|service))\b", re.I)
HN_SECURITY = re.compile(
    r"\b(hacked|breach(es|ed)?|ransomware|malware|zero[- ]days?|0[- ]?days?|exploit(s|ed|ing|ation)?|"
    r"vulnerabilit(y|ies)|CVE-\d+|backdoor(s|ed)?|supply[- ]chain attack|compromised?|data leak|RCE|"
    r"remote code execution|phishing|botnet|ddos|cyber ?attacks?|spyware|"
    r"security (flaw|bug|hole|incident|advisory))\b", re.I)
HN_MIN_POINTS = 50


def parse_ts(s):
    if not s:
        return None
    s = str(s).strip().replace(" ", "T").replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def last_complete_day(now):
    """DShield sensors keep reporting for a while after midnight UTC."""
    return (now - dt.timedelta(hours=3)).date() - DAY


def _rows(obj, key):
    # ISC returns {"0": {...}, "1": {...}, "date": "..."} - keep only the records.
    vals = obj.values() if isinstance(obj, dict) else obj
    return [v for v in vals if isinstance(v, dict) and key in v]


# --------------------------------------------------------------------------
# SANS ISC / DShield: global honeypot + firewall-log sensor network
# --------------------------------------------------------------------------
def isc(now, lookback, cache, live):
    start = now.date() - lookback * DAY
    rows = fetch_json(f"{ISC}/dailysummary/{start}/{now.date()}?json")
    daily = {
        r["date"]: {k: int(r[k]) for k in ("records", "sources", "targets")}
        for r in _rows(rows, "date")
    }
    if not daily:
        raise FetchError("ISC dailysummary returned no rows")
    out = {"daily": daily, "ports": None, "sans_infocon": None}
    if not live:
        return out
    try:
        out["sans_infocon"] = fetch_json(f"{ISC}/infocon?json").get("status")
    except FetchError:
        pass
    day = str(last_complete_day(now))
    pc = cache["dshield_ports"]
    if pc.get("day") != day:
        try:
            ports = _top_ports(dt.date.fromisoformat(day))
            pc.clear()
            pc.update(day=day, ports=ports)
        except FetchError as e:
            out["ports_error"] = str(e)
    if pc.get("day") == day:
        out["ports"] = pc["ports"]
    return out


def _top_ports(day, n=8, history_for=6, history_days=21):
    top = _rows(fetch_json(f"{ISC}/topports/records/{n}/{day}?json"), "targetport")
    ports = []
    for i, r in enumerate(top):
        p = {"port": int(r["targetport"]), "records": int(r["records"]),
             "sources": int(r["sources"]), "baseline_sources": None, "ratio": None}
        if i < history_for:
            hist = _rows(fetch_json(f"{ISC}/porthistory/{p['port']}/{day - history_days * DAY}/{day}?json"), "date")
            prior = [int(h["sources"]) for h in hist if h["date"] < str(day)]
            if len(prior) >= 7:
                med = statistics.median(prior)
                p["baseline_sources"] = med
                p["ratio"] = round(p["sources"] / med, 2) if med else None
        ports.append(p)
    return ports


# --------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities
# --------------------------------------------------------------------------
def kev():
    err = None
    for url in KEV_URLS:
        try:
            j = fetch_json(url)
            break
        except FetchError as e:
            err = e
    else:
        raise err
    return {
        "version": j.get("catalogVersion"),
        "items": [
            {
                "cve": v["cveID"],
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "added": v["dateAdded"],
                "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            }
            for v in j["vulnerabilities"]
        ],
    }


# --------------------------------------------------------------------------
# NVD: critical CVEs by publication date (window max is 120 days per request)
# --------------------------------------------------------------------------
def nvd(now, lookback):
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    items = {}
    end, remaining, first = now, lookback, True
    while remaining > 0:
        span = min(remaining, 119)
        start = end - span * DAY
        idx = 0
        while True:
            if not first:
                time.sleep(6.5)  # keyless limit: 5 requests / 30 s
            first = False
            j = fetch_json(
                f"{NVD}?pubStartDate={fmt(start)}&pubEndDate={fmt(end)}"
                f"&cvssV3Severity=CRITICAL&resultsPerPage=2000&startIndex={idx}",
                timeout=60, backoff=8.0,
            )
            for v in j.get("vulnerabilities", []):
                c = v["cve"]
                score = None
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    for m in c.get("metrics", {}).get(key, []):
                        s = m.get("cvssData", {}).get("baseScore")
                        score = max(score or 0, s or 0)
                desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
                items[c["id"]] = {"cve": c["id"], "published": c["published"], "score": score, "desc": desc[:240]}
            idx += len(j.get("vulnerabilities", []))
            if idx >= j.get("totalResults", 0) or not j.get("vulnerabilities"):
                break
        end, remaining = start, remaining - span
    return list(items.values())


def epss(cves):
    out = {}
    cves = sorted(set(cves))
    for i in range(0, len(cves), 80):
        j = fetch_json(f"{EPSS}?cve={','.join(cves[i:i + 80])}")
        for r in j.get("data", []):
            out[r["cve"]] = float(r["epss"])
    return out


# --------------------------------------------------------------------------
# ransomware.live: leak-site victim postings
# --------------------------------------------------------------------------
def _prev_month(d):
    return (d.replace(day=1) - DAY).replace(day=1)


def ransomware(now, need_days, cache, live):
    c = cache["ransomware"]
    today = now.date()
    first_needed = (today - need_days * DAY).replace(day=1)
    fetched = parse_ts(c.get("fetched"))
    stale = (
        not fetched
        or now - fetched > dt.timedelta(hours=20)
        or not c.get("trusted_from")
        or c["trusted_from"] > str(first_needed)
    )
    if stale:
        # The monthly endpoint is keyed by attack date, but we count by the date
        # the posting was discovered, which can lag - so pull one extra month.
        months, cur = [], today.replace(day=1)
        while cur >= _prev_month(first_needed):
            months.append(cur)
            cur = _prev_month(cur)
        seen, counts = set(), collections.Counter()
        for mo in months:
            for v in fetch_json(f"{RL}/victims/{mo.year}/{mo.month:02d}", timeout=60):
                d = parse_ts(v.get("discovered"))
                if not d:
                    continue
                key = (v.get("victim"), v.get("group"), d.date())
                if key not in seen:
                    seen.add(key)
                    counts[str(d.date())] += 1
        c.clear()
        c.update(
            fetched=now.isoformat(),
            trusted_from=str(first_needed),
            daily={k: n for k, n in sorted(counts.items()) if k >= str(first_needed)},
        )
    out = {"daily": c["daily"], "trusted_from": c["trusted_from"],
           "through": parse_ts(c["fetched"]).date().isoformat(), "recent": None}
    if live:
        out["recent"] = [
            {"victim": v.get("victim"), "group": v.get("group"), "country": v.get("country"),
             "sector": v.get("activity"), "discovered": v.get("discovered")}
            for v in fetch_json(f"{RL}/recentvictims")
        ]
    return out


# --------------------------------------------------------------------------
# CIRCL Vulnerability-Lookup sightings: CVE mentions across the fediverse,
# news, exploit DBs, plus honeypot "exploited" observations (Shadowserver etc.)
# --------------------------------------------------------------------------
def _circl_count(a, b, typ=None):
    # date_from / date_to are whole UTC dates, inclusive at both ends.
    url = f"{CIRCL}/sighting/?date_from={a}&date_to={b}&per_page=1"
    if typ:
        url += f"&type={typ}"
    return int(fetch_json(url)["metadata"]["count"])


def _fill_days(cache_days, days, fetch_day, workers=4, settle=2):
    """Fetch every day missing from the cache; tolerate individual failures.
    The newest `settle` days are always refetched because upstream feeds keep
    revising them (late imports, events that are still being scored)."""
    recent = set(sorted(days)[-settle:])
    missing = [d for d in days if str(d) not in cache_days or d in recent]
    failures = []

    def one(d):
        try:
            return d, fetch_day(d)
        except Exception as e:  # noqa: BLE001 - one bad day must not sink the feed
            failures.append(str(e))
            return d, None

    with ThreadPoolExecutor(workers) as pool:
        for d, val in pool.map(one, missing):
            if val is not None:
                cache_days[str(d)] = val
    if missing and len(failures) == len(missing):
        raise FetchError(failures[0])


def circl(now, need_days, cache, live):
    today = now.date()
    day_counts = lambda d: {"all": _circl_count(d, d)}
    _fill_days(cache["circl"], [today - i * DAY for i in range(1, need_days + 1)], day_counts)
    out = {"daily": cache["circl"], "today": None, "top": [], "top_exploited": []}
    if live:
        out["today"] = dict(day_counts(today), hours=(now - dt.datetime(today.year, today.month, today.day, tzinfo=UTC)).total_seconds() / 3600)
        try:
            out["top"] = fetch_json(f"{CIRCL}/stats/vulnerability/most_sighted?date_from={today - DAY}&limit=10")
            out["top_exploited"] = fetch_json(
                f"{CIRCL}/stats/vulnerability/most_sighted?date_from={today - 3 * DAY}&sighting_type=exploited&limit=10")
        except FetchError:
            pass
    return out


def cve_titles(cves, cache, known=None):
    """Human-readable names for CVE ids (cached; CIRCL serves the CVE record)."""
    titles = cache.setdefault("cve_titles", {})
    for cve in cves:
        if cve in titles:
            continue
        if known and known.get(cve):
            titles[cve] = known[cve]
            continue
        try:
            cna = fetch_json(f"{CIRCL}/vulnerability/{cve}", timeout=15, retries=0).get("containers", {}).get("cna", {})
        except Exception:  # noqa: BLE001 - names are a nicety
            continue
        title = cna.get("title")
        if not title:
            aff = (cna.get("affected") or [{}])[0]
            desc = ((cna.get("descriptions") or [{}])[0].get("value") or "").splitlines()[0:1]
            desc = desc[0] if desc else ""
            title = " ".join(x for x in (aff.get("vendor"), aff.get("product")) if x and x != "n/a")
            title = f"{title}: {desc}" if title and desc else title or desc
        if title:
            titles[cve] = title[:160]
    for old in list(titles)[:-600]:
        del titles[old]
    return {c: titles[c] for c in cves if c in titles}


# --------------------------------------------------------------------------
# IODA (Georgia Tech): country-level Internet outages
# --------------------------------------------------------------------------
def _ioda_window(a, b):
    j = fetch_json(
        f"{IODA}/outages/summary?from={int(a.timestamp())}&until={int(b.timestamp())}&entityType=country&limit=300",
        timeout=45, retries=1,
    )
    rows = [
        {"code": x["entity"]["code"], "name": x["entity"]["name"], "score": round(x["scores"]["overall"]),
         # which independent measurements flagged it: bgp, ping-slash24, gtr, merit-nt
         "via": sorted({k.split(".")[0] for k in x["scores"] if k != "overall"})}
        for x in j.get("data") or []
    ]
    return sorted((r for r in rows if r["score"] >= 1000), key=lambda r: -r["score"])


def ioda(now, need_days, cache, live):
    today = now.date()
    midnight = lambda d: dt.datetime(d.year, d.month, d.day, tzinfo=UTC)
    day_rows = lambda d: {"rows": [[r["code"], r["score"], ",".join(r["via"])]
                                   for r in _ioda_window(midnight(d), midnight(d + DAY))]}
    _fill_days(cache["ioda"], [today - i * DAY for i in range(1, need_days + 1)], day_rows)
    out = {"daily": cache["ioda"], "last24": None}
    if live:
        out["last24"] = _ioda_window(now - DAY, now)
    return out


# --------------------------------------------------------------------------
# Status pages of the services everyone notices: Microsoft 365, Azure, AWS,
# Google, Apple, Cloudflare and friends. Every incident becomes one record
#   {id, src, provider, tier, title, impact, points, started, ended, url}
# kept in the cache, so an outage that is already over still counts for a few
# hours and past days can be replayed.
# --------------------------------------------------------------------------
def _iso(epoch):
    return dt.datetime.fromtimestamp(int(epoch), UTC).isoformat()


def _plain(html, limit=160):
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>|\*\*|&nbsp;", " ", html or "")).strip()
    return text[:limit]


def _ms_points(status):
    """Microsoft service-health wording -> severity points."""
    s = re.sub(r"[^a-z]", "", str(status or "").lower())
    if s in ("", "none", "operational", "serviceoperational", "available", "servicerestored", "resolved",
             "falsepositive", "postincidentreviewpublished", "informationavailable"):
        return 0
    if "interruption" in s or "outage" in s:
        return IMPACT_POINTS["critical"]
    if "degrad" in s:
        return IMPACT_POINTS["major"]
    return 2  # investigating, restoring service, extended recovery, verifying...


def _ms_summary(post):
    text = _plain(post.get("Message"), 2000)
    m = re.search(r"User impact:\s*(.+?[.!?])(\s|$)", text)
    return (m.group(1) if m else text or str(post.get("Status")))[:150]


def _impact(points):
    return "critical" if points >= 6 else "major" if points >= 3 else "minor" if points >= 1 else "info"


def _statuspage(name, base, tier):
    out = []
    for i in fetch_json(f"{base}/api/v2/incidents.json", timeout=25, retries=1).get("incidents", []):
        done = i.get("status") in ("resolved", "postmortem", "completed")
        out.append({"id": f"sp:{name}:{i.get('id')}", "provider": name, "tier": tier, "title": i.get("name", "")[:160],
                    "impact": i.get("impact") or "minor", "points": IMPACT_POINTS.get(i.get("impact"), 1),
                    "started": i.get("started_at") or i.get("created_at"),
                    "ended": i.get("resolved_at") or (i.get("updated_at") if done else None),
                    "url": i.get("shortlink") or base})
    return out


def _microsoft365(now):
    """The public page Microsoft posts to when 365 itself is in trouble.
    Current state only: when an issue started is 'when we first saw it'."""
    out, page = [], "https://status.cloud.microsoft/"
    for row in fetch_json(f"{page}api/posts/m365Consumer", timeout=25, retries=1):
        pts = _ms_points(row.get("Status"))
        if pts:
            name = row.get("ServiceDisplayName") or "Microsoft 365"
            out.append({"id": f"ms:consumer:{name}", "provider": "Microsoft 365", "tier": 2,
                        "title": f"{name}: {_plain(row.get('Title')) or row.get('Status')}",
                        "impact": _impact(pts), "points": pts, "started": now.isoformat(), "first_seen": True, "ended": None, "url": page})
    try:  # the business / enterprise side of the same page
        post = fetch_json(f"{page}api/posts/mac", timeout=25, retries=1)
        pts = _ms_points(post.get("Status")) if isinstance(post, dict) else 0
        if pts:
            out.append({"id": f"ms:business:{post.get('Id')}", "provider": "Microsoft 365", "tier": 2,
                        "title": "Microsoft 365 for business: " + _ms_summary(post),
                        "impact": _impact(pts), "points": pts, "started": now.isoformat(), "first_seen": True, "ended": None, "url": page})
    except FetchError:
        if not out:
            raise
    return out


def _azure(now):
    xml = fetch_text("https://azure.status.microsoft/en-us/status/feed/", timeout=20, retries=1)
    out = []
    for item in re.findall(r"<item>(.*?)</item>", xml, re.S):
        title = re.search(r"<title>(.*?)</title>", item, re.S)
        pub = re.search(r"<pubDate>(.*?)</pubDate>", item, re.S)
        title = re.sub(r"<!\[CDATA\[|\]\]>", "", title.group(1)).strip() if title else "Azure incident"
        started = now.isoformat()
        if pub:
            try:
                started = parsedate_to_datetime(pub.group(1).strip()).astimezone(UTC).isoformat()
            except (TypeError, ValueError):
                pass
        out.append({"id": f"az:{title[:80]}", "provider": "Azure", "tier": 2, "title": title[:160], "impact": "major",
                    "points": IMPACT_POINTS["major"], "started": started, "ended": None,
                    "url": "https://azure.status.microsoft/en-us/status"})
    if not out:
        try:
            post = fetch_json("https://status.cloud.microsoft/api/posts/azure", timeout=20, retries=1)
            pts = _ms_points(post.get("Status")) if isinstance(post, dict) else 0
            if pts:
                out.append({"id": "az:post", "provider": "Azure", "tier": 2,
                            "title": _plain(post.get("Message")) or "Azure issue",
                            "impact": _impact(pts), "points": pts, "started": now.isoformat(), "first_seen": True, "ended": None,
                            "url": "https://status.cloud.microsoft/"})
        except FetchError:
            pass
    return out


_AWS = {"1": ("minor", 1), "2": ("major", 3), "3": ("critical", 6)}


def _aws_event(e, where=""):
    log = e.get("event_log") or []
    seen = [x for x in [str(e.get("status"))] + [str(l.get("status")) for l in log] if x in _AWS]
    if not seen or not e.get("date"):
        return None
    worst = max(seen)
    summary = str(e.get("summary", ""))
    resolved = summary.startswith("[RESOLVED]") or str(e.get("status")) == "0"
    stamps = [int(l["timestamp"]) for l in log if str(l.get("timestamp", "")).isdigit()]
    where = e.get("region_name") or e.get("service_name") or where
    title = summary.replace("[RESOLVED]", "").strip() + (f" ({where})" if where else "")
    return {"id": "aws:" + str(e.get("arn") or f"{where}:{e['date']}"), "provider": "AWS", "tier": 2, "title": title[:160],
            "impact": _AWS[worst][0], "points": _AWS[worst][1], "started": _iso(e["date"]),
            "ended": _iso(max(stamps)) if resolved and stamps else None,
            "url": "https://health.aws.amazon.com/health/status"}


def _aws_current():
    events = fetch_json("https://health.aws.amazon.com/public/currentevents", timeout=20, retries=1)
    out = [_aws_event(e) for e in events]
    return [r for r in out if r and not r["ended"]]


def _aws_history():
    j = fetch_json("https://history-events-us-east-1-prod.s3.amazonaws.com/historyevents.json", timeout=30, retries=1)
    out = [_aws_event(e, where) for where, events in j.items() for e in events]
    return [r for r in out if r and r["ended"]]


def _google(provider, base):
    pts = {"low": 1, "medium": 3, "high": 6}
    return [
        {"id": f"g:{provider}:{i.get('id')}", "provider": provider, "tier": 2,
         "title": ((i.get("service_name") + ": ") if i.get("service_name") else "") + _plain(
             re.sub(r"^\W*Summary:\W*", "", (i.get("external_desc") or "").split("**Description")[0]), 130),
         "impact": _impact(pts.get(i.get("severity"), 1)), "points": pts.get(i.get("severity"), 1),
         "started": i.get("begin"), "ended": i.get("end"), "url": base + i.get("uri", "")}
        for i in fetch_json(base + "incidents.json", timeout=25, retries=1)
    ]


def _apple():
    j = fetch_json("https://www.apple.com/support/systemstatus/data/system_status_en_US.js", timeout=20, retries=1)
    out = []
    for svc in j.get("services", []):
        for e in svc.get("events") or []:
            kind = str(e.get("statusType", ""))
            if "aintenance" in kind or e.get("eventStatus") == "upcoming" or not e.get("epochStartDate"):
                continue
            # Apple files routine maintenance as an "Outage" and says so only in the message.
            if re.search(r"maintenance|no user impact", str(e.get("message", "")), re.I):
                continue
            pts = 2 if kind == "Outage" else 1
            out.append({"id": f"apple:{e.get('messageId')}:{svc.get('serviceName')}", "provider": "Apple", "tier": 2,
                        "title": f"{svc.get('serviceName')}: {e.get('message', '')}"[:160], "impact": _impact(pts),
                        "points": pts, "started": _iso(e["epochStartDate"] / 1000),
                        "ended": _iso(e["epochEndDate"] / 1000) if e.get("epochEndDate") else None,
                        "url": "https://www.apple.com/support/systemstatus/"})
    return out


def _slack():
    pts = {"outage": 4, "incident": 2, "notice": 0.3}
    rows = fetch_json("https://slack-status.com/api/v2.0.0/history", timeout=25, retries=1)
    try:
        rows = rows + fetch_json("https://slack-status.com/api/v2.0.0/current", timeout=20, retries=1).get("active_incidents", [])
    except FetchError:
        pass
    return [
        {"id": f"slack:{i.get('id')}", "provider": "Slack", "tier": 1, "title": str(i.get("title", ""))[:160],
         "impact": _impact(pts.get(i.get("type"), 1)), "points": pts.get(i.get("type"), 1),
         "started": i.get("date_created"), "ended": i.get("date_updated") if i.get("status") == "resolved" else None,
         "url": i.get("url") or "https://slack-status.com/"}
        for i in rows
    ]


# Feeds that only show what is open right now: we note when each incident
# first appeared and close it ourselves once it drops off the page.
STATELESS = {"Microsoft 365", "Azure", "AWS"}


def services(now, cache):
    store = cache.setdefault("incidents", {})
    jobs = {name: (lambda n=name, b=base, t=tier: _statuspage(n, b, t)) for name, (base, tier) in STATUSPAGES.items()}
    jobs.update({
        "Microsoft 365": lambda: _microsoft365(now),
        "Azure": lambda: _azure(now),
        "AWS": _aws_current,
        "AWS history": _aws_history,
        "Google Cloud": lambda: _google("Google Cloud", "https://status.cloud.google.com/"),
        "Google Workspace": lambda: _google("Google Workspace", "https://www.google.com/appsstatus/dashboard/"),
        "Apple": _apple,
        "Slack": _slack,
    })

    def attempt(name):
        try:
            return name, jobs[name](), None
        except Exception as e:  # noqa: BLE001 - one dead status page is not news
            return name, None, f"{name}: {e}"[:160]

    ok, failed = [], []
    with ThreadPoolExecutor(12) as pool:
        results = list(pool.map(attempt, jobs))
    for name, records, err in sorted(results, key=lambda r: r[0] == "AWS history"):  # real history beats our guesses
        if err:
            failed.append(err)
            continue
        ok.append(name)
        live = set()
        for r in records:
            old = store.get(r["id"]) or {}
            if name in STATELESS:
                r["started"] = min(old.get("started") or r["started"], r["started"])
                r["seen"] = now.isoformat()
            r["src"] = name
            store[r["id"]] = r
            live.add(r["id"])
        if name in STATELESS:
            for key, r in store.items():
                if r.get("src") == name and r.get("seen") and not r.get("ended") and key not in live:
                    last = parse_ts(r["seen"]) or now
                    r["ended"] = (now if now - last < dt.timedelta(hours=3) else last).isoformat()
    if not ok:
        raise FetchError("no status page reachable: " + "; ".join(failed)[:200])
    cutoff = (now - 200 * DAY).isoformat()
    for key in [k for k, r in store.items() if r.get("ended") and r["ended"] < cutoff]:
        del store[key]
    return {"incidents": list(store.values()), "checked": sorted(n for n in ok if n != "AWS history"), "failed": failed}


# --------------------------------------------------------------------------
# Hacker News (Algolia search API): what the people who run the Internet are
# upvoting. A big outage or breach reaches the front page within the hour.
# --------------------------------------------------------------------------
def _hn_window(a, b):
    out, page = [], 0
    while True:
        j = fetch_json(
            f"{HN}/search_by_date?tags=story&hitsPerPage=1000&page={page}&attributesToHighlight="
            f"&attributesToRetrieve=title,points,created_at_i,objectID"
            f"&numericFilters=points%3E{HN_MIN_POINTS},created_at_i%3E%3D{int(a.timestamp())},created_at_i%3C{int(b.timestamp())}",
            timeout=40, retries=1)
        for h in j.get("hits", []):
            title = h.get("title") or ""
            kind = "outage" if HN_OUTAGE.search(title) else "security" if HN_SECURITY.search(title) else None
            if kind and h.get("created_at_i"):
                out.append({"t": int(h["created_at_i"]), "points": int(h.get("points") or 0), "title": title[:160],
                            "id": str(h.get("objectID")), "kind": kind})
        page += 1
        if page >= j.get("nbPages", 1):
            return out


def _hn_days(stories, days):
    by = {str(d): {"outage": 0, "security": 0} for d in days}
    for s in stories:
        d = str(dt.datetime.fromtimestamp(s["t"], UTC).date())
        if d in by:
            by[d][s["kind"]] += s["points"]
    return by


def hn(now, need_days, cache, live):
    c, today = cache.setdefault("hn", {}), now.date()
    midnight = lambda d: dt.datetime(d.year, d.month, d.day, tzinfo=UTC)
    missing = [d for d in (today - i * DAY for i in range(3, need_days + 1)) if str(d) not in c]
    while missing:  # oldest first, a week per request
        first = min(missing)
        week = [first + i * DAY for i in range(7) if first + i * DAY < today - 2 * DAY]
        c.update(_hn_days(_hn_window(midnight(first), midnight(week[-1] + DAY)), week))
        missing = [d for d in missing if d not in week]
    # the last three days are still collecting votes, so always refetch them
    recent = _hn_window(midnight(today - 2 * DAY), now)
    c.update(_hn_days(recent, [today - 2 * DAY, today - DAY, today]))
    out = {"daily": c, "recent": None}
    if live:
        cut = (now - DAY).timestamp()
        out["recent"] = sorted((s for s in recent if s["t"] >= cut), key=lambda s: -s["points"])
    return out


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
SOURCE_INFO = {
    "isc": ("SANS ISC / DShield", "https://isc.sans.edu/api/"),
    "kev": ("CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    "nvd": ("NIST NVD", "https://nvd.nist.gov/developers/vulnerabilities"),
    "epss": ("FIRST EPSS", "https://www.first.org/epss/api"),
    "ransomware": ("ransomware.live", "https://www.ransomware.live/apidocs"),
    "circl": ("CIRCL Vulnerability-Lookup", "https://vulnerability.circl.lu/"),
    "ioda": ("IODA (Georgia Tech)", "https://ioda.inetintel.cc.gatech.edu/"),
    "providers": ("Service status pages", "https://status.cloud.microsoft/"),
    "hn": ("Hacker News (Algolia)", "https://hn.algolia.com/api"),
}


def collect(now, cache, live=True, history_days=0):
    """Fetch everything. history_days > 0 widens the lookback for backfills."""
    for key in ("dshield_ports", "ransomware", "circl", "ioda"):
        cache.setdefault(key, {})
    h = history_days
    jobs = {
        "isc": lambda: isc(now, 45 + h, cache, live),
        "kev": kev,
        "nvd": lambda: nvd(now, 100 + h),
        "ransomware": lambda: ransomware(now, 62 + h, cache, live),
        "circl": lambda: circl(now, 16 + h, cache, live),
        "ioda": lambda: ioda(now, 15 + h, cache, live),
    }
    jobs["providers"] = lambda: services(now, cache)
    jobs["hn"] = lambda: hn(now, 3 + h, cache, live)
    raw, errors, timings = {}, {}, {}

    def run(name):
        t0 = time.monotonic()
        try:
            return name, jobs[name](), None, time.monotonic() - t0
        except Exception as e:  # noqa: BLE001 - a dead feed degrades, never crashes
            return name, None, f"{type(e).__name__}: {e}"[:300], time.monotonic() - t0

    with ThreadPoolExecutor(len(jobs)) as pool:
        for name, data, err, secs in pool.map(run, jobs):
            timings[name] = round(secs, 1)
            if err:
                errors[name] = err
            else:
                raw[name] = data
    return raw, errors, timings
