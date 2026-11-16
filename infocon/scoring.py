"""Pure scoring: raw feed data in, component scores and a level out.

Almost every signal is scored the same way: how far is the current value from
its own trailing baseline, measured as a robust z-score (median / MAD), mapped
through one fixed curve to 0-100. That keeps the level about *change*, which is
what an "infocon" is for, and means no per-feed magic thresholds.
"""
import bisect
import collections
import math
import statistics

from . import config
from .sources import DAY, parse_ts

MIN_BASELINE = 7
FIRING = 45  # a signal at or above this is "elevated"


def interp(curve, x):
    if x <= curve[0][0]:
        return float(curve[0][1])
    for (x0, y0), (x1, y1) in zip(curve, curve[1:]):
        if x <= x1:
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return float(curve[-1][1])


def robust_z(value, baseline, floor_rel=0.08, floor_abs=0.0, log=False):
    """(z, median). The spread is floored so a dead-flat baseline can't turn a
    trivial wobble into a huge z.

    log=True compares on a log scale ("how many times normal"), which is the
    right yardstick for big, heavy-tailed counts; floor_rel is then the smallest
    relative change treated as one sigma."""
    if log:
        lv = [math.log1p(max(b, 0)) for b in baseline]
        med = statistics.median(lv)
        mad = statistics.median(abs(x - med) for x in lv) * 1.4826
        return (math.log1p(max(value, 0)) - med) / max(mad, floor_rel), math.expm1(med)
    med = statistics.median(baseline)
    mad = statistics.median(abs(x - med) for x in baseline) * 1.4826
    spread = max(mad, floor_rel * abs(med), floor_abs, 1e-9)
    return (value - med) / spread, med


def fmt(n):
    if n is None:
        return "?"
    a = abs(n)
    if a >= 1e6:
        return f"{n / 1e6:.1f}M"
    if a >= 1e4:
        return f"{n / 1e3:.0f}k"
    if a >= 100 or float(n).is_integer():
        return f"{n:,.0f}"
    return f"{n:.1f}"


def signal(sid, label, value, baseline, what, damp=1.0, counted=True, **floors):
    """Baseline-relative signal. `what` completes "<value> <what>"."""
    baseline = [b for b in baseline if b is not None]
    if value is None or len(baseline) < MIN_BASELINE:
        return None
    z, med = robust_z(value, baseline, **floors)
    z *= damp
    delta = f", {(value - med) / med * 100:+.0f}%" if med else ""
    return {
        "id": sid, "label": label, "value": round(value, 2), "typical": round(med, 2),
        "z": round(z, 2), "score": round(interp(config.Z_CURVE, z), 1), "counted": counted,
        "text": f"{fmt(value)} {what} (typical {fmt(med)}{delta})",
        "short": f"{label} {(value - med) / med * 100:+.0f}%" if med else label,
    }


def absolute(sid, label, value, score, text, short=None):
    """Signal scored on a fixed curve rather than against its own history.
    `short` is the few-word version for the embeddable status card."""
    return {"id": sid, "label": label, "value": value, "typical": None, "z": None,
            "score": round(score, 1), "counted": True, "text": text, "short": short or label}


def component(cid, signals, sources):
    signals = [s for s in signals if s]
    if not signals:
        return None
    counted = [s["score"] for s in signals if s["counted"]] or [max(s["score"] for s in signals)]
    score = 0.7 * max(counted) + 0.3 * statistics.fmean(counted)
    return {"id": cid, "label": config.LABELS[cid], "weight": config.WEIGHTS[cid],
            "score": round(score, 1), "signals": signals, "sources": sources}


def _days(daily, end, n, pick=lambda v: v):
    return [pick(daily[str(end - i * DAY)]) for i in range(n) if str(end - i * DAY) in daily]


# ------------------------------------------------------------------ components
def scanning(isc, ctx):
    daily, day = isc["daily"], ctx["day"]
    for back in range(3):  # tolerate the newest day not being published yet
        if str(day - back * DAY) in daily:
            day = day - back * DAY
            break
    else:
        return None
    cur = daily[str(day)]
    per_sensor = lambda r: r["records"] / max(r["targets"], 1)
    sigs = [
        signal("sources", "Attacking IPs", cur["sources"],
               _days(daily, day - DAY, 28, lambda r: r["sources"]),
               f"distinct attacking IPs hit DShield sensors on {day:%b %d}", log=True, floor_rel=0.06),
        signal("intensity", "Attack intensity", per_sensor(cur),
               _days(daily, day - DAY, 28, per_sensor),
               "attack reports per sensor", log=True, floor_rel=0.10),
    ]
    if ctx["live"] and isc.get("ports"):
        surges = [p for p in isc["ports"] if p.get("ratio") and p["sources"] >= 2000]
        if surges:
            top = max(surges, key=lambda p: p["ratio"])
            score = interp([(1, 15), (1.5, 30), (2, 45), (3, 60), (5, 78), (8, 90), (12, 100)], top["ratio"])
            sigs.append(absolute(
                "port_surge", "Port surge", top["ratio"], score,
                f"port {top['port']} is being probed by {top['ratio']:.1f}x its usual number of sources",
                f"Port {top['port']} probes {top['ratio']:.1f}x normal"))
    return component("scanning", sigs, ["isc"])


def exploitation(kev, ctx):
    sigs = []
    if kev:
        weight, raw, rw = collections.Counter(), collections.Counter(), collections.Counter()
        for i in kev["items"]:
            weight[i["added"]] += 1.5 if i["ransomware"] else 1.0
            raw[i["added"]] += 1
            rw[i["added"]] += i["ransomware"]
        week = lambda c, d: sum(c.get(str(d - i * DAY), 0) for i in range(7))
        today = ctx["today"]
        s = signal("kev", "CISA KEV additions", week(weight, today),
                   [week(weight, today - (7 + i) * DAY) for i in range(180)],
                   "", floor_rel=0.25, floor_abs=1.5)
        if s:
            n, r = week(raw, today), week(rw, today)
            s["value"] = n
            s["text"] = (f"{n} CVE{'s' * (n != 1)} added to CISA's known-exploited list in 7 days"
                         + (f", {r} tied to ransomware" if r else "")
                         + f" (typical {fmt(s['typical'])})")
            sigs.append(s)
    return component("exploitation", sigs, ["kev"])


def _circl_current(circl, ctx, key):
    """(current daily rate, 14-day baseline). CIRCL only filters by whole UTC
    day, so the live reading blends yesterday with today-so-far as a rate."""
    daily, pick = circl["daily"], (lambda v: v[key])
    t, y = circl.get("today"), ctx["today"] - DAY
    if ctx["live"] and t and str(y) in daily:
        cur = (daily[str(y)][key] + t[key]) * 24 / (24 + t["hours"])
        return cur, _days(daily, y - DAY, 14, pick)
    d = ctx["day"]
    return (pick(daily[str(d)]) if str(d) in daily else None), _days(daily, d - DAY, 14, pick)


def corroborated(rows):
    """Countries whose outage was flagged by >= 2 independent IODA measurements
    (BGP, active probing, Google traffic, darknet). Single-source alerts are
    mostly measurement noise; a source flagging half the planet is a glitch."""
    norm = []
    for r in rows:
        code, score, via = (r["code"], r["score"], r["via"]) if isinstance(r, dict) else (r[0], r[1], r[2].split(","))
        if score >= config.IODA_MIN_SCORE:
            norm.append((code, set(via)))
    seen = collections.Counter(src for _, via in norm for src in via)
    glitching = {src for src, n in seen.items() if n > config.IODA_GLITCH}
    return [code for code, via in norm if len(via - glitching) >= 2]


def vulnerabilities(nvd, epss, ctx):
    now = ctx["now"]
    times = sorted(t for t in (parse_ts(i["published"]) for i in nvd) if t)
    week = lambda t: bisect.bisect_right(times, t) - bisect.bisect_right(times, t - 7 * DAY)
    sigs = [signal("criticals", "Critical CVEs published", week(now),
                   [week(now - (7 + i) * DAY) for i in range(84) if times and now - (14 + i) * DAY >= times[0]],
                   "critical-severity CVEs published in 7 days", log=True, floor_rel=0.20)]
    if ctx["live"] and epss:
        fresh = [i for i in nvd if (parse_ts(i["published"]) or now) > now - 30 * DAY]
        hot = [i for i in fresh if epss.get(i["cve"], 0) >= config.EPSS_WEAPONISED]
        sigs.append(absolute(
            "weaponised", "Likely-exploited fresh criticals", len(hot),
            interp(config.WEAPONISED_CURVE, len(hot)),
            f"{len(hot)} of {len(fresh)} critical CVEs from the last 30 days already have "
            f"EPSS >= {config.EPSS_WEAPONISED:.0%}",
            f"{len(hot)} new criticals likely exploited"))
    return component("vulnerabilities", sigs, ["nvd"] + (["epss"] if epss else []))


def ransomware(rl, ctx):
    daily, trusted, through = rl["daily"], rl["trusted_from"], rl["through"]
    now = ctx["now"]

    def three(end):
        if str(end - 2 * DAY) < trusted or str(end) > through:
            return None
        return sum(daily.get(str(end - i * DAY), 0) for i in range(3))

    if ctx["live"] and rl.get("recent"):
        ts = sorted(t for t in (parse_ts(v["discovered"]) for v in rl["recent"]) if t)
        recent = [t for t in ts if t > now - 3 * DAY]
        if ts and len(recent) == len(ts):  # feed is capped at its newest N: extrapolate
            hours = max((now - ts[0]).total_seconds() / 3600, 1)
            cur = len(ts) * 72 / hours
        else:
            cur = len(recent)
        end = ctx["today"]
    else:
        cur, end = three(ctx["day"]), ctx["day"]
    base = [three(end - (3 + i) * DAY) for i in range(56)]
    sig = signal("victims", "Leak-site victims", cur, base,
                 "victims posted to ransomware leak sites in 72h", log=True, floor_rel=0.18)
    return component("ransomware", [sig], ["ransomware"])


def incident_weight(inc, now, daily=False):
    """How much of an incident's severity still counts at `now` (0..1).
    daily=True replays a whole past day: anything that was open at some point
    in the 24 h before `now` counts in full."""
    start, end = parse_ts(inc.get("started")), parse_ts(inc.get("ended"))
    if not start or start > now:
        return 0.0
    if end and end <= now:
        gone = (now - end).total_seconds() / 3600
        if daily:
            return 1.0 if gone < 24 else 0.0
        return next((w for h, w in config.RESOLVED_DECAY if gone < h), 0.0)
    open_for = (now - start).total_seconds() / 3600
    return next((w for h, w in config.OPEN_DECAY if open_for < h), config.OPEN_STALE)


def tier_weight(inc, now):
    """Weight of the incident's service. Smaller services start low and earn
    their full weight only once a major or critical incident has lasted
    (SUSTAINED_HOURS). A minor one left open for days is still minor, and so
    is one feature of a service being broken ("unable to join meetings")."""
    first, full = config.TIER_WEIGHT.get(inc.get("tier"), (1.0, 1.0))
    start, end = parse_ts(inc.get("started")), parse_ts(inc.get("ended"))
    if full <= first or not start or inc.get("points", 0) < config.SUSTAINED_MIN_POINTS:
        return first
    if 0 < inc.get("parts", 0) < config.SUSTAINED_MIN_PARTS:
        return first
    lasted = (min(end or now, now) - start).total_seconds() / 3600
    lo, hi = config.SUSTAINED_HOURS
    return first + (full - first) * min(max((lasted - lo) / (hi - lo), 0.0), 1.0)


def service_load(incidents, now, daily=False):
    """(points, ranked) for big-service incidents. ranked = [(points, incident)]
    for everything that still counts, worst first. Each provider is worth its
    worst incident plus a share of its others; the worst provider leads and
    the remaining providers add a share."""
    ranked = []
    for inc in incidents:
        pts = inc.get("points", 0) * tier_weight(inc, now) * incident_weight(inc, now, daily)
        if pts > 0:
            ranked.append((pts, inc))
    ranked.sort(key=lambda r: -r[0])
    per = collections.defaultdict(list)
    for pts, inc in ranked:
        per[inc["provider"]].append(pts)
    totals = sorted((min(1.5 * v[0], v[0] + config.SAME_PROVIDER * sum(v[1:])) for v in per.values()), reverse=True)
    points = totals[0] + config.OTHER_PROVIDERS * sum(totals[1:3]) if totals else 0.0
    return points, ranked


def _ago(ts, now):
    hours = (now - ts).total_seconds() / 3600
    return f"{hours * 60:.0f} min" if hours < 1 else f"{hours:.0f}h" if hours < 48 else f"{hours / 24:.0f}d"


def _hn_points(hn, ctx, kind):
    """(points, stories) of one kind: the last 24 h live, the whole day in a replay."""
    if ctx["live"] and hn.get("recent") is not None:
        stories = [s for s in hn["recent"] if s["kind"] == kind]
        return sum(s["points"] for s in stories), stories
    day = hn["daily"].get(str(ctx["day"]))
    return (day[kind] if day else None), []


def _lead(stories):
    """The biggest story's title, for the status card."""
    return f"News: {max(stories, key=lambda s: s['points'])['title']}" if stories else None


def _headline(stories, noun):
    if not stories:
        return f"{noun} stories"
    lead = max(stories, key=lambda s: s["points"])["title"][:90]
    more = len(stories) - 1
    return f"\u201c{lead}\u201d" + (f" and {more} more {noun} stor{'y' if more == 1 else 'ies'}" if more else "")


def infrastructure(ioda, prov, hn, ctx):
    sigs, now = [], ctx["now"]
    if prov:
        pts, ranked = service_load(prov["incidents"], now, daily=not ctx["live"])
        if ranked:
            top = ranked[0][1]
            end = parse_ts(top.get("ended"))
            over = bool(end and end <= now)
            state = f"resolved {_ago(end, now)} ago" if over and ctx["live"] else "resolved" if over else "ongoing"
            more = len({i["provider"] for _, i in ranked}) - 1
            title = top["title"][:110]
            lead = title if title.startswith(top["provider"]) else f"{top['provider']}: {title}"
            text = (f"{lead} ({top['impact']}, {state})"
                    + (f", plus incidents at {more} other service{'' if more == 1 else 's'}" if more else ""))
        else:
            text = f"no incidents at {len(prov['checked'])} major services"
        short = f"{top['provider']} {top['impact']} incident{' (resolved)' if over else ''}" if ranked else None
        sigs.append(absolute("providers", "Big-service incidents", round(pts, 1),
                             interp(config.SERVICE_CURVE, pts), text, short))
    if ioda:
        daily, live = ioda["daily"], ctx["live"] and ioda.get("last24") is not None
        end = ctx["today"] - DAY if live else ctx["day"] - DAY
        cur = ioda["last24"] if live else daily.get(str(ctx["day"]), {}).get("rows")
        n = None if cur is None else len(corroborated(cur))
        sigs.append(signal("outages", "Country-level outages", n,
                           _days(daily, end, 14, lambda v: len(corroborated(v["rows"]))),
                           f"corroborated country-level Internet outage{'' if n == 1 else 's'} in 24h",
                           floor_abs=2))
    if hn:
        pts, stories = _hn_points(hn, ctx, "outage")
        if pts is not None:
            # Headlines alone are hearsay: they count in full only when a status page or IODA agrees.
            confirmed = any(s and s["score"] >= FIRING for s in sigs)
            share = 1.0 if confirmed else config.HN_UNCONFIRMED
            note = "" if confirmed or not pts else f", counted at {share:.0%}: no status page confirms an outage"
            sigs.insert(1 if prov else 0, absolute(
                "hn_outage", "Outage chatter", pts, interp(config.HN_OUTAGE_CURVE, pts * share),
                f"{_headline(stories, 'outage')} on the Hacker News front page ({fmt(pts)} points{note})"
                if pts else "no outage stories on the Hacker News front page",
                _lead(stories)))
    return component("infrastructure", sigs,
                     [s for s, d in (("providers", prov), ("hn", hn), ("ioda", ioda)) if d])


def chatter(circl, hn, ctx):
    sigs = []
    if circl:
        cur, base = _circl_current(circl, ctx, "all")
        sigs.append(signal("sightings", "CVE mentions", cur, base,
                           "CVE sightings per day across social, news and exploit feeds", log=True, floor_rel=0.25))
    if hn:
        pts, stories = _hn_points(hn, ctx, "security")
        if pts is not None:
            sigs.append(absolute("hn_security", "Security headlines", pts, interp(config.HN_SECURITY_CURVE, pts),
                                 f"{_headline(stories, 'security')} on the Hacker News front page ({fmt(pts)} points)"
                                 if pts else "no security stories on the Hacker News front page",
                                 _lead(stories)))
    return component("chatter", sigs, [s for s, d in (("circl", circl), ("hn", hn)) if d])


def evaluate(raw, epss, ctx):
    """All six components. A missing feed yields None for whatever needs it."""
    def safe(fn, *args, need=True):
        if not need:
            return None
        try:
            return fn(*args)
        except Exception:  # noqa: BLE001 - malformed upstream data degrades one component only
            return None

    g = raw.get
    return {
        "scanning": safe(scanning, g("isc"), ctx, need=bool(g("isc"))),
        "exploitation": safe(exploitation, g("kev"), ctx, need=bool(g("kev"))),
        "vulnerabilities": safe(vulnerabilities, g("nvd"), epss, ctx, need=bool(g("nvd"))),
        "ransomware": safe(ransomware, g("ransomware"), ctx, need=bool(g("ransomware"))),
        "infrastructure": safe(infrastructure, g("ioda"), g("providers"), g("hn"), ctx,
                               need=bool(g("ioda") or g("providers") or g("hn"))),
        "chatter": safe(chatter, g("circl"), g("hn"), ctx, need=bool(g("circl") or g("hn"))),
    }


# ------------------------------------------------------------------- composite
def composite(components):
    """(score, coverage): weighted power mean over the components we have."""
    live = {k: c for k, c in components.items() if c}
    coverage = sum(config.WEIGHTS[k] for k in live)
    if not live:
        return None, 0.0
    p = config.POWER
    total = sum(config.WEIGHTS[k] * c["score"] ** p for k, c in live.items())
    return round((total / coverage) ** (1 / p), 1), round(coverage, 2)


def level_for(score):
    name = config.LEVELS[0][0]
    for lvl, floor in config.LEVELS:
        if score >= floor:
            name = lvl
    return name


def settle(score, coverage, state, now):
    """The level is whatever band the score is in. Only when too few feeds
    answer to judge is the previous level kept, and marked degraded."""
    state = {k: v for k, v in (state or {}).items() if k in ("level", "since")}
    if score is None or coverage < config.MIN_COVERAGE:
        state.setdefault("level", "GREEN")
        state["degraded"] = True
        return state
    level = level_for(score)
    if level != state.get("level"):
        state.update(level=level, since=now.isoformat())
    state["degraded"] = False
    return state


def drivers(components, limit=5):
    out = []
    for c in components.values():
        if not c:
            continue
        for s in c["signals"]:
            if s["counted"] and s["score"] >= FIRING:
                out.append({"component": c["id"], "label": s["label"], "text": s["text"],
                            "short": s.get("short") or s["label"],
                            "score": s["score"], "rank": s["score"] * c["weight"]})
    out.sort(key=lambda d: -d["rank"])
    return [{k: v for k, v in d.items() if k != "rank"} for d in out[:limit]]
