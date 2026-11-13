"""Collect -> score -> remember -> publish."""
import collections
import datetime as dt
import json
import os

from . import config, scoring, sources
from .sources import DAY, UTC, parse_ts

ORDER = list(config.WEIGHTS)


# ------------------------------------------------------------------ persistence
def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def save_json(path, obj, **kw):
    save_text(path, json.dumps(obj, separators=(",", ":"), **kw))


def load_history():
    path = config.DATA_DIR / "history.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def save_history(points, now):
    cutoff = (now - config.HISTORY_KEEP_DAYS * DAY).isoformat()
    points = sorted((p for p in points if p["t"] >= cutoff), key=lambda p: p["t"])
    save_text(config.DATA_DIR / "history.jsonl", "".join(json.dumps(p, separators=(",", ":")) + "\n" for p in points))
    return points


def _prune(cache, now):
    cutoff = str(now.date() - 400 * DAY)
    for key in ("circl", "ioda", "hn"):
        cache[key] = {d: v for d, v in cache.get(key, {}).items() if d >= cutoff}


def _ctx(now, live=True, day=None):
    if live:
        return {"now": now, "today": now.date(), "day": sources.last_complete_day(now), "live": True}
    end = dt.datetime(day.year, day.month, day.day, 23, 59, 59, tzinfo=UTC)
    return {"now": end, "today": day, "day": day, "live": False}


def _point(t, score, level, coverage, comps, backfilled=False):
    p = {"t": t.isoformat(timespec="seconds"), "score": score, "level": level, "coverage": coverage,
         "c": {k: (comps[k]["score"] if comps.get(k) else None) for k in ORDER}}
    if backfilled:
        p["bf"] = 1
    return p


# ------------------------------------------------------------------- highlights
def _epss_wanted(raw, now):
    want = set()
    if raw.get("kev"):
        cut = str(now.date() - 14 * DAY)
        want |= {i["cve"] for i in raw["kev"]["items"] if i["added"] >= cut}
    if raw.get("circl"):
        for row in raw["circl"]["top"] + raw["circl"]["top_exploited"]:
            want.add(row["vulnerability"].upper())
    if raw.get("nvd"):
        want |= {i["cve"] for i in raw["nvd"] if (parse_ts(i["published"]) or now) > now - 30 * DAY}
    return {c for c in want if c.startswith("CVE-")}


def highlights(raw, epss, now, titles):
    h = {}
    kev_ids = {i["cve"] for i in raw["kev"]["items"]} if raw.get("kev") else set()
    if raw.get("kev"):
        cut = str(now.date() - 10 * DAY)
        recent = sorted((i for i in raw["kev"]["items"] if i["added"] >= cut), key=lambda i: i["added"], reverse=True)
        h["kev_recent"] = [dict(i, epss=epss.get(i["cve"])) for i in recent[:15]]
        h["kev_version"] = raw["kev"]["version"]
    if raw.get("circl"):
        row = lambda r: {"cve": r["vulnerability"].upper(), "count": r["count"],
                         "title": titles.get(r["vulnerability"].upper()),
                         "epss": epss.get(r["vulnerability"].upper()), "kev": r["vulnerability"].upper() in kev_ids}
        h["trending"] = [row(r) for r in raw["circl"]["top"][:8]]
        h["exploited"] = [row(r) for r in raw["circl"]["top_exploited"][:8]]
    if raw.get("nvd") and epss:
        fresh = [i for i in raw["nvd"] if (parse_ts(i["published"]) or now) > now - 30 * DAY]
        hot = sorted((i for i in fresh if epss.get(i["cve"], 0) >= config.EPSS_WEAPONISED),
                     key=lambda i: -epss[i["cve"]])
        h["weaponised"] = [dict(i, epss=epss[i["cve"]], kev=i["cve"] in kev_ids) for i in hot[:8]]
    rl = raw.get("ransomware")
    if rl and rl.get("recent"):
        recent = [v for v in rl["recent"] if (parse_ts(v["discovered"]) or now) > now - 3 * DAY]
        top = lambda key: [{"name": k, "count": n} for k, n in
                           collections.Counter(v[key] or "unknown" for v in recent).most_common(6)]
        h["ransomware"] = {"count_72h": len(recent), "capped": len(recent) == len(rl["recent"]),
                           "groups": top("group"), "countries": top("country"), "sectors": top("sector")}
    if raw.get("isc") and raw["isc"].get("ports"):
        h["ports"] = raw["isc"]["ports"]
    if raw.get("providers"):
        _, ranked = scoring.service_load(raw["providers"]["incidents"], now)
        h["incidents"] = [dict({k: i.get(k) for k in ("provider", "title", "impact", "started", "first_seen", "ended", "url")},
                               weight=round(pts, 1)) for pts, i in ranked[:14]]
        h["providers_checked"] = raw["providers"]["checked"]
    if raw.get("hn") and raw["hn"].get("recent") is not None:
        h["stories"] = [{"title": s["title"], "points": s["points"], "kind": s["kind"],
                         "posted": dt.datetime.fromtimestamp(s["t"], UTC).isoformat(timespec="seconds"),
                         "url": f"https://news.ycombinator.com/item?id={s['id']}"} for s in raw["hn"]["recent"][:10]]
    io = raw.get("ioda")
    if io and io.get("last24") is not None:
        days = [io["daily"][d]["rows"] for d in sorted(io["daily"])[-14:]]
        seen = collections.Counter(r[0] for d in days for r in d)
        solid = set(scoring.corroborated(io["last24"]))
        rows = sorted(io["last24"], key=lambda r: (r["code"] not in solid, -r["score"]))
        h["outages"] = [dict(r, corroborated=r["code"] in solid,
                             chronic=bool(days) and seen[r["code"]] >= 0.6 * len(days)) for r in rows[:10]]
    return h


def summarise(level, state, drivers, components):
    if state.get("degraded"):
        return f"Too few feeds are reachable to judge; holding at {level}."
    if not drivers:
        return "Every signal is within its normal range."
    names = []
    for d in drivers:
        label = config.LABELS[d["component"]].lower()
        if label not in names:
            names.append(label)
    lead = " and ".join(names[:2]) if len(names) <= 2 else f"{names[0]}, {names[1]} and {len(names) - 2} more"
    text = f"Elevated {lead}."
    if state.get("below_since"):
        text += f" Score has eased; holding {level} until it stays down for {config.HOLD_HOURS}h."
    return text


# -------------------------------------------------------------------------- run
def run(now=None, log=print):
    now = now or dt.datetime.now(UTC)
    cache = load_json(config.DATA_DIR / "cache.json", {})
    state = load_json(config.DATA_DIR / "state.json", {})
    raw, errors, timings = sources.collect(now, cache, live=True)
    epss = {}
    try:
        epss = sources.epss(_epss_wanted(raw, now))
    except Exception as e:  # noqa: BLE001
        errors["epss"] = f"{type(e).__name__}: {e}"[:300]
    if raw.get("isc", {}).get("ports_error"):
        errors["isc"] = "port detail unavailable: " + raw["isc"]["ports_error"]

    titles = {}
    if raw.get("circl"):
        ids = [r["vulnerability"].upper() for r in raw["circl"]["top"][:8] + raw["circl"]["top_exploited"][:8]]
        known = {i["cve"]: i["name"][:160] for i in (raw.get("kev") or {}).get("items", [])}
        titles = sources.cve_titles([c for c in ids if c.startswith("CVE-")], cache, known)

    comps = scoring.evaluate(raw, epss, _ctx(now))
    score, coverage = scoring.composite(comps)
    state = scoring.apply_hysteresis(score, coverage, state, now)
    level = state["level"]
    drv = scoring.drivers(comps)

    status = {
        "schema": 1,
        "generated": now.isoformat(timespec="seconds"),
        "level": level,
        "level_since": state.get("since"),
        "score": score,
        "raw_level": scoring.level_for(score) if score is not None else None,
        "easing_since": state.get("below_since"),
        "coverage": coverage,
        "degraded": state.get("degraded", False),
        "summary": summarise(level, state, drv, comps),
        "drivers": drv,
        "components": [
            comps[k] or {"id": k, "label": config.LABELS[k], "weight": config.WEIGHTS[k],
                         "score": None, "signals": [], "sources": []}
            for k in ORDER
        ],
        "sans_infocon": (raw.get("isc") or {}).get("sans_infocon"),
        "highlights": highlights(raw, epss, now, titles),
        "sources": [
            {"id": sid, "name": name, "url": url, "ok": sid in raw or (sid == "epss" and bool(epss)),
             "note": errors.get(sid), "seconds": timings.get(sid)}
            for sid, (name, url) in sources.SOURCE_INFO.items()
        ],
        "method": {"levels": config.LEVELS, "weights": config.WEIGHTS, "power": config.POWER,
                   "hold_hours": config.HOLD_HOURS, "margin": config.MARGIN},
    }

    history = load_history()
    if score is not None:
        history.append(_point(now, score, level, coverage, comps))
    history = save_history(history, now)
    _prune(cache, now)
    save_json(config.DATA_DIR / "cache.json", cache)
    save_json(config.DATA_DIR / "state.json", state)

    from . import render
    render.publish(status, history)
    log(render.console(status))
    return status


def backfill(days=60, now=None, log=print):
    """Replay the scoring over past days using feeds that expose history.
    Port surges, EPSS and the status pages that publish no history (Microsoft,
    Azure) are absent, so this is a slightly conservative reconstruction - good
    for calibration and for seeding the chart, and flagged as such."""
    now = now or dt.datetime.now(UTC)
    cache = load_json(config.DATA_DIR / "cache.json", {})
    log(f"Fetching {days} days of history (first time takes a few minutes)...")
    raw, errors, timings = sources.collect(now, cache, live=False, history_days=days)
    _prune(cache, now)
    save_json(config.DATA_DIR / "cache.json", cache)
    for name, err in errors.items():
        log(f"  ! {name}: {err}")

    points, tally = [], collections.Counter()
    for i in range(days, 0, -1):
        day = now.date() - i * DAY
        ctx = _ctx(now, live=False, day=day)
        comps = scoring.evaluate(raw, {}, ctx)
        score, coverage = scoring.composite(comps)
        if score is None or coverage < config.MIN_COVERAGE:
            continue
        level = scoring.level_for(score)
        tally[level] += 1
        points.append(_point(ctx["now"], score, level, coverage, comps, backfilled=True))

    history = [p for p in load_history() if not p.get("bf")] + points
    history = save_history(history, now)
    status = load_json(config.SITE_DIR / "status.json", None)
    if status:
        from . import render
        render.publish(status, history)
    log(f"Backfilled {len(points)} days: " + ", ".join(f"{l} {tally[l]}" for l, _ in config.LEVELS))
    return points
