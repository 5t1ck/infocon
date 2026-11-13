"""Write the publishable outputs: JSON API, data for the dashboard, badge, text."""
import json
from xml.sax.saxutils import escape as _esc

from . import config
from .engine import save_json, save_text
from .sources import DAY, parse_ts

# Same four status colours the dashboard uses.
COLORS = {"GREEN": "#0ca30c", "YELLOW": "#fab219", "ORANGE": "#ec835a", "RED": "#d03b3b"}
INK = {"YELLOW": "#0b0b0b"}


def thin(history, now):
    """Full resolution for two weeks, then one point per day."""
    cutoff = (now - 14 * DAY).isoformat()
    out, last_day = [], None
    for p in history:
        if p["t"] >= cutoff:
            out.append(p)
        elif p["t"][:10] != last_day:
            out.append(p)
            last_day = p["t"][:10]
        else:
            out[-1] = p
    return out


def badge(level, score):
    left, right = "5t1ck infocon", f"{level} {score:.0f}" if score is not None else level
    lw, rw = 96, 14 + 7 * len(right)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + rw}" height="20" role="img" '
        f'aria-label="{left}: {right}"><title>{left}: {right}</title>'
        f'<rect width="{lw + rw}" height="20" rx="3" fill="#333"/>'
        f'<rect x="{lw}" width="{rw}" height="20" rx="3" fill="{COLORS[level]}"/>'
        f'<rect x="{lw}" width="6" height="20" fill="{COLORS[level]}"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
        f'<text x="{lw / 2}" y="14">{left}</text>'
        f'<text x="{lw + rw / 2}" y="14" font-weight="bold" fill="{INK.get(level, "#fff")}">{right}</text>'
        f"</g></svg>\n"
    )


def escape(text, attr=False):
    return _esc(text, {'"': "&quot;"} if attr else {})


def _wrap(text, width, lines):
    """Greedy word wrap to at most `lines` lines; the last one ends in an ellipsis if cut."""
    out, words = [], text.split()
    while words and len(out) < lines:
        line = words.pop(0)
        while words and len(line) + 1 + len(words[0]) <= width:
            line += " " + words.pop(0)
        out.append(line)
    if words:
        out[-1] = out[-1][:width - 1].rstrip(" ,;:(") + "…"
    return [l if len(l) <= width else l[:width - 1] + "…" for l in out]


def card(status):
    """status.svg: the level plus the main reason for it, sized to embed in a dashboard."""
    level, score, drivers = status["level"], status["score"], status["drivers"]
    color, ink = COLORS[level], INK.get(level, "#fff")
    if status.get("degraded"):
        why, more = "Too few feeds answered, so the last level is being held.", ""
    elif drivers:
        why = drivers[0]["text"]
        rest = [d["label"] for d in drivers[1:]]
        more = f"Also: {', '.join(rest)}" if rest else ""
    else:
        why, more = "Nothing unusual: every signal is near its normal range.", ""
    why = why[0].upper() + why[1:]
    head = config.LABELS.get(drivers[0]["component"], "") if drivers and not status.get("degraded") else ""
    updated = parse_ts(status["generated"]).strftime("%d %b %H:%M UTC")
    label = f"5t1ck InfoCon {level}" + ("" if score is None else f" {score:.0f}") + f". {why}"
    w, h, lw = 500, 96, 112
    body = "".join(f'<text x="{lw + 12}" y="{39 + 15 * i}" fill="#eee" font-size="12">{escape(l)}</text>'
                   for i, l in enumerate(_wrap(why, 52, 3)))
    more = _wrap(more, 60, 1)[0] if more else ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
        f'aria-label="{escape(label, True)}"><title>{escape(label)}</title>'
        f'<clipPath id="c"><rect width="{w}" height="{h}" rx="6"/></clipPath>'
        f'<g clip-path="url(#c)" font-family="Verdana,DejaVu Sans,sans-serif">'
        f'<rect width="{w}" height="{h}" fill="#1c1c1e"/><rect width="{lw}" height="{h}" fill="{color}"/>'
        f'<g fill="{ink}" text-anchor="middle">'
        f'<text x="{lw / 2}" y="26" font-size="9" opacity=".8">5T1CK INFOCON</text>'
        f'<text x="{lw / 2}" y="52" font-size="19" font-weight="bold">{level}</text>'
        + ("" if score is None else f'<text x="{lw / 2}" y="74" font-size="12">{score:.0f} / 100</text>')
        + f'</g><text x="{lw + 12}" y="20" fill="#9a9aa0" font-size="10" font-weight="bold">'
        f'{escape((head or "Status").upper())}</text>'
        f'<text x="{w - 10}" y="20" fill="#9a9aa0" font-size="10" text-anchor="end">{updated}</text>'
        f'{body}<text x="{lw + 12}" y="87" fill="#9a9aa0" font-size="10">{escape(more)}</text>'
        f"</g></svg>\n"
    )


def publish(status, history):
    now = parse_ts(status["generated"])
    slim = thin(history, now)
    site = config.SITE_DIR
    # The page itself ships inside the package so site/ is entirely generated.
    page = config.ROOT / "infocon" / "dashboard.html"
    save_text(site / "index.html", page.read_text(encoding="utf-8"))
    save_json(site / "status.json", status)
    save_json(site / "history.json", slim)
    # data.js lets index.html work straight from disk (file://) as well as over HTTP.
    save_text(site / "data.js",
              "window.INFOCON_STATUS=" + json.dumps(status, separators=(",", ":")) + ";\n"
              "window.INFOCON_HISTORY=" + json.dumps(slim, separators=(",", ":")) + ";\n")
    save_text(site / "badge.svg", badge(status["level"], status["score"]))
    save_text(site / "status.svg", card(status))
    score = "" if status["score"] is None else f" {status['score']:.0f}"
    save_text(site / "status.txt", f"{status['level']}{score}\n")


def console(status):
    score = "n/a" if status["score"] is None else f"{status['score']:.0f}/100"
    lines = [f"5T1CK INFOCON  {status['level']}  {score}   (SANS InfoCon says: {status['sans_infocon'] or 'unknown'})",
             f"  {status['summary']}", ""]
    for c in status["components"]:
        if c["score"] is None:
            lines.append(f"  {c['label']:<26}  n/a  (feed unavailable)")
            continue
        lines.append(f"  {c['label']:<26} {c['score']:5.1f}  {'#' * round(c['score'] / 5)}")
        for s in c["signals"]:
            lines.append(f"      {s['score']:5.1f}  {s['text']}")
    bad = [s for s in status["sources"] if not s["ok"]]
    lines += ["", f"  feeds: {len(status['sources']) - len(bad)}/{len(status['sources'])} ok"
              + ("  | down: " + "; ".join(f"{s['name']} ({s['note']})" for s in bad) if bad else "")]
    return "\n".join(lines)
