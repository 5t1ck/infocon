"""Write the publishable outputs: JSON API, data for the dashboard, badge, text."""
import json

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
    left, right = "infocon", f"{level} {score:.0f}" if score is not None else level
    lw, rw = 62, 14 + 7 * len(right)
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
    score = "" if status["score"] is None else f" {status['score']:.0f}"
    save_text(site / "status.txt", f"{status['level']}{score}\n")


def console(status):
    score = "n/a" if status["score"] is None else f"{status['score']:.0f}/100"
    lines = [f"INFOCON  {status['level']}  {score}   (SANS InfoCon says: {status['sans_infocon'] or 'unknown'})",
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
