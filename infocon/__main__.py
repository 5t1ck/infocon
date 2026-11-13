"""CLI: python -m infocon {run,backfill,serve,status}"""
import argparse
import functools
import http.server
import json
import os
import signal
import sys
import threading
import time
import traceback

from . import config, engine


def cmd_run(args):
    status = engine.run(log=(lambda *_: None) if args.quiet else print)
    if args.quiet:
        print(open(config.SITE_DIR / "status.txt", encoding="utf-8").read().strip())
    return 0 if not status["degraded"] else 2


def cmd_backfill(args):
    engine.backfill(days=args.days)
    return 0


def cmd_status(args):
    status = engine.load_json(config.SITE_DIR / "status.json", None)
    if not status:
        print("No status yet - run `python -m infocon run` first.", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        from . import render
        print(render.console(status))
        print(f"\n  as of {status['generated']}")
    return 0


WARMING_UP = """<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="10">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>5t1ck InfoCon</title>
<body style="font:16px system-ui,sans-serif;margin:15vh auto;max-width:32em;padding:0 16px;color:#888;background:#111">
<h1 style="color:#eee;font-size:20px">Collecting the first reading</h1>
<p>The feeds are being fetched for the first time. This page reloads itself; expect a result in about a minute.</p>
"""


def cmd_serve(args):
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # `docker stop` should be instant
    if not (config.SITE_DIR / "index.html").exists():
        engine.save_text(config.SITE_DIR / "index.html", WARMING_UP)
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a, **k):  # the log is for refreshes, not for every page view
            pass

    handler = functools.partial(Quiet, directory=str(config.SITE_DIR))
    server = http.server.ThreadingHTTPServer((args.host, args.port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Dashboard: http://{args.host}:{args.port}/   (refreshing every {args.interval} min, Ctrl+C to stop)", flush=True)
    seed = args.backfill
    try:
        while True:
            try:
                status = engine.run(log=lambda *_: None)
                print(f"{status['generated']}  {status['level']}  {status['score']}  {status['summary']}", flush=True)
                if seed and not any(p.get("bf") for p in engine.load_history()):
                    engine.backfill(days=seed, log=lambda m: print(m, flush=True))
                seed = 0
            except Exception:  # noqa: BLE001 - keep serving the last good result
                traceback.print_exc()
            time.sleep(args.interval * 60)
    except KeyboardInterrupt:
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="infocon", description="5t1ck InfoCon: an automated Internet threat level.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="collect, score, publish to site/")
    r.add_argument("-q", "--quiet", action="store_true", help="print only 'LEVEL score'")
    r.set_defaults(fn=cmd_run)
    b = sub.add_parser("backfill", help="reconstruct past days to seed the history chart")
    b.add_argument("--days", type=int, default=60)
    b.set_defaults(fn=cmd_backfill)
    s = sub.add_parser("status", help="show the last computed status")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    v = sub.add_parser("serve", help="serve the dashboard and refresh on a timer")
    env = os.environ.get
    v.add_argument("--port", type=int, default=int(env("INFOCON_PORT") or 8377))
    v.add_argument("--host", default=env("INFOCON_HOST") or "127.0.0.1")
    v.add_argument("--interval", type=int, default=int(env("INFOCON_INTERVAL") or 30), help="minutes between refreshes")
    v.add_argument("--backfill", type=int, default=int(env("INFOCON_BACKFILL_DAYS") or 0), metavar="DAYS",
                   help="on first start, reconstruct this many past days for the chart")
    v.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
