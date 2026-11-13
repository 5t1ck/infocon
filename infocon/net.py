"""Tiny stdlib HTTP helpers: gzip, retries, one User-Agent."""
import gzip
import json
import time
import urllib.error
import urllib.request

from . import config


class FetchError(Exception):
    pass


def fetch(url, timeout=40, retries=2, backoff=4.0):
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": config.USER_AGENT,
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip" or body[:2] == b"\x1f\x8b":
                    body = gzip.decompress(body)
                return body
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            # 4xx other than rate limiting will not fix itself.
            if e.code not in (403, 408, 429) and e.code < 500:
                break
        except Exception as e:  # timeouts, DNS, resets
            last = f"{type(e).__name__}: {e}"
        if attempt < retries:
            time.sleep(backoff * (attempt + 1))
    raise FetchError(f"{url.split('?')[0]} -> {last}")


def decode(body):
    if body[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return body.decode("utf-16")
    return body.decode("utf-8-sig", errors="replace")


def fetch_text(url, **kw):
    return decode(fetch(url, **kw))


def fetch_json(url, **kw):
    text = fetch_text(url, **kw)
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise FetchError(f"{url.split('?')[0]} -> not JSON ({e.msg}): {text[:80]!r}")
