#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V2Ray / Clash subscription aggregator (sanchuner2000 fork).

Outputs 3 formats:
  - data/V2.txt         (V2RayN base64)
  - data/V2_plain.txt   (plain text node list)
  - data/V2.yaml        (Clash YAML)
"""

import argparse
import base64
import json
import logging
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests

# ---- Config ----
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
HISTORY_DIR = SCRIPT_DIR / "history"
SOURCES_FILE = SCRIPT_DIR / "sources.txt"

FNAME_V2RAYN = "V2.txt"
FNAME_V2RAYN_PLAIN = "V2_plain.txt"
FNAME_CLASH = "V2.yaml"

DEFAULT_URLS = [
    "https://www.xrayvip.com/free.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
]

PROTOCOLS = (
    "vmess://", "vless://", "ss://", "trojan://",
    "hysteria://", "hysteria2://", "tuic://", "naive+",
)

FORMAT_V2RAYN = "v2rayn"
FORMAT_V2RAYN_PLAIN = "v2rayn-plain"
FORMAT_CLASH = "clash"
ALL_FORMATS = (FORMAT_V2RAYN, FORMAT_V2RAYN_PLAIN, FORMAT_CLASH)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
}

TIMEOUT = 15
RETRIES = 2
RETRY_BACKOFF = 3.0

DEFAULT_HISTORY_KEEP = 30

# ---- Logging ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("v2agg")


# ---- Utils ----
def is_likely_base64(text):
    if not text or len(text) < 100:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r ")
    return all(c in allowed for c in text.strip())


def try_decode_base64(text):
    cleaned = "".join(text.split())
    if not cleaned:
        return None
    try:
        return base64.b64decode(cleaned, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return None


def write_v2rayn_compatible(path, content):
    """UTF-8 no BOM + LF + trailing newline."""
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    with open(path, "wb") as f:
        f.write(normalized.encode("utf-8"))


def fetch_with_retry(url):
    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            if not r.encoding or r.encoding.lower() == "iso-8859-1":
                r.encoding = r.apparent_encoding or "utf-8"
            return r.text
        except Exception as e:
            last_err = e
            if attempt < RETRIES:
                log.warning("retry %d/%d (%s): %s", attempt + 1, RETRIES, url, e)
                time.sleep(RETRY_BACKOFF)
    log.error("failed after %d retries (%s): %s", RETRIES, url, last_err)
    return ""


def extract_nodes(text):
    if not text:
        return []
    if is_likely_base64(text):
        decoded = try_decode_base64(text)
        if decoded:
            text = decoded
        else:
            log.warning("looks like base64 but decode failed")
    nodes = []
    for raw in text.splitlines():
        line = raw.replace("\r", "").strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if any(line.startswith(p) for p in PROTOCOLS):
            nodes.append(line)
    return nodes


def dedup_preserve_order(items):
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# ---- Source loading ----
def load_sources():
    if not SOURCES_FILE.exists():
        log.warning("no %s, using built-in defaults", SOURCES_FILE)
        return list(DEFAULT_URLS)
    try:
        text = SOURCES_FILE.read_text(encoding="utf-8")
    except OSError as e:
        log.error("read %s failed: %s", SOURCES_FILE, e)
        return list(DEFAULT_URLS)
    urls = []
    seen = set()
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("http://") and not line.startswith("https://"):
            log.warning("[%s:%d] skip non-URL: %s", SOURCES_FILE.name, line_no, line)
            continue
        if line in seen:
            log.warning("[%s:%d] skip duplicate: %s", SOURCES_FILE.name, line_no, line)
            continue
        seen.add(line)
        urls.append(line)
    if not urls:
        log.error("no valid URL in %s, using defaults", SOURCES_FILE)
        return list(DEFAULT_URLS)
    log.info("loaded %d sources from %s", len(urls), SOURCES_FILE.name)
    return urls


# ---- Node parsers (for Clash YAML) ----
def b64_pad(s):
    return s + "=" * (-len(s) % 4)


def parse_vmess(url):
    try:
        body = url[len("vmess://"):]
        if "#" in body:
            body, frag = body.split("#", 1)
            name = urllib.parse.unquote(frag)
        else:
            name = ""
        info = json.loads(base64.b64decode(b64_pad(body)).decode("utf-8", errors="ignore"))
        return {
            "name": name or info.get("ps") or "vmess-" + str(info.get("add", "")),
            "type": "vmess",
            "server": info.get("add", ""),
            "port": int(info.get("port", 0)),
            "uuid": info.get("id", ""),
            "alterId": int(info.get("aid", 0)),
            "cipher": info.get("type", "auto") or "auto",
            "udp": True,
            "tls": str(info.get("tls", "")).lower() == "tls",
            "network": info.get("net", "tcp"),
        }
    except Exception as e:
        log.debug("vmess parse fail: %s (%s)", url[:60], e)
        return None


def parse_vless(url):
    try:
        u = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(u.query)
        name = urllib.parse.unquote(u.fragment) if u.fragment else ""
        return {
            "name": name or "vless-" + str(u.hostname),
            "type": "vless",
            "server": u.hostname or "",
            "port": int(u.port or 0),
            "uuid": u.username or "",
            "flow": params.get("flow", [""])[0],
            "tls": params.get("security", ["none"])[0] in ("reality", "tls"),
            "network": params.get("type", ["tcp"])[0],
            "udp": True,
        }
    except Exception as e:
        log.debug("vless parse fail: %s (%s)", url[:60], e)
        return None


def parse_ss(url):
    try:
        u = urllib.parse.urlparse(url)
        if u.username is None:
            body = url[len("ss://"):]
            if "#" in body:
                body, frag = body.split("#", 1)
                name = urllib.parse.unquote(frag)
            else:
                name = ""
            mp = base64.b64decode(b64_pad(body)).decode("utf-8", errors="ignore")
            method, password = mp.split(":", 1)
            host = u.hostname
            port = u.port
        else:
            method = urllib.parse.unquote(u.username or "")
            password = urllib.parse.unquote(u.password or "")
            host = u.hostname
            port = u.port
            name = urllib.parse.unquote(u.fragment) if u.fragment else ""
        return {
            "name": name or "ss-" + str(host),
            "type": "ss",
            "server": host or "",
            "port": int(port or 0),
            "cipher": method,
            "password": password,
            "udp": True,
        }
    except Exception as e:
        log.debug("ss parse fail: %s (%s)", url[:60], e)
        return None


def parse_trojan(url):
    try:
        u = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(u.query)
        name = urllib.parse.unquote(u.fragment) if u.fragment else ""
        return {
            "name": name or "trojan-" + str(u.hostname),
            "type": "trojan",
            "server": u.hostname or "",
            "port": int(u.port or 0),
            "password": urllib.parse.unquote(u.username or ""),
            "udp": True,
            "skip-cert-verify": True,
            "network": params.get("type", ["tcp"])[0],
        }
    except Exception as e:
        log.debug("trojan parse fail: %s (%s)", url[:60], e)
        return None


PARSERS = {
    "vmess://": parse_vmess,
    "vless://": parse_vless,
    "ss://": parse_ss,
    "trojan://": parse_trojan,
}


def parse_node(url):
    for prefix, parser in PARSERS.items():
        if url.startswith(prefix):
            return parser(url)
    return None


# ---- Output formats ----
CLASH_HEADER = """\
# Clash / Mihomo / Stash subscription
# auto-generated, refresh by re-running main.py
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
proxies:
"""


def to_clash_yaml(nodes):
    proxies = []
    failed = 0
    for n in nodes:
        info = parse_node(n)
        if info is None:
            failed += 1
            continue
        proxies.append(info)
    lines = [CLASH_HEADER]
    for p in proxies:
        block = json.dumps(p, ensure_ascii=False, indent=2)
        block_lines = block.splitlines()
        block_lines[0] = "  - " + block_lines[0]
        for ln in block_lines[1:]:
            lines.append("  " + ln)
        lines.append("")
    return "\n".join(lines), len(proxies), failed


def write_format(fmt, nodes, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    if fmt == FORMAT_V2RAYN:
        combined = "\n".join(nodes)
        encoded = base64.b64encode(combined.encode("utf-8")).decode("ascii")
        out = out_dir / FNAME_V2RAYN
        write_v2rayn_compatible(out, encoded)
    elif fmt == FORMAT_V2RAYN_PLAIN:
        out = out_dir / FNAME_V2RAYN_PLAIN
        write_v2rayn_compatible(out, "\n".join(nodes))
    elif fmt == FORMAT_CLASH:
        yaml_text, ok, fail = to_clash_yaml(nodes)
        out = out_dir / FNAME_CLASH
        write_v2rayn_compatible(out, yaml_text)
        if fail:
            log.warning("clash: ok=%d fail=%d", ok, fail)
    else:
        raise ValueError("unknown format: " + fmt)
    log.info("wrote %s -> %s", fmt, out)
    return out


# ---- Main flow ----
def run(formats, keep):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    # 1. fetch
    urls = load_sources()
    all_nodes = []
    per_source = {}
    for url in urls:
        log.info("fetch: %s", url)
        text = fetch_with_retry(url)
        if not text:
            per_source[url] = 0
            continue
        nodes = extract_nodes(text)
        per_source[url] = len(nodes)
        all_nodes.extend(nodes)
        log.info("  parsed: %d", len(nodes))

    # 2. dedup
    unique = dedup_preserve_order(all_nodes)
    total = sum(per_source.values())
    log.info("summary: raw=%d unique=%d dup=%d", total, len(unique), total - len(unique))
    if not unique:
        log.error("no nodes, skip")
        return 1

    # 3. write to data/
    log.info("formats: %s", ",".join(formats))
    for fmt in formats:
        try:
            write_format(fmt, unique, DATA_DIR)
        except Exception as e:
            log.error("format %s failed: %s", fmt, e)

    # 4. snapshot to history/
    ts = datetime.now().strftime("%Y%m%d%H%M")
    base_map = {
        FORMAT_V2RAYN: FNAME_V2RAYN,
        FORMAT_V2RAYN_PLAIN: FNAME_V2RAYN_PLAIN,
        FORMAT_CLASH: FNAME_CLASH,
    }
    for fmt in formats:
        try:
            hist_dir = HISTORY_DIR / fmt
            hist_dir.mkdir(parents=True, exist_ok=True)
            write_format(fmt, unique, hist_dir)
            base = base_map[fmt]
            src = hist_dir / base
            stem = Path(base).stem
            suf = Path(base).suffix
            dst = hist_dir / (stem + "_" + ts + suf)
            if src.exists():
                src.replace(dst)
        except Exception as e:
            log.error("history %s failed: %s", fmt, e)

    # 5. prune old history
    for fmt in formats:
        hist_dir = HISTORY_DIR / fmt
        if not hist_dir.exists():
            continue
        files = sorted(hist_dir.glob("*.*"), key=lambda p: p.name, reverse=True)
        for old in files[keep:]:
            try:
                old.unlink()
            except OSError as e:
                log.warning("cannot delete %s: %s", old, e)

    log.info("done: %d nodes, %d formats", len(unique), len(formats))
    return 0


def parse_args():
    p = argparse.ArgumentParser(description="V2Ray subscription aggregator")
    p.add_argument("--keep", type=int, default=DEFAULT_HISTORY_KEEP)
    p.add_argument("--formats", type=str, default=",".join(ALL_FORMATS))
    return p.parse_args()


def main():
    args = parse_args()
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    for f in formats:
        if f not in ALL_FORMATS:
            log.error("unknown format: %s", f)
            return 2
    try:
        return run(formats=formats, keep=args.keep)
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
