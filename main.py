#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray / Clash 公开订阅聚合脚本 (sanchuner2000 fork)
==================================================
- 订阅源从 sources.txt 读取 (一行一个,支持 # 注释)
- 自动识别 base64 / 明文
- 按协议前缀过滤 (vmess/vless/ss/trojan/hysteria/tuic)
- 全局去重 (保留首次出现顺序)
- 多格式输出:
    * V2RayN     -> data/V2.txt           (整篇 base64,V2RayN 6.x/7.x 主用)
    * V2RayN-X   -> data/V2_plain.txt     (明文,V2RayN-X / Nekoray / 其他)
    * Clash      -> data/V2.yaml          (YAML,Clash for Windows / Stash / Mihomo)
- V2RayN 友好:UTF-8 无 BOM + 强制 LF + 末尾换行 + 节点内去 \r
- 历史目录自动清理 (默认保留最近 30 份)
- 单源失败不中断整体,重试 2 次,带超时

云端 (GitHub Actions) 跑法:
    python main.py            # 默认:拉源 + 写 3 种格式 (无测速)
    python main.py --formats v2rayn,clash

本地 (Windows) 跑法 (可选测速/自启):
    python main.py --test --threshold 2000
    python main.py --install-startup

sources.txt 格式:
    # 注释行
    https://example.com/sub1
    https://example.com/sub2
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import logging
import re
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Callable

import requests

# ============== 配置 ==============

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
HISTORY_DIR = SCRIPT_DIR / "history"
SOURCES_FILE = SCRIPT_DIR / "sources.txt"

# 输出文件名 (各格式)
FNAME_V2RAYN = "V2.txt"
FNAME_V2RAYN_PLAIN = "V2_plain.txt"
FNAME_CLASH = "V2.yaml"

# 内置兜底源
DEFAULT_URLS = [
    "https://etoneya.su/1",
    "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/base64.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality ",
]

PROTOCOLS = (
    "vmess://",
    "vless://",
    "ss://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "tuic://",
    "naive+",
)

FORMAT_V2RAYN = "v2rayn"
FORMAT_V2RAYN_PLAIN = "v2rayn-plain"
FORMAT_CLASH = "clash"
ALL_FORMATS = (FORMAT_V2RAYN, FORMAT_V2RAYN_PLAIN, FORMAT_CLASH)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

TIMEOUT = 15
RETRIES = 2
RETRY_BACKOFF = 3.0

DEFAULT_V2RAYN_EXE = Path(r"C:\Program Files\V2RayN\v2rayN.exe")
DEFAULT_TEST_THRESHOLD_MS = 2000
DEFAULT_TEST_CONCURRENCY = 5
DEFAULT_TEST_TIMEOUT_S = 8

DEFAULT_HISTORY_KEEP = 30

# ============== 日志 ==============

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("v2agg")


# ============== 通用工具 ==============

def is_likely_base64(text: str) -> bool:
    if not text or len(text) < 100:
        return False
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/=\n\r "
    )
    return all(c in allowed for c in text.strip())


def try_decode_base64(text: str) -> str | None:
    cleaned = "".join(text.split())
    if not cleaned:
        return None
    try:
        return base64.b64decode(cleaned, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return None


def write_v2rayn_compatible(path: Path, content: str) -> None:
    """UTF-8 无 BOM + 强制 LF + 末尾换行"""
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    with open(path, "wb") as f:
        f.write(normalized.encode("utf-8"))


def fetch_with_retry(url: str) -> str:
    last_err: Exception | None = None
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
                log.warning(
                    "第 %d/%d 次失败 (%s): %s, %.1fs 后重试",
                    attempt + 1, RETRIES + 1, url, e, RETRY_BACKOFF,
                )
                time.sleep(RETRY_BACKOFF)
    log.error("重试 %d 次仍失败 (%s): %s", RETRIES, url, last_err)
    return ""


def extract_nodes(text: str) -> list[str]:
    if not text:
        return []
    if is_likely_base64(text):
        decoded = try_decode_base64(text)
        if decoded:
            text = decoded
        else:
            log.warning("看起来像 base64 但解码失败,按明文处理")
    nodes: list[str] = []
    for raw in text.splitlines():
        line = raw.replace("\r", "").strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if any(line.startswith(p) for p in PROTOCOLS):
            nodes.append(line)
    return nodes


def dedup_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# ============== 订阅源加载 ==============

def load_sources() -> list[str]:
    if not SOURCES_FILE.exists():
        log.warning(
            "未找到 %s, 退回内置默认源 (%d 条).",
            SOURCES_FILE, len(DEFAULT_URLS),
        )
        return list(DEFAULT_URLS)
    try:
        text = SOURCES_FILE.read_text(encoding="utf-8")
    except OSError as e:
        log.error("读取 %s 失败: %s, 退回默认源", SOURCES_FILE, e)
        return list(DEFAULT_URLS)
    urls: list[str] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not (line.startswith("http://") or line.startswith("https://")):
            log.warning("[%s:%d] 忽略非 URL: %s", SOURCES_FILE.name, line_no, line)
            continue
        if line in seen:
            log.warning("[%s:%d] 跳过重复: %s", SOURCES_FILE.name, line_no, line)
            continue
        seen.add(line)
        urls.append(line)
    if not urls:
        log.error("%s 解析后无有效 URL, 退回默认源", SOURCES_FILE)
        return list(DEFAULT_URLS)
    log.info("从 %s 加载 %d 个订阅源", SOURCES_FILE.name, len(urls))
    return urls


# ============== 节点解析 (供 Clash YAML 转换) ==============

def _b64_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def parse_vmess(url: str) -> dict | None:
    try:
        body = url[len("vmess://"):]
        if "#" in body:
            body, frag = body.split("#", 1)
            name = urllib.parse.unquote(frag)
        else:
            name = ""
        info = json.loads(base64.b64decode(_b64_pad(body)).decode("utf-8", errors="ignore"))
        return {
            "name": name or info.get("ps") or f"vmess-{info.get('add','')}",
            "type": "vmess",
            "server": info.get("add", ""),
            "port": int(info.get("port", 0)),
            "uuid": info.get("id", ""),
            "alterId": int(info.get("aid", 0)),
            "cipher": info.get("type", "auto") or "auto",
            "udp": True,
            "tls": str(info.get("tls", "")).lower() == "tls",
            "skip-cert-verify": False,
            "network": info.get("net", "tcp"),
            "_raw": url,
        }
    except Exception as e:
        log.debug("vmess 解析失败: %s (%s)", url[:60], e)
        return None


def parse_vless(url: str) -> dict | None:
    try:
        u = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(u.query)
        name = urllib.parse.unquote(u.fragment) if u.fragment else ""
        return {
            "name": name or f"vless-{u.hostname}",
            "type": "vless",
            "server": u.hostname or "",
            "port": int(u.port or 0),
            "uuid": u.username or "",
            "flow": params.get("flow", [""])[0],
            "tls": params.get("security", ["none"])[0] in ("reality", "tls"),
            "network": params.get("type", ["tcp"])[0],
            "reality-opts": (
                {"public-key": params.get("pbk", [""])[0],
                 "short-id": params.get("sid", [""])[0]}
                if params.get("security", [""])[0] == "reality" else {}
            ),
            "udp": True,
            "_raw": url,
        }
    except Exception as e:
        log.debug("vless 解析失败: %s (%s)", url[:60], e)
        return None


def parse_ss(url: str) -> dict | None:
    try:
        u = urllib.parse.urlparse(url)
        if u.username is None:
            body = url[len("ss://"):]
            if "#" in body:
                body, frag = body.split("#", 1)
                name = urllib.parse.unquote(frag)
            else:
                name = ""
            mp = base64.b64decode(_b64_pad(body)).decode("utf-8", errors="ignore")
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
            "name": name or f"ss-{host}",
            "type": "ss",
            "server": host or "",
            "port": int(port or 0),
            "cipher": method,
            "password": password,
            "udp": True,
            "_raw": url,
        }
    except Exception as e:
        log.debug("ss 解析失败: %s (%s)", url[:60], e)
        return None


def parse_trojan(url: str) -> dict | None:
    try:
        u = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(u.query)
        name = urllib.parse.unquote(u.fragment) if u.fragment else ""
        return {
            "name": name or f"trojan-{u.hostname}",
            "type": "trojan",
            "server": u.hostname or "",
            "port": int(u.port or 0),
            "password": urllib.parse.unquote(u.username or ""),
            "udp": True,
            "skip-cert-verify": True,
            "network": params.get("type", ["tcp"])[0],
            "_raw": url,
        }
    except Exception as e:
        log.debug("trojan 解析失败: %s (%s)", url[:60], e)
        return None


_PARSERS: dict[str, Callable[[str], dict | None]] = {
    "vmess://": parse_vmess,
    "vless://": parse_vless,
    "ss://": parse_ss,
    "trojan://": parse_trojan,
}


def parse_node(url: str) -> dict | None:
    for prefix, parser in _PARSERS.items():
        if url.startswith(prefix):
            return parser(url)
    return None


# ============== 多格式输出 ==============

CLASH_YAML_HEADER = """\
# Clash / Mihomo / Stash 订阅
# 自动生成,运行 main.py 刷新
# 导入方式: Clash for Windows / Stash -> Profiles -> 拖入或粘贴 URL
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
proxies:
"""


def to_clash_yaml(nodes: list[str]) -> tuple[str, int, int]:
    proxies: list[dict] = []
    failed = 0
    for n in nodes:
        info = parse_node(n)
        if info is None:
            failed += 1
            continue
        info.pop("_raw", None)
        proxies.append(info)
    lines = [CLASH_YAML_HEADER]
    for p in proxies:
        block = json.dumps(p, ensure_ascii=False, indent=2)
        block_lines = block.splitlines()
        block_lines[0] = "  - " + block_lines[0]
        lines.extend("  " + ln for ln in block_lines[1:])
        lines.append("")
    return "\n".join(lines), len(proxies), failed


def write_format(fmt: str, nodes: list[str], out_dir: Path) -> Path:
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
            log.warning("Clash YAML: 成功 %d / 失败 %d (只支持 vmess/vless/ss/trojan)",
                        ok, fail)
    else:
        raise ValueError(f"未知格式: {fmt}")
    log.info("已输出 %s -> %s", fmt, out)
    return out


# ============== V2RayN testurl 测速 (仅本地) ==============

_LATENCY_RE = re.compile(
    r"(?:latency|延迟|延时|time)\s*[:：]?\s*(\d+)\s*(?:ms|毫秒)?", re.IGNORECASE
)
_FAIL_PATTERNS = re.compile(
    r"(?:timeout|超时|fail|failed|error|错误|0\s*ms)", re.IGNORECASE
)


def test_one_node(url: str, v2rayn_exe: Path, timeout_s: int) -> tuple[str, int | None, str]:
    try:
        proc = subprocess.run(
            [str(v2rayn_exe), "testurl", url],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            encoding="utf-8",
            errors="ignore",
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        m = _LATENCY_RE.search(out)
        if m:
            return (url, int(m.group(1)), out)
        if _FAIL_PATTERNS.search(out):
            return (url, None, out)
        return (url, None, out)
    except subprocess.TimeoutExpired:
        return (url, None, "[timeout]")
    except FileNotFoundError:
        return (url, None, f"[v2rayn.exe not found: {v2rayn_exe}]")
    except Exception as e:
        return (url, None, f"[error: {e}]")


def test_nodes(
    nodes: list[str],
    v2rayn_exe: Path,
    threshold_ms: int,
    concurrency: int,
    timeout_s: int,
) -> list[str]:
    if not v2rayn_exe.exists():
        log.error("v2rayn.exe 不存在: %s, 跳过测速", v2rayn_exe)
        return nodes
    log.info("开始测速 %d 个节点 (并发 %d, 阈值 %dms, 单次超时 %ds)",
             len(nodes), concurrency, threshold_ms, timeout_s)
    passed: list[str] = []
    failed: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = {
            pool.submit(test_one_node, n, v2rayn_exe, timeout_s): n for n in nodes
        }
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            url, latency, raw = fut.result()
            done += 1
            short = url[:50] + ("..." if len(url) > 50 else "")
            if latency is None:
                failed.append((url, raw.strip().splitlines()[-1] if raw.strip() else ""))
                log.info("[%d/%d] 失败  %s", done, len(nodes), short)
            elif latency > threshold_ms:
                failed.append((url, f"{latency}ms > {threshold_ms}ms"))
                log.info("[%d/%d] 慢速  %s (%dms)", done, len(nodes), short, latency)
            else:
                passed.append(url)
                log.info("[%d/%d] 通过  %s (%dms)", done, len(nodes), short, latency)
    log.info("测速完成: 通过 %d, 失败/剔除 %d", len(passed), len(failed))
    order = {n: i for i, n in enumerate(nodes)}
    passed.sort(key=lambda n: order.get(n, 1 << 30))
    return passed


# ============== 开机自启 (仅 Windows) ==============

STARTUP_BAT_NAME = "v2agg_startup.bat"
SCHTASK_NAME = "V2RaySubscriptionAggregator"


def generate_startup_bat(target_dir: Path) -> Path:
    bat = target_dir / STARTUP_BAT_NAME
    py = Path(sys.executable)
    pyw = py.with_name("pythonw.exe") if py.with_name("pythonw.exe").exists() else py
    content = f"""@echo off
rem V2Ray 订阅聚合 - 开机自启脚本
rem 由 main.py --install-startup 自动生成
chcp 65001 >nul
cd /d "{SCRIPT_DIR}"
"{pyw}" "{Path(__file__).resolve()}"
"""
    bat.write_text(content, encoding="utf-8")
    return bat


def install_startup() -> int:
    bat = generate_startup_bat(SCRIPT_DIR)
    log.info("已生成: %s", bat)
    cmd = [
        "schtasks", "/Create",
        "/TN", SCHTASK_NAME,
        "/TR", f'"{bat}"',
        "/SC", "ONLOGON",
        "/RL", "LIMITED",
        "/F",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        log.info("已注册计划任务: %s (登录时触发)", SCHTASK_NAME)
        log.info("卸载: schtasks /Delete /TN %s /F", SCHTASK_NAME)
    except subprocess.CalledProcessError as e:
        log.error("schtasks 注册失败: %s", e.stderr or e)
        log.info("可手动把 %s 拖到 shell:startup 目录", bat)
        return 1
    return 0


# ============== 主流程 ==============

def run(
    keep: int,
    formats: list[str],
    do_test: bool,
    v2rayn_exe: Path,
    threshold_ms: int,
    concurrency: int,
    timeout_s: int,
) -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    # 1. 拉源
    urls = load_sources()
    all_nodes: list[str] = []
    per_source: dict[str, int] = {}
    for url in urls:
        log.info("==> 拉取: %s", url)
        text = fetch_with_retry(url)
        if not text:
            per_source[url] = 0
            continue
        nodes = extract_nodes(text)
        per_source[url] = len(nodes)
        all_nodes.extend(nodes)
        log.info("    解析: %d 条", len(nodes))

    # 2. 去重
    unique = dedup_preserve_order(all_nodes)
    total_raw = sum(per_source.values())
    log.info("汇总: 原始 %d -> 去重 %d (剔除 %d 重复)",
             total_raw, len(unique), total_raw - len(unique))
    if not unique:
        log.error("没有任何可用节点, 本次不写文件")
        return 1

    # 3. (可选) 测速
    if do_test:
        unique = test_nodes(unique, v2rayn_exe, threshold_ms, concurrency, timeout_s)
        if not unique:
            log.error("测速后无存活节点, 本次不写文件")
            return 1

    # 4. 多格式输出到 data/
    log.info("输出格式: %s", ",".join(formats))
    for fmt in formats:
        try:
            write_format(fmt, unique, DATA_DIR)
        except Exception as e:
            log.error("格式 %s 输出失败: %s", fmt, e)

    # 5. 写历史快照
    ts = datetime.now().strftime("%Y%m%d%H%M")
    for fmt in formats:
        try:
            hist_dir = HISTORY_DIR / fmt
            hist_dir.mkdir(parents=True, exist_ok=True)
            write_format(fmt, unique, hist_dir)
            base_name = {
                FORMAT_V2RAYN: FNAME_V2RAYN,
                FORMAT_V2RAYN_PLAIN: FNAME_V2RAYN_PLAIN,
                FORMAT_CLASH: FNAME_CLASH,
            }[fmt]
            src = hist_dir / base_name
            dst = hist_dir / f"{Path(base_name).stem}_{ts}{Path(base_name).suffix}"
            if src.exists():
                src.replace(dst)
        except Exception as e:
            log.error("历史快照 %s 失败: %s", fmt, e)

    # 6. 清理过期历史
    for fmt in formats:
        hist_dir = HISTORY_DIR / fmt
        if not hist_dir.exists():
            continue
        files = sorted(hist_dir.glob("*.*"), key=lambda p: p.name, reverse=True)
        for old in files[keep:]:
            try:
                old.unlink()
            except OSError as e:
                log.warning("无法删除 %s: %s", old, e)
    log.info("✓ 完成 (节点 %d, 格式 %d 种)", len(unique), len(formats))
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="V2Ray 订阅聚合 (多格式 + 测速)")
    p.add_argument("--keep", type=int, default=DEFAULT_HISTORY_KEEP,
                   help=f"历史保留份数/格式 (默认 {DEFAULT_HISTORY_KEEP})")
    p.add_argument("--formats", type=str, default=",".join(ALL_FORMATS),
                   help=f"输出格式,逗号分隔。可选: {','.join(ALL_FORMATS)}")
    p.add_argument("--test", action="store_true",
                   help="用 v2rayn.exe testurl 测速并剔除慢节点 (仅 Windows)")
    p.add_argument("--v2rayn-path", type=Path, default=DEFAULT_V2RAYN_EXE,
                   help=f"v2rayn.exe 路径 (默认 {DEFAULT_V2RAYN_EXE})")
    p.add_argument("--threshold", type=int, default=DEFAULT_TEST_THRESHOLD_MS,
                   help=f"测速阈值 ms (默认 {DEFAULT_TEST_THRESHOLD_MS})")
    p.add_argument("--concurrency", type=int, default=DEFAULT_TEST_CONCURRENCY,
                   help=f"测速并发数 (默认 {DEFAULT_TEST_CONCURRENCY})")
    p.add_argument("--test-timeout", type=int, default=DEFAULT_TEST_TIMEOUT_S,
                   help=f"单节点测速超时 s (默认 {DEFAULT_TEST_TIMEOUT_S})")
    p.add_argument("--install-startup", action="store_true",
                   help="生成 .bat 并注册到 Windows 任务计划 (登录时跑)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.install_startup:
        return install_startup()
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    for f in formats:
        if f not in ALL_FORMATS:
            log.error("未知格式: %s, 可选: %s", f, ",".join(ALL_FORMATS))
            return 2
    try:
        return run(
            keep=args.keep,
            formats=formats,
            do_test=args.test,
            v2rayn_exe=args.v2rayn_path,
            threshold_ms=args.threshold,
            concurrency=args.concurrency,
            timeout_s=args.test_timeout,
        )
    except KeyboardInterrupt:
        log.warning("用户中断")
        return 130


if __name__ == "__main__":
    sys.exit(main())
)

# 浏览器 UA: 避免 GitHub raw / 部分 CDN 因无 UA 返回 403
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}

# 网络参数
TIMEOUT = 15          # 单次请求超时 (秒)
RETRIES = 2           # 失败重试次数
RETRY_BACKOFF = 3.0   # 重试间隔 (秒)

# 历史保留
DEFAULT_HISTORY_KEEP = 30

# ============== 日志 ==============

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("v2agg")


# ============== 工具函数 ==============

def is_likely_base64(text: str) -> bool:
    """粗略判断文本是否是 base64 编码的订阅内容"""
    if not text or len(text) < 100:
        return False
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/=\n\r "
    )
    stripped = text.strip()
    return all(c in allowed for c in stripped)


def try_decode_base64(text: str) -> str | None:
    """尝试 base64 解码,失败返回 None"""
    cleaned = "".join(text.split())
    if not cleaned:
        return None
    try:
        decoded = base64.b64decode(cleaned, validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def fetch_with_retry(url: str) -> str:
    """拉取 URL,带超时和重试。失败返回空串"""
    last_err: Exception | None = None
    for attempt in range(RETRIES + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            # 显式按 utf-8 解,乱码则退回 apparent_encoding
            if not r.encoding or r.encoding.lower() == "iso-8859-1":
                r.encoding = r.apparent_encoding or "utf-8"
            return r.text
        except Exception as e:  # requests.RequestException, Timeout, etc.
            last_err = e
            if attempt < RETRIES:
                log.warning(
                    "第 %d/%d 次失败 (%s): %s, %.1fs 后重试",
                    attempt + 1, RETRIES + 1, url, e, RETRY_BACKOFF,
                )
                time.sleep(RETRY_BACKOFF)
    log.error("重试 %d 次仍失败 (%s): %s", RETRIES, url, last_err)
    return ""


def extract_nodes(text: str) -> list[str]:
    """从原始文本中提取节点行 (自动尝试 base64 解码)"""
    if not text:
        return []
    # 优先尝试 base64 解码
    if is_likely_base64(text):
        decoded = try_decode_base64(text)
        if decoded:
            text = decoded
        else:
            log.warning("看起来像 base64 但解码失败,按明文处理")
    # 按协议前缀过滤
    nodes: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if any(line.startswith(p) for p in PROTOCOLS):
            nodes.append(line)
    return nodes


def load_sources() -> list[str]:
    """从 sources.txt 加载订阅源。

    文件格式:
        - 一行一个 URL
        - 以 # 开头的行视为注释 (整行忽略)
        - 空行忽略
        - 重复 URL 自动去重,日志告警
        - 非 http(s) 开头的行忽略,日志告警

    兜底:文件不存在 / 解析为空 -> 使用 DEFAULT_URLS。
    """
    if not SOURCES_FILE.exists():
        log.warning(
            "未找到 %s, 退回内置默认源 (%d 条). 可创建该文件后自定义。",
            SOURCES_FILE, len(DEFAULT_URLS),
        )
        return list(DEFAULT_URLS)

    try:
        text = SOURCES_FILE.read_text(encoding="utf-8")
    except OSError as e:
        log.error("读取 %s 失败: %s, 退回默认源", SOURCES_FILE, e)
        return list(DEFAULT_URLS)

    urls: list[str] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not (line.startswith("http://") or line.startswith("https://")):
            log.warning("[%s:%d] 忽略非 URL: %s", SOURCES_FILE.name, line_no, line)
            continue
        if line in seen:
            log.warning("[%s:%d] 跳过重复: %s", SOURCES_FILE.name, line_no, line)
            continue
        seen.add(line)
        urls.append(line)

    if not urls:
        log.error("%s 解析后无有效 URL, 退回默认源", SOURCES_FILE)
        return list(DEFAULT_URLS)

    log.info("从 %s 加载 %d 个订阅源", SOURCES_FILE.name, len(urls))
    return urls


def dedup_preserve_order(items: list[str]) -> list[str]:
    """去重,保留首次出现顺序"""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def prune_history(keep: int) -> int:
    """清理历史,只保留最近 keep 份,返回清理数量"""
    if not HISTORY_DIR.exists():
        return 0
    files = sorted(HISTORY_DIR.glob("V2_*.txt"), key=lambda p: p.name, reverse=True)
    removed = 0
    for old in files[keep:]:
        try:
            old.unlink()
            log.info("清理历史: %s", old.name)
            removed += 1
        except OSError as e:
            log.warning("无法删除 %s: %s", old, e)
    return removed


# ============== 主流程 ==============

def run(keep: int) -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    all_nodes: list[str] = []
    per_source: dict[str, int] = {}

    urls = load_sources()
    for url in urls:
        log.info("==> 拉取: %s", url)
        text = fetch_with_retry(url)
        if not text:
            per_source[url] = 0
            continue
        nodes = extract_nodes(text)
        per_source[url] = len(nodes)
        all_nodes.extend(nodes)
        log.info("    解析: %d 条", len(nodes))

    # 全局去重
    unique = dedup_preserve_order(all_nodes)
    total_raw = sum(per_source.values())
    log.info("汇总: 原始 %d -> 去重 %d (剔除 %d 重复)",
             total_raw, len(unique), total_raw - len(unique))

    if not unique:
        log.error("没有任何可用节点,本次不写文件")
        return 1

    # 重新 base64 编码 (输出标准 V2RayN 订阅格式)
    combined = "\n".join(unique)
    encoded = base64.b64encode(combined.encode("utf-8")).decode("ascii")

    # 写 data/V2.txt (始终覆盖,App 直接读这个)
    out_main = DATA_DIR / V2_FILENAME
    out_main.write_text(encoded, encoding="utf-8")
    log.info("已写入: %s (%d chars, %d 节点)", out_main, len(encoded), len(unique))

    # 写 history/V2_YYYYMMDDHHMM.txt
    ts = datetime.now().strftime("%Y%m%d%H%M")
    out_hist = HISTORY_DIR / f"V2_{ts}.txt"
    out_hist.write_text(encoded, encoding="utf-8")
    log.info("已写入: %s", out_hist)

    # 清理过期历史
    removed = prune_history(keep)
    if removed:
        log.info("历史清理: 删 %d, 剩 %d", removed, keep)

    # 简易分源统计
    log.info("分源明细:")
    for u, n in per_source.items():
        log.info("  - %-60s %d 条", u, n)

    log.info("✓ 完成")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="V2Ray 订阅聚合")
    p.add_argument(
        "--keep", type=int, default=DEFAULT_HISTORY_KEEP,
        help=f"历史文件保留份数 (默认 {DEFAULT_HISTORY_KEEP})",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return run(keep=args.keep)
    except KeyboardInterrupt:
        log.warning("用户中断")
        return 130


if __name__ == "__main__":
    sys.exit(main())
