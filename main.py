#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2Ray / Clash 公开订阅聚合脚本
=============================
- 订阅源从 sources.txt 读取 (一行一个,支持 # 注释)
- 自动识别 base64 / 明文
- 按协议前缀过滤 (vmess/vless/ss/trojan/hysteria/tuic)
- 全局去重 (保留首次出现顺序)
- 写入 data/V2.txt + history/V2_YYYYMMDDHHMM.txt
- 历史目录自动清理 (默认保留最近 30 份)
- 单源失败不中断整体,重试 2 次,带超时

用法:
    python aggregate_v2ray.py
    # 或: python aggregate_v2ray.py --keep 50  (自定义历史保留数)

sources.txt 格式:
    # 注释行
    https://example.com/sub1
    https://example.com/sub2
    # 重复 / 非 URL 行会被跳过,日志告警
"""

from __future__ import annotations

import argparse
import base64
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

# ============== 配置 ==============

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
HISTORY_DIR = SCRIPT_DIR / "history"
V2_FILENAME = "V2.txt"
SOURCES_FILE = SCRIPT_DIR / "sources.txt"  # 订阅源列表,一行一个,支持 # 注释

# 内置兜底源:仅在 sources.txt 缺失或解析为空时使用
DEFAULT_URLS = [
    "https://etoneya.su/1",
    "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/base64.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality ",
]

# 关注的协议前缀
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
