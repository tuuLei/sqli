# sqli
一个好用的sql注入工具，持续更新维护中

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
