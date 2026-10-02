# 完整版脚本测试

`npm run check` 无需外网，检查生成文件一致性、ES2020、Node／QuickJS 输出、个人功能开关、私有 DNS／hosts 兼容，以及规则维护工具和代理探测工具的行为。

`npm run rules:update -- --check` 检查已生成文本、MRS 和来源／增删清单的校验值。它不联网拉取最新来源。

## 真实规则路由

```powershell
npm run test:routing -- --mihomo .test-runtime/tools/mihomo.exe
npm run test:ai-udp -- --mihomo .test-runtime/tools/mihomo.exe
npm run test:dns-behavior -- --mihomo .test-runtime/tools/mihomo.exe
```

路由测试启动独立官方 Mihomo 进程，加载全部 16 个真实生成 MRS；使用回环 HTTP／DNS／代理服务，检查控制器报告的实际策略组。它覆盖 AI、普通 Google、媒体、微软精确例外、学术、下载、DLsite 和上游风控分组。

Windows 额外将 Node 复制为测试目录中的 `OneDrive.exe`，验证同一域名按进程进入 OneDrive 组；普通 `node.exe` 是反向对照。测试不运行或改动真实 OneDrive。

AI UDP 测试验证所选节点不支持 UDP 时，个人保护规则会阻止流量改用后续出口，同时使用移除保护规则的配置作负向对照。

DNS 行为测试通过真正的 UDP DNS 监听检查 Fake-IP 与 Real-IP，另外检查 DoH 查询路径和报文中的 ECS。它覆盖个人直连、精确域名反例、下载选择、AI／DLsite 服务出口、广告优先，以及保留订阅私有 DNS 的 ECS。控制器真实解析 API 不用于推断 Fake-IP 是否生效。

## 实际订阅联网

```powershell
npm run test:live -- --subscription input.yaml
```

需要本机已安装 Bettbox，默认内核位置为 `C:/Program Files/Bettbox/BettboxCore.exe`，可通过 `BETTBOX_CORE_PATH` 指定。测试使用本地生成规则集和真实订阅节点，检查候选节点基础 HTTPS、ChatGPT 公开地址和 DLsite 首页；DLsite 保持默认日本组。

真实订阅内容不打印，临时订阅配置结束时删除，摘要保存在 `.test-runtime/live-results.json`。原订阅、活动客户端及系统代理不变。公开页面响应不等于登录、支付、AI 对话或其他完整业务验证。

## 维护工具的失败保护

规则维护测试使用回环服务和假编译器，验证有限并发、重试上限、显式代理、重定向、格式错误、空数据、异常缩减、部分排除和编译失败。失败不得覆盖原发布目录。离线缓存必须匹配同 URL 和原文 SHA-256。
