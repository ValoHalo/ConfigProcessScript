# ConfigProcessScript

参考 [Echsfxy](https://github.com/echs-top/proxy) 的规则分类方案，直接维护规则来源、配置脚本与个人功能；自动更新只处理规则数据。

## 使用

将下面的脚本地址添加到 Bettbox 的订阅覆写脚本中：

```text
https://raw.githubusercontent.com/ValoHalo/ConfigProcessScript/main/Script/mihomoScript.js
```

启用“AI固定出口”后，“国外AI”菜单只列出订阅中已有的美国、日本分组及其具体节点。首次使用时默认走美国分组；没有美国节点时走日本，两地都没有节点时跟随“代理连接”。要固定使用某个节点，可以直接在“国外AI”里选它。

“国外AI”排在“代理连接”后面。YouTube 和 Netflix 等视频服务共用“海外媒体”分组；切换这个组即可一起更换出口，普通 Google 服务仍跟随“GOOGLE”。

Google Drive 的文件下载和数据导出跟随“GOOGLE”，与网盘页面使用同一出口。Discord 附件上传跟随 Discord；Google 推送跟随 FCM，默认直连。

OneDrive 和 Microsoft 不单独设组。商店首页和菜单（`storeedge.microsoft.com`）、已列出的微软登录入口和 OneDrive 文件主机都使用直连 DNS 和“直接连接”。文件主机列在 `Rules/personal/onedrive.list`，客户端和浏览器下载都适用。其他地址沿用通用规则，例如 `onedrive.live.com` 和 `skyapi.onedrive.live.com` 随“代理连接”；新的存储域名也按通用规则处理。

卡巴斯基官网、My Kaspersky 账户页、登录和官网 API 使用“直接连接”，域名解析也走直连。域名清单在 `Rules/personal/extra-direct.list`。

2026-11-25 从大陆 IPv4 出口实测能取得目标文件的下载主机列在 `Rules/personal/downloads.list`，按完整主机名匹配，连接和 DNS 都走“直接连接”。包括 Office 更新、Defender 病毒库、VS Code 和 Epic 安装包、Windows PowerShell 的 NuGet 提供程序，以及 WSL 使用的 Ubuntu 镜像。其余微软服务按通用规则分流；Steam 内容下载跟随 Steam 分组。

Windows 联网检测域名 `dns.msftncsi.com` 使用直连 DNS，返回 Windows 检查的真实地址。本机证书缓存用到的 DigiCert 和 Sectigo 状态查询、吊销列表也按完整主机名直连，见 `Rules/personal/extra-direct.list`。

## 节点域名 DNS

订阅提供的节点解析列表全部为已识别的国内公共 DNS 时，替换为以下直连 DoH：

- `https://odvr.nic.cz/doh#DIRECT`
- `https://dns.digitale-gesellschaft.ch/dns-query#DIRECT`
- `https://doh.applied-privacy.net/query#DIRECT`

原配置未提供节点 DNS 时不主动补充；匹配节点域名的私有 DNS 策略继续沿用。已有境外 DNS、私有 DNS 或混合列表保留原有处理方式，节点专用策略按各自列表判断。仅提供节点 DNS 策略时，沿用策略中的解析器作为内核要求的默认节点解析列表。普通直连 DNS 和通用 v.recipes 设置保持原样。

三个端点已于 2026-11-01 在当前网络完成 IPv4 直连 DoH 查询及 TLS 证书校验；可达性随网络变化。替换列表位于 `src/personal-dns.js`，修改后运行 `npm run build` 生成发布脚本。

## 来源

- [echs-top/proxy](https://github.com/echs-top/proxy)
- [AIsouler/MyClash](https://github.com/AIsouler/MyClash)
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)
