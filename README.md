# ConfigProcessScript

参考 [Echsfxy](https://github.com/echs-top/proxy) 的规则分类方案，直接维护规则来源、配置脚本与个人功能；自动更新只处理规则数据。

## 使用

将下面的脚本地址添加到 Bettbox 的订阅覆写脚本中：

```text
https://raw.githubusercontent.com/ValoHalo/ConfigProcessScript/main/Script/mihomoScript.js
```

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
