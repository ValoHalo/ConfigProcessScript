// Base configuration adapted from https://github.com/echs-top/proxy (1f35b88941854531a2876382bb29d234850da57b).
// Maintained here; published rule providers come from config/rule-sources.json.

function buildBaseConfig(config) {
  const subscriptionProxies = config.proxies || [];
  const optionalProviders = new Set([
    'dlsite', 'download', 'safe', 'steam', 'apple', 'meta', 'line', 'facebook_ip',
    ...applicationGroups.flatMap(app => [app.domain, app.ip, app.baseIp].filter(Boolean)),
  ]);
  const directDns = publicDnsResolvers(personalSettings.dns.direct, '直接连接', personalSettings.dns.ecsMode);
  const proxyDns = publicDnsResolvers(personalSettings.dns.proxy, '代理DNS', personalSettings.dns.ecsMode);
  const fallAnchor = { "type": "fallback", "include-all-providers": true, "empty-fallback": "REJECT", "hidden": true };
  const dlAnchor = { "type": "select", "proxies": ["代理连接", "直接连接", "最低延迟", "故障转移"], "include-all-providers": true, "empty-fallback": "REJECT" };
  const originDns = config.dns || {};
  const appendDirectTag = (val) => { if (typeof val === 'string') { return val.split('#')[0] + '#直接连接'; } return val; };
  const formatDnsValues = (dnsValue) => { if (Array.isArray(dnsValue)) return dnsValue.map(appendDirectTag); return appendDirectTag(dnsValue); };
  let finalProxyServerNameserver = directDns;
  const originPsn = originDns['proxy-server-nameserver'];
  if (originPsn != null && originPsn !== '' && (!Array.isArray(originPsn) || originPsn.length > 0)) { finalProxyServerNameserver = formatDnsValues(originPsn); }
  let finalProxyServerNameserverPolicy = undefined;
  const originPolicy = originDns['proxy-server-nameserver-policy'];
  if (originPolicy && typeof originPolicy === 'object' && !Array.isArray(originPolicy) && Object.keys(originPolicy).length > 0) { finalProxyServerNameserverPolicy = {}; for (const [domain, servers] of Object.entries(originPolicy)) { finalProxyServerNameserverPolicy[domain] = formatDnsValues(servers); } }
  const originHosts = config.hosts || {};
  const defaultHosts = {
    "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    "doh.pub": ["120.53.53.53", "1.12.12.12"],
    "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    "services.googleapis.cn": "services.googleapis.com",
    "google.cn": "google.com",
    "cn.bing.com": "global.bing.com"
  };
  const finalHosts = { ...originHosts, ...defaultHosts };
  return {
    // 节点IP优先级：ip-version: ipv6-prefer
    "proxy-providers": { "节点": { "type": "inline", "health-check": { "enable": true, "url": "https://dns.google/generate_204", "expected-status": 204, "interval": 600, "timeout": 3000, "max-failed-times": 2, "lazy": false }, "override": { "ip-version": "dual" }, "exclude-filter": "(?i)套餐|剩余|流量|到期|重置|频道|订阅|官网|禁止|客户端|有效|联系|测试|节点|日期|群组|加入|通知|维护|网址|地址|下载|更新|APP|登录|严禁|恢复|处理|谢谢", "payload": subscriptionProxies } },
    "ipv6": true,
    "allow-lan": false,
    "bind-address": "*",
    "mode": "rule",
    "log-level": "error",
    "unified-delay": true,
    "tcp-concurrent": true,
    "find-process-mode": "off",
    "disable-keep-alive": false,
    "keep-alive-interval": 15,
    "keep-alive-idle": 600,
    "etag-support": true,
    "profile": { "store-selected": true, "store-fake-ip": true },
    "experimental": { "quic-go-disable-gso": false, "quic-go-disable-ecn": true, "dialer-ip4p-convert": false },
    "port": 0,
    "socks-port": 0,
    "mixed-port": 0,
    "redir-port": 0,
    "tproxy-port": 0,
    "tun": {
      "enable": true,
      "stack": "mixed",
      "auto-route": true,
      "auto-redirect": true,
      "auto-detect-interface": true,
      "strict-route": true,
      "disable-icmp-forwarding": true,
      "dns-hijack": ["any:53", "tcp://any:53"],
      "udp-timeout": 600
    },
    "hosts": finalHosts,
    "dns": {
      "enable": true,
      "ipv6": true,
      "ipv6-timeout": 300,
      "cache-algorithm": "arc",
      "use-hosts": true,
      "use-system-hosts": false,
      "prefer-h3": true,
      "respect-rules": false,
      "enhanced-mode": "fake-ip",
      "fake-ip-range": "198.18.0.0/15",
      "fake-ip-range6": "fd00:a4c5:9b12:d3f8:e760:00df::/96",
      "fake-ip-ttl": 1,
      "fake-ip-filter-mode": "rule",
      "fake-ip-filter": [
        "RULE-SET,ads,fake-ip",
        "RULE-SET,ai,fake-ip",
        "RULE-SET,proxy@direct,real-ip",
        "RULE-SET,google,fake-ip",
        "RULE-SET,media,fake-ip",
        "RULE-SET,proxy-lite,fake-ip",
        "RULE-SET,direct-lite,real-ip",
        "MATCH,fake-ip"
      ],
      "default-nameserver": ["223.6.6.6", "119.29.29.29"],
      "proxy-server-nameserver": finalProxyServerNameserver,
      ...(finalProxyServerNameserverPolicy !== undefined && { "proxy-server-nameserver-policy": finalProxyServerNameserverPolicy }),
      "nameserver": proxyDns,
      "nameserver-policy": {
        "rule-set:ads": ["rcode://name_error"],
        "rule-set:ai": proxyDns,
        "rule-set:proxy@direct": directDns,
        "rule-set:google": proxyDns,
        "rule-set:media": proxyDns,
        "rule-set:proxy-lite": proxyDns,
        "rule-set:direct-lite,dnsmasq-china-lite": directDns
      },
      "direct-nameserver": directDns,
      "direct-nameserver-follow-policy": true
    },
    "sniffer": {
      "enable": true,
      "force-dns-mapping": true,
      "parse-pure-ip": true,
      "override-destination": false,
      "sniff": { "HTTP": { "ports": [80, "8080-8880"], "override-destination": true }, "TLS": { "ports": [443, 8443] }, "QUIC": { "ports": [443, 8443] } },
      "skip-domain": ["rule-set:ads,proxy@direct,ai,google,media,proxy-lite,direct-lite,dnsmasq-china-lite"],
      "skip-src-address": ["rule-set:telegram_ip,google_ip,media_ip,direct_ip"]
    },
    "rule-providers": Object.fromEntries(Object.entries(ruleProviderDefinitions)
      .filter(([name]) => !optionalProviders.has(name))
      .map(([name, provider]) => [name, JSON.parse(JSON.stringify(provider))])),
    "rules": [
      "RULE-SET,ads,REJECT",
      "RULE-SET,ai,AI",
      "RULE-SET,proxy@direct,直接连接",
      "RULE-SET,google,GOOGLE",
      "RULE-SET,media,Media",
      "RULE-SET,proxy-lite,代理连接",
      "RULE-SET,direct-lite,直接连接",
      "DST-PORT,5228-5230,直接连接",
      "RULE-SET,telegram_ip,TELEGRAM,no-resolve",
      "RULE-SET,media_ip,Media",
      "RULE-SET,direct_ip,直接连接",
      "RULE-SET,google_ip,GOOGLE",
      "MATCH,代理连接"
    ],
    "proxies": [{ "name": "IPV4优先", "type": "direct", "udp": true, "ip-version": "ipv4-prefer" }, { "name": "IPV6优先", "type": "direct", "udp": true, "ip-version": "ipv6-prefer" }, { "name": "仅IPV4", "type": "direct", "udp": true, "ip-version": "ipv4" }, { "name": "仅IPV6", "type": "direct", "udp": true, "ip-version": "ipv6" }],
    "proxy-groups": [
      { "name": "代理连接", "type": "select", "proxies": ["最低延迟", "故障转移"], "include-all-providers": true },
      { "name": "直接连接", "type": "select", "proxies": ["DIRECT", "IPV4优先", "IPV6优先", "仅IPV4", "仅IPV6"] },
      { "name": "代理DNS", ...dlAnchor },
      { "name": "TELEGRAM", ...dlAnchor },
      { "name": "AI", ...dlAnchor },
      { "name": "GOOGLE", ...dlAnchor },
      { "name": "Media", ...dlAnchor },
      { "name": "最低延迟", "type": "url-test", "tolerance": 30, "include-all-providers": true, "empty-fallback": "REJECT", "hidden": true },
      { "name": "故障转移", ...fallAnchor, "filter": "(?i)🇭🇰|香港|\\bHK\\b|\\bhongkong\\b|\\bhong\\s?kong\\b|🇸🇬|新加坡|狮城|\\bSG\\b|\\bsingapore\\b|🇯🇵|日本|\\bJP\\b|\\bjapan\\b|🇺🇸|美国|\\bUS\\b|\\bunitedstates\\b|\\bunited\\s?states\\b" },
      { "name": "GLOBAL", "type": "select", "proxies": ["最低延迟", "故障转移", "代理连接", "直接连接", "代理DNS", "TELEGRAM", "AI", "GOOGLE", "Media"], "include-all-providers": true, "hidden": true }
    ]
  };
}
