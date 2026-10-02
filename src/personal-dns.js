// Private subscription DNS and hosts preservation for the Echsfxy configuration.
const personalDnsCommonDnsList = [
  // IPv4（国内）
  '223.5.5.5',
  '223.6.6.6',
  '119.29.29.29',
  '1.12.12.12',
  '120.53.53.53',
  '114.114.114.114',
  '180.76.76.76',
  '1.2.4.8',
  '116.116.116.116',
  '101.226.4.6',
  '123.125.81.6',
  '180.184.1.1',
  '180.184.2.2',

  // IPv6（国内）
  '2400:3200::1',
  '2400:3200:baba::1',
  '2402:4e00::',
  '2400:da00::6666',

  // IPv4（国外）
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  '149.112.112.112',
  '208.67.222.222',
  '208.67.220.220',
  '94.140.14.14',
  '94.140.15.15',
  '76.76.2.0',
  '76.76.10.0',
  '185.228.168.9',
  '185.228.169.9',
  '77.88.8.8',
  '77.88.8.1',
  '156.154.70.1',
  '156.154.71.1',

  // IPv6（国外）
  '2606:4700:4700::1111',
  '2606:4700:4700::1001',
  '2001:4860:4860::8888',
  '2001:4860:4860::8844',
  '2620:fe::fe',
  '2620:fe::9',
  '2620:119:35::35',
  '2620:119:53::53',
  '2a10:50c0::bad1:ff',
  '2a10:50c0::bad2:ff',
  '2a10:50c0::ad1:ff',
  '2a10:50c0::ad2:ff',
  '2a0d:2a00:1::2',
  '2a0d:2a00:2::2',
  '2a02:6b8::feed:0ff',
  '2a02:6b8:0:1::feed:0ff',
  '2610:a1:1018::1',
  '2610:a1:1019::1',

  // 公共解析服务的主机名及其子域
  'alidns.com',
  'doh.pub',
  'dot.pub',
  'dns.pub',
  'dnspod.cn',
  'dnspod.com',
  'dns.baidu.com',
  'dns.google',
  'dns.cloudflare.com',
  'cloudflare-dns.com',
  'quad9.net',
  'opendns.com',
  'nextdns.io',
  'adguard.com',
  'adguard-dns.com',
  'dns.apple.com',
  'one.one.one.one',
];

// 展开 IPv6 后按地址比较，DNS 路径、参数及相似域名不参与公共解析器判定。
function personalDnsNormalizeDnsHost(host) {
  host = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host.includes(':')) return host;
  const parts = host.split('::');
  if (parts.length > 2) return host;
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  const words = parts.length === 2 && missing > 0 ? [...left, ...Array(missing).fill('0'), ...right] : left;
  return words.length === 8 && words.every((word) => /^[0-9a-f]{1,4}$/.test(word))
    ? words.map((word) => parseInt(word, 16).toString(16)).join(':')
    : host;
}

function personalDnsParseDnsEndpoint(value) {
  const address = String(value).trim().split('#')[0];
  const schemeMatch = address.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'udp';
  let authority = (schemeMatch ? address.slice(schemeMatch[0].length) : address).split(/[/?]/)[0];
  authority = authority.slice(authority.lastIndexOf('@') + 1);
  const bracket = authority.match(/^\[([^\]]+)\](?::(\d+))?$/);
  const hostPort = authority.match(/^([^:]+):(\d+)$/);
  const host = bracket ? bracket[1] : hostPort ? hostPort[1] : authority;
  const port = bracket ? bracket[2] : hostPort ? hostPort[2] : undefined;
  return {
    host: personalDnsNormalizeDnsHost(host),
    port: Number(port || { https: 443, http: 80, tls: 853, quic: 853 }[scheme] || 53),
    scheme,
  };
}

const personalDnsCommonDnsHosts = personalDnsCommonDnsList.map(personalDnsNormalizeDnsHost);
function personalDnsIsPublicDns(dns) {
  const { host, scheme } = personalDnsParseDnsEndpoint(dns);
  if (scheme === 'system' || host === 'system') return true;
  return personalDnsCommonDnsHosts.some(
    (known) => host === known || (!known.includes(':') && !/^\d/.test(known) && host.endsWith(`.${known}`)),
  );
}

function personalDnsCreateHostsLookup(hosts) {
  const makeNode = () => ({ children: new Map(), value: undefined });
  const root = makeNode();
  const insert = (parts, value) => {
    let node = root;
    for (let index = parts.length - 1; index >= 0; index--) {
      if (!node.children.has(parts[index])) node.children.set(parts[index], makeNode());
      node = node.children.get(parts[index]);
    }
    node.value = value;
  };
  for (const [pattern, value] of Object.entries(hosts)) {
    const values = (Array.isArray(value) ? value : [value]).filter((item) => typeof item === 'string' && item.trim());
    if (!values.length) continue;
    const parts = pattern.toLowerCase().split('.');
    if (parts[0] === '+') {
      insert(parts.slice(1), values);
      parts[0] = '';
    }
    insert(parts, values);
  }
  const search = (node, parts, index) => {
    if (!node) return undefined;
    if (index < 0) return node.value;
    return (
      search(node.children.get(parts[index]), parts, index - 1) ||
      search(node.children.get('*'), parts, index - 1) ||
      node.children.get('')?.value
    );
  };
  return (domain) => {
    const parts = domain.toLowerCase().split('.');
    return search(root, parts, parts.length - 1);
  };
}

/**
 * 判断域名规则（精确/通配）是否匹配节点域名集合，忽略大小写
 */
function personalDnsMatchDomainPattern(pattern, domains) {
  pattern = pattern.toLowerCase();

  // 精确匹配
  if (!pattern.includes('*') && !pattern.startsWith('+.') && !pattern.startsWith('.')) {
    return typeof domains === 'string'
      ? domains.toLowerCase() === pattern
      : [...domains].some((d) => d.toLowerCase() === pattern);
  }

  // 通配匹配：统一转为数组遍历（字符串时直接构建单元素数组，避免 Set 中转）
  const domainList = typeof domains === 'string' ? [domains.toLowerCase()] : [...domains].map((d) => d.toLowerCase());

  // +.example.com
  if (pattern.startsWith('+.')) {
    const suffix = pattern.slice(2);
    return domainList.some((domain) => domain === suffix || domain.endsWith(`.${suffix}`));
  }

  // .example.com
  if (pattern.startsWith('.')) {
    const suffix = pattern.slice(1);
    return domainList.some((domain) => domain !== suffix && domain.endsWith(`.${suffix}`));
  }

  // *.example.com、example.*.com 等
  const patternParts = pattern.split('.');
  return domainList.some((domain) => {
    const domainParts = domain.split('.');
    return (
      patternParts.length === domainParts.length &&
      patternParts.every((part, index) => part === '*' || part === domainParts[index])
    );
  });
}

/**
 * 单地址 hosts 改写为节点 server；多地址保存为节点精确 hosts，由内核按 IP 偏好选择。
 * 地址改写保留 TLS 身份；域名映射循环会报错。
 */
function personalDnsApplyHostsToProxies(proxies, hosts, retainedHosts = {}) {
  if (!hosts || typeof hosts !== 'object' || Array.isArray(hosts)) return proxies;
  const lookup = personalDnsCreateHostsLookup(hosts);
  const cache = new Map();
  const resolve = (server) => {
    const key = server.toLowerCase();
    if (cache.has(key)) return cache.get(key);
    const seen = new Set();
    let current = server;
    while (true) {
      const domain = current.toLowerCase();
      if (seen.has(domain)) throw new Error(`hosts 域名映射存在循环：${server}`);
      seen.add(domain);
      const values = lookup(domain);
      if (!values) {
        const result = { server: current };
        cache.set(key, result);
        return result;
      }
      if (values.length > 1) {
        const result = { addresses: [...values] };
        cache.set(key, result);
        return result;
      }
      current = values[0];
    }
  };
  return proxies.map((proxy) => {
    if (typeof proxy.server !== 'string') return proxy;
    const resolved = resolve(proxy.server);
    if (resolved.addresses) {
      retainedHosts[proxy.server] = [...resolved.addresses];
      return proxy;
    }
    if (resolved.server === proxy.server) return proxy;
    // WS、gRPC 等传输及插件可能从 server 派生 Host/authority，交由 hosts 保留原始传输身份。
    if ((proxy.network && proxy.network !== 'tcp') || proxy.plugin) {
      retainedHosts[proxy.server] = resolved.server;
      return proxy;
    }
    const mapped = { ...proxy, server: resolved.server };
    const type = String(proxy.type || '').toLowerCase();
    const usesTls = proxy.tls || ['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls'].includes(type);
    const field = type === 'vmess' || type === 'vless' ? 'servername' : 'sni';
    if (usesTls && !proxy[field]) mapped[field] = proxy.server;
    return mapped;
  });
}

// Replace only the routing selector; transport/ECS parameters remain unchanged.
function personalDnsThroughGroup(value, group) {
  if (typeof value !== 'string' || !value.trim()) return '';
  const [base, ...suffixes] = value.trim().split('#');
  const parameters = suffixes.join('&').split('&').filter((part) => part.includes('='));
  return base + '#' + [group, ...parameters].join('&');
}

/**
 * Add subscription-specific node DNS/hosts without replacing Echsfxy's general
 * resolvers, prefer-h3, fake-IP policy or other network settings. Returns a new
 * configuration; neither input is mutated. All inputs are plain JSON data.
 */
function patchPersonalDns(originalSubscription, echConfig, settings = {}, groupNames = {}) {
  const object = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const values = (value) => (Array.isArray(value) ? value : [value]).filter((item) => typeof item === 'string' && item.trim());
  const copy = (value) => JSON.parse(JSON.stringify(value));
  const original = object(originalSubscription);
  const originDns = object(original.dns);
  const dns = { ...object(echConfig.dns) };
  const next = { ...echConfig, dns };
  const directGroup = groupNames.direct || 'DIRECT';
  const collectProxies = (config) => [
    ...(Array.isArray(config.proxies) ? config.proxies : []),
    ...Object.values(object(config['proxy-providers'])).flatMap((provider) =>
      provider && Array.isArray(provider.payload) ? provider.payload : []),
  ];
  const nodeDomains = new Set(collectProxies(original)
    .filter((proxy) => proxy && typeof proxy.server === 'string')
    .map((proxy) => proxy.server.toLowerCase()));

  const listen = typeof originDns.listen === 'string' && originDns.listen.trim()
    ? personalDnsParseDnsEndpoint(originDns.listen) : null;
  const localListener = (value) => {
    if (!listen) return false;
    const endpoint = personalDnsParseDnsEndpoint(value);
    if (!['udp', 'tcp'].includes(endpoint.scheme) || endpoint.port !== listen.port) return false;
    return endpoint.host === listen.host ||
      (listen.host === '0.0.0.0' && endpoint.host === '127.0.0.1') ||
      (listen.host === '0:0:0:0:0:0:0:0' && endpoint.host === '0:0:0:0:0:0:0:1');
  };
  const originNodeResolvers = values(originDns['proxy-server-nameserver']);
  const retainedHosts = {};
  if (originNodeResolvers.length === 1 && localListener(originNodeResolvers[0])) {
    if (Array.isArray(next.proxies)) {
      next.proxies = personalDnsApplyHostsToProxies(next.proxies, original.hosts, retainedHosts);
    }
    if (next['proxy-providers']) {
      next['proxy-providers'] = Object.fromEntries(Object.entries(next['proxy-providers']).map(([name, provider]) => [
        name,
        Array.isArray(provider.payload)
          ? { ...provider, payload: personalDnsApplyHostsToProxies(provider.payload, original.hosts, retainedHosts) }
          : provider,
      ]));
    }
  }
  next.hosts = { ...object(original.hosts), ...object(echConfig.hosts), ...retainedHosts };
  for (const proxy of collectProxies(next)) {
    if (proxy && typeof proxy.server === 'string') nodeDomains.add(proxy.server.toLowerCase());
  }
  for (const value of Object.values(retainedHosts).flatMap(values)) nodeDomains.add(value.toLowerCase());
  const matchesNode = (pattern) => !pattern.startsWith('rule-set:') && personalDnsMatchDomainPattern(pattern, nodeDomains);
  let importedHttpsWithoutForcedH3 = false;
  const sanitize = (value, privateOnly = false) => [...new Set(values(value)
    .filter((address) => !localListener(address) && (!privateOnly || !personalDnsIsPublicDns(address)))
    .map((address) => {
      let forceH3 = false;
      for (const part of address.split('#').slice(1).join('&').split('&')) {
        const equals = part.indexOf('=');
        if (part.slice(0, equals).trim() === 'h3') forceH3 = part.slice(equals + 1).trim() === 'true';
      }
      if (personalDnsParseDnsEndpoint(address).scheme === 'https' && !forceH3) importedHttpsWithoutForcedH3 = true;
      return personalDnsThroughGroup(address, directGroup);
    }))];
  const originalPolicy = object(originDns['nameserver-policy']);
  const explicitPolicy = object(originDns['proxy-server-nameserver-policy']);
  const nodePolicy = { ...object(dns['proxy-server-nameserver-policy']) };
  // Echsfxy already copied these keys but removed their parameters. Replace them
  // from the original input, including any renamed rule-set dependencies.
  for (const pattern of Object.keys(explicitPolicy)) delete nodePolicy[pattern];
  const inheritedPrivate = [];
  for (const [pattern, addresses] of Object.entries(originalPolicy)) {
    if (!matchesNode(pattern)) continue;
    const cleaned = sanitize(addresses, true);
    if (!cleaned.length) continue;
    nodePolicy[pattern] = Array.isArray(addresses) ? cleaned : cleaned[0];
    inheritedPrivate.push(...cleaned);
  }

  const originalProviders = object(original['rule-providers']);
  const ruleProviders = { ...object(next['rule-providers']) };
  const copiedProviders = new Map();
  const validGroups = new Set(['DIRECT', 'REJECT', directGroup,
    ...(next['proxy-groups'] || []).map((group) => group.name)]);
  let copiedRuleProvider = false;
  const copyProvider = (sourceName) => {
    if (copiedProviders.has(sourceName)) return copiedProviders.get(sourceName);
    const provider = originalProviders[sourceName];
    if (!provider) return ruleProviders[sourceName] && ['domain', 'classical'].includes(ruleProviders[sourceName].behavior) ? sourceName : null;
    if (!['domain', 'classical'].includes(provider.behavior)) return null;
    let name = sourceName === '__proto__' ? 'personal-dns-' + sourceName : sourceName;
    for (let suffix = 1; Object.prototype.hasOwnProperty.call(ruleProviders, name); suffix++) {
      name = 'personal-dns-' + sourceName + (suffix === 1 ? '' : '-' + suffix);
    }
    const copied = copy(provider);
    if (copied.type === 'http') {
      const extension = ['mrs', 'text'].includes(copied.format) ? copied.format : 'yaml';
      const paths = new Set(Object.values(ruleProviders).map((entry) => entry.path));
      const stem = './rules/personal-dns/' + encodeURIComponent(name);
      copied.path = stem + '.' + extension;
      for (let index = 2; paths.has(copied.path); index++) copied.path = stem + '-' + index + '.' + extension;
    }
    if (copied.proxy && !validGroups.has(copied.proxy)) copied.proxy = directGroup;
    ruleProviders[name] = copied;
    copiedProviders.set(sourceName, name);
    copiedRuleProvider = true;
    return name;
  };
  for (const [pattern, addresses] of Object.entries(explicitPolicy)) {
    const cleaned = sanitize(addresses);
    if (!cleaned.length) continue;
    let key = pattern;
    if (pattern.startsWith('rule-set:')) {
      const names = pattern.slice(9).split(',').map((name) => copyProvider(name.trim())).filter(Boolean);
      if (!names.length) continue;
      key = 'rule-set:' + [...new Set(names)].join(',');
    }
    nodePolicy[key] = Array.isArray(addresses) ? cleaned : cleaned[0];
    if (matchesNode(pattern)) inheritedPrivate.push(...sanitize(addresses, true));
  }
  if (copiedRuleProvider) next['rule-providers'] = ruleProviders;
  if (Object.keys(nodePolicy).length) dns['proxy-server-nameserver-policy'] = nodePolicy;
  else delete dns['proxy-server-nameserver-policy'];

  const explicitResolvers = sanitize(originNodeResolvers);
  const privateResolvers = [...new Set(inheritedPrivate)];
  if (explicitResolvers.length || privateResolvers.length) {
    dns['proxy-server-nameserver'] = [...new Set([...explicitResolvers, ...privateResolvers])];
  } else if (originNodeResolvers.some(localListener)) {
    // The imported local DNS listener is not present in the generated config.
    dns['proxy-server-nameserver'] = copy(dns['direct-nameserver'] || dns['default-nameserver'] || []);
  }
  // Mihomo only handles h3=true as a per-resolver override; h3=false does not
  // cancel prefer-h3. Preserve the source transport preference when importing
  // node HTTPS resolvers, while leaving configurations without them unchanged.
  if (dns['prefer-h3'] === true && originDns['prefer-h3'] !== true && importedHttpsWithoutForcedH3) {
    dns['prefer-h3'] = false;
  }

  // Preserve only node-specific real-IP exceptions when importing a blacklist
  // into Echsfxy's ordered fake-IP rules, rather than widening service bypasses.
  const filters = values(originDns['fake-ip-filter']);
  const realIpNodes = [...nodeDomains].filter((domain) => {
    if (domain.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(domain)) return false;
    return filters.some((filter) => {
      if (originDns['fake-ip-filter-mode'] !== 'rule') return personalDnsMatchDomainPattern(filter, domain);
      const [type, value, action] = filter.split(',');
      return action === 'real-ip' && ((type === 'DOMAIN' && domain === value.toLowerCase()) ||
        (type === 'DOMAIN-SUFFIX' && personalDnsMatchDomainPattern('+.' + value, domain)));
    });
  });
  if (realIpNodes.length) {
    const additions = dns['fake-ip-filter-mode'] === 'rule'
      ? realIpNodes.map((domain) => 'DOMAIN,' + domain + ',real-ip') : realIpNodes;
    dns['fake-ip-filter'] = [...new Set([...additions, ...values(dns['fake-ip-filter'])])];
  }

  const follow = settings.dnsFollowServices;
  const servicePolicies = {};
  for (const service of ['ai', 'dlsite']) {
    const enabled = follow === true || (follow && follow[service]);
    const group = groupNames[service];
    if (!enabled || !group || !validGroups.has(group) || !ruleProviders[service]) continue;
    servicePolicies[service] = values(dns.nameserver).map((address) => personalDnsThroughGroup(address, group));
  }
  if (Object.keys(servicePolicies).length) {
    const policies = {};
    const inserted = new Set();
    for (const [pattern, addresses] of Object.entries(object(dns['nameserver-policy']))) {
      if (!pattern.startsWith('rule-set:')) {
        policies[pattern] = addresses;
        continue;
      }
      // DLsite is an early personal route. Its domains also occur in proxy-lite,
      // so appending its DNS policy after the upstream sets would never win.
      const policySets = pattern.slice(9).split(',').map((name) => name.trim());
      if (servicePolicies.dlsite && !inserted.has('dlsite') &&
          policySets.some((name) => !['ads', 'personal-download', 'personal-direct'].includes(name))) {
        policies['rule-set:dlsite'] = servicePolicies.dlsite;
        inserted.add('dlsite');
      }
      const remaining = [];
      for (const name of pattern.slice(9).split(',').map((name) => name.trim())) {
        if (servicePolicies[name]) {
          policies['rule-set:' + name] = servicePolicies[name];
          inserted.add(name);
        } else remaining.push(name);
      }
      if (remaining.length) policies['rule-set:' + remaining.join(',')] = addresses;
    }
    for (const [name, addresses] of Object.entries(servicePolicies)) {
      if (!inserted.has(name)) policies['rule-set:' + name] = addresses;
    }
    dns['nameserver-policy'] = policies;
  }
  return next;
}

