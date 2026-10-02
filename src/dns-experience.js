// Keep DNS classification consistent with the personal traffic rules.
// Run before importing subscription DNS, whose explicit ECS must be preserved.
function publicDnsResolvers(addresses, group, ecsMode) {
  const upstreamEcs = {
    'https://dns.google/dns-query': '8.8.8.8/24',
    'https://dns.quad9.net/dns-query': '9.9.9.9/24',
  };
  return addresses.map(address => {
    let routed = personalDnsThroughGroup(address, group);
    const subnet = upstreamEcs[address.split('#')[0]];
    if (ecsMode === 'upstream' && subnet && !/[#&]ecs=/.test(routed)) routed += '&ecs=' + subnet + '&ecs-override=true';
    return routed;
  });
}

// General resolvers keep their explicitly configured route. Application and
// node-specific DNS policies have already been built and remain independent.
function configureGeneralDns(config, addresses) {
  const extra = addresses.map(address => {
    const selector = (address.split('#')[1] || '').split('&').find(part => part && !part.includes('='));
    return personalDnsThroughGroup(address, !selector || selector === 'DIRECT' ? '直接连接' : selector);
  });
  config.dns.nameserver = [...new Set([...config.dns.nameserver, ...extra])];
  for (const [key, resolvers] of Object.entries(config.dns['nameserver-policy'])) {
    if (Array.isArray(resolvers) && resolvers.length && resolvers.every(address =>
      typeof address === 'string' && address.split('#')[1]?.split('&')[0] === '代理DNS')) {
      config.dns['nameserver-policy'][key] = [...new Set([...resolvers, ...extra])];
    }
  }
}

function withoutForcedEcs(address) {
  if (typeof address !== 'string' || !address.includes('#')) return address;
  const split = address.indexOf('#');
  const parameters = address.slice(split + 1).split('&').filter(part => {
    const key = part.split('=')[0].toLowerCase();
    return key !== 'ecs' && key !== 'ecs-override';
  });
  return address.slice(0, split) + (parameters.length ? '#' + parameters.join('&') : '');
}

function patchDnsExperience(config, lists, options, downloadEnabled, downloadGroup) {
  const settings = options || {};
  const mode = settings.ecsMode || 'resolver-default';
  if (!['resolver-default', 'upstream'].includes(mode)) throw new Error('未知 ECS 模式：' + mode);
  const dns = config.dns;
  const mapResolvers = value => Array.isArray(value) ? value.map(withoutForcedEcs) : withoutForcedEcs(value);
  if (mode === 'resolver-default') {
    for (const key of ['nameserver', 'direct-nameserver']) if (dns[key]) dns[key] = mapResolvers(dns[key]);
    for (const [key, value] of Object.entries(dns['nameserver-policy'] || {})) dns['nameserver-policy'][key] = mapResolvers(value);
  }
  if (settings.directRules === false) return config;
  const payload = entries => [...new Set(entries.map(rule => {
    const [type, domain] = rule.split(',');
    if (type === 'DOMAIN') return domain;
    if (type === 'DOMAIN-SUFFIX') return '+.' + domain;
    throw new Error('DNS 域名清单包含不支持的规则类型：' + type);
  }))];
  const providers = config['rule-providers'];
  if (providers['personal-direct'] || providers['personal-download']) throw new Error('个人 DNS 规则集与基础配置重名');
  providers['personal-direct'] = { type: 'inline', behavior: 'domain', payload: payload([...lists['microsoft-direct'], ...lists['extra-direct'], ...lists['academic-direct']]) };
  if (downloadEnabled) providers['personal-download'] = { type: 'inline', behavior: 'domain', payload: payload(lists.downloads) };
  const filterIndex = dns['fake-ip-filter'].indexOf('RULE-SET,ads,fake-ip');
  if (dns['fake-ip-filter-mode'] !== 'rule' || filterIndex < 0) throw new Error('基础配置的 Fake-IP 规则不支持个人 DNS 分类');
  dns['fake-ip-filter'].splice(filterIndex + 1, 0,
    ...(downloadEnabled ? ['RULE-SET,personal-download,fake-ip'] : []),
    'RULE-SET,personal-direct,real-ip');
  const policies = {};
  let inserted = false;
  for (const [key, value] of Object.entries(dns['nameserver-policy'])) {
    policies[key] = value;
    if (key !== 'rule-set:ads') continue;
    if (downloadEnabled) {
      // A manually switched download keeps its domain and resolves through the
      // same selected group. The domestic resolver endpoints remain reachable
      // for its default direct route.
      policies['rule-set:personal-download'] = dns['direct-nameserver'].map(address => {
        const [base, ...suffix] = address.split('#');
        const parameters = suffix.join('&').split('&').filter(part => part.includes('='));
        return base + '#' + [downloadGroup, ...parameters].join('&');
      });
    }
    policies['rule-set:personal-direct'] = [...dns['direct-nameserver']];
    inserted = true;
  }
  if (!inserted) throw new Error('基础配置缺少广告 DNS 规则，无法确定个人 DNS 顺序');
  dns['nameserver-policy'] = policies;
  return config;
}
