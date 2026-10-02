// Only personal additions override the Echsfxy configuration.
const Compatible_With_Bettbox = { ruleOptionsEnable: true };
const ruleOptionsEnable = {
  OneDrive: personalSettings.oneDrive,
  DLsite: personalSettings.dlsite.enabled,
  AI固定出口: personalSettings.ai.enabled,
  大流量下载直连: personalSettings.downloads.enabled,
  DNS跟随服务: true,
};

function personalClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function main(subscription) {
  if (!subscription || !Array.isArray(subscription.proxies) || !subscription.proxies.length) throw new Error('需要包含 proxies 的订阅配置');
  let config = echsfxyMain(personalClone(subscription));
  const groups = config['proxy-groups'];
  const required = ['直接连接', '代理连接', '国外AI', personalSettings.dlsite.defaultGroup];
  for (const name of required) if (!groups.some(group => group.name === name)) throw new Error('上游策略组已变化，需要检查个人配置：' + name);
  const aiGroup = groups.find(group => group.name === '国外AI');
  const originalService = personalClone(aiGroup);
  const extraGroups = [];
  const earlyRules = [];

  if (ruleOptionsEnable.OneDrive) {
    extraGroups.push({ name: 'OneDrive', type: 'select', proxies: ['直接连接', '代理连接'] });
    for (const rule of personalLists.onedrive) earlyRules.push(rule + ',OneDrive');
    config['find-process-mode'] = 'strict';
  }
  if (ruleOptionsEnable.大流量下载直连) {
    extraGroups.push({ name: personalSettings.downloads.name, type: 'select', proxies: ['直接连接', '代理连接', '下载相关'] });
    for (const rule of personalLists.downloads) earlyRules.push(rule + ',' + personalSettings.downloads.name);
  }
  for (const key of ['microsoft-direct', 'extra-direct', 'academic-direct']) for (const rule of personalLists[key]) earlyRules.push(rule + ',直接连接');

  if (ruleOptionsEnable.AI固定出口) {
    const provider = config['proxy-providers']['节点'];
    const excluded = provider['exclude-filter'] ? new RegExp(provider['exclude-filter'].replace(/^\(\?i\)/, ''), 'i') : null;
    const candidates = [];
    for (const region of personalSettings.ai.regions) {
      const regional = groups.find(group => group.name === region + '|故障转移');
      if (!regional?.filter) throw new Error('上游地区匹配已变化：' + region);
      const filter = new RegExp(regional.filter.replace(/^\(\?i\)/, ''), 'i');
      for (const proxy of provider.payload) if (filter.test(proxy.name) && !(excluded && excluded.test(proxy.name)) && !candidates.includes(proxy.name)) candidates.push(proxy.name);
    }
    aiGroup.type = 'select';
    aiGroup.proxies = ['REJECT'];
    // Provider nodes must be referenced through use, not the top-level proxies list.
    // Match names exactly so an update cannot add a different region to this group.
    aiGroup.use = ['节点'];
    aiGroup.filter = '^(?:' + ['REJECT', ...candidates].map(name => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')$';
    aiGroup['default-selected'] = 'REJECT';
    delete aiGroup['include-all-providers'];
    delete aiGroup['include-all'];
  }
  if (ruleOptionsEnable.DLsite) {
    const group = { ...originalService, name: 'DLsite', proxies: [personalSettings.dlsite.defaultGroup, ...originalService.proxies.filter(name => name !== personalSettings.dlsite.defaultGroup)], 'default-selected': personalSettings.dlsite.defaultGroup };
    group.icon = groups.find(item => item.name === personalSettings.dlsite.defaultGroup).icon;
    extraGroups.push(group);
    config['rule-providers'].dlsite = { type: 'http', interval: 86400, proxy: '代理连接', behavior: 'domain', format: 'mrs', url: managedProviders.dlsite.originalUrl, path: './rules/dlsite.mrs' };
    earlyRules.push('RULE-SET,dlsite,DLsite');
  }
  const insertion = config.rules.indexOf('RULE-SET,ads,REJECT');
  if (insertion < 0) throw new Error('上游规则顺序已变化，需要检查个人规则插入位置');
  config.rules.splice(insertion + 1, 0, ...earlyRules);
  if (ruleOptionsEnable.AI固定出口) {
    const aiRule = config.rules.indexOf('SUB-RULE,(RULE-SET,ai),sub-ai');
    if (aiRule < 0) throw new Error('上游 AI 规则已变化，需要检查固定出口');
    // Mihomo can skip a selected node without UDP support. Stop before another
    // service or the catch-all can send this traffic through a different exit.
    config.rules.splice(aiRule + 1, 0, 'AND,((NETWORK,UDP),(RULE-SET,ai)),REJECT');
  }
  const aiIndex = groups.indexOf(aiGroup);
  groups.splice(aiIndex + 1, 0, ...extraGroups);
  const global = groups.find(group => group.name === 'GLOBAL');
  if (global) global.proxies.push(...extraGroups.map(group => group.name));

  const dnsSettings = { dnsFollowServices: ruleOptionsEnable.DNS跟随服务 ? { ai: personalSettings.dnsFollowServices.ai && ruleOptionsEnable.AI固定出口, dlsite: personalSettings.dnsFollowServices.dlsite && ruleOptionsEnable.DLsite } : false };
  config = patchDnsExperience(config, personalLists, personalSettings.dns, ruleOptionsEnable.大流量下载直连, personalSettings.downloads.name);
  config = patchPersonalDns(subscription, config, dnsSettings, { direct: '直接连接', proxy: '代理连接', ai: '国外AI', dlsite: 'DLsite' });
  if (personalSettings.preserveClientSettings) {
    for (const key of ['port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port', 'allow-lan', 'bind-address', 'tun', 'external-controller', 'external-controller-tls', 'external-controller-unix', 'external-controller-pipe', 'secret', 'external-ui', 'external-ui-url', 'external-doh-server']) delete config[key];
  }
  if (rulesBaseUrl) {
    for (const [name, provider] of Object.entries(config['rule-providers'])) {
      const managed = managedProviders[name];
      if (managed && provider.url === managed.originalUrl) {
        provider.url = rulesBaseUrl + '/' + managed.behavior + '/' + name + '.mrs';
        provider.path = './rules/personal-' + name + '.mrs';
        delete provider['path-in-bundle'];
      }
    }
  }
  return config;
}
