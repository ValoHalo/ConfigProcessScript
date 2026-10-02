// Application selectors take priority over broad download, security and media categories.
function configureApplicationGroups(config, nodeGroups, template, options) {
  const enabled = applicationGroups.filter(app => app.existingGroup || options[app.name]);
  const groups = config['proxy-groups'];
  const addProvider = id => {
    if (!ruleProviderDefinitions[id]) throw new Error('Missing rule provider definition: ' + id);
    config['rule-providers'][id] = personalClone(ruleProviderDefinitions[id]);
  };
  const appRules = [], ipRules = [];
  for (const app of enabled) {
    if (!app.existingGroup) {
      const preferred = nodeGroups.regionGroups[app.defaultGroup] || app.defaultGroup;
      const selected = groups.some(group => group.name === preferred) ? preferred : '代理连接';
      groups.push({ ...personalClone(template), name: app.name, proxies: [selected, ...template.proxies.filter(name => name !== selected)], 'default-selected': selected });
    }
    addProvider(app.domain);
    const subRule = 'sub-app-' + app.domain;
    config['sub-rules'][subRule] = ['AND,((NETWORK,udp),(DST-PORT,443)),代理QUIC', 'MATCH,' + app.name];
    const domainRule = 'SUB-RULE,(RULE-SET,' + app.domain + '),' + subRule;
    if (app.name === 'FCM') {
      const portIndex = config.rules.indexOf('DST-PORT,5228-5230,直接连接');
      if (portIndex >= 0) config.rules[portIndex] = 'DST-PORT,5228-5230,FCM';
      const directIndex = config.rules.indexOf('RULE-SET,proxy@direct,直接连接');
      if (directIndex < 0) throw new Error('Missing direct exception rule for FCM insertion');
      config.rules.splice(directIndex, 0, domainRule);
    } else appRules.push(domainRule);
    if (app.ip) {
      addProvider(app.ip);
      ipRules.push('SUB-RULE,(RULE-SET,' + app.ip + ',no-resolve),' + subRule);
    }
    if (app.baseIp) {
      const index = config.rules.findIndex(rule => rule.startsWith('SUB-RULE,(RULE-SET,' + app.baseIp + ')'));
      if (index < 0) throw new Error('Missing application IP rule: ' + app.baseIp);
      config.rules[index] = 'SUB-RULE,(RULE-SET,' + app.baseIp + '),' + subRule;
    }
  }
  const appIndex = config.rules.indexOf('SUB-RULE,(RULE-SET,download),sub-download');
  if (appIndex < 0) throw new Error('Missing aggregate download rule for application insertion');
  config.rules.splice(appIndex, 0, ...appRules);
  const ipIndex = config.rules.findIndex(rule => rule.startsWith('SUB-RULE,(RULE-SET,safe_ip)'));
  if (ipIndex < 0) throw new Error('Missing aggregate IP rules for application insertion');
  config.rules.splice(ipIndex, 0, ...ipRules);
  const global = groups.find(group => group.name === 'GLOBAL');
  if (global) global.proxies = [...new Set([...global.proxies, ...enabled.map(app => app.name)])];
  return enabled;
}

// Resolve application domains through their selected exit, after personal and AI exceptions.
function configureApplicationDns(config, enabled, followServices) {
  if (!enabled.length) return;
  const dns = config.dns;
  const fcm = enabled.filter(app => app.name === 'FCM');
  const other = enabled.filter(app => app.name !== 'FCM');
  const filters = dns['fake-ip-filter'];
  const fcmIndex = filters.indexOf('RULE-SET,proxy@direct,real-ip');
  const appIndex = filters.indexOf('RULE-SET,download,fake-ip');
  if (fcmIndex < 0 || appIndex < 0) throw new Error('Missing DNS classification for application insertion');
  filters.splice(appIndex, 0, ...other.map(app => 'RULE-SET,' + app.domain + ',fake-ip'));
  filters.splice(fcmIndex, 0, ...fcm.map(app => 'RULE-SET,' + app.domain + ',real-ip'));
  if (!followServices) return;
  const policies = {};
  const insert = apps => {
    for (const app of apps) {
      const resolvers = app.name === 'FCM' ? dns['direct-nameserver'] : dns.nameserver;
      policies['rule-set:' + app.domain] = resolvers.map(address => personalDnsThroughGroup(address, app.name));
    }
  };
  let appsInserted = false;
  for (const [key, value] of Object.entries(dns['nameserver-policy'])) {
    if (key === 'rule-set:proxy@direct') insert(fcm);
    if (key.startsWith('rule-set:') && key.slice(9).split(',').includes('download')) {
      const names = key.slice(9).split(',');
      if (names.includes('ai')) policies['rule-set:ai'] = value;
      insert(other);
      appsInserted = true;
      const remaining = names.filter(name => name !== 'ai');
      if (remaining.length) policies['rule-set:' + remaining.join(',')] = value;
    } else policies[key] = value;
  }
  if (!appsInserted) throw new Error('Missing aggregate DNS policy for application insertion');
  dns['nameserver-policy'] = policies;
}
