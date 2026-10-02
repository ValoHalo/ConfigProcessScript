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
    }
    appRules.push(domainRule);
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
  const appIndex = config.rules.indexOf('SUB-RULE,(RULE-SET,google),sub-google');
  if (appIndex < 0) throw new Error('Missing Google rule for application insertion');
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
  const dns = config.dns;
  const filters = dns['fake-ip-filter'];
  const appIndex = filters.indexOf('RULE-SET,google,fake-ip');
  if (appIndex < 0) throw new Error('Missing Google DNS classification for application insertion');
  filters.splice(appIndex, 0, ...enabled.map(app => 'RULE-SET,' + app.domain + ',' + (app.name === 'FCM' ? 'real-ip' : 'fake-ip')));
  if (!followServices) return;
  const policies = {};
  const through = (resolvers, group) => resolvers.map(address => personalDnsThroughGroup(address, group));
  let appsInserted = false;
  for (const [key, value] of Object.entries(dns['nameserver-policy'])) {
    if (key === 'rule-set:google') {
      for (const app of enabled) {
        const resolvers = app.name === 'FCM' ? dns['direct-nameserver'] : dns.nameserver;
        policies['rule-set:' + app.domain] = through(resolvers, app.name);
      }
      appsInserted = true;
      policies[key] = through(dns.nameserver, 'GOOGLE');
    } else if (key === 'rule-set:media') {
      policies[key] = through(dns.nameserver, '海外媒体');
    } else policies[key] = value;
  }
  if (!appsInserted) throw new Error('Missing Google DNS policy for application insertion');
  dns['nameserver-policy'] = policies;
}
