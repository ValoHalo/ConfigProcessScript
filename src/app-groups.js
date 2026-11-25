// Application selectors take priority over broad media and fallback categories.
function appDomainSets(app) {
  return Array.isArray(app.extraDomains) && app.extraDomains.length ? [app.domain, app.domain + '-extra'] : [app.domain];
}

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
    appRules.push('RULE-SET,' + app.domain + ',' + app.name);
    if (Array.isArray(app.extraDomains) && app.extraDomains.length) {
      const extraId = app.domain + '-extra';
      config['rule-providers'][extraId] = { type: 'inline', behavior: 'domain', payload: [...app.extraDomains] };
      appRules.push('RULE-SET,' + extraId + ',' + app.name);
    }
    if (app.name === 'FCM') {
      const portIndex = config.rules.indexOf('DST-PORT,5228-5230,直接连接');
      if (portIndex >= 0) config.rules[portIndex] = 'DST-PORT,5228-5230,FCM';
    }
    if (app.ip) {
      addProvider(app.ip);
      ipRules.push('RULE-SET,' + app.ip + ',' + app.name + ',no-resolve');
    }
    if (app.baseIp) {
      addProvider(app.baseIp);
      ipRules.push('RULE-SET,' + app.baseIp + ',' + app.name);
    }
  }
  const appIndex = config.rules.indexOf('RULE-SET,proxy@direct,直接连接');
  if (appIndex < 0) throw new Error('Missing direct exceptions for application insertion');
  config.rules.splice(appIndex, 0, ...appRules);
  const ipIndex = config.rules.indexOf('RULE-SET,media_ip,Media');
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
  const appIndex = filters.indexOf('RULE-SET,proxy@direct,real-ip');
  if (appIndex < 0) throw new Error('Missing direct DNS classification for application insertion');
  filters.splice(appIndex, 0, ...enabled.flatMap(app => appDomainSets(app).map(id => 'RULE-SET,' + id + ',' + (app.name === 'FCM' ? 'real-ip' : 'fake-ip'))));
  if (!followServices) return;
  const policies = {};
  const through = (resolvers, group) => resolvers.map(address => personalDnsThroughGroup(address, group));
  let appsInserted = false;
  for (const [key, value] of Object.entries(dns['nameserver-policy'])) {
    if (key === 'rule-set:proxy@direct') {
      for (const app of enabled) {
        const resolvers = app.name === 'FCM' ? dns['direct-nameserver'] : dns.nameserver;
        for (const id of appDomainSets(app)) policies['rule-set:' + id] = through(resolvers, app.name);
      }
      appsInserted = true;
      policies[key] = value;
    } else if (key === 'rule-set:google') {
      policies[key] = through(dns.nameserver, 'GOOGLE');
    } else if (key === 'rule-set:media') {
      policies[key] = through(dns.nameserver, 'Media');
    } else policies[key] = value;
  }
  if (!appsInserted) throw new Error('Missing direct DNS policy for application insertion');
  dns['nameserver-policy'] = policies;
}
