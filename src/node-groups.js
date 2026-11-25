// Dynamic region and multiplier menus, based on the nodes actually imported.
function personalNodeRate(name) {
  const match = name.match(
    /(?:^|[^\dA-Za-z.])(\d+(?:\.\d+)?)\s*[*×✕✖⨯⨉x倍](?=$|[^\dA-Za-z.])|(?:[*×✕✖⨯⨉]|(?<![A-Za-z])x)\s*(\d+(?:\.\d+)?)(?=$|[^\dA-Za-z.])/i,
  );
  if (match) return Number(match[1] === undefined ? match[2] : match[1]);
  const labelled = name.match(/(?:倍率|[低高]倍)\s*[:：=]?\s*(\d+(?:\.\d+)?)(?=$|[^\dA-Za-z.])/i);
  return labelled ? Number(labelled[1]) : null;
}

function personalNodeFilter(names) {
  return '^(?:' + names.map(name => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')$';
}

function configurePersonalNodeGroups(config, reservedGroupNames = []) {
  const definitions = [
    ['香港', /🇭🇰|香港|(?<![A-Za-z])HKG?(?![A-Za-z])|hong\s*kong/i],
    ['日本', /🇯🇵|日本|东京|大阪|京都|(?<![A-Za-z])JPN?(?![A-Za-z])|japan/i],
    ['美国', /🇺🇸|美国|纽约|洛杉矶|旧金山|芝加哥|休斯顿|迈阿密|西雅图|波士顿|华盛顿|拉斯维加斯|圣何塞|圣地亚哥|(?<![A-Za-z])USA?(?![A-Za-z])|america|united\s*states/i],
    ['新加坡', /🇸🇬|新加坡|狮城|(?<![A-Za-z])SGP?(?![A-Za-z])|singapore/i],
    ['台湾', /🇹🇼|台湾|台北|高雄|(?<![A-Za-z])TWN?(?![A-Za-z])|taiwan/i],
    ['德国', /🇩🇪|德国|法兰克福|(?<![A-Za-z])DEU?(?![A-Za-z])|germany/i],
    ['英国', /🇬🇧|英国|伦敦|(?<![A-Za-z])(?:UK|GBR?)(?![A-Za-z])|united\s*kingdom/i],
    ['荷兰', /🇳🇱|荷兰|阿姆斯特丹|(?<![A-Za-z])NLD?(?![A-Za-z])|netherlands?/i],
  ];
  const provider = config['proxy-providers']?.['节点'];
  if (!Array.isArray(provider?.payload)) throw new Error('基础配置缺少节点提供器，无法生成动态分组');
  const excluded = provider['exclude-filter'] ? new RegExp(provider['exclude-filter'].replace(/^\(\?i\)/, ''), 'i') : null;
  const nodes = provider.payload.filter(proxy => typeof proxy.name === 'string' &&
    !['direct', 'reject', 'reject-drop', 'pass', 'dns'].includes(String(proxy.type).toLowerCase()) &&
    !(excluded && excluded.test(proxy.name)));
  const regions = Object.create(null);
  for (const [name, pattern] of definitions) regions[name] = [...new Set(nodes.filter(proxy => pattern.test(proxy.name)).map(proxy => proxy.name))];
  const recognized = new Set(Object.values(regions).flat());
  const other = [...new Set(nodes.filter(proxy => !recognized.has(proxy.name)).map(proxy => proxy.name))];
  const low = [], high = [];
  for (const proxy of nodes) {
    const rate = personalNodeRate(proxy.name);
    if (rate !== null ? rate <= 0.5 : /低倍|免费|(?<![A-Za-z])free(?![A-Za-z])/i.test(proxy.name)) low.push(proxy.name);
    if (rate !== null && rate >= 2) high.push(proxy.name);
  }
  const original = config['proxy-groups'];
  const reserved = new Set([
    ...original.map(group => group.name),
    ...(config.proxies || []).map(proxy => proxy.name),
    ...Object.values(config['proxy-providers']).flatMap(entry => (entry.payload || []).map(proxy => proxy.name)),
    'DLsite', 'DIRECT', 'REJECT', 'PASS-RULE',
    ...reservedGroupNames,
  ]);
  const allocate = name => {
    let result = name;
    for (let suffix = 1; reserved.has(result); suffix++) result = name + '（分组' + (suffix === 1 ? '' : suffix) + '）';
    reserved.add(result);
    return result;
  };
  const automatic = original.find(group => group.name === '最低延迟');
  if (!automatic) throw new Error('基础配置缺少最低延迟模板');
  const health = provider['health-check'] || {};
  const generated = [], parents = [], buckets = [], regionGroups = Object.create(null);
  function createBucket(label, names, kind) {
    names = [...new Set(names)];
    if (!names.length) return null;
    const parent = allocate(label), auto = allocate(parent + '|最低延迟');
    const common = { use: ['节点'], filter: personalNodeFilter(names), 'empty-fallback': 'REJECT', hidden: true };
    const autoGroup = { ...automatic, ...common, name: auto };
    delete autoGroup['include-all-providers'];
    delete autoGroup['include-all'];
    delete autoGroup.proxies;
    for (const field of ['url', 'interval', 'timeout', 'expected-status', 'lazy', 'max-failed-times']) {
      if (health[field] !== undefined) autoGroup[field] = health[field];
    }
    generated.push({ name: parent, type: 'select', proxies: [auto], use: ['节点'], filter: personalNodeFilter([auto, ...names]), 'default-selected': auto }, autoGroup);
    parents.push(parent);
    buckets.push({ kind, label, parent, children: [auto] });
    return parent;
  }
  for (const [region] of definitions) {
    const parent = createBucket(region, regions[region], 'region');
    if (parent) regionGroups[region] = parent;
  }
  createBucket('其他节点', other, 'other');
  createBucket('低倍率节点', low, 'multiplier');
  createBucket('高倍率节点', high, 'multiplier');
  for (const group of original) {
    if (!Array.isArray(group.proxies)) continue;
    const anchor = group.proxies.indexOf('故障转移');
    if (anchor < 0) continue;
    group.proxies = [...new Set([...group.proxies.slice(0, anchor + 1), ...parents, ...group.proxies.slice(anchor + 1)])];
  }
  config['proxy-groups'] = [...original, ...generated];
  return { regions, regionGroups, buckets };
}
