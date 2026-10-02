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
  const oldRegional = new Set(original.filter(group => /\|(?:故障转移|轮询下载)$/.test(group.name)).map(group => group.name));
  const remaining = original.filter(group => !oldRegional.has(group.name));
  const reserved = new Set([
    ...remaining.map(group => group.name),
    ...(config.proxies || []).map(proxy => proxy.name),
    ...Object.values(config['proxy-providers']).flatMap(entry => (entry.payload || []).map(proxy => proxy.name)),
    'OneDrive', 'DLsite', '下载更新', 'DIRECT', 'REJECT', 'PASS-RULE',
    ...reservedGroupNames,
  ]);
  const allocate = name => {
    let result = name;
    for (let suffix = 1; reserved.has(result); suffix++) result = name + '（分组' + (suffix === 1 ? '' : suffix) + '）';
    reserved.add(result);
    return result;
  };
  const automatic = original.find(group => group.name === '最低延迟');
  const balance = original.find(group => group.type === 'load-balance');
  if (!automatic || !balance) throw new Error('基础配置缺少最低延迟或负载均衡模板');
  const health = provider['health-check'] || {};
  const generated = [], parents = [], regionGroups = Object.create(null);
  const references = Object.create(null);
  function createBucket(label, names, icon) {
    names = [...new Set(names)];
    if (!names.length) return null;
    const parent = allocate(label), auto = allocate(parent + '|最低延迟'), load = allocate(parent + '|负载均衡');
    const common = { use: ['节点'], filter: personalNodeFilter(names), 'empty-fallback': 'REJECT', hidden: true };
    const autoGroup = { ...automatic, ...common, name: auto };
    const loadGroup = { ...balance, ...common, name: load };
    for (const child of [autoGroup, loadGroup]) {
      delete child['include-all-providers']; delete child['include-all']; delete child.proxies;
      for (const field of ['url', 'interval', 'timeout', 'expected-status', 'lazy', 'max-failed-times']) if (health[field] !== undefined) child[field] = health[field];
      if (icon) child.icon = icon;
    }
    generated.push({ name: parent, type: 'select', proxies: [auto, load], use: ['节点'], filter: personalNodeFilter([auto, load, ...names]), 'default-selected': auto, ...(icon ? { icon } : {}) }, autoGroup, loadGroup);
    parents.push(parent);
    return parent;
  }
  for (const [region] of definitions) {
    const old = original.find(group => group.name === region + '|故障转移');
    const parent = createBucket(region, regions[region], old?.icon);
    if (parent) regionGroups[region] = parent;
    references[region + '|故障转移'] = parent;
    references[region + '|轮询下载'] = parent;
  }
  createBucket('低倍率节点', low, automatic.icon);
  createBucket('高倍率节点', high, balance.icon);
  createBucket('其他节点', other, automatic.icon);
  for (const group of remaining) {
    if (!Array.isArray(group.proxies) || !group.proxies.some(name => oldRegional.has(name))) continue;
    const menu = [];
    let inserted = false;
    for (const name of group.proxies) {
      if (oldRegional.has(name)) {
        if (!inserted) { menu.push(...parents); inserted = true; }
      } else menu.push(name);
    }
    group.proxies = [...new Set(menu)];
    if (oldRegional.has(group['default-selected'])) group['default-selected'] = references[group['default-selected']] || group.proxies[0] || 'REJECT';
  }
  config['proxy-groups'] = [...remaining, ...generated];
  return { regions, regionGroups, references };
}
