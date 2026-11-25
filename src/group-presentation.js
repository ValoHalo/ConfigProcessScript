function personalGroupIcons() {
  const qure = name => 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/' + name + '.png';
  const lige = name => 'https://fastly.jsdelivr.net/gh/lige47/QuanX-icon-rule@main/icon/' + name + '.png';
  return Object.assign(Object.create(null), {
    '代理连接': qure('Proxy'),
    '直接连接': qure('Direct'),
    '代理DNS': qure('Server'),
    'AI': qure('ChatGPT'),
    'GOOGLE': qure('Google_Search'),
    'TELEGRAM': qure('Telegram'),
    'Discord': qure('Discord'),
    'Twitter': qure('Twitter'),
    'PikPak': lige('03CNSoft/pikpak'),
    'EHentai': lige('04ProxySoft/exhentai'),
    'DLsite': 'https://www.dlsite.com/modpub/images/web/common/apple_touch_icon_152x152.png',
    'FCM': 'https://fastly.jsdelivr.net/gh/MiToverG422/Qure@master/IconSet/Color/fcm.png',
    'Media': qure('ForeignMedia'),
    '最低延迟': qure('Auto'),
    '故障转移': qure('Available'),
    'GLOBAL': qure('Global'),
  });
}

// Bettbox reads this metadata when rendering the script's custom switches.
const serviceConfigs = Object.entries(ruleOptionsEnable).map(([name]) => {
  const aliases = { AI固定出口: 'AI', DNS跟随服务: '代理DNS' };
  const icons = personalGroupIcons();
  return { name, icon: icons[aliases[name] || name] };
});

// Group menus and icons follow the service order, then region/multiplier, then utility groups.
function configureGroupPresentation(config, nodeGroups) {
  const qure = name => 'https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/' + name + '.png';
  const lige = name => 'https://fastly.jsdelivr.net/gh/lige47/QuanX-icon-rule@main/icon/' + name + '.png';
  const icons = personalGroupIcons();
  const regionIcons = Object.assign(Object.create(null), {
    '香港': qure('Hong_Kong'),
    '日本': qure('Japan'),
    '美国': qure('United_States'),
    '新加坡': qure('Singapore'),
    '台湾': qure('Taiwan'),
    '德国': qure('Germany'),
    '英国': qure('United_Kingdom'),
    '荷兰': lige('01Country/Netherlands'),
  });
  const order = [
    '代理连接', 'AI', 'TELEGRAM', 'Discord', 'Twitter',
    'DLsite', 'EHentai', 'Media', 'GOOGLE', 'PikPak', 'FCM',
  ];
  const trailingVisible = ['直接连接', '代理DNS'];
  const hiddenLast = ['最低延迟', '故障转移', 'GLOBAL'];
  const groups = config['proxy-groups'];
  const byName = new Map(groups.map(group => [group.name, group]));
  const buckets = nodeGroups.buckets || [];
  const bucketNames = new Set(buckets.flatMap(bucket => [bucket.parent, ...bucket.children]));

  // Keep additional services before the node menus without guessing from names.
  for (const group of groups) {
    if (!order.includes(group.name) && !bucketNames.has(group.name) && !trailingVisible.includes(group.name) && !hiddenLast.includes(group.name)) {
      order.push(group.name);
    }
    if (icons[group.name]) group.icon = icons[group.name];
    else if (!group.icon) group.icon = qure('Stack');
  }
  for (const kind of ['region', 'other', 'multiplier']) {
    for (const bucket of buckets.filter(item => item.kind === kind)) {
      order.push(bucket.parent, ...bucket.children);
      const parent = byName.get(bucket.parent);
      if (parent) parent.icon = bucket.kind === 'region'
        ? regionIcons[bucket.label] || qure('World_Map')
        : bucket.kind === 'other' ? qure('World_Map')
          : qure(bucket.label === '低倍率节点' ? 'Available_1' : 'Airport');
      for (const name of bucket.children) {
        const child = byName.get(name);
        if (child) {
          child.hidden = true;
          child.icon = qure('Auto');
        }
      }
    }
  }
  order.push(...trailingVisible, ...hiddenLast);
  for (const name of hiddenLast) if (byName.has(name)) byName.get(name).hidden = true;
  const rank = new Map(order.map((name, index) => [name, index]));
  const compare = (left, right) => (rank.get(left) ?? order.length) - (rank.get(right) ?? order.length);
  groups.sort((left, right) => compare(left.name, right.name));
  const global = byName.get('GLOBAL');
  if (Array.isArray(global?.proxies)) {
    // Reordering the menu must not silently change its initial selected route.
    if (global['default-selected'] === undefined && global.proxies.length) global['default-selected'] = global.proxies[0];
    global.proxies.sort(compare);
  }
  return config;
}
