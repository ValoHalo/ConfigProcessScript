"""Refresh the Echsfxy source snapshot. Publication is gated by the CI checks."""
import argparse
import hashlib
import json
import pathlib
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proxy')
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {'http': args.proxy, 'https': args.proxy} if args.proxy else {}))

    def fetch(url):
        request = urllib.request.Request(url, headers={'User-Agent': 'ConfigProcessScript-maintenance'})
        with opener.open(request, timeout=30) as response:
            body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise RuntimeError('Upstream response too large')
        return body

    repository = 'echs-top/proxy'
    commit = json.loads(fetch('https://api.github.com/repos/' + repository + '/commits/main'))['sha']
    if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise RuntimeError('Invalid upstream commit')
    url = 'https://raw.githubusercontent.com/' + repository + '/' + commit + '/mihomo.js'
    script = fetch(url)
    if b'function main(config)' not in script or len(script) < 1000:
        raise RuntimeError('Unexpected upstream script format')
    target = root / 'vendor/echsfxy/mihomo.js'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(script)
    lock = {'repository': repository, 'commit': commit, 'files': {'mihomo.js': {'url': url, 'sha256': hashlib.sha256(script).hexdigest()}}}
    (root / 'config/upstream.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')
    print('Echsfxy snapshot: ' + commit)


if __name__ == '__main__':
    main()
