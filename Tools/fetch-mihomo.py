"""Fetch the pinned rule compiler; verify the archive before extracting it."""
import argparse
import gzip
import hashlib
import io
import json
import pathlib
import platform
import os
import urllib.request
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--proxy', help='Explicit HTTP proxy for this download')
    parser.add_argument('--platform', choices=['windows-amd64', 'linux-x86_64'])
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    lock = json.loads((root / 'config/mihomo-tool.json').read_text(encoding='utf-8'))
    machine = platform.machine() or os.environ.get('PROCESSOR_ARCHITEW6432') or os.environ.get('PROCESSOR_ARCHITECTURE', '')
    key = args.platform or platform.system().lower() + '-' + machine.lower()
    entry = lock['platforms'].get(key)
    if not entry:
        raise SystemExit('No pinned compiler for ' + key + '; pass your own binary to update-rules.js --mihomo')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {'http': args.proxy, 'https': args.proxy} if args.proxy else {}))
    output = pathlib.Path(args.output).resolve()
    archive = output.parent / ('mihomo-' + entry['sha256'] + '.archive')
    if archive.exists() and hashlib.sha256(archive.read_bytes()).hexdigest() == entry['sha256']:
        data = archive.read_bytes()
    else:
        request = urllib.request.Request(entry['url'], headers={'User-Agent': 'ConfigProcessScript-rule-builder'})
        with opener.open(request, timeout=90) as response:
            data = response.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise SystemExit('Compiler archive size or SHA-256 verification failed')
        output.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(data)
    if entry['url'].endswith('.gz'):
        binary = gzip.decompress(data)
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            names = [n for n in bundle.namelist() if n.lower().endswith('.exe')]
            if len(names) != 1:
                raise SystemExit('Expected one compiler executable in verified archive')
            binary = bundle.read(names[0])
    output.write_bytes(binary)
    if platform.system() != 'Windows':
        output.chmod(0o755)
    print('Verified Mihomo ' + lock['version'] + ': ' + str(output))


if __name__ == '__main__':
    main()
