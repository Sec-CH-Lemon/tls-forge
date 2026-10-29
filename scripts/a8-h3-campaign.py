#!/usr/bin/env python3
"""Collect paired native H3 cohorts. This producer does not grant acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time
from urllib.request import Request, urlopen


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def stats(address):
    with urlopen(address + '/stats', timeout=10) as source:
        return json.load(source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chrome', type=Path, required=True)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--scenario', type=Path, default=Path('scripts/a8-h3-scenario.json'))
    parser.add_argument('--installers', type=Path, default=Path('verification/chrome156-installers.json'))
    parser.add_argument('--samples', type=int)
    parser.add_argument('--browser-arg', action='append', default=[])
    args = parser.parse_args()
    scenario = json.loads(args.scenario.read_text())
    count = args.samples if args.samples is not None else scenario['connections_per_cohort']
    if not 1 <= count <= 4096 or scenario['cohorts_per_actor'] != 2:
        raise ValueError('invalid bounded cohort specification')
    for request in scenario['requests']:
        if not request['path'].startswith('/') or request['path'].startswith('//'):
            raise ValueError('scenario paths must stay on the owned origin')
    if args.out.exists() and any(args.out.iterdir()):
        raise ValueError('refusing to replace original evidence in nonempty output directory')
    args.out.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(args.out, 0o700)
    source_root = Path(__file__).resolve().parent.parent
    actor_profile = args.out / 'candidate-profile.json'
    shutil.copy2(args.profile, actor_profile)
    shutil.copy2(args.scenario, args.out / 'scenario.json')
    subprocess.run([str(args.peer), '-mode', 'validate', '-profile', str(actor_profile), '-scenario', str(args.scenario)], check=True)
    system = {'Darwin': 'macOS', 'Linux': 'Linux', 'Windows': 'Windows'}[platform.system()]
    expected = json.loads(args.installers.read_text())['platforms'][system]['version']
    identity = {
        'platform': platform.platform(), 'machine': platform.machine(),
        'expected_browser': expected, 'profile_sha256': sha(actor_profile),
        'peer_sha256': sha(args.peer), 'chrome_launcher_sha256': sha(args.chrome),
        'scenario_sha256': sha(args.scenario),
        'environment_limits': {key: value for key, value in os.environ.items() if key in ['GODEBUG', 'QUIC_GO_DISABLE_ECN', 'QUIC_GO_DISABLE_GSO', 'QUIC_GO_DISABLE_CLIENT_HELLO_SCRAMBLING']},
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source_root, text=True).strip(),
        'source_files': {str(path.relative_to(source_root)): sha(path) for path in [source_root / 'scripts' / name for name in ['a8-h3-peer.go', 'a8-h3-chrome.mjs', 'a8-h3-campaign.py', 'a8-h3-scenario.json', 'a8-h3-analyze.py']]},
        'node': subprocess.check_output(['node', '--version'], text=True).strip(),
        'producer_only': True, 'acceptance': 'pending independent packet/QPACK/negative-control analysis',
    }
    (args.out / 'identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    results = []
    log = (args.out / 'peer.log').open('w')
    peer = subprocess.Popen([str(args.peer), '-mode', 'server', '-out', str(args.out), '-scenario', str(args.scenario)], stdout=log, stderr=log)
    address = None
    try:
        for _ in range(200):
            if (args.out / 'address.json').exists():
                break
            if peer.poll() is not None:
                raise RuntimeError('observation peer exited before binding')
            time.sleep(0.05)
        config = json.loads((args.out / 'address.json').read_text())
        address = config['api']
        config['expected_version'] = expected
        groups = [(actor, cohort, 0, count, 'natural') for actor in ['chrome', 'client'] for cohort in [1, 2]]
        groups += [(actor, cohort, delay, scenario['controlled_connections_per_cohort'], 'controlled-settings') for delay in scenario['controlled_settings_delays'] for actor in ['chrome', 'client'] for cohort in [1, 2]]
        for actor, cohort, delay, group_count, role in groups:
            directory = args.out / (f'{actor}-{role}{delay}-{cohort}')
            directory.mkdir()
            (directory / 'address.json').write_text(json.dumps(config))
            shutil.copy2(args.scenario, directory / 'scenario.json')
            with urlopen(Request(address + '/settings-delay', data=json.dumps({'requests': delay}).encode(), headers={'Content-Type':'application/json'}, method='POST'), timeout=5):
                pass
            offset = len(stats(address)['connections'] or [])
            if actor == 'chrome':
                command = ['node', str(source_root / 'scripts/a8-h3-chrome.mjs'), str(args.chrome), str(directory), str(group_count), *args.browser_arg]
            else:
                command = [str(args.peer), '-mode', 'client', '-out', str(directory), '-scenario', str(args.scenario), '-profile', str(actor_profile), '-samples', str(group_count)]
            with (directory / 'actor.log').open('w') as output:
                result = subprocess.run(command, stdout=output, stderr=output, timeout=1800)
            observed = stats(address)
            (directory / 'stats.json').write_text(json.dumps(observed, indent=2) + '\n')
            record = {'actor': actor, 'cohort': cohort, 'role': role, 'settings_after_requests':delay, 'exit_code': result.returncode, 'first_connection': offset + 1, 'last_connection': len(observed['connections'] or []), 'samples': group_count}
            results.append(record)
            (args.out / 'campaign.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps(record), flush=True)
            if result.returncode or record['last_connection'] - offset != group_count:
                raise RuntimeError('actor failed or connection cardinality differs')
    finally:
        if address is not None:
            try:
                with urlopen(Request(address + '/finish', method='POST'), timeout=5):
                    pass
            except OSError:
                # The exit code and immutable output below still have to pass.
                pass
        else:
            peer.terminate()
        try:
            peer.wait(timeout=15)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait()
        log.close()
        identity['peer_exit_code'] = peer.returncode
        identity['complete_cohorts'] = len(results)
        identity['observation_sha256'] = sha(args.out / 'observations.json') if (args.out / 'observations.json').exists() else None
        (args.out / 'identity.json').write_text(json.dumps(identity, indent=2) + '\n')
        if peer.returncode != 0 or identity['observation_sha256'] is None:
            raise RuntimeError('peer did not preserve a complete final observation')


if __name__ == '__main__':
    main()
