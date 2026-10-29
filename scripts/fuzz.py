#!/usr/bin/env python3
"""Discover every Go fuzz target; run one with explicit finite budgets."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


def discover():
    run = subprocess.run(['go', 'test', '-json', '-list', '^Fuzz', './...'], capture_output=True, text=True, timeout=180)
    if run.returncode:
        raise RuntimeError('fuzz discovery failed; compile the clean source tree first')
    targets = set()
    for line in run.stdout.splitlines():
        event = json.loads(line)
        name = event.get('Output', '').strip()
        if re.fullmatch(r'Fuzz[A-Za-z0-9_]+', name):
            targets.add((event['Package'], name))
    if not targets:
        raise RuntimeError('no fuzz targets discovered')
    return [{'package': package, 'target': target} for package, target in sorted(targets)]


def run_target(args, targets):
    selected = {'package': args.package, 'target': args.target}
    if selected not in targets:
        raise ValueError('package/target is not a discovered fuzz target')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cache = args.output.resolve() / 'cache'
    command = ['go', 'test', '-run', '^$', '-fuzz', '^' + args.target + '$',
               '-fuzztime=' + str(args.seconds) + 's', '-fuzzminimizetime=1s',
               '-parallel=2', '-timeout=' + str(args.seconds + 120) + 's',
               '-count=1', args.package, '-test.fuzzcachedir=' + str(cache)]
    start = time.monotonic()
    with (args.output / 'run.log').open('w') as log:
        try:
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=args.seconds + 150)
            code = process.returncode
        except subprocess.TimeoutExpired:
            code = 124
    text = (args.output / 'run.log').read_text(errors='replace')
    counts = [int(n) for n in re.findall(r'execs: (\d+)', text)]
    # Preserve both generated interesting inputs and failing, minimized inputs.
    package = subprocess.check_output(['go', 'list', '-f', '{{.Dir}}', args.package], text=True).strip()
    corpus = Path(package) / 'testdata' / 'fuzz' / args.target
    if corpus.exists():
        shutil.copytree(corpus, args.output / 'corpus')
    result = dict(selected, command=command, returncode=code, executions=max(counts, default=0),
                  seconds=round(time.monotonic() - start, 3),
                  go=subprocess.check_output(['go', 'version'], text=True).strip(),
                  gowork=subprocess.check_output(['go', 'env', 'GOWORK'], text=True).strip(),
                  corpus_files=sum(1 for p in args.output.rglob('*') if p.is_file() and p.name not in ('run.log', 'result.json')))
    if code == 0 and result['executions'] == 0:
        result['returncode'] = code = 1
        result['error'] = 'no fuzz executions recorded'
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true', help='emit the complete discovered CI matrix')
    parser.add_argument('--package')
    parser.add_argument('--target')
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--output', type=Path, help='new private directory for logs, corpus, cache and summary')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error('--seconds must be between1 and300')
    if not args.list and not (args.package and args.target and args.output):
        parser.error('provide --list or --package, --target and --output')
    os.umask(0o077)
    targets = discover()
    if args.list:
        print(json.dumps({'include': targets}))
        return 0
    return run_target(args, targets)


if __name__ == '__main__':
    sys.exit(main())
