"""Run isolated, read-only native login checks for explicitly listed accounts.

Manifest: {"accounts": [{"name": "demo-a", "config_path": "a.env",
"profile_path": "a-profile.json", "address": "broker-host:701"}]}
Paths are relative to the manifest. Credentials are passed only in each child
process's environment. Reports omit passwords, profiles and account numbers.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import time


def environment(row, base):
    config = {}
    for line in (base / row['config_path']).read_text(encoding='utf-8-sig').splitlines():
        if '=' not in line or line.lstrip().startswith('#'):
            continue
        key, value = line.split('=', 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        config[key.strip()] = value
    login = config.get('MT5_LOGIN') or config.get('MT5_ACCOUNT')
    if not login or not login.isdecimal() or not config.get('MT5_PASSWORD') or not config.get('MT5_SERVER'):
        raise ValueError('config requires numeric MT5_LOGIN/MT5_ACCOUNT, MT5_PASSWORD and MT5_SERVER')
    profile = (base / row['profile_path']).resolve(strict=True)
    identity = json.loads(profile.read_text(encoding='utf-8-sig'))['account']
    if identity['login'] != int(login) or identity['server'] != config['MT5_SERVER']:
        raise ValueError('profile does not match the configured login and server')
    # Never inherit another account's credentials, build or probe options.
    env = {key: value for key, value in os.environ.items() if not key.startswith('MT5_')}
    env.update(MT5_LOGIN=login, MT5_PASSWORD=config['MT5_PASSWORD'],
               MT5_ADDRESS=row['address'], MT5_LOGIN_PROFILE=str(profile), MT5_SERVER=config['MT5_SERVER'])
    if 'build' in row:
        env['MT5_BUILD'] = str(int(row['build']))
    return env


def run(executable, row, env, round_number, hold_seconds):
    start = time.monotonic()
    result = dict(name=row['name'], round=round_number, success=False)
    try:
        child = subprocess.run([str(executable), '--json', '--hold-seconds', str(hold_seconds)], env=env,
                               capture_output=True, text=True, timeout=90+hold_seconds)
        report = json.loads(child.stdout)
        result.update(report)
        result['success'] = (child.returncode == 0 and report.get('synchronized') is True
                             and report.get('account_identity_verified') is True
                             and report.get('server_identity_verified') is True)
    except subprocess.TimeoutExpired:
        result['error'] = 'probe exceeded its observation and connection deadline'
    except (OSError, ValueError):
        # Never echo arbitrary child output or credential-file contents.
        result['error'] = 'probe could not run or returned an invalid report'
    result['elapsed_seconds'] = round(time.monotonic() - start, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--parallelism', type=int, default=2)
    parser.add_argument('--hold-seconds', type=int, default=0)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 5 or not 1 <= args.parallelism <= 4:
        parser.error('rounds must be 1..5; parallelism must be 1..4')
    if not 0 <= args.hold_seconds <= 300:
        parser.error('hold-seconds must be 0..300')
    manifest = args.manifest.resolve(strict=True)
    executable = args.executable.resolve(strict=True)
    rows = json.loads(manifest.read_text(encoding='utf-8-sig'))['accounts']
    if not rows or len(rows) > 16 or len({r['name'] for r in rows}) != len(rows):
        parser.error('list 1..16 accounts with unique names')
    prepared = []
    for row in rows:
        try:
            prepared.append((row, environment(row, manifest.parent)))
        except (OSError, ValueError, KeyError):
            parser.error('account configuration is missing or invalid; no probes started')
    results = []
    for round_number in range(1, args.rounds + 1):
        with ThreadPoolExecutor(max_workers=args.parallelism) as pool:
            futures = [pool.submit(run, executable, row, env, round_number, args.hold_seconds) for row, env in prepared]
            for future in futures:
                result = future.result()
                results.append(result)
                print(json.dumps(result), flush=True)
        # Do not retry failed credentials or unsupported profiles automatically.
        if any(not r['success'] for r in results):
            break
    report = dict(accounts=len(rows), rounds_requested=args.rounds, attempts=results,
                  all_passed=all(r['success'] for r in results))
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    raise SystemExit(0 if report['all_passed'] else 1)


if __name__ == '__main__':
    main()
