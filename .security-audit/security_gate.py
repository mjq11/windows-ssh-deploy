#!/usr/bin/env python3
"""Bind a Cloudflare security-audit report to the Git index or a commit."""
import argparse
import hashlib
import json
import re
import os
import stat
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_ROOT = ROOT
STATE = '.security-audit/attestation.json'
SIGNATURE = '.security-audit/attestation.sig'
PUBLIC_KEY = '.security-audit/attestation-public.pem'
CONFIG = '.security-audit/config.json'
LEVELS = ['informational', 'low', 'medium', 'high', 'critical']


def git(*args, binary=False):
    p = subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.decode(errors='replace').strip())
    return p.stdout if binary else p.stdout.decode().strip()


def entries(ref):
    if ref == 'index':
        data = git('ls-files', '--stage', '-z', binary=True)
        parts = data.split(b'\0')
        for part in parts:
            if not part:
                continue
            meta, path = part.split(b'\t', 1)
            mode, oid, stage = meta.split()
            if stage != b'0':
                raise RuntimeError('Unmerged index entries; resolve conflicts first')
            yield mode, oid, path
    else:
        data = git('ls-tree', '-rz', '--full-tree', ref, binary=True)
        for part in data.split(b'\0'):
            if not part:
                continue
            meta, path = part.split(b'\t', 1)
            mode, kind, oid = meta.split()
            if kind in (b'blob', b'commit'):
                yield mode, oid, path


def source_digest(ref):
    h = hashlib.sha256()
    for mode, oid, path in sorted(entries(ref), key=lambda e: e[2]):
        if path in (STATE.encode(), SIGNATURE.encode()):
            continue
        h.update(mode + b' ' + oid + b'\t' + path + b'\0')
    return h.hexdigest()


def read_at(path, ref):
    if ref == 'index':
        return git('show', ':' + path, binary=True)
    return git('show', ref + ':' + path, binary=True)


def policy(ref):
    raw = json.loads(read_at(CONFIG, ref))
    level = raw.get('block_at', 'high')
    if level not in LEVELS or LEVELS.index(level) > LEVELS.index('high'):
        raise RuntimeError('block_at must be high or stricter')
    return raw, level


def finding_counts(findings):
    counts = {level: 0 for level in LEVELS}
    for item in findings:
        if item['verdict'] == 'confirmed':
            counts[item['severity']['overall_severity']] += 1
    return counts


def check(ref):
    config, level = policy(ref)
    record_bytes = read_at(STATE, ref)
    record = json.loads(record_bytes)
    signature = read_at(SIGNATURE, ref)
    with __import__('tempfile').TemporaryDirectory() as temp:
        signature_path = Path(temp) / 'attestation.sig'
        record_path = Path(temp) / 'attestation.json'
        signature_path.write_bytes(signature)
        record_path.write_bytes(record_bytes)
        verified = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin',
            '-inkey', str(TRUSTED_ROOT / PUBLIC_KEY), '-rawin',
            '-in', str(record_path), '-sigfile', str(signature_path)],
            capture_output=True)
        if verified.returncode:
            raise RuntimeError('Attestation signature is invalid: ' + verified.stderr.decode(errors='replace').strip())
    actual = source_digest(ref)
    if record.get('source_digest') != actual:
        raise RuntimeError('Security audit is stale for this source snapshot')
    if record.get('status') != 'validated' or record.get('profile') == 'quick':
        raise RuntimeError('A validated standard/deep audit is required')
    counts = record.get('confirmed_counts', {})
    if set(counts) != set(LEVELS) or any(type(counts[s]) is not int or counts[s] < 0 for s in LEVELS):
        raise RuntimeError('Malformed confirmed finding counts')
    report_hash = record.get('report_sha256', '')
    if len(report_hash) != 64 or any(c not in '0123456789abcdef' for c in report_hash):
        raise RuntimeError('Malformed report digest')
    blocked = [s for s in LEVELS[LEVELS.index(level):] if counts.get(s, 0)]
    if blocked:
        raise RuntimeError('Blocking confirmed findings: ' + ', '.join(blocked))
    print(f'PASS: attestation {report_hash[:12]} matches {ref}; threshold={level}; findings={counts}')


def attest(report_dir):
    report_dir = Path(report_dir).resolve()
    metadata = json.loads((report_dir / 'run-metadata.json').read_text())
    if Path(metadata['target']).resolve() != ROOT.resolve():
        raise RuntimeError('Report target does not match this repository')
    if metadata.get('run_status') not in ('complete', 'completed'):
        raise RuntimeError('Audit run_status must be complete or completed')
    if metadata.get('profile') not in ('standard', 'deep'):
        raise RuntimeError('A standard or deep audit is required')
    if metadata.get('scope_paths') not in ([], ['.']):
        raise RuntimeError('Scoped audit cannot attest the whole repository')
    if metadata.get('source_ref', {}).get('index_digest') != source_digest('index'):
        raise RuntimeError('Report source snapshot does not match the staged source')
    required = ['REPORT.md', 'FINDINGS-DETAIL.md', 'NEEDS-VALIDATION.md',
                'coverage-ledger.json', 'findings.json']
    for name in required:
        if not (report_dir / name).is_file():
            raise RuntimeError(f'Missing audit artifact: {name}')
    skill = Path.home() / '.codex/skills/security-audit'
    for validator, name in [('validate-findings.cjs', 'findings.json'),
                            ('validate-coverage-ledger.cjs', 'coverage-ledger.json')]:
        subprocess.run(['node', str(skill / validator), str(report_dir / name)], check=True)
    findings_path = report_dir / 'findings.json'
    counts = finding_counts(json.loads(findings_path.read_text()))
    config, level = policy('index')
    if any(counts[s] for s in LEVELS[LEVELS.index(level):]):
        raise RuntimeError('Report contains blocking confirmed findings')
    report_hash = hashlib.sha256()
    for name in ['run-metadata.json', *required]:
        report_hash.update(name.encode() + b'\0')
        report_hash.update((report_dir / name).read_bytes())
    record = {'status': 'validated', 'profile': metadata['profile'],
              'source_digest': source_digest('index'),
              'report_sha256': report_hash.hexdigest(),
              'confirmed_counts': counts,
              'needs_validation_count': sum(x['verdict'] == 'needs_validation' for x in json.loads(findings_path.read_text()))}
    (ROOT / STATE).write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n')
    key_id = config.get('signing_key_id', '')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', key_id):
        raise RuntimeError('Invalid signing_key_id in config.json')
    key = Path.home() / '.codex/security-audit-gate' / (key_id + '.pem')
    if not key.is_file():
        raise RuntimeError(f'Missing local signing key: {key}')
    key_stat = key.lstat()
    if not stat.S_ISREG(key_stat.st_mode) or key_stat.st_uid != os.getuid() or key_stat.st_mode & 0o077:
        raise RuntimeError('Signing key must be owner-owned regular file with owner-only permissions')
    signed = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(key),
        '-rawin', '-in', str(ROOT / STATE), '-out', str(ROOT / SIGNATURE)],
        capture_output=True)
    if signed.returncode:
        raise RuntimeError('Could not sign audit attestation')
    git('add', '--', STATE, SIGNATURE)
    check('index')


def main():
    global ROOT, TRUSTED_ROOT
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    a = sub.add_parser('attest'); a.add_argument('report_dir')
    c = sub.add_parser('check'); c.add_argument('--ref', default='index'); c.add_argument('--repo'); c.add_argument('--trusted-root')
    d = sub.add_parser('digest'); d.add_argument('--ref', default='index')
    args = parser.parse_args()
    try:
        if args.action == 'attest':
            attest(args.report_dir)
        elif args.action == 'digest':
            print(source_digest(args.ref))
        else:
            if args.repo:
                ROOT = Path(args.repo).resolve()
            if args.trusted_root:
                TRUSTED_ROOT = Path(args.trusted_root).resolve()
            check(args.ref)
    except (RuntimeError, KeyError, ValueError, FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f'BLOCK: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
