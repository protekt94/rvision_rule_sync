import argparse
import json
import shutil
import tempfile
import uuid
from collections import Counter
from pathlib import Path
from .archive import extract, index
from .core import SyncError, blocks, compare, digest, dump, read
from .direct import direct_compare, block_diff, fenced, region_markdown


def source_index(source, scratch, prefix, allow_empty=False):
    source = Path(source)
    if not source.exists():
        raise SyncError(f'Source does not exist: {source}')
    if source.is_file() and source.suffix.lower() != '.ro':
        source = extract(source, scratch)
    result = index(source, prefix)
    if not result and not allow_empty:
        raise SyncError(f'No {prefix} rules found in {source}')
    return result


def bootstrap(workspace, base, custom, verified=False):
    workspace = Path(workspace)
    if workspace.exists():
        raise SyncError('Bootstrap destination already exists; choose a new workspace')
    workspace.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=workspace.parent) as temporary:
        temp = Path(temporary)
        vendor = source_index(base, temp / 'vendor', 'RV-')
        ours = source_index(custom, temp / 'custom-source', 'VI-')
        staged = temp / 'workspace'
        for folder in ('custom', 'base'):
            (staged / folder).mkdir(parents=True)
        state = {'schema': 1, 'rules': {}}
        for cid, (path, rule) in ours.items():
            uid = 'RV-' + cid[3:]
            if uid not in vendor:
                raise SyncError(f'Baseline missing: {uid}')
            base_path, baseline = vendor[uid]
            shutil.copyfile(path, staged / 'custom' / f'{cid}.ro')
            shutil.copyfile(base_path, staged / 'base' / f'{uid}.ro')
            state['rules'][cid] = {'upstream_id': uid, 'base_hash': digest(baseline), 'baseline_verified': verified}
        (staged / 'state.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
        staged.rename(workspace)
    return workspace


def report(results, vendor_count):
    counts = Counter(r['status'] for r in results)
    lines = ['# R-Vision rule sync', '', 'test/tests исключены из сравнения и переноса; сохраняются из custom.', '', f'Vendor rules: {vendor_count}; custom rules: {len(results)}', '',
             '| Status | Count |', '|---|---:|']
    for status in ('NO_CHANGE', 'METADATA_ONLY', 'AUTO_MERGE', 'REVIEW_REQUIRED', 'ORPHANED'):
        lines.append(f'| {status} | {counts[status]} |')
    for r in results:
        lines += ['', f"## {r['id']} ← {r['upstream_id']}: {r['status']}", '',
                  'Custom blocks: ' + (', '.join(r['custom']) or 'none'), '',
                  'Vendor blocks: ' + (', '.join(r['vendor']) or 'none'), '',
                  'Conflicts: ' + (', '.join(r['conflicts']) or 'none'), '', r.get('reason', '')]
        if r.get('output'):
            lines += ['', f"Candidate: [{r['output']}]({r['output']})"]
        lines += region_markdown(r)
        for block, comparisons in r.get('diffs', {}).items():
            lines += ['', f'### {block}']
            for label, diff in comparisons.items():
                lines += ['', label, ''] + fenced(diff)
    return '\n'.join(lines) + '\n'


def analyze(workspace, upstream):
    workspace = Path(workspace)
    state = json.loads((workspace / 'state.json').read_text(encoding='utf-8'))
    if state.get('schema') != 1:
        raise SyncError('Unsupported state schema')
    ours = index(workspace / 'custom', 'VI-')
    if not ours:
        raise SyncError('No custom rules')
    runs = workspace / 'runs'
    runs.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=runs) as temporary:
        temp = Path(temporary)
        vendor = source_index(upstream, temp / 'unpacked', 'RV-', allow_empty=True)
        staged = temp / 'result'
        for folder in ('BASE', 'OURS', 'THEIRS', 'generated'):
            (staged / folder).mkdir(parents=True)
        results = []
        for cid, (path, custom) in ours.items():
            uid = 'RV-' + cid[3:]
            entry = state['rules'].get(cid)
            if not entry or entry.get('upstream_id') != uid:
                raise SyncError(f'Bootstrap entry missing or invalid: {cid}')
            baseline = read(workspace / 'base' / f'{uid}.ro')
            if baseline.get('id') != uid or digest(baseline) != entry['base_hash']:
                raise SyncError(f'Baseline integrity check failed: {uid}')
            theirs = vendor.get(uid, (None, None))[1]
            r = compare(baseline, custom, theirs, entry.get('baseline_verified') is True)
            r.update(id=cid, upstream_id=uid)
            for label, rule in [('BASE', baseline), ('OURS', custom), ('THEIRS', theirs)]:
                if rule is not None:
                    (staged / label / f'{rule["id"]}.ro').write_text(dump(rule), encoding='utf-8')
            generated = r.pop('generated')
            if generated is not None:
                r['output'] = f'generated/{cid}.ro'
                (staged / r['output']).write_text(dump(generated), encoding='utf-8')
            r['diffs'] = {key: {f'BASE → {label}': block_diff(blocks(baseline), blocks(rule), key, 'BASE', label)
                for label, rule in [('OURS', custom), ('THEIRS', theirs)] if rule is not None}
                for key in sorted(set(r['custom']) | set(r['vendor']))}
            results.append(r)
        (staged / 'report.md').write_text(report(results, len(vendor)), encoding='utf-8')
        (staged / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
        destination = runs / uuid.uuid4().hex
        staged.rename(destination)
    return destination, results


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline R-Vision rule comparison and synchronization')
    commands = parser.add_subparsers(dest='command', required=True)
    direct = commands.add_parser('compare', help='Compare custom/ with SIEM/*.roc; no bootstrap required')
    direct.add_argument('--custom', type=Path, default=Path('custom'))
    direct.add_argument('--output', type=Path, default=Path('reports'))
    direct.add_argument('packages', nargs='*', default=['SIEM'], help='Files, directories or quoted .roc globs')
    boot = commands.add_parser('bootstrap')
    boot.add_argument('--workspace', required=True, type=Path)
    boot.add_argument('--base', required=True, type=Path)
    boot.add_argument('--custom', required=True, type=Path)
    boot.add_argument('--baseline-verified', action='store_true')
    analysis = commands.add_parser('analyze')
    analysis.add_argument('--workspace', required=True, type=Path)
    analysis.add_argument('upstream', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'bootstrap':
            print(bootstrap(args.workspace, args.base, args.custom, args.baseline_verified))
            return 0
        if args.command == 'compare':
            destination, results = direct_compare(args.custom, args.packages, args.output)
        else:
            destination, results = analyze(args.workspace, args.upstream)
        print(destination / 'report.md')
        print(dict(Counter(r['status'] for r in results)))
        return 2 if any(r['status'] in ('REVIEW_REQUIRED', 'ORPHANED') for r in results) else 0
    except (SyncError, OSError, ValueError) as exc:
        parser.exit(1, f'Error: {exc}\n')
