"""Compare current custom rules with each supplied package without a baseline."""
import difflib
import glob
import json
import re
import tempfile
import uuid
from collections import Counter
from pathlib import Path
from .archive import extract, index
from .markers import custom_regions
from .core import SyncError, blocks, changes, digest, dump


def packages(sources):
    found = {}
    for source in sources:
        source = str(source)
        path = Path(source)
        if path.is_dir():
            matches = sorted(path.iterdir())
        elif path.is_file():
            matches = [path]
        else:
            matches = [Path(p) for p in glob.glob(source.replace('\\', '/'))]
        matches = [p for p in matches if p.is_file() and p.suffix.lower() == '.roc']
        if not matches:
            raise SyncError(f'No .roc packages found: {source}')
        for match in matches:
            found[str(match.resolve())] = match.resolve()
    return [found[key] for key in sorted(found)]


def block_diff(left, right, key, left_label, right_label):
    def text(values):
        return dump({key: values[key]}) if key in values else '# BLOCK ABSENT\n'
    return ''.join(difflib.unified_diff(text(left).splitlines(True), text(right).splitlines(True),
                                       fromfile=left_label, tofile=right_label))


def fenced(diff, language="diff"):
    fence = '`' * max(3, max((len(x) for x in re.findall(r'`+', diff)), default=0) + 1)
    return [fence + language, diff, fence, '']


def region_markdown(result):
    lines = []
    if result.get('custom_regions'):
        lines += ['### Мои критичные изменения', '',
                  'Строки отсчитываются внутри текстового блока, включая строки маркеров.', '']
        for region in result['custom_regions']:
            path = '/'.join(str(part) for part in region['path'])
            lines += [f"**{path}, строки {region['start_line']}–{region['end_line']}**", '']
            lines += fenced(region['code'], 'vrl')
    if result.get('marker_warnings'):
        lines += ['### Проверьте маркеры', '']
        for warning in result['marker_warnings']:
            path = '/'.join(str(part) for part in warning['path'])
            lines += [f"- {path}, строка {warning['line']}: {warning['message']}"]
        lines += ['']
    return lines


def compare_pair(custom, vendor):
    ours = blocks(custom)
    result = {'id': custom['id'], 'upstream_id': 'RV-' + custom['id'][3:],
              'status': 'ORPHANED', 'different_blocks': [], 'diffs': {},
              'hashes': {'CUSTOM': {k: digest(v) for k, v in ours.items()}}}
    result.update(custom_regions(custom))
    if vendor is None:
        return result
    theirs = blocks(vendor)
    different = changes(ours, theirs)
    result.update(different_blocks=different, status=('NO_CHANGE' if not different else
                  'METADATA_ONLY' if different == ['metadata'] else 'REVIEW_REQUIRED'))
    if result['marker_warnings']:
        result['status'] = 'REVIEW_REQUIRED'
    result['hashes']['SIEM'] = {k: digest(v) for k, v in theirs.items()}
    result['versions'] = {'CUSTOM': custom.get('version'), 'SIEM': vendor.get('version')}
    result['diffs'] = {k: block_diff(ours, theirs, k, 'CUSTOM', 'SIEM') for k in different}
    return result


def markdown(results):
    lines = ['# Сравнение custom с пакетами SIEM', '',
             'Прямое сравнение без BASE. Различия могут быть намеренными кастомизациями.',
             'Знаки − показывают custom, знаки + — SIEM. Автоматического слияния нет.',
             '`id`, `rid`, `test`, `tests` исключены из сравнения. Отмеченные правки учитываются целиком.', '',
             '| Статус | Количество пар правило/пакет |', '|---|---:|']
    counts = Counter(r['status'] for r in results)
    for status in ('NO_CHANGE', 'METADATA_ONLY', 'REVIEW_REQUIRED', 'ORPHANED'):
        lines.append(f'| {status} | {counts[status]} |')
    for r in results:
        lines += ['', f"## {r['id']} ← {r['upstream_id']}: {r['status']}", '',
                  f"Пакет: {r['package_label']} (снимки: {r['snapshot']})", '',
                  'Различающиеся блоки: ' + (', '.join(r['different_blocks']) or 'нет'), '']
        if r['status'] == 'ORPHANED':
            lines.append('Соответствующее RV-правило отсутствует в этом пакете.')
        lines += region_markdown(r)
        critical = {region['block'] for region in r.get('custom_regions', [])}
        for key in sorted(r['diffs'], key=lambda k: (k not in critical, k)):
            label = ' — содержит мои критичные изменения' if key in critical else ''
            lines += [f'### {key}{label}', ''] + fenced(r['diffs'][key])
    return '\n'.join(lines) + '\n'


def direct_compare(custom, sources, output):
    custom, output = Path(custom), Path(output)
    if not custom.exists():
        raise SyncError(f'Custom source does not exist: {custom}')
    ours = index(custom, 'VI-')
    if not ours:
        raise SyncError(f'No VI- rules found: {custom}')
    selected = packages(sources)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        temp = Path(temporary)
        staged = temp / 'result'
        staged.mkdir()
        results, manifest = [], []
        for number, package in enumerate(selected, 1):
            with tempfile.TemporaryDirectory(dir=temp) as unpacked:
                vendor = index(extract(package, unpacked), 'RV-')
                label = f'package-{number:03d}'
                for folder in ('CUSTOM', 'SIEM'):
                    (staged / label / folder).mkdir(parents=True)
                manifest.append({'label': label, 'source': str(package), 'vendor_rules': len(vendor)})
                for cid, (custom_path, rule) in ours.items():
                    uid = 'RV-' + cid[3:]
                    counterpart = vendor.get(uid, (None, None))[1]
                    result = compare_pair(rule, counterpart)
                    result.update(package=str(package), package_label=package.name,
                                  snapshot=label, custom_source=str(custom_path.resolve()))
                    for folder, data in [('CUSTOM', rule), ('SIEM', counterpart)]:
                        if data is not None:
                            (staged / label / folder / f'{data["id"]}.ro').write_text(dump(data), encoding='utf-8')
                    results.append(result)
        (staged / 'report.md').write_text(markdown(results), encoding='utf-8')
        for name, data in [('results', results), ('packages', manifest)]:
            (staged / f'{name}.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        destination = output / uuid.uuid4().hex
        staged.rename(destination)
    return destination, results
