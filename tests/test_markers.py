from copy import deepcopy
import json
from pathlib import Path
import pytest
from rvision_rule_sync.core import VRL, blocks, compare, dump, parse
from rvision_rule_sync.direct import compare_pair, markdown
from rvision_rule_sync.markers import custom_regions, START, END
from rvision_rule_sync.cli import analyze, bootstrap, report


def marked(code='.custom = true\n'):
    return VRL(START + '\n' + code + END + '\n')


@pytest.mark.parametrize('key', ['test', 'tests'])
@pytest.mark.parametrize('operation', ['added', 'changed', 'removed'])
def test_tests_excluded_everywhere(key, operation):
    base = {'id': 'RV-D-1', 'filter': VRL('true\n'), key: ['base']}
    ours = dict(base, id='VI-D-1')
    vendor = deepcopy(base)
    if operation == 'added':
        base.pop(key)
        ours.pop(key)
    elif operation == 'removed':
        vendor.pop(key)
    else:
        vendor[key] = ['vendor']
        ours[key] = ['custom']
    direct = compare_pair(ours, vendor)
    three = compare(base, ours, vendor)
    assert direct['status'] == three['status'] == 'NO_CHANGE'
    assert not direct['diffs'] and not three['vendor']
    assert key not in direct['hashes']['CUSTOM']
    assert key not in three['hashes']['THEIRS']
    vendor['filter'] = VRL('false\n')
    merged = compare(base, ours, vendor)
    assert merged['status'] == 'AUTO_MERGE'
    assert (key in merged['generated']) == (key in ours)
    assert merged['generated'].get(key) == ours.get(key)


def test_markers_nested_paths_and_crlf():
    rule = {'aliases': {'x': {'filter': marked('.a = 1\r\n')}},
            'on_correlate': VRL(marked() + '\n' + marked('.b = 2\n')),
            'tests': [{'assertion': marked()}]}
    annotation = custom_regions(rule)
    assert not annotation['marker_warnings']
    assert len(annotation['custom_regions']) == 3
    first = annotation['custom_regions'][0]
    assert first['path'] == ['aliases', 'x', 'filter']
    assert (first['start_line'], first['end_line']) == (1, 3)
    assert first['code'] == '.a = 1\n'
    assert custom_regions(parse(dump(rule))) == annotation


@pytest.mark.parametrize('text', [START+'\ntrue', END, START+'\n'+START+'\n'+END])
def test_bad_markers_require_review(text):
    ours = {'id': 'VI-D-1', 'filter': VRL(text)}
    vendor = dict(ours, id='RV-D-1')
    assert compare_pair(ours, vendor)['status'] == 'REVIEW_REQUIRED'
    assert compare_pair(ours, vendor)['marker_warnings']
    assert compare(vendor, ours, vendor)['status'] == 'REVIEW_REQUIRED'
    # Orphan remains visible even when markers are invalid.
    assert compare_pair(ours, None)['status'] == 'ORPHANED'


def test_markers_are_not_ignored_or_overwritten():
    base = {'id': 'RV-D-1', 'filter': VRL('true\n'), 'on_correlate': VRL('.x = 0\n')}
    ours = dict(base, id='VI-D-1', on_correlate=marked('.x = 1\n'))
    vendor = dict(base, filter=VRL('false\n'))
    result = compare(base, ours, vendor)
    assert result['status'] == 'AUTO_MERGE'
    assert result['generated']['on_correlate'] == ours['on_correlate']
    vendor['on_correlate'] = VRL('.x = 2\n')
    result = compare(base, ours, vendor)
    assert result['status'] == 'REVIEW_REQUIRED' and result['generated'] is None
    assert result['conflicts'] == ['on_correlate']
    assert 'on_correlate' in compare_pair(ours, vendor)['different_blocks']
    assert compare_pair(ours, vendor)['custom_regions'][0]['code'] == '.x = 1\n'


def test_report_shows_regions_and_not_tests():
    ours = {'id': 'VI-D-1', 'aliases': [{'filter': marked('.x = "```"\n')}], 'tests': ['SECRET_TEST']}
    vendor = {'id': 'RV-D-1', 'aliases': [], 'tests': ['DIFFERENT_TEST']}
    result = compare_pair(ours, vendor)
    result.update(package_label='new.roc', snapshot='package-001')
    text = markdown([result])
    assert 'Мои критичные изменения' in text and 'aliases/0/filter' in text
    assert 'содержит мои критичные изменения' in text
    assert '````vrl' in text  # source cannot close its own fence
    assert 'SECRET_TEST' not in text and 'DIFFERENT_TEST' not in text
    three = compare(vendor, ours, vendor)
    three.update(id='VI-D-1', upstream_id='RV-D-1')
    assert 'Мои критичные изменения' in report([three], 1)


def test_inline_marker_string_is_not_annotation():
    rule = {'filter': VRL('.x = "# начало моих изменений"\n')}
    assert custom_regions(rule) == {'custom_regions': [], 'marker_warnings': []}


def test_analyze_preserves_tests_and_regions(tmp_path):
    base = {'id': 'RV-D-1', 'filter': VRL('true\n'), 'on_correlate': VRL('.x = 0\n'), 'tests': ['BASE']}
    ours = dict(base, id='VI-D-1', on_correlate=marked(), tests=['CUSTOM'])
    vendor = dict(base, filter=VRL('false\n'), tests=['VENDOR'])
    for name, rule in [('base',base), ('custom',ours), ('vendor',vendor)]:
        (tmp_path / f'{name}.ro').write_text(dump(rule))
    ws = bootstrap(tmp_path/'ws', tmp_path/'base.ro', tmp_path/'custom.ro', True)
    run, results = analyze(ws, tmp_path/'vendor.ro')
    assert results[0]['status'] == 'AUTO_MERGE'
    generated = parse((run/'generated/VI-D-1.ro').read_text())
    assert generated['tests'] == ['CUSTOM']
    assert generated['on_correlate'] == ours['on_correlate']
    assert 'tests' not in results[0]['diffs']
    assert json.loads((run/'results.json').read_text())[0]['custom_regions']
