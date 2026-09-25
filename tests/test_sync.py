import copy
import io
import json
import tarfile
import zipfile
from pathlib import Path
import pytest
from rvision_rule_sync.core import SyncError, VRL, blocks, changes, compare, digest, dump, parse, read
from rvision_rule_sync.archive import extract, index
from rvision_rule_sync.cli import analyze, bootstrap, main
from rvision_rule_sync.direct import compare_pair, direct_compare, packages

@pytest.fixture(scope='session')
def FIX(tmp_path_factory):
    import shutil
    source = Path(__file__).parent / 'fixtures'
    destination = tmp_path_factory.mktemp('synthetic-fixtures')
    for path in source.glob('*.ro'):
        shutil.copyfile(path, destination / path.name)
    with zipfile.ZipFile(destination / 'demo.roc', 'w') as archive:
        archive.write(destination / 'RV-D-DEMO1.package.ro', 'nested/vendor.ro')
    return destination

@pytest.fixture
def pair(FIX):
    return read(FIX / 'RV-D-DEMO1.package.ro'), read(FIX / 'SOC-D-DEMO1.ro')


def test_fixture_roundtrip(pair):
    for rule in pair:
        assert isinstance(rule['on_correlate'], VRL)
        assert isinstance(rule['aliases']['virus_detected']['filter'], VRL)
        assert isinstance(rule['tests'][0]['assertion'], VRL)
        assert digest(parse(dump(rule))) == digest(rule)
    assert 'on_correlate' in changes(blocks(pair[0]), blocks(pair[1]))


def test_canonicalization(pair):
    text = dump(pair[0])
    assert digest(parse(text)) == digest(parse('# comment\r\n' + text.replace('\n', '\r\n')))
    assert digest(parse('a: {x: 1, y: 2}\n')) == digest(parse('a:\n  y: 2\n  x: 1\n'))
    assert digest(parse('x: !vrl |\n  .x = "a b"\n')) != digest(parse('x: !vrl |\n  .x = "ab"\n'))
    assert digest(parse('x: !vrl test')) != digest(parse('x: test'))


def test_no_change(pair):
    b, o = pair
    assert compare(b, o, b)['status'] == 'NO_CHANGE'


def test_auto_merge_custom(pair):
    b, o = pair
    t = copy.deepcopy(b)
    t['filter'] = VRL('true\n')
    r = compare(b, o, t)
    assert r['status'] == 'AUTO_MERGE'
    assert r['generated']['filter'] == t['filter']
    for key in ('id', 'rid', 'on_correlate', 'tests'):
        assert r['generated'][key] == o[key]


@pytest.mark.parametrize('block', ['filter', 'aliases', 'select', 'group', 'ttl', 'throttle_time_sec', 'on_correlate', 'metadata'])
def test_same_block_requires_review(pair, block):
    b, _ = pair
    o, t = copy.deepcopy(b), copy.deepcopy(b)
    o['id'] = 'SOC-D-DEMO1'
    if block == 'metadata':
        o['description'], t['description'] = 'custom', 'vendor'
    else:
        o[block] = t[block] = VRL('changed\n')
    assert compare(b, o, t)['status'] == 'REVIEW_REQUIRED'
    assert compare(b, o, t)['generated'] is None


def test_metadata(pair):
    b, _ = pair
    o = dict(b, id='SOC-D-DEMO1', rid='custom-rid')
    t = dict(b, description='changed')
    r = compare(b, o, t)
    assert r['status'] == 'METADATA_ONLY'
    assert r['generated']['rid'] == 'custom-rid'


def test_missing_unverified_unknown_deletion(pair):
    b, o = pair
    assert compare(b, o, None)['status'] == 'ORPHANED'
    assert compare(b, o, b, False)['status'] == 'REVIEW_REQUIRED'
    assert compare(b, o, dict(b, new_logic=True))['status'] == 'REVIEW_REQUIRED'
    t = copy.deepcopy(b)
    del t['filter']
    assert 'filter' not in compare(b, o, t)['generated']


@pytest.mark.parametrize('text', ['id: A\nid: B', 'a: !unknown foo', 'a: !!python/object:foo {}', 'a: &a [*a]'])
def test_invalid_yaml(text):
    with pytest.raises(SyncError):
        parse(text)


@pytest.mark.parametrize('kind', ['zip', 'tar'])
def test_archives_and_traversal(tmp_path, kind):
    good, bad = tmp_path / 'good.roc', tmp_path / 'bad.roc'
    for path, name in [(good, 'nested/a.ro'), (bad, '../escape.ro')]:
        if kind == 'zip':
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr(name, 'id: RV-D-1')
        else:
            with tarfile.open(path, 'w:gz') as z:
                data = b'id: RV-D-1'
                member = tarfile.TarInfo(name)
                member.size = len(data)
                z.addfile(member, io.BytesIO(data))
    assert index(extract(good, tmp_path / 'good'), 'RV-')['RV-D-1']
    with pytest.raises(SyncError):
        extract(bad, tmp_path / 'bad')
    assert not (tmp_path / 'escape.ro').exists()


def test_duplicate_id(tmp_path):
    for name in ['a.ro', 'b.ro']:
        (tmp_path / name).write_text('id: RV-D-1')
    with pytest.raises(SyncError):
        index(tmp_path, 'RV-')


def test_package_cli(tmp_path, FIX):
    ws = tmp_path / 'workspace'
    assert main(['bootstrap', '--custom-prefix', 'SOC-', '--workspace', str(ws), '--base', str(FIX / 'RV-D-DEMO1.package.ro'),
                 '--custom', str(FIX / 'SOC-D-DEMO1.ro'), '--baseline-verified']) == 0
    assert main(['analyze', '--workspace', str(ws), str(FIX / 'demo.roc')]) == 0
    result = next((ws / 'runs').iterdir())
    assert json.loads((result / 'results.json').read_text(encoding='utf-8'))[0]['status'] == 'NO_CHANGE'
    assert (result / 'BASE/RV-D-DEMO1.ro').exists()
    assert not list((result / 'generated').iterdir())
    with pytest.raises(SyncError):
        bootstrap(ws, FIX / 'RV-D-DEMO1.package.ro', FIX / 'SOC-D-DEMO1.ro', custom_prefix='SOC-')


def test_runs_do_not_reuse_candidates(tmp_path, pair, FIX):
    b, o = pair
    ws = bootstrap(tmp_path / 'ws', FIX / 'RV-D-DEMO1.package.ro', FIX / 'SOC-D-DEMO1.ro', True, custom_prefix='SOC-')
    t = dict(b, filter=VRL('true\n'))
    vendor = tmp_path / 'vendor.ro'
    vendor.write_text(dump(t), encoding='utf-8')
    first, _ = analyze(ws, vendor)
    assert (first / 'generated/SOC-D-DEMO1.ro').exists()
    t['on_correlate'] = VRL('true\n')
    vendor.write_text(dump(t), encoding='utf-8')
    second, results = analyze(ws, vendor)
    assert results[0]['status'] == 'REVIEW_REQUIRED'
    assert not list((second / 'generated').iterdir())
    assert read(ws / 'custom/SOC-D-DEMO1.ro') == o
    (ws / 'base/RV-D-DEMO1.ro').write_text('id: RV-D-DEMO1')
    with pytest.raises(SyncError):
        analyze(ws, vendor)


def test_original_pair(FIX):
    b, o, t = [read(FIX / n) for n in ('RV-D-DEMO1.ro', 'SOC-D-DEMO1.ro', 'RV-D-DEMO1.package.ro')]
    assert b['version'] == t['version'] == '1.0.3'
    assert changes(blocks(b), blocks(t)) == ['metadata']
    assert changes(blocks(b)['metadata'], blocks(t)['metadata']) == ['known_false_positives']
    assert t['known_false_positives'] == [line + '.' for line in b['known_false_positives']]
    r = compare(b, o, t)
    assert r['custom'] == ['metadata', 'on_correlate']
    assert r['vendor'] == r['conflicts'] == ['metadata']
    assert r['status'] == 'REVIEW_REQUIRED' and r['generated'] is None


def test_empty_vendor_orphan(tmp_path, FIX):
    ws = bootstrap(tmp_path / 'ws', FIX / 'RV-D-DEMO1.package.ro', FIX / 'SOC-D-DEMO1.ro', True, custom_prefix='SOC-')
    empty = tmp_path / 'empty'
    empty.mkdir()
    assert analyze(ws, empty)[1][0]['status'] == 'ORPHANED'


def test_on_key_and_bool():
    r = parse('on: yes\nenabled: true\n')
    assert r == {'on': 'yes', 'enabled': True}
    assert parse(dump(r)) == r


def package(path, rule=None):
    with zipfile.ZipFile(path, 'w') as z:
        if rule is not None:
            z.writestr('nested/vendor.ro', dump(rule))
    return path


def test_direct_fixture_pair(pair):
    vendor, ours = pair
    r = compare_pair(ours, vendor, custom_prefix='SOC-')
    assert r['different_blocks'] == ['metadata', 'on_correlate']
    assert r['status'] == 'REVIEW_REQUIRED'
    assert '--- CUSTOM' in r['diffs']['on_correlate']
    assert '+++ SIEM' in r['diffs']['on_correlate']
    assert 'generated' not in r


def test_direct_statuses():
    ours = {'id': 'SOC-D-1', 'rid': 'custom', 'filter': VRL('true\n')}
    vendor = dict(ours, id='RV-D-1', rid='vendor')
    assert compare_pair(ours, vendor, custom_prefix='SOC-')['status'] == 'NO_CHANGE'
    vendor['description'] = 'new'
    assert compare_pair(ours, vendor, custom_prefix='SOC-')['status'] == 'METADATA_ONLY'
    vendor['unknown_logic'] = 3
    assert compare_pair(ours, vendor, custom_prefix='SOC-')['status'] == 'REVIEW_REQUIRED'
    assert compare_pair(ours, None, custom_prefix='SOC-')['status'] == 'ORPHANED'


def test_default_cli_repeated_and_new_custom(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path('custom').mkdir()
    Path('SIEM').mkdir()
    custom = Path('custom/any-name.ro')
    custom.write_text('id: SOC-D-1\nfilter: !vrl true\n')
    before = custom.read_bytes()
    package(Path('SIEM/new.roc'), {'id': 'RV-D-1', 'filter': VRL('false')})
    assert main(['compare', '--custom-prefix', 'SOC-']) == 2
    first = set(Path('reports').iterdir())
    assert custom.read_bytes() == before
    assert not Path('state.json').exists()
    Path('custom/another.ro').write_text('id: SOC-D-2\n')
    assert main(['compare', '--custom-prefix', 'SOC-']) == 2
    second = next(iter(set(Path('reports').iterdir()) - first))
    results = json.loads((second / 'results.json').read_text(encoding='utf-8'))
    assert len(results) == 2
    assert next(r for r in results if r['id'] == 'SOC-D-2')['status'] == 'ORPHANED'
    assert not list(second.rglob('generated'))


def test_multiple_packages_no_cross_contamination(tmp_path):
    custom = tmp_path / 'custom.ro'
    custom.write_text('id: SOC-D-1\nfilter: !vrl true\n')
    folder = tmp_path / 'SIEM'
    folder.mkdir()
    a = package(folder / 'a.roc', {'id': 'RV-D-1', 'filter': VRL('true')})
    package(folder / 'b.roc')
    assert len(packages([str(folder / '*.roc'), a])) == 2
    _, results = direct_compare(custom, [folder], tmp_path / 'reports', custom_prefix='SOC-')
    assert [r['status'] for r in results] == ['NO_CHANGE', 'ORPHANED']
    assert len({r['snapshot'] for r in results}) == 2


def test_no_inputs(tmp_path):
    with pytest.raises(SyncError, match='No .roc'):
        packages([tmp_path])
    with pytest.raises(SyncError, match='No .roc'):
        packages([tmp_path / '*.roc'])
    with pytest.raises(SyncError, match='No SOC-'):
        direct_compare(tmp_path, [tmp_path], tmp_path / 'reports', custom_prefix='SOC-')


def test_corrupt_package_does_not_publish_report(tmp_path):
    custom = tmp_path / 'custom.ro'
    custom.write_text('id: SOC-D-1\n')
    valid = package(tmp_path / 'a.roc')
    corrupt = tmp_path / 'b.roc'
    corrupt.write_text('not an archive')
    with pytest.raises(SyncError):
        direct_compare(custom, [valid, corrupt], tmp_path / 'reports', custom_prefix='SOC-')
    assert not list((tmp_path / 'reports').iterdir())
