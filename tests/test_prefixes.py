import json
import zipfile
from types import SimpleNamespace
import pytest
from rvision_rule_sync.core import SyncError, VRL, dump, read, normalize_custom_prefix, upstream_id
from rvision_rule_sync.direct import compare_pair, direct_compare
from rvision_rule_sync.cli import bootstrap, analyze, load_state, main


@pytest.mark.parametrize('prefix', ['SOC-', 'COMPANY-', 'CUSTOM-', 'My_Team-', 'ACME-SOC-', 'X2'])
def test_configurable_prefix_end_to_end(tmp_path, prefix):
    normalized = normalize_custom_prefix(prefix)
    cid = normalized + 'D-100'
    base = {'id': 'RV-D-100', 'rid': 'vendor-rid', 'filter': VRL('true\n'), 'ttl': 10}
    custom = dict(base, id=cid, rid='custom-rid', ttl=20)
    vendor = dict(base, filter=VRL('false\n'))
    for name, data in [('base', base), ('custom', custom), ('vendor', vendor)]:
        (tmp_path/f'{name}.ro').write_text(dump(data), encoding='utf-8')
    package = tmp_path/'new.roc'
    with zipfile.ZipFile(package, 'w') as z:
        z.writestr('nested/rule.ro', dump(vendor))
    run, results = direct_compare(tmp_path/'custom.ro', [package], tmp_path/'reports', custom_prefix=prefix)
    assert results[0]['id'] == cid and results[0]['upstream_id'] == 'RV-D-100'
    assert results[0]['custom_prefix'] == normalized
    assert (run/'package-001/CUSTOM'/f'{cid}.ro').exists()
    ws = bootstrap(tmp_path/'ws', tmp_path/'base.ro', tmp_path/'custom.ro', True, custom_prefix=prefix)
    state = load_state(ws/'state.json')
    assert state['schema'] == 2 and state['custom_prefix'] == normalized
    run, results = analyze(ws, package)
    assert results[0]['status'] == 'AUTO_MERGE'
    merged = read(run/'generated'/f'{cid}.ro')
    assert merged['id'] == cid and merged['rid'] == 'custom-rid'
    assert merged['ttl'] == 20 and merged['filter'] == vendor['filter']
    with pytest.raises(SyncError, match='cannot remap'):
        analyze(ws, package, custom_prefix='OTHER-')


@pytest.mark.parametrize('prefix', ['', '-', '../', 'TEAM/', 'TEAM\\', 'C:', ' SPACE', 'SPACE ', '1TEAM-', 'RV-', 'rv', 'RV-TEAM-', 'КОМАНДА-', None])
def test_invalid_prefixes_rejected(prefix):
    with pytest.raises(SyncError):
        normalize_custom_prefix(prefix)


@pytest.mark.parametrize('cid', ['SOC-', 'SOC-../x', 'SOC-/file', 'SOC-_bad', 'OTHER-D-1', 'soc-D-1'])
def test_invalid_or_mismatched_custom_id(cid):
    with pytest.raises(SyncError):
        upstream_id(cid, 'SOC-')


def test_replace_only_leading_prefix_and_accept_bare_value():
    assert upstream_id('COMPANY-D-COMPANY-10', 'COMPANY') == 'RV-D-COMPANY-10'
    assert normalize_custom_prefix('CUSTOM') == 'CUSTOM-'
    with pytest.raises(SyncError, match='Expected vendor'):
        compare_pair({'id':'SOC-D-1'}, {'id':'RV-D-2'}, custom_prefix='SOC')


def test_mixed_directory_uses_only_chosen_prefix(tmp_path):
    custom = tmp_path/'custom'
    custom.mkdir()
    for prefix in ['SOC-', 'OTHER-', 'CUSTOM-']:
        (custom/f'{prefix}D-1.ro').write_text(f'id: {prefix}D-1\n', encoding='utf-8')
    package = tmp_path/'package.roc'
    with zipfile.ZipFile(package, 'w') as z:
        z.writestr('vendor.ro', 'id: RV-D-1\n')
    _, results = direct_compare(custom, [package], tmp_path/'reports', custom_prefix='OTHER')
    assert [r['id'] for r in results] == ['OTHER-D-1']
    with pytest.raises(SyncError, match='No ABSENT-'):
        direct_compare(custom, [package], tmp_path/'missing', custom_prefix='ABSENT')


def test_legacy_state_without_prefix_inferred_from_ids(tmp_path):
    base = tmp_path/'base.ro'
    custom = tmp_path/'custom.ro'
    base.write_text('id: RV-D-1\n', encoding='utf-8')
    custom.write_text('id: CUSTOM-D-1\n', encoding='utf-8')
    ws = bootstrap(tmp_path/'ws', base, custom, True, custom_prefix='CUSTOM-')
    state = json.loads((ws/'state.json').read_text(encoding='utf-8'))
    state['schema'] = 1
    state.pop('custom_prefix')
    (ws/'state.json').write_text(json.dumps(state), encoding='utf-8')
    before = (ws/'state.json').read_bytes()
    assert analyze(ws, base)[1][0]['status'] == 'NO_CHANGE'
    assert (ws/'state.json').read_bytes() == before


def test_schema_2_requires_prefix(tmp_path):
    state = tmp_path/'state.json'
    state.write_text(json.dumps({'schema':2, 'rules':{}}), encoding='utf-8')
    with pytest.raises(SyncError):
        load_state(state)


def test_cli_without_terminal_requires_explicit_prefix(monkeypatch, capsys):
    monkeypatch.setattr('rvision_rule_sync.cli.sys.stdin', SimpleNamespace(isatty=lambda:False))
    with pytest.raises(SystemExit) as exc:
        main(['compare'])
    assert exc.value.code == 1
    assert '--custom-prefix' in capsys.readouterr().err


def test_cli_interactive_prefix(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path/'custom').mkdir()
    (tmp_path/'SIEM').mkdir()
    (tmp_path/'custom/custom.ro').write_text('id: TEAM-D-1\n', encoding='utf-8')
    with zipfile.ZipFile(tmp_path/'SIEM/new.roc', 'w') as z:
        z.writestr('vendor.ro', 'id: RV-D-1\n')
    monkeypatch.setattr('rvision_rule_sync.cli.sys.stdin', SimpleNamespace(isatty=lambda:True))
    prompts = []
    monkeypatch.setattr('builtins.input', lambda prompt: prompts.append(prompt) or 'TEAM')
    assert main(['compare']) == 0
    assert len(prompts) == 1
    results = json.loads(next((tmp_path/'reports').glob('*/results.json')).read_text(encoding='utf-8'))
    assert results[0]['custom_prefix'] == 'TEAM-'
    monkeypatch.setattr('builtins.input', lambda prompt: pytest.fail('Explicit prefix must not prompt'))
    assert main(['compare', '--custom-prefix', 'TEAM-']) == 0


def test_cli_bootstrap_persists_prefix(tmp_path, monkeypatch):
    b, c, ws = tmp_path/'b.ro', tmp_path/'c.ro', tmp_path/'ws'
    b.write_text('id: RV-D-1\n', encoding='utf-8')
    c.write_text('id: SOC-D-1\n', encoding='utf-8')
    monkeypatch.setattr('builtins.input', lambda _:pytest.fail('Analyze must use saved prefix'))
    assert main(['bootstrap', '--base',str(b),'--custom',str(c),'--workspace',str(ws),
                 '--custom-prefix','SOC','--baseline-verified']) == 0
    assert main(['analyze','--workspace',str(ws),str(b)]) == 0


@pytest.mark.parametrize('mapping', [
    {},
    {'SOC-D-1':'RV-D-1', 'CUSTOM-D-2':'RV-D-2'},
    {'SOC-D-1':'RV-D-2'},
])
def test_ambiguous_or_invalid_legacy_mapping_rejected(tmp_path, mapping):
    state = {'schema':1, 'rules':{cid:{'upstream_id':uid,'base_hash':'0'*64,'baseline_verified':True}
                                 for cid,uid in mapping.items()}}
    path = tmp_path/'state.json'
    path.write_text(json.dumps(state),encoding='utf-8')
    with pytest.raises(SyncError):
        load_state(path)
