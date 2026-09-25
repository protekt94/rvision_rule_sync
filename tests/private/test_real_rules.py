"""Optional local regression suite. No private input is stored in Git."""
import json
from rvision_rule_sync.cli import analyze, bootstrap
from rvision_rule_sync.core import blocks, changes, compare, read
from rvision_rule_sync.direct import direct_compare


def test_original_triple(private_fixtures, private_custom_prefix, tmp_path):
    f = private_fixtures
    b, o, t = [read(f/name) for name in ('vendor-base.ro','custom.ro','vendor-current.ro')]
    assert changes(blocks(b), blocks(t)) == ['metadata']
    assert changes(blocks(b)['metadata'], blocks(t)['metadata']) == ['known_false_positives']
    result = compare(b, o, t)
    assert result['vendor'] == result['conflicts'] == ['metadata']
    assert result['custom'] == ['metadata','on_correlate']
    assert result['status'] == 'REVIEW_REQUIRED'
    ws = bootstrap(tmp_path/'workspace', f/'vendor-base.ro', f/'custom.ro', True, custom_prefix=private_custom_prefix)
    run, results = analyze(ws, f/'vendor-current.ro')
    assert results[0]['status'] == 'REVIEW_REQUIRED'
    assert not list((run/'generated').iterdir())


def test_full_private_package(private_fixtures, private_custom_prefix, tmp_path):
    f = private_fixtures
    run, results = direct_compare(f/'custom.ro', [f/'content.roc'], tmp_path/'reports', custom_prefix=private_custom_prefix)
    assert len(results) == 1
    assert results[0]['status'] == 'REVIEW_REQUIRED'
    assert results[0]['different_blocks'] == ['metadata','on_correlate']
    assert json.loads((run/'packages.json').read_text(encoding='utf-8'))[0]['vendor_rules'] == 1410
