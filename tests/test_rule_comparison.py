import copy
import json
import tempfile
import unittest
from pathlib import Path

from rvision_rule_sync.core import VRL, blocks, changes, compare, dump, parse
from rvision_rule_sync.direct import compare_pair, direct_compare


class ComparisonTests(unittest.TestCase):
    def test_normalizer_identity_version_only_does_not_trigger_review(self):
        ours = dict(id='VI-N-197', version='1.0.3', author='user',
                    filter=VRL('x = true\n'),
                    normalizer=VRL('# Блок метаданных\n.normalization_rule_id = "VI-N-197"\n.normalization_rule_version = "1.0.3"\n.model_version = "2.0"\n'))
        vendor = dict(id='RV-N-197', version='1.0.13', author='vendor',
                      filter=VRL('y = true\n'),
                      normalizer=VRL('# Блок метаданных\n.normalization_rule_id = "RV-N-197"\n.normalization_rule_version = "1.0.13"\n.model_version = "2.0"\n'))
        result = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(result['different_blocks'], ['filter'])
        self.assertEqual(set(result['diffs']), {'filter'})
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')
        self.assertEqual(ours['normalizer'].splitlines()[1], '.normalization_rule_id = "VI-N-197"')

    def test_marker_lines_and_correlation_version_are_ignored(self):
        ours = dict(id='VI-D-100', on_correlate=VRL('.correlation_rule_version = "1.2.3"\n### start\n.dst_ip = .src_ip\n### end\n'))
        vendor = dict(id='RV-D-100', on_correlate=VRL('.correlation_rule_version = "9.9.9"\n.dst_ip = .src_ip\n'))
        result = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(result['status'], 'NO_CHANGE')
        self.assertEqual(result['different_blocks'], [])
        self.assertTrue(result['custom_regions'])

    def test_entire_marked_code_is_ignored(self):
        ours = dict(id='VI-D-100', on_correlate=VRL('### start\n.dst_ip = .src_ip\n### end\n'))
        vendor = dict(id='RV-D-100', on_correlate=VRL('.dst_ip = .dst_ip\n'))
        self.assertEqual(compare_pair(ours, vendor, custom_prefix='VI-')['different_blocks'], [])

    def test_marked_addition_does_not_make_false_diff(self):
        ours = {'id': 'VI-D-1008', 'aliases': {'failed': {'filter': VRL(
            '### start\nextra_condition &&\n### end\nordinary_condition\n')}}}
        vendor = {'id': 'RV-D-1008', 'aliases': {'failed': {'filter': VRL(
            'ordinary_condition\n')}}}
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'NO_CHANGE')
        self.assertEqual(row['diffs'], {})
        self.assertNotIn('extra_condition', str(row['hashes']))

    def test_marked_replacement_does_not_make_false_diff(self):
        ours = {'id': 'VI-D-950', 'on_correlate': VRL(
            'a = 1\n### start\n.device_fqdn = .src_hostname\n### end\nb = 2\n')}
        vendor = {'id': 'RV-D-950', 'on_correlate': VRL(
            'a = 1\n.device_fqdn = .device_fqdn\nb = 2\n')}
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'NO_CHANGE')
        self.assertFalse(row['marker_warnings'])

    def test_vendor_changes_outside_marked_area_still_visible(self):
        ours = {'id': 'VI-D-950', 'on_correlate': VRL(
            'a = 1\n### start\nmy = protected\n### end\nb = 2\n')}
        vendor = {'id': 'RV-D-950', 'on_correlate': VRL(
            'a = 1\nvendor = protected\nb = 3\n')}
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'REVIEW_REQUIRED')
        self.assertIn('on_correlate', row['different_blocks'])
        self.assertIn('b = 3', row['diffs']['on_correlate'])
        self.assertNotIn('my = protected', row['diffs']['on_correlate'])
        self.assertTrue(row['marker_warnings'], 'Cannot mask vendor content when the neighbouring unprotected line changed')

    def test_marked_filter_entirely_ignored(self):
        ours = {'id': 'VI-N-197', 'filter': VRL(
            '### start\nstarts_with(.raw.alert_asa, "asa-")\n### end\n'),
            'normalizer': VRL('.normalization_rule_id = "VI-N-197"\n'
                               '.normalization_rule_version = "1.0.3"\nx = true\n')}
        vendor = {'id': 'RV-N-197', 'filter': VRL(
            'starts_with(.raw.appname, "%ASA-")\n'),
            'normalizer': VRL('.normalization_rule_id = "RV-N-197"\n'
                               '.normalization_rule_version = "1.0.13"\nx = true\n')}
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'NO_CHANGE')

    def test_unaligned_marker_raises_review_instead_of_hiding_vendor_change(self):
        ours = {'id': 'VI-D-10', 'filter': VRL(
            'a = mine\n### start\nprotected = true\n### end\nb = 2\n')}
        vendor = {'id': 'RV-D-10', 'filter': VRL('a = vendor\nprotected = false\nb = 2\n')}
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'REVIEW_REQUIRED')
        self.assertTrue(any('сопоставить' in warning['message'] for warning in row['marker_warnings']))

    def test_3way_protected_vendor_update_does_not_trigger_update(self):
        base = {'id': 'RV-D-1', 'filter': VRL('a = 1\nvendor = 1\nb = 2\n')}
        ours = {'id': 'VI-D-1', 'filter': VRL(
            'a = 1\n### start\ncustom = 100\n### end\nb = 2\n')}
        vendor = {'id': 'RV-D-1', 'filter': VRL('a = 1\nvendor = 2\nb = 2\n')}
        row = compare(base, ours, vendor)
        self.assertEqual(row['status'], 'NO_CHANGE')
        self.assertEqual(row['vendor'], [])
        self.assertEqual(row['custom'], [])

    def test_3way_protected_and_unprotected_updates_keep_conservative_review(self):
        base = {'id': 'RV-D-1', 'filter': VRL('a = 1\nvendor = 1\nb = 2\n')}
        ours = {'id': 'VI-D-1', 'filter': VRL(
            'a = 1\n### start\ncustom = 100\n### end\nb = 2\n')}
        vendor = {'id': 'RV-D-1', 'filter': VRL('a = 1\nvendor = 2\nb = 3\n')}
        row = compare(base, ours, vendor)
        self.assertEqual(row['status'], 'REVIEW_REQUIRED')
        self.assertIn('filter', row['vendor'])
        self.assertIsNone(row['generated'])

    def test_invalid_markers_never_auto_accepted(self):
        ours = {'id': 'VI-D-1', 'filter': VRL('### start\na = 1\n')}
        vendor = {'id': 'RV-D-1', 'filter': VRL('a = 1\n')}
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'REVIEW_REQUIRED')
        self.assertTrue(row['marker_warnings'])

    def test_no_stripping_of_comments_and_references(self):
        left = dict(id='VI-N-1', normalizer=VRL('# .normalization_rule_id = "note"\nif .normalization_rule_id == "x" {\n  x = 1\n}\n'))
        right = dict(id='RV-N-1', normalizer=VRL('# .normalization_rule_id = "another note"\nif .normalization_rule_id == "y" {\n  x = 1\n}\n'))
        self.assertIn('normalizer', compare_pair(left, right, custom_prefix='VI-')['different_blocks'])

    def test_nested_ignored_yaml_fields(self):
        left = dict(id='VI-D-3', aliases={'any': {'filter': VRL('true\n'), 'version': '1', 'tests': [1]}})
        right = dict(id='RV-D-3', aliases={'any': {'filter': VRL('true\n'), 'version': '2', 'tests': [2]}})
        self.assertEqual(compare_pair(left, right, custom_prefix='VI-')['status'], 'NO_CHANGE')

    def test_metadata_only_direct_and_3way(self):
        ours = dict(id='VI-D-1', description='ours', filter=VRL('true\n'))
        vendor = dict(id='RV-D-1', description='vendor', filter=VRL('true\n'))
        result = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(result['status'], 'METADATA_ONLY')
        self.assertEqual(result['different_blocks'], ['metadata'])
        base = dict(id='RV-D-1', description='old', filter=VRL('true\n'))
        custom = dict(id='VI-D-1', description='old', filter=VRL('true\n'))
        merged = compare(base, custom, vendor, verified=True)
        self.assertEqual(merged['status'], 'METADATA_ONLY')
        self.assertEqual(merged['generated']['description'], 'vendor')
        self.assertEqual(merged['generated']['id'], 'VI-D-1')

    def test_3way_merge_preserves_original_vrl_and_custom_service_fields(self):
        base = dict(id='RV-D-1', filter=VRL('a\n'), on_correlate=VRL('.correlation_rule_version = "1.0"\nx = 1\n'))
        ours = dict(id='VI-D-1', filter=VRL('### start\na\n### end\n'), on_correlate=VRL('.correlation_rule_version = "12.0"\nx = 1\n'))
        vendor = dict(id='RV-D-1', filter=VRL('a\n'), on_correlate=VRL('.correlation_rule_version = "2.0"\nx = 2\n'))
        merged = compare(base, ours, vendor, verified=True)
        self.assertEqual(merged['status'], 'AUTO_MERGE')
        self.assertIn('"12.0"', merged['generated']['on_correlate'])
        self.assertIn('x = 2', merged['generated']['on_correlate'])
        self.assertIn('### start', merged['generated']['filter'])
        self.assertEqual(ours['on_correlate'].splitlines()[0], '.correlation_rule_version = "12.0"')

    def test_normalizer_3way_remains_conservative(self):
        base = dict(id='RV-N-197', filter=VRL('true\n'), normalizer=VRL('.normalization_rule_id = "RV-N-197"\n.normalization_rule_version = "1"\nx=1\n'))
        ours = dict(id='VI-N-197', filter=VRL('true\n'), normalizer=VRL('.normalization_rule_id = "VI-N-197"\n.normalization_rule_version = "3"\nx=1\n'))
        theirs = dict(id='RV-N-197', filter=VRL('true\n'), normalizer=VRL('.normalization_rule_id = "RV-N-197"\n.normalization_rule_version = "4"\nx=2\n'))
        result = compare(base, ours, theirs)
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')
        self.assertEqual(result['vendor'], ['normalizer'])
        self.assertIsNone(result['generated'])

    def test_3way_metadata_conflict_requires_review(self):
        base = dict(id='RV-D-1', description='old', filter=VRL('true\n'))
        ours = dict(id='VI-D-1', description='ours', filter=VRL('true\n'))
        vendor = dict(id='RV-D-1', description='vendor', filter=VRL('true\n'))
        merged = compare(base, ours, vendor, verified=True)
        self.assertEqual(merged['status'], 'REVIEW_REQUIRED')
        self.assertIn('metadata', merged['conflicts'])
        self.assertIsNone(merged['generated'])

    def test_direct_report_has_no_duplicated_expertise(self):
        with tempfile.TemporaryDirectory() as t:
            # Smoke test output structure directly via a ZIP-based .roc.
            import zipfile
            root = Path(t)
            (root / 'custom').mkdir()
            custom = {'id': 'VI-D-1', 'filter': VRL('true\n'), 'on_correlate': VRL('x = 1\n')}
            vendor = {'id': 'RV-D-1', 'filter': VRL('true\n'), 'on_correlate': VRL('x = 2\n')}
            (root / 'custom' / 'VI-D-1.ro').write_text(dump(custom), encoding='utf-8')
            with zipfile.ZipFile(root / 'SIEM.roc', 'w') as z:
                z.writestr('RV-D-1.ro', dump(vendor))
            destination, rows = direct_compare(root / 'custom', [root / 'SIEM.roc'], root / 'reports', custom_prefix='VI-')
            self.assertEqual(rows[0]['different_blocks'], ['on_correlate'])
            self.assertEqual(sorted(p.name for p in destination.iterdir()), ['packages.json','report.md','results.json'])
            self.assertTrue((root / 'custom' / 'VI-D-1.ro').exists())

    def test_3way_status_nochange_for_ignored_only_vendor_changes(self):
        base = dict(id='RV-D-2', filter=VRL('true\n'), on_correlate=VRL('.correlation_rule_version = "1"\nx = 1\n'))
        ours = dict(id='VI-D-2', filter=VRL('true\n'), on_correlate=VRL('.correlation_rule_version = "1"\nx = 1\n'))
        vendor = dict(id='RV-D-2', filter=VRL('true\n'), on_correlate=VRL('.correlation_rule_version = "2"\nx = 1\n'))
        self.assertEqual(compare(base, ours, vendor)['status'], 'NO_CHANGE')

if __name__ == '__main__':
    unittest.main()


class YAMLMarkerTests(unittest.TestCase):
    USER_RULE = '''id: VI-D-997
version: 1.0.4
filter: !vrl |
  ### start
  contains(to_string(.device_vendor) ?? "-", "kaspersky") &&
  # Фильтр по событию выполнения задачи
  includes(["000007d0", "000000d6"], to_string(.device_event_id) ?? "-")
  ### end
### start
aliases:
  event:
    filter: !vrl |
      device_message = downcase(.device_message) ?? "-"
      rv_contains_any(device_message, ["protection is disabled"])
  password:
    filter: !vrl |
      rv_contains_any(.device_message, ["ввод имени пользователя и пароля"])
select:
  alias: event
  join:
    alias: password
    on:
      - eq: { event: device_hostname, password: device_hostname }
    wait_for_secs: 120
### end
on_correlate: !vrl |
  .correlation_rule_version = "1.0.4"
  .device_hostname = %event.device_hostname
### start
ttl: 180
throttle_time_sec: 60
### end
'''
    VENDOR_RULE = '''id: RV-D-997
version: 1.0.9
filter: !vrl |
  .device_event_id == "000000d6"
aliases:
  event:
    filter: !vrl |
      to_string(.device_message)
select:
  alias: event
on_correlate: !vrl |
  .correlation_rule_version = "1.0.9"
  .device_hostname = %event.device_hostname
'''

    def test_user_realistic_marker_layout_ignored(self):
        ours, vendor = parse(self.USER_RULE), parse(self.VENDOR_RULE)
        self.assertEqual(ours.yaml_protected_keys, {'aliases', 'select', 'ttl', 'throttle_time_sec'})
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'NO_CHANGE')
        self.assertEqual(row['different_blocks'], [])
        self.assertEqual(row['marker_warnings'], [])
        self.assertEqual(set(row['hashes']['CUSTOM']), {'on_correlate', 'filter'})
        self.assertEqual(len([r for r in row['custom_regions'] if r.get('kind') == 'yaml']), 2)

    def test_only_unprotected_code_change_is_reported(self):
        vendor_text = self.VENDOR_RULE.replace('.device_hostname = %event.device_hostname',
                                               '.device_hostname = %event.src_hostname')
        row = compare_pair(parse(self.USER_RULE), parse(vendor_text), custom_prefix='VI-')
        self.assertEqual(row['status'], 'REVIEW_REQUIRED')
        self.assertEqual(row['different_blocks'], ['on_correlate'])
        self.assertNotIn('ttl', str(row['diffs']))
        self.assertNotIn('alias', str(row['diffs']))

    def test_yaml_markers_preserved_after_roundtrip(self):
        ours = parse(self.USER_RULE)
        generated = dump(ours)
        self.assertIn('### start\naliases:', generated)
        self.assertIn('### end\non_correlate:', generated)
        self.assertIn('### start\nttl: 180\nthrottle_time_sec: 60\n### end', generated)
        restored = parse(generated)
        self.assertEqual(restored.yaml_protected_keys, ours.yaml_protected_keys)
        self.assertEqual(blocks(restored), blocks(ours))

    def test_three_way_merge_preserves_root_yaml_markers(self):
        ours = parse(self.USER_RULE)
        base = parse(self.VENDOR_RULE)
        changed = parse(self.VENDOR_RULE.replace('.device_hostname = %event.device_hostname',
                                                     '.device_hostname = %event.src_hostname'))
        result = compare(base, ours, changed)
        self.assertEqual(result['status'], 'AUTO_MERGE')
        merged = dump(result['generated'])
        self.assertIn('### start\naliases:', merged)
        self.assertIn('.device_hostname = %event.src_hostname', merged)
        self.assertEqual(parse(merged).yaml_protected_keys, ours.yaml_protected_keys)

    def test_partial_root_yaml_marker_is_reported_not_masked(self):
        ours = parse('''id: VI-D-3
aliases:
  first: 1
### start
  second: 2
### end
''')
        vendor = parse('''id: RV-D-3
aliases:
  first: 1
  second: 999
''')
        self.assertFalse(ours.yaml_protected_keys)
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'REVIEW_REQUIRED')
        self.assertTrue(row['marker_warnings'])

    def test_invalid_yaml_root_marker_is_not_silent(self):
        ours = parse('id: VI-D-1\n### start\naliases: {}\n')
        vendor = parse('id: RV-D-1\naliases: {}\n')
        row = compare_pair(ours, vendor, custom_prefix='VI-')
        self.assertEqual(row['status'], 'REVIEW_REQUIRED')
        self.assertTrue(row['marker_warnings'])

    def test_only_vrl_marker_does_not_count_as_root_yaml_comment(self):
        ours = parse('id: VI-D-1\nfilter: !vrl |\n  ### start\n  secret\n  ### end\n')
        self.assertFalse(ours.yaml_protected_keys)
        self.assertFalse(ours.yaml_marker_warnings)

    def test_legacy_single_hash_yaml_markers_are_plain_comments(self):
        custom = parse("""id: VI-D-997
# start
aliases:
  added: true
# end
""")
        vendor = parse("""id: RV-D-997
aliases:
  added: false
""")
        self.assertEqual(custom.yaml_protected_keys, frozenset())
        result = compare_pair(custom, vendor, custom_prefix='VI-')
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')
        self.assertEqual(result['different_blocks'], ['aliases'])
        self.assertFalse(result['custom_regions'])

    def test_legacy_single_hash_vrl_markers_do_not_hide_code(self):
        custom = parse("""id: VI-D-100
filter: !vrl |
  # start
  foo = 1
  # end
""")
        vendor = parse("""id: RV-D-100
filter: !vrl |
  foo = 2
""")
        result = compare_pair(custom, vendor, custom_prefix='VI-')
        self.assertEqual(result['different_blocks'], ['filter'])
        self.assertEqual(result['status'], 'REVIEW_REQUIRED')
        self.assertFalse(result['custom_regions'])

    def test_regular_comments_containing_words_start_end_are_not_markers(self):
        custom = parse("""id: VI-D-1
# start of my explanation
aliases:
  test_alias: true
# end of explanation
filter: !vrl |
  # start watching the logs
  foo = 1
  # end watching the logs
""")
        vendor = parse("""id: RV-D-1
aliases:
  test_alias: false
filter: !vrl |
  foo = 2
""")
        result = compare_pair(custom, vendor, custom_prefix='VI-')
        self.assertEqual(set(result['different_blocks']), {'aliases', 'filter'})
        self.assertFalse(result['custom_regions'])

    def test_direct_report_with_top_level_protected_markers(self):
        import zipfile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'custom').mkdir()
            (root / 'custom' / 'VI-D-997.ro').write_text(self.USER_RULE, encoding='utf-8')
            with zipfile.ZipFile(root / 'vendor.roc', 'w') as archive:
                archive.writestr('RV-D-997.ro', self.VENDOR_RULE)
            folder, rows = direct_compare(root / 'custom', [root / 'vendor.roc'], root / 'reports', custom_prefix='VI-')
            self.assertEqual(rows[0]['status'], 'NO_CHANGE')
            self.assertEqual(rows[0]['different_blocks'], [])
            report = (folder / 'report.md').read_text(encoding='utf-8')
            self.assertIn('поля: aliases, select', report)
            self.assertIn('поля: ttl, throttle\\_time\\_sec', report)
            self.assertEqual(sorted(p.name for p in folder.iterdir()), ['packages.json', 'report.md', 'results.json'])