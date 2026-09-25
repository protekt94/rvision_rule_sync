import io
import json
import stat
import struct
import tarfile
import zipfile
from pathlib import Path
import pytest
from rvision_rule_sync import archive
from rvision_rule_sync.cli import load_state, main
from rvision_rule_sync.core import SyncError, VRL, compare, parse, read
from rvision_rule_sync.direct import markdown, packages


def test_critical_region_in_unchanged_custom_still_protected():
    code = VRL('# начало моих изменений\n.x = 1\n# конец моих изменений\n')
    base = {'id':'RV-D-1', 'on_correlate':code}
    ours = dict(base, id='CUSTOM-D-1')
    theirs = dict(base, on_correlate=VRL('.x = 2\n'))
    result = compare(base, ours, theirs)
    assert result['status'] == 'REVIEW_REQUIRED'
    assert result['conflicts'] == ['on_correlate'] and result['generated'] is None


def test_protected_metadata_maps_to_semantic_block():
    base = {'id':'RV-D-1','description':'# начало моих изменений\ncustom\n# конец моих изменений'}
    result = compare(base, dict(base,id='CUSTOM-D-1'), dict(base,description='changed'))
    assert result['status'] == 'REVIEW_REQUIRED' and result['conflicts'] == ['metadata']


def test_casefold_duplicate_ids(tmp_path):
    (tmp_path/'first.ro').write_text('id: RV-D-Ab\n', encoding='utf-8')
    (tmp_path/'second.ro').write_text('id: RV-D-aB\n', encoding='utf-8')
    with pytest.raises(SyncError, match='case-insensitive'):
        archive.index(tmp_path, 'RV-')


@pytest.mark.parametrize('key', ['../escape.ro','/absolute.ro','C:/drive.ro','dir\\escape.ro'])
def test_archive_unsafe_paths(tmp_path, key):
    path = tmp_path/'bad.roc'
    with zipfile.ZipFile(path,'w') as z:
        z.writestr(key,'id: RV-D-1')
    with pytest.raises(SyncError, match='Unsafe archive path'):
        archive.extract(path,tmp_path/'out')


def test_zip_symlink(tmp_path):
    path = tmp_path/'link.roc'
    with zipfile.ZipFile(path,'w') as z:
        info=zipfile.ZipInfo('linked.ro')
        info.create_system=3
        info.external_attr=(stat.S_IFLNK | 0o777) << 16
        z.writestr(info,'outside')
    with pytest.raises(SyncError, match='links'):
        archive.extract(path,tmp_path/'out')


def test_tar_hardlink(tmp_path):
    path=tmp_path/'link.roc'
    with tarfile.open(path,'w') as tar:
        info=tarfile.TarInfo('linked.ro')
        info.type=tarfile.LNKTYPE
        info.linkname='outside'
        tar.addfile(info)
    with pytest.raises(SyncError, match='regular'):
        archive.extract(path,tmp_path/'out')


def test_archive_duplicate_paths(tmp_path):
    path=tmp_path/'duplicate.roc'
    with zipfile.ZipFile(path,'w') as z:
        z.writestr('a.ro','id: RV-D-1')
        z.writestr('A.ro','id: RV-D-2')
    with pytest.raises(SyncError,match='Duplicate archive path'):
        archive.extract(path,tmp_path/'out')


@pytest.mark.parametrize('limit', ['MAX_FILES','MAX_BYTES'])
def test_archive_limits(tmp_path,monkeypatch,limit):
    path=tmp_path/'large.roc'
    with zipfile.ZipFile(path,'w') as z:
        z.writestr('a.ro','id: RV-D-1')
    monkeypatch.setattr(archive,limit,0)
    with pytest.raises(SyncError,match='limits'):
        archive.extract(path,tmp_path/'out')


def test_crc_error_is_cli_error_not_traceback(tmp_path,capsys):
    custom=tmp_path/'custom.ro'
    custom.write_text('id: CUSTOM-D-1',encoding='utf-8')
    path=tmp_path/'corrupt.roc'
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_STORED) as z:
        z.writestr('vendor.ro','id: RV-D-1')
    data=bytearray(path.read_bytes())
    name_len,extra_len=struct.unpack_from('<HH',data,26)
    data[30+name_len+extra_len] ^= 1
    path.write_bytes(data)
    with pytest.raises(SystemExit) as result:
        main(['compare', '--custom-prefix', 'CUSTOM-','--custom',str(custom),'--output',str(tmp_path/'reports'),str(path)])
    assert result.value.code == 1
    output=capsys.readouterr().err
    assert 'Cannot read archive' in output and 'Traceback' not in output
    assert not list((tmp_path/'reports').iterdir())


@pytest.mark.parametrize('state', [[],{}, {'schema':True,'rules':{}}, {'schema':1,'rules':[]},
                                  {'schema':1,'rules':{'CUSTOM-D-1':[]}}])
def test_corrupt_state_has_clear_error(tmp_path,state):
    path=tmp_path/'state.json'
    path.write_text(json.dumps(state),encoding='utf-8')
    with pytest.raises(SyncError):
        load_state(path)


def test_alias_expansion_rejected_early():
    with pytest.raises(SyncError,match='aliases'):
        parse('a: &a [1, 2]\nb: [*a, *a]\n')


def test_deep_yaml_rejected():
    with pytest.raises(SyncError,match='nested'):
        parse('a: '+('['*90)+'1'+(']'*90))


def test_large_rule_rejected(tmp_path,monkeypatch):
    import rvision_rule_sync.core as core
    path=tmp_path/'large.ro'
    path.write_text('id: RV-D-1',encoding='utf-8')
    monkeypatch.setattr(core,'MAX_RULE_BYTES',4)
    with pytest.raises(SyncError,match='exceeds'):
        read(path)


def test_report_escapes_external_markup():
    item={'id':'CUSTOM-D-1','upstream_id':'RV-D-1','status':'NO_CHANGE',
          'package_label':'![x](https://example.invalid/x)<script>', 'snapshot':'package-001',
          'different_blocks':[], 'diffs':{}}
    text=markdown([item])
    assert '![x](' not in text and '<script>' not in text
    assert '&lt;script&gt;' in text


def test_windows_glob(tmp_path):
    (tmp_path/'a.roc').write_bytes(b'placeholder')
    assert packages([str(tmp_path).replace('/','\\')+'\\*.roc']) == [(tmp_path/'a.roc').resolve()]
