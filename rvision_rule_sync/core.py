from __future__ import annotations
import copy
import hashlib
import json
import re
from pathlib import Path
import yaml
from .markers import custom_regions


class SyncError(ValueError):
    pass


class VRL(str):
    """Scalar text retaining its !vrl tag."""


class Loader(yaml.SafeLoader):
    pass


Loader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag not in {
        'tag:yaml.org,2002:timestamp', 'tag:yaml.org,2002:bool'}]
    for k, v in Loader.yaml_implicit_resolvers.items()
}
Loader.add_implicit_resolver('tag:yaml.org,2002:bool',
    re.compile(r'^(?:true|false|True|False|TRUE|FALSE)$'), list('tTfF'))


def mapping(loader, node, deep=False):
    result = {}
    for kn, vn in node.value:
        key = loader.construct_object(kn, deep=True)
        if not isinstance(key, str) or key in result:
            raise SyncError(f'Non-string or duplicate YAML key: {key!r}')
        result[key] = loader.construct_object(vn, deep=True)
    return result


Loader.add_constructor('tag:yaml.org,2002:map', mapping)
Loader.add_constructor('!vrl', lambda loader, node: VRL(loader.construct_scalar(node)))


class Dumper(yaml.SafeDumper):
    pass


Dumper.add_representer(VRL, lambda d, s: d.represent_scalar('!vrl', str(s), style='|'))


def canonical(value, depth=0):
    if depth > 80:
        raise SyncError('Cyclic or excessively nested YAML')
    if isinstance(value, dict):
        return ['map', [[k, canonical(v, depth + 1)] for k, v in sorted(value.items())]]
    if isinstance(value, list):
        return ['list', [canonical(v, depth + 1) for v in value]]
    if isinstance(value, str):
        # Preserve VRL whitespace: it may belong to a string literal.
        return ['vrl' if isinstance(value, VRL) else 'str', value.replace('\r\n', '\n').replace('\r', '\n')]
    if value is None or isinstance(value, (bool, int, float)):
        return [type(value).__name__, value]
    raise SyncError(f'Unsupported YAML value: {type(value).__name__}')


def digest(value):
    return hashlib.sha256(json.dumps(canonical(value), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def parse(text):
    try:
        data = yaml.load(text, Loader=Loader)
        if not isinstance(data, dict):
            raise SyncError('Rule must be a YAML mapping')
        digest(data)
        return data
    except (yaml.YAMLError, RecursionError) as exc:
        raise SyncError(f'Invalid YAML: {exc}') from exc


def read(path):
    return parse(Path(path).read_text(encoding='utf-8-sig'))


def dump(data):
    return yaml.dump(data, Dumper=Dumper, allow_unicode=True, sort_keys=False, width=120)


BLOCKS = ('metadata', 'filter', 'aliases', 'select', 'group', 'ttl', 'throttle_time_sec', 'on_correlate')
META = set('name version date author status description response reference references incident_taxonomy tags data_source known_false_positives metadata'.split())
IDENTITY = {'id', 'rid'}
IGNORED = {'test', 'tests'}
ID = re.compile(r'^(?:VI|RV)-[A-Za-z0-9][A-Za-z0-9_-]*$')


def blocks(rule):
    result = {'metadata': {k: v for k, v in rule.items() if k in META}}
    result.update({k: v for k, v in rule.items() if k not in META | IDENTITY | IGNORED})
    return result


def changes(base, other):
    return sorted(k for k in base.keys() | other.keys()
                  if k not in base or k not in other or digest(base[k]) != digest(other[k]))


def compare(base, ours, theirs, verified=True):
    b, o = blocks(base), blocks(ours)
    custom = changes(b, o)
    result = dict(custom=custom, vendor=[], conflicts=[], status='ORPHANED', generated=None)
    result.update(custom_regions(ours))
    if theirs is None:
        return result
    t = blocks(theirs)
    vendor = changes(b, t)
    conflicts = sorted(set(custom) & set(vendor))
    result.update(vendor=vendor, conflicts=conflicts)
    if not verified:
        result.update(status='REVIEW_REQUIRED', reason='Baseline is not verified')
    elif result['marker_warnings']:
        result.update(status='REVIEW_REQUIRED', reason='Invalid custom change markers')
    elif not vendor:
        result['status'] = 'NO_CHANGE'
    elif conflicts or set(vendor) - set(BLOCKS):
        result.update(status='REVIEW_REQUIRED', reason='Overlapping blocks or changed unclassified fields')
    else:
        result['status'] = 'METADATA_ONLY' if vendor == ['metadata'] else 'AUTO_MERGE'
        merged = copy.deepcopy(ours)
        for key in vendor:
            if key == 'metadata':
                for field in META:
                    merged.pop(field, None)
                merged.update(copy.deepcopy(t.get(key, {})))
            elif key in t:
                merged[key] = copy.deepcopy(t[key])
            else:
                merged.pop(key, None)
        result['generated'] = merged
    result['hashes'] = {label: {k: digest(v) for k, v in blocks(rule).items()}
        for label, rule in [('BASE', base), ('OURS', ours), ('THEIRS', theirs)]}
    return result
