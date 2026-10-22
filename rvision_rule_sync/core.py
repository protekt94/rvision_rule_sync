from __future__ import annotations
import copy
import difflib
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


class Rule(dict):
    """Parsed rule plus YAML-level comment annotations (not YAML fields)."""

    def __init__(self, *args, yaml_protected_keys=(), yaml_regions=(), yaml_marker_warnings=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.yaml_protected_keys = frozenset(yaml_protected_keys)
        self.yaml_regions = list(yaml_regions)
        self.yaml_marker_warnings = list(yaml_marker_warnings)


class Loader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise SyncError('YAML aliases are not supported')
        depth = getattr(self, '_rule_depth', 0)
        if depth >= 80:
            raise SyncError('Excessively nested YAML')
        self._rule_depth = depth + 1
        try:
            return super().compose_node(parent, index)
        finally:
            self._rule_depth = depth


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
Dumper.add_representer(Rule, lambda d, s: d.represent_dict(dict(s)))


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


def yaml_protected_regions(text):
    """Find top-level ### start/### end regions BEFORE YAML discards comments.

    Only whole top-level keys can be protected. Ambiguous/partial regions are
    reported as warnings, never silently masked from comparison.
    """
    lines = text.replace('\r\n', '\n').replace('\r', '\n').splitlines(keepends=True)
    spans, warnings, opening = [], [], None
    invalid_opening = False
    for number, line in enumerate(lines):
        marker = line.rstrip('\n').rstrip(' \t')
        if marker == '### start':
            if opening is not None:
                warnings.append({'path': ['YAML'], 'line': number + 1,
                                 'message': 'Вложенный маркер ### start на уровне YAML'})
                invalid_opening = True
            else:
                opening = number
                invalid_opening = False
        elif marker == '### end':
            if opening is None:
                warnings.append({'path': ['YAML'], 'line': number + 1,
                                 'message': 'Маркер ### end на уровне YAML без ### start'})
            elif not invalid_opening:
                spans.append((opening, number))
            opening = None
            invalid_opening = False
    if opening is not None:
        warnings.append({'path': ['YAML'], 'line': opening + 1,
                         'message': 'Маркер ### start на уровне YAML без ### end'})
    if not spans:
        return set(), [], warnings

    node = yaml.compose(text, Loader=Loader)
    if not isinstance(node, yaml.MappingNode):
        raise SyncError('Rule must be a YAML mapping')
    root_keys = [(key.value, key.start_mark.line) for key, _ in node.value]
    protected, regions = set(), []

    def meaningful(line):
        stripped = line.strip()
        return bool(stripped and not stripped.startswith('#'))

    for begin, end in spans:
        enclosed = [(key, number) for key, number in root_keys if begin < number < end]
        unsafe = not enclosed
        if enclosed:
            # All non-comment content within the marked region must belong to
            # complete top-level keys that start after ### start.
            if any(meaningful(lines[n]) for n in range(begin + 1, enclosed[0][1])):
                unsafe = True
            # If a protected key continues below ### end, a partial YAML value
            # was annotated; do not silently discard part of a field.
            final_line = enclosed[-1][1]
            next_root = next((number for _, number in root_keys if number > final_line), len(lines))
            if any(meaningful(lines[n]) for n in range(end + 1, next_root)):
                unsafe = True
        if unsafe:
            warnings.append({'path': ['YAML'], 'line': begin + 1,
                             'message': 'Маркеры YAML должны охватывать целые поля верхнего уровня; исключение не применено'})
            continue
        keys = [key for key, _ in enclosed]
        protected.update(keys)
        regions.append({'kind': 'yaml', 'path': ['YAML'], 'block': keys[0],
                        'keys': keys, 'start_line': begin + 1, 'end_line': end + 1,
                        'code': ''.join(lines[begin + 1:end])})
    return protected, regions, warnings


def parse(text):
    try:
        data = yaml.load(text, Loader=Loader)
        if not isinstance(data, dict):
            raise SyncError('Rule must be a YAML mapping')
        digest(data)
        protected, regions, warnings = yaml_protected_regions(text)
        return Rule(data, yaml_protected_keys=protected,
                    yaml_regions=regions, yaml_marker_warnings=warnings)
    except (yaml.YAMLError, RecursionError) as exc:
        raise SyncError(f'Invalid YAML: {exc}') from exc


MAX_RULE_BYTES = 16 * 1024 * 1024


def read(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_RULE_BYTES + 1)
    if len(raw) > MAX_RULE_BYTES:
        raise SyncError(f'Rule exceeds {MAX_RULE_BYTES} bytes: {path}')
    return parse(raw.decode('utf-8-sig'))


def dump(data):
    content = yaml.dump(data, Dumper=Dumper, allow_unicode=True, sort_keys=False, width=120)
    annotations = getattr(data, 'yaml_regions', ())
    if not annotations:
        return content

    # A generated .ro must retain root-level ### start/### end markers. Without
    # this, the next synchronization would unexpectedly compare custom blocks.
    nodes = yaml.compose(content, Loader=Loader)
    if not isinstance(nodes, yaml.MappingNode):
        raise SyncError('Cannot restore YAML markers outside a mapping')
    names = [key.value for key, _ in nodes.value]
    lines = content.splitlines(keepends=True)
    inserts = {}
    for region in annotations:
        protected_keys = region['keys']
        indexes = [names.index(key) for key in protected_keys if key in names]
        if len(indexes) != len(protected_keys) or indexes != list(range(indexes[0], indexes[0] + len(indexes))):
            raise SyncError(f'Cannot safely restore YAML markers for {protected_keys}')
        before = nodes.value[indexes[0]][0].start_mark.line
        after = (nodes.value[indexes[-1] + 1][0].start_mark.line
                 if indexes[-1] + 1 < len(nodes.value) else len(lines))
        inserts.setdefault(before, []).append('### start\n')
        inserts.setdefault(after, []).append('### end\n')
    return ''.join(''.join(inserts.get(n, ())) + line for n, line in enumerate(lines)) + ''.join(inserts.get(len(lines), ()))


BLOCKS = ('filter', 'aliases', 'select', 'group', 'ttl', 'throttle_time_sec', 'on_correlate')
META = set('name status description response reference references incident_taxonomy tags data_source known_false_positives metadata'.split())
IDENTITY = {'id', 'rid'}
IGNORED = {'test', 'tests', 'version', 'author', 'date', 'correlation_rule_version'}
ID = re.compile(r'^[A-Za-z][A-Za-z0-9_-]*$')
SUFFIX = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]*$')


def normalize_custom_prefix(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', value):
        raise SyncError('Custom prefix must start with an ASCII letter and contain only letters, digits, _ or -')
    prefix = value if value.endswith('-') else value + '-'
    if prefix.casefold().startswith('rv-'):
        raise SyncError('RV- is reserved for vendor rules; choose a different custom prefix')
    return prefix


def upstream_id(custom_id, custom_prefix):
    prefix = normalize_custom_prefix(custom_prefix)
    if (not isinstance(custom_id, str) or not ID.fullmatch(custom_id) or
            not custom_id.startswith(prefix) or not SUFFIX.fullmatch(custom_id[len(prefix):])):
        raise SyncError(f'Invalid custom rule id for prefix {prefix}: {custom_id!r}')
    return 'RV-' + custom_id[len(prefix):]


# Ignore service assignments only when they occupy a complete VRL line.
# Matching an anchored assignment avoids removing references in conditions,
# comments and most string literals.
IGNORED_VRL_ASSIGNMENTS = re.compile(
    r"^[ \t]*\.(?:correlation_rule_version|normalization_rule_id|normalization_rule_version)[ \t]*="
)
CUSTOM_MARKERS = {'### start', '### end'}


def _vrl_lines(value):
    """Comparison-only physical lines, without service assignments."""
    return [line for line in str(value).replace('\r\n', '\n').replace('\r', '\n').splitlines(keepends=True)
            if not IGNORED_VRL_ASSIGNMENTS.match(line)]


def _unprotected_regions(lines):
    """Remove the entire ### start ... ### end span (including its code).

    Return unprotected lines and their marker-gap positions; malformed markers
    are diagnosed by custom_regions and NOT used to mask vendor code.
    """
    result = []
    gaps = []
    in_region = False
    for number, line in enumerate(lines, 1):
        marker = line.strip()
        if marker == '### start':
            if in_region:
                return None, None
            in_region = True
            gaps.append((len(result), number))
        elif marker == '### end':
            if not in_region:
                return None, None
            in_region = False
        elif not in_region:
            result.append(line)
    if in_region:
        return None, None
    return result, gaps


def _mask_matching_vendor_span(vendor_lines, custom_lines, *, warnings=None, path=()):
    """Mask vendor text at each custom-marked region using matching flank lines.

    The vendor .ro does not contain custom ### start / ### end annotations. We
    therefore match the nearest unchanged lines on either side against the
    vendor. If an anchor has changed, DO NOT guess how much vendor code to
    discard; leave it visible and demand review instead.
    """
    remaining, gaps = _unprotected_regions(custom_lines)
    if remaining is None:
        return vendor_lines
    if not gaps:
        return vendor_lines

    # Locate unprotected unchanged flanks in the vendor. Matched indexes are
    # monotonic, including in the presence of duplicated lines.
    matcher = difflib.SequenceMatcher(None, remaining, vendor_lines, autojunk=False)
    mapped = {}
    for left, right, size in matcher.get_matching_blocks():
        for n in range(size):
            mapped[left + n] = right + n

    intervals = []
    for gap, source_line in gaps:
        left = (mapped.get(gap - 1) if gap > 0 else -1)
        right = (mapped.get(gap) if gap < len(remaining) else len(vendor_lines))
        if left is None or right is None or left >= right:
            if warnings is not None:
                warnings.append({'path': list(path), 'line': source_line,
                                 'message': 'Невозможно однозначно сопоставить границы ### start / ### end с SIEM; участок не скрыт'})
            continue
        intervals.append((left + 1, right))

    # Do not remove any vendor code in a region unless its flanks match.
    drop = set()
    for start, end in intervals:
        drop.update(range(start, end))
    return [line for i, line in enumerate(vendor_lines) if i not in drop]


def normalize_for_comparison(value, *, protected_by=None, warnings=None, path=()):
    """Return a comparison-only view; never mutate or reuse it for .ro output.

    Marked code is ignored in CUSTOM, and corresponding vendor spans are
    masked by surrounding common lines (when safely alignable).
    """
    if isinstance(value, VRL):
        lines = _vrl_lines(value)
        if isinstance(protected_by, VRL):
            template = _vrl_lines(protected_by)
            lines = _mask_matching_vendor_span(lines, template, warnings=warnings, path=path)
        cleaned, _ = _unprotected_regions(lines)
        # On malformed marker pairs avoid masking the contents. The marker
        # validator separately marks the rule REVIEW_REQUIRED.
        if cleaned is None:
            cleaned = lines
        return VRL(''.join(cleaned))
    if isinstance(value, dict):
        return {k: normalize_for_comparison(v,
                    protected_by=(protected_by.get(k) if isinstance(protected_by, dict) else None),
                    warnings=warnings, path=path + (k,))
                for k, v in value.items() if k not in IGNORED}
    if isinstance(value, list):
        return [normalize_for_comparison(v,
                    protected_by=(protected_by[i] if isinstance(protected_by, list) and i < len(protected_by) else None),
                    warnings=warnings, path=path + (i,))
                for i, v in enumerate(value)]
    return value


def preserve_service_assignments(vendor, custom):
    """Restore custom service values in a vendor block copied for auto-merge.

    Comparison ignores these VRL assignments, but generated rules must not
    accidentally get the RV normalization ID or vendor rule version.
    """
    if isinstance(vendor, VRL) and isinstance(custom, VRL):
        custom_lines = custom.splitlines(keepends=True)
        preserved = {}
        for line in custom_lines:
            match = IGNORED_VRL_ASSIGNMENTS.match(line)
            if match:
                name = line[match.start():match.end()].split('=')[0].strip()
                preserved.setdefault(name, []).append(line)
        fixed = []
        for line in vendor.splitlines(keepends=True):
            match = IGNORED_VRL_ASSIGNMENTS.match(line)
            if match:
                name = line[match.start():match.end()].split('=')[0].strip()
                matching = preserved.get(name, [])
                if len(matching) == 1:
                    # Maintain vendor indentation/newline, user assignment value.
                    indentation = line[:len(line) - len(line.lstrip(' \t'))]
                    custom_assignment = matching[0].lstrip(' \t').rstrip('\r\n')
                    newline = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
                    line = indentation + custom_assignment + newline
            fixed.append(line)
        return VRL(''.join(fixed))
    if isinstance(vendor, dict) and isinstance(custom, dict):
        return {key: preserve_service_assignments(value, custom[key])
                if key in custom else copy.deepcopy(value)
                for key, value in vendor.items()}
    if isinstance(vendor, list) and isinstance(custom, list):
        return [preserve_service_assignments(value, custom[i])
                if i < len(custom) else copy.deepcopy(value)
                for i, value in enumerate(vendor)]
    return copy.deepcopy(vendor)


def blocks(rule, *, protected_by=None, warnings=None):
    """Semantic comparison blocks; metadata is one separately tracked block.

    The returned data is normalized for diff/hash ONLY. Use original rule
    dictionaries when producing merged .ro files.
    """
    template = rule if protected_by is None else protected_by
    yaml_protected = getattr(template, 'yaml_protected_keys', frozenset())
    result = {k: normalize_for_comparison(v,
                  protected_by=(protected_by.get(k) if isinstance(protected_by, dict) else None),
                  warnings=warnings, path=(k,))
              for k, v in rule.items() if k not in META | IDENTITY | IGNORED | yaml_protected}
    metadata = {k: normalize_for_comparison(v,
                    protected_by=(protected_by.get(k) if isinstance(protected_by, dict) else None),
                    warnings=warnings, path=(k,))
                for k, v in rule.items() if k in META and k not in yaml_protected}
    if metadata:
        result['metadata'] = metadata
    return result


def changes(base, other):
    return sorted(k for k in base.keys() | other.keys()
                  if k not in base or k not in other or digest(base[k]) != digest(other[k]))


def compare(base, ours, theirs, verified=True):
    result = dict(custom=[], vendor=[], conflicts=[], status='ORPHANED', generated=None)
    result.update(custom_regions(ours))
    alignment_warnings = []
    b, o = blocks(base, protected_by=ours, warnings=alignment_warnings), blocks(ours)
    custom = changes(b, o)
    result['custom'] = custom
    if theirs is None:
        return result
    t = blocks(theirs, protected_by=ours, warnings=alignment_warnings)
    if alignment_warnings:
        result['marker_warnings'].extend(alignment_warnings)
    vendor = changes(b, t)
    protected = {('metadata' if key in META else key)
                 for region in result['custom_regions'] for key in region.get('keys', [region['block']])}
    conflicts = sorted((set(custom) | protected) & set(vendor))
    result.update(vendor=vendor, conflicts=conflicts)
    if not verified:
        result.update(status='REVIEW_REQUIRED', reason='Baseline is not verified')
    elif result['marker_warnings']:
        result.update(status='REVIEW_REQUIRED', reason='Invalid custom change markers')
    elif not vendor:
        result['status'] = 'NO_CHANGE'
    elif conflicts or set(vendor) - (set(BLOCKS) | {'metadata'}):
        result.update(status='REVIEW_REQUIRED', reason='Overlapping blocks or changed unclassified fields')
    else:
        result['status'] = 'METADATA_ONLY' if vendor == ['metadata'] else 'AUTO_MERGE'
        merged = copy.deepcopy(ours)
        for key in vendor:
            if key == 'metadata':
                for field in META:
                    merged.pop(field, None)
                merged.update(copy.deepcopy({field: value for field, value in theirs.items() if field in META}))
            elif key in theirs:
                merged[key] = preserve_service_assignments(theirs[key], ours.get(key))
            else:
                merged.pop(key, None)
        result['generated'] = merged
    result['hashes'] = {label: {k: digest(v) for k, v in snapshot.items()}
        for label, snapshot in [('BASE', b), ('OURS', o), ('THEIRS', t)]}
    return result