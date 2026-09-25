"""Bounded ZIP/TAR extraction without links or traversal."""
import stat
import zlib
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from .core import SyncError, read, ID, SUFFIX

MAX_FILES = 20000
MAX_BYTES = 512 * 1024 * 1024


def _extract(source, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    seen, total = set(), 0

    def target(name, size):
        nonlocal total
        p = PurePosixPath(name)
        if '\\' in name or p.is_absolute() or '..' in p.parts or ':' in name:
            raise SyncError(f'Unsafe archive path: {name}')
        normalized = str(p).casefold()
        if normalized in seen:
            raise SyncError(f'Duplicate archive path: {name}')
        seen.add(normalized)
        total += size
        if len(seen) > MAX_FILES or total > MAX_BYTES:
            raise SyncError('Archive limits exceeded')
        out = destination / p
        if not out.resolve().is_relative_to(destination.resolve()):
            raise SyncError('Archive escapes destination')
        return out

    def write(out, stream, expected):
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('xb') as f:
            remaining = expected
            while chunk := stream.read(min(1024 * 1024, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise SyncError('Archive size mismatch')
                f.write(chunk)
            if remaining:
                raise SyncError('Truncated archive member')

    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            for item in archive.infolist():
                out = target(item.filename, item.file_size)
                if stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1:
                    raise SyncError('Archive links/encryption are unsupported')
                if not item.is_dir():
                    with archive.open(item) as stream:
                        write(out, stream, item.file_size)
    elif tarfile.is_tarfile(source):
        with tarfile.open(source) as archive:
            for item in archive:
                out = target(item.name, item.size)
                if item.isdir():
                    continue
                if not item.isfile():
                    raise SyncError('Only regular TAR members are supported')
                with archive.extractfile(item) as stream:
                    write(out, stream, item.size)
    else:
        raise SyncError('Unsupported .roc format: expected ZIP or TAR (optionally compressed)')
    return destination


def extract(source, destination):
    try:
        return _extract(source, destination)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, tarfile.TarError,
            EOFError, RuntimeError, NotImplementedError, zlib.error) as exc:
        raise SyncError(f'Cannot read archive {source}: {exc}') from exc


def index(source, prefix):
    source = Path(source)
    paths = [source] if source.is_file() else sorted(source.rglob('*.ro'))
    result, folded_ids = {}, set()
    for path in paths:
        if path.is_symlink():
            raise SyncError(f'Symlink rule: {path}')
        try:
            rule = read(path)
        except Exception as exc:
            raise SyncError(f'{path}: {exc}') from exc
        rule_id = rule.get('id')
        if not isinstance(rule_id, str):
            raise SyncError(f'Missing string id: {path}')
        if not rule_id.startswith(prefix):
            continue
        if not ID.fullmatch(rule_id) or not SUFFIX.fullmatch(rule_id[len(prefix):]):
            raise SyncError(f'Unsafe rule id: {rule_id}')
        if rule_id.casefold() in folded_ids:
            raise SyncError(f'Duplicate rule id (case-insensitive): {rule_id}')
        folded_ids.add(rule_id.casefold())
        result[rule_id] = (path, rule)
    return result
