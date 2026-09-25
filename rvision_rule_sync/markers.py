"""Locate user annotations without removing or rewriting any source text."""
START = '# начало моих изменений'
END = '# конец моих изменений'


def custom_regions(rule):
    regions, warnings = [], []

    def walk(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, path + [key])
        elif isinstance(value, list):
            for number, child in enumerate(value):
                walk(child, path + [number])
        elif isinstance(value, str):
            opening = None
            lines = value.replace('\r\n', '\n').replace('\r', '\n').splitlines(keepends=True)
            for number, line in enumerate(lines, 1):
                marker = line.strip()
                if marker == START:
                    if opening is not None:
                        warnings.append({'path': path, 'line': number, 'message': 'Вложенное начало моих изменений'})
                    else:
                        opening = number
                elif marker == END:
                    if opening is None:
                        warnings.append({'path': path, 'line': number, 'message': 'Конец моих изменений без начала'})
                    else:
                        regions.append({'path': path, 'block': path[0], 'start_line': opening,
                                        'end_line': number, 'code': ''.join(lines[opening:number - 1])})
                        opening = None
            if opening is not None:
                warnings.append({'path': path, 'line': opening, 'message': 'Начало моих изменений без конца'})

    # test/tests are intentionally outside the comparison and annotation scope.
    for key, value in rule.items():
        if key not in ('test', 'tests'):
            walk(value, [key])
    return {'custom_regions': regions, 'marker_warnings': warnings}
