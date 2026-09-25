"""Build a ZIP .roc from a synthetic rule, without any third-party content."""
from pathlib import Path
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    destination = root / 'examples' / 'SIEM' / 'demo.roc'
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.write(root / 'tests/fixtures/RV-D-DEMO1.package.ro', 'demo/vendor.ro')
    print(destination)


if __name__ == '__main__':
    main()
