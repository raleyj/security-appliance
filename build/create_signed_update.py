#!/usr/bin/env python3
"""Create a deterministic signed Security Appliance update bundle."""
import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--private-key', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    records = []
    for value in args.paths:
        relative = Path(value).as_posix()
        source = root / relative
        if not source.is_file() or not (relative.startswith('app/') or relative.startswith('provisioning/')):
            raise SystemExit(f'Unsupported update path: {relative}')
        payload = source.read_bytes()
        records.append({'path': relative, 'sha256': hashlib.sha256(payload).hexdigest(), 'mode': '0755' if relative.endswith(('.py', '.sh')) else '0644'})
    manifest = {
        'schemaVersion': 1,
        'version': args.version,
        'createdUtc': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        'files': sorted(records, key=lambda row: row['path']),
    }
    manifest_raw = json.dumps(manifest, separators=(',', ':'), sort_keys=True).encode()
    private_key = serialization.load_pem_private_key(Path(args.private_key).read_bytes(), password=None)
    signature = private_key.sign(manifest_raw, padding.PKCS1v15(), hashes.SHA256())
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + '.new')
    with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('manifest.json', manifest_raw)
        bundle.writestr('manifest.sig', signature)
        for record in manifest['files']:
            bundle.writestr('payload/' + record['path'], (root / record['path']).read_bytes())
    temporary.replace(output)
    print(json.dumps({'bundle': str(output), 'version': args.version, 'files': len(records), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}, indent=2))


if __name__ == '__main__':
    main()
