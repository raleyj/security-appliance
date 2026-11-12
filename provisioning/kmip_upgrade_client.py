#!/usr/bin/env python3
"""Small KMIP upgrade/rotation qualification client using disposable key data."""
import argparse
import json
from pathlib import Path

from kmip.core import enums
from kmip.pie.client import ProxyKmipClient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--operation', choices=('create', 'read', 'expect-rejected'), required=True)
    parser.add_argument('--id-file', required=True)
    args = parser.parse_args()
    root = Path('/qualification')
    id_file = Path(args.id_file)
    client = ProxyKmipClient(
        hostname=args.host,
        port=5696,
        cert=str(root / 'client.pem'),
        key=str(root / 'client.key'),
        ca=str(root / 'ca.pem'),
        ssl_version='PROTOCOL_TLSv1_2',
    )
    if args.operation == 'expect-rejected':
        try:
            with client as connection:
                connection.get(id_file.read_text().strip())
        except Exception:
            print(json.dumps({'operation': args.operation, 'rejected': True}))
            return
        raise SystemExit('The certificate removed from the KMIP trust bundle was still accepted.')
    with client as connection:
        if args.operation == 'create':
            uid = connection.create(enums.CryptographicAlgorithm.AES, 256)
            connection.activate(uid)
            id_file.write_text(uid)
        else:
            uid = id_file.read_text().strip()
        connection.get(uid)
    print(json.dumps({'operation': args.operation, 'uid': uid, 'retrieved': True}))


if __name__ == '__main__':
    main()
