#!/usr/bin/env python3
"""Verify and install signed appliance update bundles with atomic rollback."""
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import time
import sqlite3
from pathlib import Path, PurePosixPath

APPLIANCE_ROOT = Path('/opt/security-appliance')
STATE_ROOT = Path('/etc/security-appliance')
PUBLIC_KEY = APPLIANCE_ROOT / 'provisioning/release-signing-key.pub.pem'
ALLOWED_PREFIXES = ('app/', 'provisioning/')
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
NATIVE_VIEWER_ROLES=True
MANAGEMENT_DB=Path('/var/lib/security-appliance/management/management.sqlite')

def enabled_viewers():
    if not MANAGEMENT_DB.exists():return False
    with sqlite3.connect(MANAGEMENT_DB) as connection:
        tables={r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'user_roles' not in tables:return False
        return bool(connection.execute("SELECT 1 FROM users u JOIN user_roles r ON r.name=u.name LEFT JOIN account_state a ON a.name=u.name WHERE r.role='viewer' AND COALESCE(a.enabled,1)=1 LIMIT 1").fetchone())

def require_viewer_compatible(contents):
    if enabled_viewers():
        for name,raw in contents:
            if name in ('app/server.py','provisioning/update_bundle.py') and b'NATIVE_VIEWER_ROLES=True' not in raw:
                raise ValueError('Disable viewer accounts before restoring or installing code without native viewer authorization.')


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def valid_relative_path(value):
    if not isinstance(value, str) or not value or '\\' in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and '..' not in path.parts and any(value.startswith(prefix) for prefix in ALLOWED_PREFIXES) and bool(re.fullmatch(r'[A-Za-z0-9._/-]+', value))


def verify_signature(data, signature, public_key):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        key = serialization.load_pem_public_key(Path(public_key).read_bytes())
        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return
    except ImportError:
        pass
    except Exception as exc:
        raise ValueError('Update signature verification failed.') from exc
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        data_path = folder / 'manifest.json'
        signature_path = folder / 'manifest.sig'
        data_path.write_bytes(data)
        signature_path.write_bytes(signature)
        result = subprocess.run(
            ['openssl', 'dgst', '-sha256', '-verify', str(public_key), '-signature', str(signature_path), str(data_path)],
            capture_output=True, timeout=30,
        )
        if result.returncode:
            raise ValueError('Update signature verification failed.')


def inspect_bundle(bundle, public_key=PUBLIC_KEY):
    bundle = Path(bundle)
    if not bundle.is_file() or bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError('Invalid appliance update bundle.')
    try:
        with zipfile.ZipFile(bundle) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError('Update contains duplicate records.')
            if names.count('manifest.json') != 1 or names.count('manifest.sig') != 1:
                raise ValueError('Update manifest or signature is missing.')
            if len(names) > 256:
                raise ValueError('Update contains too many files.')
            manifest_raw = archive.read('manifest.json')
            signature = archive.read('manifest.sig')
            verify_signature(manifest_raw, signature, public_key)
            manifest = json.loads(manifest_raw)
            if manifest.get('schemaVersion') != 1 or not re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z._-]{0,63}', manifest.get('version', '')):
                raise ValueError('Unsupported update manifest.')
            files = manifest.get('files')
            if not isinstance(files, list) or not files:
                raise ValueError('Update payload is empty.')
            expected_names = {'manifest.json', 'manifest.sig'}
            seen = set()
            for item in files:
                path = item.get('path') if isinstance(item, dict) else None
                digest = item.get('sha256') if isinstance(item, dict) else None
                mode = item.get('mode', '0644') if isinstance(item, dict) else None
                if not valid_relative_path(path) or path in seen or not re.fullmatch(r'[0-9a-f]{64}', digest or '') or mode not in ('0644', '0755'):
                    raise ValueError('Update manifest contains an invalid file entry.')
                seen.add(path)
                member = 'payload/' + path
                expected_names.add(member)
                info = archive.getinfo(member)
                if info.is_dir() or info.external_attr >> 28 == 0xA:
                    raise ValueError('Update payload cannot contain links or directories.')
                content = archive.read(member)
                if len(content) > 8 * 1024 * 1024 or sha256_bytes(content) != digest:
                    raise ValueError('Update payload digest verification failed.')
            if set(names) != expected_names:
                raise ValueError('Update contains undeclared content.')
            require_viewer_compatible([(row['path'],archive.read('payload/'+row['path'])) for row in files])
            return manifest
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError, OSError) as exc:
        raise ValueError('Invalid appliance update bundle.') from exc


def _write_atomic(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.update-new')
    temporary.write_bytes(content)
    os.chmod(temporary, int(mode, 8))
    temporary.replace(path)


def _history(state_root, entry):
    path = state_root / 'update-history.json'
    try:
        current = json.loads(path.read_text())
        if not isinstance(current, list):current = []
    except (OSError, ValueError):
        current = []
    current.append(entry)
    _write_atomic(path, (json.dumps(current[-20:], sort_keys=True) + '\n').encode(), '0600')


def _default_post_install(changed, root):
    def run(*args):
        subprocess.run(args, check=True, capture_output=True, timeout=900)
    if 'app/Dockerfile' in changed:
        base=re.search(r'^FROM\s+(\S+)',(root/'app/Dockerfile').read_text(),re.M)
        if not base:raise ValueError('The management image base is invalid.')
        run('docker','pull',base.group(1))
    if any(path.startswith('app/') for path in changed):
        run('docker', 'build', '--pull=false', '-t', 'lab-security-management:0.3.0', str(root / 'app'))
    if any(path.startswith('provisioning/kmip-client/') for path in changed):
        base=re.search(r'^FROM\s+(\S+)',(root/'provisioning/kmip-client/Dockerfile').read_text(),re.M)
        if not base:raise ValueError('The KMIP client image base is invalid.')
        run('docker','pull',base.group(1))
        run('docker','build','--pull=false','-t','lab-security-kmip-client:0.2.0',str(root/'provisioning/kmip-client'))
    proxy_changed=any(path.startswith('provisioning/reverse-proxy/') for path in changed) or any(path in changed for path in ('provisioning/proxy-image.json','provisioning/compose_runtime.py','provisioning/render_proxy.py'))
    proxy_lock=root/'provisioning/proxy-image.json'
    if proxy_changed and proxy_lock.exists():
        proxy=json.loads(proxy_lock.read_text())
        source,local=proxy.get('source',''),proxy.get('local','')
        if not re.fullmatch(r'nginx:[0-9.]+-alpine@sha256:[0-9a-f]{64}',source) or not re.fullmatch(r'lab-security-proxy:[0-9.]+-alpine-security-[0-9]{8}',local):
            raise ValueError('The proxy image lock is invalid.')
        run('docker','pull',source)
        dockerfile=root/'provisioning/reverse-proxy/Dockerfile'
        if dockerfile.exists():run('docker','build','--provenance=false','--pull=false','-t',local,str(dockerfile.parent))
        else:run('docker','tag',source,local)
    run('python3', str(root / 'provisioning/compose_runtime.py'))
    run('python3', str(root / 'provisioning/compose_runtime.py'), '--verify')
    restart_host = any(path.startswith('provisioning/') for path in changed)
    if 'provisioning/console.py' in changed or 'provisioning/console_recovery.py' in changed:
        run('systemctl', 'restart', 'security-console')
    run('docker', 'compose', '-f', '/etc/security-appliance/compose.json', 'up', '-d', '--no-build', '--pull', 'never', 'management')
    if proxy_changed:
        run('python3',str(root/'provisioning/render_proxy.py'))
        run('docker','compose','-f','/etc/security-appliance/compose.json','up','-d','--no-build','--pull','never','--no-deps','--force-recreate','proxy')
        run('docker','exec','security-proxy','nginx','-t')
    import service_control
    for _ in range(20):
        rows=service_control.status()['services']
        if len(rows)==len(service_control.SERVICES) and all(row['ready'] for row in rows):break
        time.sleep(3)
    else:raise ValueError('A service did not become ready after the update.')
    if restart_host:
        # The caller runs in this service. Restart only after install_bundle commits
        # its signed-release history and rollback metadata.
        unit='security-host-control-update-'+os.urandom(4).hex()
        run('systemd-run','--unit='+unit,'--on-active=30s','/usr/bin/systemctl','restart','security-host-control')


def install_bundle(bundle, public_key=PUBLIC_KEY, root=APPLIANCE_ROOT, state_root=STATE_ROOT, post_install=None):
    root, state_root = Path(root), Path(state_root)
    manifest = inspect_bundle(bundle, public_key)
    update_root = state_root / 'update-rollback'
    prior_rollback = state_root / 'update-rollback-prior'
    if prior_rollback.exists():shutil.rmtree(prior_rollback)
    if update_root.exists():update_root.rename(prior_rollback)
    update_root.mkdir(parents=True, mode=0o700)
    previous_release = (state_root / 'release.json').read_bytes() if (state_root / 'release.json').exists() else None
    changed = []
    existed = []
    installed_at = time.time()
    bundle_digest = hashlib.sha256(Path(bundle).read_bytes()).hexdigest()
    try:
        with zipfile.ZipFile(bundle) as archive:
            for item in manifest['files']:
                relative = item['path']
                target = root / relative
                backup = update_root / relative
                if target.exists():
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target, backup)
                    existed.append(relative)
                _write_atomic(target, archive.read('payload/' + relative), item.get('mode', '0644'))
                changed.append(relative)
        _write_atomic(state_root / 'release.json', json.dumps({'version': manifest['version'], 'manifestSha256': sha256_bytes(json.dumps(manifest, separators=(',', ':'), sort_keys=True).encode())}, sort_keys=True).encode() + b'\n', '0600')
        (post_install or _default_post_install)(changed, root)
        metadata={'version':manifest['version'],'previousVersion':json.loads(previous_release).get('version') if previous_release else None,
                  'installedAt':installed_at,'bundleSha256':bundle_digest,'manifestSha256':json.loads((state_root/'release.json').read_text())['manifestSha256'],
                  'signingKeySha256':hashlib.sha256(Path(public_key).read_bytes()).hexdigest(),'healthResult':'passed',
                  'changed':changed,'existed':existed}
        _write_atomic(update_root/'metadata.json',(json.dumps(metadata,sort_keys=True)+'\n').encode(),'0600')
        if previous_release is not None:_write_atomic(update_root/'release.previous.json',previous_release,'0600')
        _history(state_root,{k:metadata[k] for k in ('version','previousVersion','installedAt','bundleSha256','manifestSha256','signingKeySha256','healthResult')})
        if prior_rollback.exists():shutil.rmtree(prior_rollback)
    except Exception:
        for relative in reversed(changed):
            target, backup = root / relative, update_root / relative
            if backup.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup, target)
            else:
                target.unlink(missing_ok=True)
        release = state_root / 'release.json'
        if previous_release is None:
            release.unlink(missing_ok=True)
        else:
            _write_atomic(release, previous_release, '0600')
        try:
            (post_install or _default_post_install)(changed, root)
        except Exception:
            pass
        shutil.rmtree(update_root,ignore_errors=True)
        if prior_rollback.exists():prior_rollback.rename(update_root)
        raise ValueError('Update installation failed and was rolled back.') from None
    return {'installed': True, 'version': manifest['version'], 'files': len(changed), 'rollbackRetained': True}


def status(state_root=STATE_ROOT, public_key=PUBLIC_KEY):
    state_root = Path(state_root)
    try:
        release = json.loads((state_root / 'release.json').read_text())
    except (OSError, json.JSONDecodeError):
        release = {'version': 'build-candidate'}
    fingerprint = hashlib.sha256(Path(public_key).read_bytes()).hexdigest() if Path(public_key).exists() else None
    try:metadata=json.loads((state_root/'update-rollback/metadata.json').read_text())
    except (OSError,ValueError):metadata={}
    try:history=json.loads((state_root/'update-history.json').read_text())
    except (OSError,ValueError):history=[]
    return {'version': release.get('version', 'build-candidate'), 'signatureVerification': bool(fingerprint), 'signingKeySha256': fingerprint,
            'rollbackAvailable': bool(metadata) and (state_root/'update-rollback/release.previous.json').is_file(),'previousVersion':metadata.get('previousVersion'),'installedAt':metadata.get('installedAt'),
            'bundleSha256':metadata.get('bundleSha256'),'manifestSha256':release.get('manifestSha256'),'healthResult':metadata.get('healthResult'),
            'history':history[-20:] if isinstance(history,list) else []}


def restore_previous(root=APPLIANCE_ROOT,state_root=STATE_ROOT,post_install=None):
    root,state_root=Path(root),Path(state_root)
    backup=state_root/'update-rollback'
    try:
        metadata=json.loads((backup/'metadata.json').read_text())
        previous=(backup/'release.previous.json').read_bytes()
        changed=metadata['changed'];existed=set(metadata['existed'])
        if not changed or any(not valid_relative_path(path) for path in changed):raise ValueError()
        if any(not (backup/path).is_file() for path in existed):raise ValueError()
    except (OSError,KeyError,TypeError,ValueError):raise ValueError('A qualified prior release is not available.') from None
    current_release=(state_root/'release.json').read_bytes()
    require_viewer_compatible([(name,(backup/name).read_bytes()) for name in existed])
    with tempfile.TemporaryDirectory(prefix='security-restore-',dir=state_root) as folder:
        snapshot=Path(folder)
        for relative in changed:
            target=root/relative
            if target.is_file():
                (snapshot/relative).parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(target,snapshot/relative)
        try:
            for relative in changed:
                target=root/relative
                if relative in existed:shutil.copy2(backup/relative,target)
                else:target.unlink(missing_ok=True)
            _write_atomic(state_root/'release.json',previous,'0600')
            (post_install or _default_post_install)(changed,root)
        except Exception:
            for relative in changed:
                target=root/relative
                if (snapshot/relative).is_file():shutil.copy2(snapshot/relative,target)
                else:target.unlink(missing_ok=True)
            _write_atomic(state_root/'release.json',current_release,'0600')
            try:(post_install or _default_post_install)(changed,root)
            except Exception:pass
            raise ValueError('Prior release restoration failed; current release was retained.') from None
    _history(state_root,{'version':metadata.get('previousVersion'),'previousVersion':metadata.get('version'),'installedAt':time.time(),
                         'bundleSha256':None,'manifestSha256':json.loads(previous).get('manifestSha256'),'signingKeySha256':metadata.get('signingKeySha256'),
                         'healthResult':'passed','operation':'restore'})
    shutil.rmtree(backup)
    return {'restored':True,'version':metadata.get('previousVersion'),'healthResult':'passed'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('status', 'verify', 'install'))
    parser.add_argument('bundle', nargs='?')
    args = parser.parse_args()
    if args.operation == 'status':
        result = status()
    elif args.operation == 'verify':
        result = inspect_bundle(args.bundle)
    else:
        result = install_bundle(args.bundle)
    print(json.dumps(result, separators=(',', ':')))
