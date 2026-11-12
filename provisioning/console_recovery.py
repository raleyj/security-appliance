#!/usr/bin/env python3
"""Testable fixed-function console recovery operations."""
import hashlib
import hmac
import json
import os
import subprocess
import time
from pathlib import Path

STATE = Path('/etc/security-appliance')


def _atomic_json(path, value):
    temporary = path.with_name(path.name + '.new')
    temporary.write_text(json.dumps(value, separators=(',', ':')))
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def begin_attempt(state=STATE, now=None):
    state, now = Path(state), time.time() if now is None else now
    path = state / 'recovery-attempts.json'
    try:
        attempts = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        attempts = {'failures': 0, 'notBefore': 0}
    if float(attempts.get('notBefore', 0)) > now:
        raise ValueError('Recovery temporarily locked.')
    failures = min(int(attempts.get('failures', 0)) + 1, 10)
    pending = {'failures': failures, 'notBefore': now + min(300, 5 * 2 ** (failures - 1))}
    _atomic_json(path, pending)
    return pending


def finish_attempt(password, state=STATE):
    state = Path(state)
    record = json.loads((state / 'recovery.json').read_text())
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(record['salt']), n=16384, r=8, p=1, dklen=64)
    valid = hmac.compare_digest(candidate, bytes.fromhex(record['hash']))
    if valid:
        _atomic_json(state / 'recovery-attempts.json', {'failures': 0, 'notBefore': 0})
    return valid


def verify_password(password, state=STATE, now=None):
    begin_attempt(state, now)
    return finish_attempt(password, state)


def _run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=30, **kwargs)


def reset_web_administrator(username, password, runner=_run):
    payload = json.dumps({'username': username, 'password': password})
    stopped = False
    reset_error = None
    try:
        runner(['docker', 'stop', 'security-management'])
        stopped = True
        result = runner([
            'docker', 'run', '--rm', '-i', '--network', 'none', '--user', '0',
            '-v', '/var/lib/security-appliance/management:/var/lib/security-appliance/management',
            'lab-security-management:0.3.0', 'python', '-c',
            'import json,sys;from server import reset_password;d=json.load(sys.stdin);reset_password(d["username"],d["password"])'
        ], input=payload)
    except Exception as exc:
        reset_error = exc
    restart_error = None
    if stopped:
        try:
            runner(['docker', 'start', 'security-management'])
        except Exception as exc:
            restart_error = exc
    if restart_error:
        raise RuntimeError('The administrator reset completed or failed, but the management service did not restart.') from restart_error
    if reset_error:
        raise ValueError('Recovery rejected the administrator name or password policy.') from None
    return {'reset': True, 'sessionsInvalidated': True, 'managementRestarted': True}
