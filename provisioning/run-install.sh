#!/usr/bin/env bash
umask 077
bash /opt/security-appliance/provisioning/install.sh >/var/log/security-build.log 2>&1
result=$?
if [ "$result" != 0 ]; then
  python3 - <<'PY'
import json,subprocess
from pathlib import Path
# Provisioning log contains package/build output, not password values.
lines=Path('/var/log/security-build.log').read_text(errors='replace').splitlines()[-25:]
subprocess.run(['vmtoolsd','--cmd','info-set guestinfo.security.build '+json.dumps({'status':'failed','tail':lines})])
PY
fi
exit "$result"
