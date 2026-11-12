#!/usr/bin/python3
"""Fixed-function VM console; never offers an OS shell."""
import os,sys,json,time,getpass,signal,subprocess
from pathlib import Path
import console_recovery
STATE=Path('/etc/security-appliance')
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=30).stdout.strip()
def ask(label,secret=False):
 signal.alarm(60)
 try:return getpass.getpass(label) if secret else input(label)
 finally:signal.alarm(0)
def auth():
 console_recovery.begin_attempt(STATE);pw=ask('Console recovery password: ',True)
 good=console_recovery.finish_attempt(pw,STATE)
 run('logger','-t','security-recovery','authentication-success' if good else 'authentication-failed')
 if not good:raise ValueError('Authentication failed.')
def interrupted(*args):raise InterruptedError()
if os.geteuid()!=0 or not os.isatty(0) or os.ttyname(0)!='/dev/tty1':raise SystemExit('Local appliance console only.')
for sig in [signal.SIGINT,signal.SIGQUIT,signal.SIGTSTP,signal.SIGALRM]:signal.signal(sig,interrupted)
while True:
 try:
  print('\033[2J\033[HLab Security Appliance\n'+run('hostname')+'\n'+run('ip','-4','-brief','address'))
  print('1. Recover web administrator\n2. Service and firewall status\n3. Restart appliance')
  choice=ask('Selection: ')
  if choice=='2':print(run('ufw','status'));print(run('docker','ps','--format','{{.Names}}: {{.Status}}'))
  elif choice=='1':
   auth();name=ask('Existing web administrator: ');pw=ask('New password: ',True)
   if pw!=ask('Confirm password: ',True):raise ValueError('Passwords do not match.')
   if ask('Type RESET: ')=='RESET':
    console_recovery.reset_web_administrator(name,pw)
    print('Password reset. All GUI sessions invalidated.');run('logger','-t','security-recovery','password-reset-success')
  elif choice=='3':
   auth()
   if ask('Type RESTART: ')=='RESTART':run('systemctl','reboot')
  ask('Press Enter to continue: ')
 except (Exception,KeyboardInterrupt):print('Operation unavailable or cancelled.');time.sleep(2)
