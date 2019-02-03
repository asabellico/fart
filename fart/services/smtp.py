from __future__ import print_function

import nmap
import socket
import tempfile

from fart.utils import *

def enumusers(host, port, service, output_file, **kwargs):
    USERNAME_FILES = [
        '/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/names/namelist.txt'
    ]
    
    usernames = []
    for file in USERNAME_FILES:
        with open(file, 'r') as uf:
            usernames += uf.read().split()

    for name in usernames:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        connect=s.connect((host,int(port)))
        banner=s.recv(1024)
        s.send('HELO test@test.org \r\n')
        result= s.recv(1024)
        s.send('VRFY ' + name.strip() + '\r\n')
        result=s.recv(1024)
        no_vrfy_strings = ('not implemented', 'disallowed', 'not supported')
        if any(no_vrfy_str in result for no_vrfy_str in no_vrfy_strings):
           print('[{}] SMTP VRFY Command not available'.format(host))
           s.close()
           return

        if (('250' in result) or ('252' in result) and ('Cannot VRFY' not in result)):
           print_green('[{}] SMTP VRFY account found: {}'.format(host, name.strip()))

        s.close()

