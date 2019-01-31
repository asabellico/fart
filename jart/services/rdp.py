from __future__ import print_function

import nmap
import subprocess
import tempfile
from jart.utils import *



def commonlogins(host, port, service, output_file, **kwargs):
    COMMON_USERS = [ 'Administrator' ]
    COMMON_PASS = [ 's3cr3t', 'admin', 'password', 'pass123', 'Password1', '12345678', '?????' ]

    usernames_path = tempfile.mktemp()
    passwords_path = tempfile.mktemp()
    with open(usernames_path, 'w') as usernames_file:
        usernames_file.write('\n'.join(COMMON_USERS))
        usernames_file.write('\n')

    with open(passwords_path, 'w') as passwords_file:
        passwords_file.write('\n'.join(COMMON_PASS))
        passwords_file.write('\n')

    NCRACK = 'ncrack -vv -f -U {} -P {} --passwords-first rdp://{}:{},CL=1'.format(usernames_path, passwords_path, host, port)
    try:
        results = subprocess.check_output(NCRACK, shell=True)
        _results = results.split('\n')
        for line in _results:
            if 'Discovered credentials on' in line:
                user = line.split(' ')[4].strip('\'')
                pwd = line.split(' ')[5].strip('\'')
                print_green('[{}] Valid RDP credentials found: {}:{}'.format(host, user, pwd))

        with open(output_file, 'w') as output:
            output.write(results)
    except Exception as e:
        print_red('Error during ncrack (rdp): {}'.format(NCRACK))
        print_red('Error message: {}'.format(e))

    os.unlink(usernames_path)
    os.unlink(passwords_path)
