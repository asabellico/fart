from __future__ import print_function

import nmap
import tempfile

from fart.utils import *

def nmapscripts(host, port, service, output_file, **kwargs):
    FTP_SCRIPTS= [
        'ftp-anon',
        'ftp-bounce',
        'ftp-libopie',
        'ftp-proftpd-backdoor',
        'ftp-vsftpd-backdoor',
        'ftp-vuln*',
    ]

    nm = nmap.PortScanner()
    args = '-vv -Pn -sV --script={} -oN {} '.format(','.join(FTP_SCRIPTS), output_file)
    res = nm.scan(hosts=host, ports=port, arguments=args)


def commonlogins(host, port, service, output_file, **kwargs):
    COMMON_USERS = [ 'root', 'toor', 'user', 'r00t' ]
    COMMON_PASS = [ 'root', 'toor', 'password', 'r00t', 'Password1', '12345678', '?????' ]

    usernames_path = tempfile.mktemp()
    passwords_path = tempfile.mktemp()
    with open(usernames_path, 'w') as usernames_file:
        usernames_file.write('\n'.join(COMMON_USERS))
        usernames_file.write('\n')


    with open(passwords_path, 'w') as passwords_file:
        passwords_file.write('\n'.join(COMMON_PASS))
        passwords_file.write('\n')

    HYDRA = 'hydra -v -I -L {} -P {} -t4 ftp://{}:{} 2>/dev/null'.format(usernames_path, passwords_path, host, port)
    try:
        results, __ = execute_cmd(HYDRA)
        _results = results.split('\n')

        for line in _results:
            if 'login:' in line:
                user = line.split(' ')[6]
                pwd = line.split(' ')[10]
                print_green('[{}] Valid FTP credentials found: {}:{}'.format(host, user, pwd))

        with open(output_file, 'w') as output:
            output.write(results)
    except Exception as e:
        print_red('Error during hydra (ftp): {}'.format(HYDRA))
        print_red('Error message: {}'.format(e))

    os.unlink(usernames_path)
    os.unlink(passwords_path)
