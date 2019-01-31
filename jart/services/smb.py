from __future__ import print_function

import nmap
import subprocess
import tempfile
from jart.utils import *

def nmapscripts(host, port, http_service, output_file, **kwargs):
    SMB_SCRIPTS= [
        'smb-vuln*'
    ]

    nm = nmap.PortScanner()
    args = '-vv -Pn -sV --script={} -oN {} '.format(','.join(SMB_SCRIPTS), output_file)
    res = nm.scan(hosts=host, ports=port, arguments=args)
    

def enum4linux(host, port, http_service, output_file, **kwargs):
    ENUM4LINUX = 'enum4linux -v {}'.format(host)
    try:
        results = subprocess.check_output(DIRBSCAN, shell=True)
    except Exception as e:
        print_red('Error during enum4linux: {}'.format(ENUM4LINUX))
        print_red('Error message: {}'.format(e))

    with open(output_file, 'w') as output:
        output.write(results)
