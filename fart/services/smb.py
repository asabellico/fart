from __future__ import print_function

import nmap
import tempfile

from fart.utils import *

def nmapscripts(host, port, http_service, output_file, **kwargs):
    SMB_SCRIPTS= [
        'smb-vuln*'
    ]

    nm = nmap.PortScanner()
    args = '-vv -Pn -sV --script={} -oN {} '.format(','.join(SMB_SCRIPTS), output_file)
    res = nm.scan(hosts=host, ports=port, arguments=args)
    

def enum4linux(host, port, http_service, output_file, **kwargs):
    ENUM4LINUX = 'enum4linux -v {} 2>&1'.format(host)
    try:
        results, __  = execute_cmd(ENUM4LINUX)

        with open(output_file, 'w') as output:
            output.write(results)
    except Exception as e:
        print_red('Error during enum4linux: {}'.format(ENUM4LINUX))
        print_red('Error message: {}'.format(e))

    