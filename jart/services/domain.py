import nmap
import subprocess
import tempfile
from utils import *

def nmapscripts(host, port, service, output_file, **kwargs):
    DOMAIN_SCRIPTS= [
        'dns-zone-transfer'
    ]

    nm = nmap.PortScanner()
    args = '-vv -Pn -sV --script={} -oN {} '.format(','.join(DOMAIN_SCRIPTS), output_file)
    res = nm.scan(hosts=host, ports=port, arguments=args)


def dnsrecon(host, port, service, output_file, **kwargs):
    target = kwargs.get('target')
    # if target is None, set it to the host relative /24 subnet
    if not target:
        target = '.'.join(host.split('.')[0:3])+'.0/24'
        print_yellow('[{}] Cannot retrieve target network in dnsrecon. Setting it to {}'.format(host, target))

    DNSRECON = 'dnsrecon -n {} -t rvl -r {}'.format(host, target)
    found = []
    try:
        results = subprocess.check_output(DNSRECON, shell=True)
        _results = results.split("\n")
        for line in _results:
            if '+' in line and line not in found:
                found.append(line)
    except Exception as e:
       print_red('Error during dnsrecon: {}'.format(DNSRECON))
       print_red('Error message: {}'.format(e.message))

    if len(found) > 0:
        print_green('[*] Dnsrecon found the following items...')
        for item in found:
            print_green(item)
    else:
        print('No items found during dnsrecon')    


    with open(output_file, 'w') as output:
        output.write(results)
