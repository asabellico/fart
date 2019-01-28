import nmap
import subprocess
import tempfile
from utils import *

VENDOR_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'vendor')

def nmapscripts(host, port, service, output_file, **kwargs):
    SCRIPTS= [
        'snmp-netstat',
        'snmp-processes',
        'snmp-interfaces',
        'snmp-win32-users',
        'snmp-win32-services',
        'snmp-win32-shares',
        'snmp-win32-software',
        'snmp-win32-sysdescr',
    ]

    nm = nmap.PortScanner()
    args = '-vv -Pn -sV --script={} -oN {} '.format(','.join(SCRIPTS), output_file)
    res = nm.scan(hosts=host, ports=port, arguments=args)

def enum(host, port, service, output_file, **kwargs):
    COMMUNITIES = [
        'public',
        'private',
        'manager'
    ]
    community_file_path = tempfile.mktemp()
    with open(community_file_path, 'w') as community_file:
        for comm in COMMUNITIES:
            community_file.write('{}\n'.format(comm))
    
    ONESIXONESCAN = "onesixtyone -c {} {}".format(community_file_path, host)
    results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()
    _results = results.split('\n')
    snmp_active = False
    for line in _results:
        if 'Scanning' in line:
            continue

        snmp_active = True
        print_green('[{}] Host responds to SNMP request: {}'.format(host, line))
        if 'Windows' in line:
            print_green('[{}] Detected Windows system during SNMP enumeration'.format(host))
        elif 'Linux' in line:
            print_green('[{}] Detected Linux system during SNMP enumeration'.format(host))

    if not snmp_active:
        return

    output = open(output_file, 'w')
    output.write('*** ONESIXONE output ***')
    output.write(results)
    output.write('\n')

    MIB_VALUES = [
        ('1.3.6.1.2.1.25.1.6.0',   'System Processes'),
        ('1.3.6.1.2.1.25.4.2.1.2', 'Running programs'),
        ('1.3.6.1.2.1.25.4.2.1.4', 'Processes path'),
        ('1.3.6.1.2.1.25.2.3.1.4', 'Storage units'),
        ('1.3.6.1.2.1.25.6.3.1.2', 'Software name'),
        ('1.3.6.1.4.1.77.1.2.25',  'User accounts'),
        ('1.3.6.1.2.1.6.13.1.3',   'TCP local ports'),
    ]

    output.write('*** SNMPWALK OUTPUT ***\n')
    for mib, mib_name in MIB_VALUES:
        output.write('- MIB value: {} ({})\n'.format(mib, mib_name))
        for comm in COMMUNITIES:
            output.write('-- Community string: {}\n'.format(comm))
            SNMPWALK = "snmpwalk -c {} -v1 {} {} 2>/dev/null".format(comm, host, mib)
            p = subprocess.Popen(SNMPWALK, stdout=subprocess.PIPE, shell=True)
            results, __ = p.communicate()
            output.write(results)
    output.write('\n')

    output.write('*** SNMP-CHECK OUTPUT ***\n')
    for comm in COMMUNITIES:
        output.write('-- Community string: {}\n'.format(comm))
        SNMPWALK = "snmp-check -c {} {} 2>/dev/null".format(comm, host)
        p = subprocess.Popen(SNMPWALK, stdout=subprocess.PIPE, shell=True)
        results, __ = p.communicate()
        output.write(results)
    output.write('\n')

    output.close()
    os.unlink(community_file_path)
