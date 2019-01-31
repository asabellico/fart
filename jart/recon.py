#!/usr/bin/python
from __future__ import print_function

import nmap
import os
import re
import subprocess
import time
import ipaddress
import tempfile

from jart.services import (
    domain, 
    ftp, 
    http, 
    rdp,
    snmp,
    smb, 
    smtp,
    ssh
)
from jart.utils import *
VENDOR_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'vendor')

from multiprocessing import Process

def target_recon(args):
    complete_recon_start_time = time.time()

    target_list = parse_targets(args.target)
    if target_list is None:
        print_red('Error while parsing target(s)')
        exit(1)

    # alive host scan
    if not args.skip_icmp_sweep:
        targets_to_scan = check_alive_hosts(target_list)
        print_green('Found {} alive host(s) during ICMP alive host scan'.format(len(targets_to_scan)))    
    else:
        print_yellow('Skipping ICMP ping sweep...')
        targets_to_scan = target_list

    beep()
    print_green('Scanning host(s): {}'.format(', '.join(targets_to_scan)))
    print('Max concurrent host scan set to {}'.format(args.max_concurrent))

    targets_to_scan.reverse()

    # services scan
    scan_queue = []
    for host in targets_to_scan:
        host = str(host)

        try:
            host_work_dir = os.path.join(args.output, host)
            os.makedirs(host_work_dir)
        except OSError:
            print_yellow('Output directory for host {} does exist. Overwriting!'.format(host))

        scan_proc = Process(target=host_recon, args=(host, host_work_dir, args.skip_tcp, args.skip_udp, args.fast_port_scan))
        scan_queue.append(scan_proc)


    running_scans = []
    while True:
        # start pending scans
        while len(running_scans) < args.max_concurrent and len(scan_queue) > 0:
            p = scan_queue.pop()

            p_info = {
                'start_time': time.time(),
                'host': p._args[0]
            }

            print('[{}] Launching {}recon'.format(p._args[0], '(fast-port-scan) '*args.fast_port_scan))
            p.start()
            
            running_scans.append( (p, p_info) )

        # remove terminated scans
        for p_data in running_scans:
            p, p_info = p_data

            if not p.is_alive():
                running_scans.remove(p_data)

                print('[{}] Finished host recon (duration: {})'.format(p_info.get('host'), hms_string(time.time()-float(p_info.get('start_time')))))
                beep()


        # exit loop when nothing to do
        if len(running_scans) + len(scan_queue) == 0:
            break

        time.sleep(3)

    # TODO post-scan 
    # check for duplicated ssh keys
    # ...

    print('')
    print_green('Recon terminated. Output reports placed in {}'.format(args.output))
    print('Total execution time: {}'.format(hms_string(time.time()-complete_recon_start_time)))
    beep()


def parse_targets(target):
    cidr_pattern = re.compile(r'\d{1,3}.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}')
    range_pattern = re.compile(r'\d{1,3}.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}')
    ip_pattern = re.compile(r'\d{1,3}.\d{1,3}\.\d{1,3}\.\d{1,3}')

    if cidr_pattern.match(target):
        # cidr
        try:
            target_network = ipaddress.ip_network(unicode(target))
            if target_network.num_addresses == 1:
                targets = [ str(target_network)[:-3] ]
            else:
                targets = [ str(addr) for addr in target_network.hosts() ]
        except Exception:
            print_red('Invalid CIDR target: {}'.format(target))
            return None

    elif range_pattern.match(target):
        try:
            targets = []

            # range
            prefix_str = '.'.join(target.split('.')[0:3])
            range_str = target.split('.')[3]
            
            start = int(range_str.split('-')[0])
            end = int(range_str.split('-')[1])

            if start not in range(1, 255+1) or end not in range(1, 255+1):
                raise Exception

            for lb in range(start, end+1):
                targets.append(prefix_str + '.' + str(lb))
        except Exception:
            print_red('Invalid IP range target: {}'.format(target))
            return None

    elif ip_pattern.match(target):
        # single ip
        targets = [ target ]

    elif os.path.isfile(target):
        # file list
        with open(target) as targets_file:
            targets = [ line.strip() for line in targets_file.readlines() ]

    else:
        # error
        return None

    return targets

def check_alive_hosts(target):
    # generate host file list
    target_file_path = tempfile.mktemp()
    with open(target_file_path, 'w') as target_file:
        for h in target:
            target_file.write(h+'\n')

    nm = nmap.PortScanner()
    res = nm.scan(arguments='-sn -iL {}'.format(target_file_path))

    os.unlink(target_file_path)
    
    nmap_alive_hosts = []
    for host in res['scan']:
        if res['scan'][host]['status']['state'] == 'up':
            nmap_alive_hosts.append(host)
        else:
            print_yellow('{} does not respond to ICMP ping request'.format(host))

    #print_green('Nmap (-sn) found {} alive host(s)'.format(len(nmap_alive_hosts)))
    return nmap_alive_hosts

    # PINGSWEEP = 'sh {}/pingsweep.sh {}'.format(VENDOR_PATH, target)
    # results = subprocess.check_output(PINGSWEEP, shell=True)
    # _results = results.split('\n')
    # pingsweep_alive_hosts = []
    # for line in _results:
    #     if 'responds to ICMP ping request' in line:
    #         pingsweep_alive_hosts.append(line.split()[0])
    
    # print_green('Pingsweep found {} alive host(s)'.format(len(pingsweep_alive_hosts)))

    # merge_alive_hosts = set()
    # for h in nmap_alive_hosts + pingsweep_alive_hosts:
    #     merge_alive_hosts.add(h)
    # return list(merge_alive_hosts)


def host_recon(host, work_dir, skip_tcp, skip_udp, fast_port_scan):
    SERVICES_RECON_MAP = {
        'domain': [
            domain.nmapscripts,
            domain.dnsrecon,
        ],

        'ftp': [
            ftp.nmapscripts,
            ftp.commonlogins,
        ],

        'http': [
            http.nmapscripts,
            http.webdav,
            http.shellshock,

            http.dirbuster,
        ],

        'https': [
            http.nmapscripts,
            http.heartbleed,
            http.webdav,
            http.shellshock,

            http.dirbuster,
        ],

        'microsoft-ds': [
            smb.nmapscripts,
        ],

        'rdp': [
            rdp.commonlogins,
        ],

        'smtp': [
            smtp.enumusers,
        ],
        
        'snmp': [
            snmp.nmapscripts,
            snmp.enum,
        ],
        
        'ssh': [
            ssh.nmapscripts,
            ssh.commonlogins,
        ],

    }

    # TCP recon
    if not skip_tcp:
        print('[{}] Starting nmap {}TCP port scan...'.format(host, '(fast) '*fast_port_scan))
        tcp_txt_output_path = os.path.join(work_dir, '{}_TCP.txt'.format(host))
        tcp_xml_output_path = os.path.join(work_dir, '{}_TCP.xml'.format(host))
        tcp_services = initial_host_tcp_recon(host, tcp_txt_output_path, tcp_xml_output_path, fast_port_scan)
        print('[{}] Finished nmap {}TCP port scan...'.format(host, '(fast) '*fast_port_scan))
    else:
        tcp_services = {}

    # UDP recon
    if not skip_udp:
        print('[{}] Starting nmap {}UDP port scan...'.format(host, '(fast) '*fast_port_scan))
        udp_txt_output_path = os.path.join(work_dir, '{}_UDP.txt'.format(host))
        udp_xml_output_path = os.path.join(work_dir, '{}_UDP.xml'.format(host))
        udp_services = initial_host_udp_recon(host, udp_txt_output_path, udp_xml_output_path, fast_port_scan)
        print('[{}] Finished nmap {}UDP port scan...'.format(host, '(fast) '*fast_port_scan))
    else:
        udp_services = {}

    # merge TCP and UDP services
    services = tcp_services.copy()
    services.update(udp_services)

    print('[{}] Starting host available services scan...'.format(host))
    for serv_port, serv in services.items():
        if 'open' not in serv.get('state'):
            print_yellow('[{}] {} service is not open. Skipping analysis...'.format(host, serv.get('name')))
            continue

        if serv.get('name') in SERVICES_RECON_MAP:
            for serv_recon in SERVICES_RECON_MAP[serv.get('name')]:
                serv_recon_output = os.path.join(work_dir, '{}_{}.txt'.format(serv.get('name'), serv_recon.__name__))
                
                print('[{}] Starting {} recon for {} service...'.format(host, serv_recon.__name__, serv.get('name')))
                start_time = time.time()

                try:
                    serv_recon(host, str(serv_port), serv, serv_recon_output)
                except Exception as e:
                    print_red('[{}] Exception while executing {} recon procedure'.format(host, serv_recon.__name__))
                    print_red('[{}] Error message: {}'.format(host, e))
                print('[{}] Finished {} recon for {} service (duration: {})'.format(
                    host, serv_recon.__name__, serv.get('name'), 
                    hms_string(time.time()-start_time))
                )
        else:
            if serv.get('name') in ('tcpwrapped'):
                print_red('[{}] No recon procedure defined for {}. Skipping..'.format(host, serv.get('name')))
            else:
                print('[{}] No recon procedure defined for {}. Skipping..'.format(host, serv.get('name')))
    
    print('[{}] Finished host services scan...'.format(host))
 

def initial_host_tcp_recon(host, txt_output_path=None, xml_output_path=None, fast_port_scan=False):
    nm = nmap.PortScanner()

    if fast_port_scan:
        args = '-vv -Pn -A -sC -sS --top-ports=20 --open -T4 -oN {}'.format(txt_output_path)
        res = nm.scan(hosts=host, arguments=args)
    else:
        args = '-vv -Pn -A -sC -sS -T4 --open -oN {}'.format(txt_output_path)
        res = nm.scan(hosts=host, ports='-', arguments=args)        
    
    # output XML (if requested)
    if xml_output_path:
        with open(xml_output_path, 'w') as xml_output:
            xml_output.write(nm.get_nmap_last_output())

    if host not in nm.all_hosts() or not nm[host].get('tcp'):
        print_yellow('[{}] Host has no TCP service available'.format(host))
        return {}

    print('[{}] Available TCP services'.format(host))
    for service_port, service in nm[host].get('tcp').items():
        if service.get('name') == 'http' and 'ssl-cert' in service.get('script', {}):
            service['name'] = 'https'
        if service_port == 3389:
            service['name'] = 'rdp'
        
        if 'open' in service.get('state'):
            print_fn = print_green
        else:
            print_fn = print_yellow

        print_fn('[{}]\t{} {} {} {} {}'.format(
            host,
            str(service_port).ljust(10), 
            service.get('state').ljust(10), 
            service.get('name').ljust(20),
            service.get('product'), 
            service.get('version')
        ))

    return nm[host].get('tcp')


def initial_host_udp_recon(host, txt_output_path=None, xml_output_path=None, fast_port_scan=False):
    nm = nmap.PortScanner()

    if fast_port_scan:
        args = '-vv -Pn -A -sC -sU -T4 --top-ports 20 --open -oN {}'.format(txt_output_path)  ## DEBUG MODE
        res = nm.scan(hosts=host, arguments=args)
    else:
        args = '-vv -Pn -A -sC -sU -T4 --top-ports 200 --open -oN {}'.format(txt_output_path)
        res = nm.scan(hosts=host, arguments=args)

        
    # output XML (if requested)
    if xml_output_path:
        with open(xml_output_path, 'w') as xml_output:
            xml_output.write(nm.get_nmap_last_output())

    if host not in nm.all_hosts() or not nm[host].get('udp'):
        print_yellow('[{}] Host has no UDP service available'.format(host))
        return {}

    print('[{}] Available UDP services: '.format(host))
    for service_port, service in nm[host]['udp'].items():
        if 'open' in service.get('state'):
            print_fn = print_green
        else:
            print_fn = print_yellow

        print_fn('[{}]\t{} {} {} {} {}'.format(
            host,
            str(service_port).ljust(10), 
            service.get('state').ljust(10), 
            service.get('name').ljust(20),
            service.get('product'), 
            service.get('version')
        ))

    return nm[host]['udp']
