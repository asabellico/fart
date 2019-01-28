#!/usr/bin/python

import nmap
import os
import subprocess
import time
import ipaddress

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
from utils import *
VENDOR_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'vendor')


def target_recon(hosts, output_dir, skip_icmp_sweep, fast_port_scan):
    # alive host scan
    if not skip_icmp_sweep:
        targets = check_alive_hosts(hosts)
        print_green('Found {} alive hosts during ICMP alive host scan'.format(len(targets)))    
    else:
        target_network = ipaddress.ip_network(unicode(hosts))
        if target_network.num_addresses == 1:
            targets = [ str(target_network)[:-3] ]
        else:
            targets = [ str(addr) for addr in target_network.hosts() ]

        print_green('Scanning {} hosts (skipped ICMP ping sweep)'.format(len(targets)))    

    beep()

    # services scan
    for host in targets:
        host = str(host)

        try:
            host_work_dir = os.path.join(output_dir, host)
            os.makedirs(host_work_dir)
        except OSError:
            print_yellow('Output directory for host {} does exist. Overwriting!'.format(host))

        start_time = time.time()
        print('[{}] Launching {}recon'.format(host, '(fast-port-scan) '*fast_port_scan))
        host_recon(host, host_work_dir, fast_port_scan)
        print('[{}] Finished recon (duration: {})'.format(host, hms_string(time.time()-start_time)))
        beep()

    # TODO post-scan 
    # check for duplicated ssh keys
    # ...

    print('')
    print_green('Recon terminated. Output reports placed in {}'.format(output_dir))    
    beep()


def check_alive_hosts(target):
    nm = nmap.PortScanner()
    res = nm.scan(hosts=target, arguments='-sn')

    nmap_alive_hosts = []
    for host in res['scan']:
        if res['scan'][host]['status']['state'] == 'up':
            nmap_alive_hosts.append(host)

    print_green('Nmap (-sn) found {} alive host(s)'.format(len(nmap_alive_hosts)))

    PINGSWEEP = 'sh {}/pingsweep.sh {}'.format(VENDOR_PATH, target)
    results = subprocess.check_output(PINGSWEEP, shell=True)
    _results = results.split('\n')
    pingsweep_alive_hosts = []
    for line in _results:
        if 'responds to ICMP ping request' in line:
            pingsweep_alive_hosts.append(line.split()[0])
    
    print_green('Pingsweep found {} alive host(s)'.format(len(pingsweep_alive_hosts)))

    merge_alive_hosts = set()
    for h in nmap_alive_hosts + pingsweep_alive_hosts:
        merge_alive_hosts.add(h)
    return list(merge_alive_hosts)


def host_recon(host, work_dir, fast_port_scan):
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

        #    http.dirbuster,
        ],

        'https': [
            http.nmapscripts,
            http.heartbleed,
            http.webdav,
            http.shellshock,

        #    http.dirbuster,
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
    print('[{}] Starting nmap {}TCP port scan...'.format(host, '(fast) '*fast_port_scan))
    tcp_txt_output_path = os.path.join(work_dir, '{}_TCP.txt'.format(host))
    tcp_xml_output_path = os.path.join(work_dir, '{}_TCP.xml'.format(host))
    tcp_services = initial_host_tcp_recon(host, tcp_txt_output_path, tcp_xml_output_path, fast_port_scan)
    print('[{}] Finished nmap {}TCP port scan...'.format(host, '(fast) '*fast_port_scan))

    # UDP recon
    print('[{}] Starting nmap {}UDP port scan...'.format(host, '(fast) '*fast_port_scan))
    udp_txt_output_path = os.path.join(work_dir, '{}_UDP.txt'.format(host))
    udp_xml_output_path = os.path.join(work_dir, '{}_UDP.xml'.format(host))
    udp_services = initial_host_udp_recon(host, udp_txt_output_path, udp_xml_output_path, fast_port_scan)
    print('[{}] Finished nmap {}UDP port scan...'.format(host, '(fast) '*fast_port_scan))

    # merge TCP and UDP services
    services = tcp_services.copy()
    services.update(udp_services)

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
                    print_red('[{}] Error message: {}'.format(host, e.message))
                print('[{}] Finished {} recon for {} service (duration: {})'.format(
                    host, serv_recon.__name__, serv.get('name'), 
                    hms_string(time.time()-start_time))
                )
        else:
            if serv.get('name') in ('tcpwrapped'):
                print_red('[{}] No recon procedure defined for {}. Skipping..'.format(host, serv.get('name')))
            else:
                print('[{}] No recon procedure defined for {}. Skipping..'.format(host, serv.get('name')))
    
            

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

    if host in nm.all_hosts() and nm[host].get('tcp'):
        host_tcp_services = nm[host]['tcp']
    else:
        print_yellow('[{}] Host has no TCP service available'.format(host))
        host_tcp_services = {}

    print('[{}] Available TCP services'.format(host))
    for service_port, service in host_tcp_services.items():
        if service.get('name') == 'http' and service.get('script', {}).has_key('ssl-cert'):
            service['name'] = 'https'
        if service_port == 3389:
            service['name'] = 'rdp'
        
        if 'open' in service.get('state'):
            print_fn = print_green
        else:
            print_fn = print_yellow

        print_fn('{} {} {} {} {}'.format(
            str(service_port).ljust(10), 
            service.get('state').ljust(10), 
            service.get('name').ljust(20),
            service.get('product'), 
            service.get('version')
        ))

    return host_tcp_services


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

    if host in nm.all_hosts() and nm[host].get('udp'):
        host_udp_services = nm[host]['udp']
    else:
        print_yellow('[{}] Host has no UDP service available'.format(host))
        host_udp_services = {}

    print('Available UDP services')
    for service_port, service in host_udp_services.items():
        if 'open' in service.get('state'):
            print_fn = print_green
        else:
            print_fn = print_yellow

        print_fn('{} {} {} {} {}'.format(
            str(service_port).ljust(10), 
            service.get('state').ljust(10), 
            service.get('name').ljust(20),
            service.get('product'), 
            service.get('version')
        ))

    return host_udp_services


