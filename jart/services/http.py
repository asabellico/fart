from __future__ import print_function

import nmap
import os
import subprocess
import tempfile
from utils import *


VENDOR_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'vendor')

def dirbuster(host, port, http_service, output_file, **kwargs):
    DICTS = [
        '/usr/share/dirb/wordlists/common.txt',
        #'/usr/share/seclists/Discovery/Web-Content/CGIs.txt',
        #'/usr/share/dirb/wordlists/vulns',
        #'/usr/share/dirb/wordlists/big.txt',
        #'/usr/share/dirb/wordlists/indexes.txt',
        #'/usr/share/dirb/wordlists/spanish.txt',
        #'/usr/share/dirb/wordlists/mutations_common.txt',
        
    ]
    # TODO evaluate additional wordlists to use

    url = '{}://{}:{}'.format(http_service.get('name', 'http'), host, port)

    dictionaries = []
    for dictionary in DICTS:
        if not os.path.exists(dictionary):
            print_yellow('Cannot find dictionary: {}. Skipping...'.format(dictionary))
            continue

        if os.path.isfile(dictionary):
            dictionaries.append(dictionary)
        elif os.path.isdir(dictionary):
            for filename in os.listdir(dictionary):
                dict_path = os.path.join(dictionary, filename)
                if dict_path not in dictionaries:
                    dictionaries.append(dict_path)

    found = []
    for dictionary in dictionaries:
        DIRBSCAN = 'dirb {} {} -o {} -S -r'.format(url, dictionary, output_file)
        try:
            results = subprocess.check_output(DIRBSCAN, bufsize=-1, shell=True)
            _results = results.split('\n')
            for line in _results:
                if '+' in line and line not in found:
                    found.append(line)
        except Exception as e:
           print_red('Error during dirb scan: {}'.format(DIRBSCAN))
           print_red('Error message: {}'.format(e))

    if len(found) > 0:
        print_green('[*] Dirb found the following items...')
        for item in found:
            print_green('   ' + item)
    else:
        print('No items found during dirb scan of ' + url)    


def nmapscripts(host, port, service, output_file, **kwargs):
    SCRIPTS= [
        'http-vhosts',
        'http-userdir-enum',
        'http-apache-negotiation',
        'http-backup-finder',
        'http-config-backup',
        'http-default-accounts',
        'http-email-harvest',
        'http-methods',
        'http-method-tamper',
        'http-passwd',
        'http-robots.txt',
        'http-webdav-scan'
    ]

    nm = nmap.PortScanner()
    args = '-vv -Pn -sV --script={} -oN {} '.format(','.join(SCRIPTS), output_file)
    res = nm.scan(hosts=host, ports=port, arguments=args)


def heartbleed(host, port, http_service, output_file, **kwargs):
    HBCMD = os.path.join(VENDOR_PATH, 'heartbleed.py')

    HBSCAN = 'python {} {} -p {}'.format(HBCMD, host, port)
    try:
        results = subprocess.check_output(HBSCAN, shell=True)
        _results = results.split("\n")
        
        for line in _results:
            if 'server is vulnerable!' in line:
                print_green('{} is probably vulnerable to heartbleed!'.format(host))
                break

        with open(output_file, 'w') as output:
            output.write(results)

    except Exception as e:
        print_red('Error during heartbleed check: {}'.format(e))


def shellshock(host, port, http_service, output_file, **kwargs):
    pass

def webdav(host, port, http_service, output_file, **kwargs):
    if port == 80:
        DAVTEST = 'davtest -cleanup -url {}://{}/ 2>1'.format(http_service.get('name', 'http'), host)
    else:
        DAVTEST = 'davtest -cleanup -url {}://{}:{}/ 2>1'.format(http_service.get('name', 'http'), host, port)

    results = subprocess.check_output(DAVTEST, shell=True)
    if 'SUCCEED' in results:
        print_green('[{}] Host has WebDAV enabled and something interesting can be done (check output file)'.format(host))

    with open(output_file, 'w') as output:
        output.write(results)