==============================
Just Another Recon Tool (JART)
==============================

Project Setup
=============

JART executes a complete recon on a subnet by checking various procotols common vulnerabilities, common logins, etc. 

Protocol handled in current version:

* HTTP (resources enumeration and more..)
* HTTPS (include heartbleed check)
* FTP
* RDP
* DNS
* SNMP
* SMTP
* SSH

Instructions
------------

APT packages required:

    `apt install dnsrecon hydra dirb davtest ncrack enum4linux snmp snmpwalk snmp-check onesixtyone`

PIP packages dependecies:
```
ipaddress==1.0.17
python-nmap==0.6.1
```

Some command-line examples:

* Fast port scan on a subnet:
    `jart --fast-port-scan -t 10.11.1.0./24`
* Complete analysis on a single host:
    `jart -t 10.11.1.123`
* Complete analysis skipping ICMP host discovery:
    `jart --skip-icmp-sweep -t 10.11.1.123`

Tested on Kali GNU/Linux

Supported Python Versions
=========================

* Python 2.7

Issues
======

Please report any bugs or requests that you have using the GitHub issue tracker!

Authors
=======

* Alessandro Sabellico
