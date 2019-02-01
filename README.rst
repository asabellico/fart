=================================
Finally Another Recon Tool (fart)
=================================

Project Setup
=============

Fart executes a complete recon on a subnet by checking various procotols common vulnerabilities, common logins, etc. 

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

Some command-line examples:

* Fast port scan on a subnet (TCP top1000 - UDP top200):
    `fart -t 10.11.1.0./24`
* Fast port scan on a subnet only TCP (TCP top1000):
    `fart --skip-udp -t 10.11.1.0./24`
* Complete analysis on a single host:
    `fart -t --pedantic-port-scan 10.11.1.123`
* Complete analysis skipping ICMP host discovery:
    `fart --skip-icmp-sweep -t 10.11.1.123`

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
