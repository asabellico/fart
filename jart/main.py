#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Program entry point"""

from __future__ import print_function
from datetime import datetime

import argparse
import os
import sys

from jart import metadata
from jart import recon

def main(argv):
    """Program entry point.

    :param argv: command-line arguments
    :type argv: :class:`list`
    """
    author_strings = []
    for name, email in zip(metadata.authors, metadata.emails):
        author_strings.append('Author: {0} <{1}>'.format(name, email))

    epilog = '''
{project} {version}

{authors}
URL: <{url}>
'''.format(
        project=metadata.project,
        version=metadata.version,
        authors='\n'.join(author_strings),
        url=metadata.url)

    arg_parser = argparse.ArgumentParser(
        prog=argv[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=metadata.description,
        epilog=epilog)
    arg_parser.add_argument(
        '-V', '--version',
        action='version',
        version='{0} {1}'.format(metadata.project, metadata.version))

    arg_parser.add_argument(
    	'-t', '--target',
    	type=str,
    	required=True
    )
    arg_parser.add_argument(
    	'-o', '--output',
    	type=str,
    	default=os.path.join(os.getcwd(), datetime.now().strftime("recon_%Y%m%d%H%M"))
    )
    arg_parser.add_argument(
        '-s', '--skip-icmp-sweep',
        action='store_true',
        help='Disable initial ICMP ping sweep'
    )
    arg_parser.add_argument(
        '-f', '--fast-port-scan',
        action='store_true',
        help='Enable fast TCP port scan (only TOP200 ports)'
    )

    args = arg_parser.parse_args(args=argv[1:])

    if '-' in args.target:
        print('Sorry, only CIDR and single host format are accepted!')
        exit(0)
    elif '/' not in args.target:
        args.target += '/32'

    recon.target_recon(args.target, args.output, args.skip_icmp_sweep, args.fast_port_scan)

    return 0


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    raise SystemExit(main(sys.argv))


if __name__ == '__main__':
    entry_point()
