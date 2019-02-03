from __future__ import print_function

import os
import subprocess

def execute_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=-1, shell=True)
    _stdout, _stderr = p.communicate()

    return _stdout, _stderr

def print_red(msg):
	print('\033[91m{}\033[0m'.format(msg))

def print_yellow(msg):
	print('\033[93m{}\033[0m'.format(msg))

def print_green(msg):
	print('\033[92m{}\033[0m'.format(msg))

def hms_string(sec_elapsed):
    h = int(sec_elapsed / (60 * 60))
    m = int((sec_elapsed % (60 * 60)) / 60)
    s = sec_elapsed % 60.
    if h == 0:
	    return "{:>02}m:{:>02.0f}s".format(m, s)
    else:
    	return "{}h:{:>02}m:{:>02.0f}s".format(h, m, s)

def beep(num=1):
	os.system("echo -n '\a';sleep 0.2;" * num)
