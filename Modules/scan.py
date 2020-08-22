from datetime import datetime
from termcolor import colored
from multiprocessing import Pool
from Modules.create import appendlog
from Modules.parser import http
import os
import re


def allports(host, location, options):
    start = datetime.now()
    message = colored("[+] {0} : TCP SCAN STARTED AT {1}\n".format(host, start), 'green')
    appendlog(location, message)

    output = location + host + '/TCP-' + host
    scan = "nmap {0} -Pn -sSV -n -r -O {1} -p- -oA {2}".format(host, options, output)
    appendlog(location, "[+] PERFORMING TCP SCAN: {0}\n".format(scan))
    os.system(scan)
    http(location, host)

    finish = datetime.now()
    message = colored("[+] {0} : TCP SCAN FINISHED AT {1}\n".format(host, finish), 'green')
    appendlog(location, message)

def topudpports(host, location):
    start = datetime.now()
    message = colored("[+] {0} : UDP SCAN STARTED AT {1}\n".format(host, start), 'green')
    appendlog(location, message)

    output = location + host + '/UDP-' + host
    scan = "nmap {0} -Pn -sU -n -r -oA {1}".format(host, output)
    appendlog(location, "[+] PERFORMING UDP SCAN: {0}\n".format(scan))
    os.system(scan)
    http(location, host)

    finish = datetime.now()
    message = colored("[+] {0} : UDP SCAN FINISHED AT {1}\n".format(host, finish), 'green')
    appendlog(location, message)

def sslscan(location, target):
    match = re.compile("^([^:]*)*")
    start = datetime.now()
    message = colored("[+] {0} : PERFORMING SSLSCAN ON TARGET AT {1}\n".format(target, start), 'green')
    appendlog(location, message)
    op = target.replace(':', '-')
    host = re.search(match, target).group(0)
    sslscan = "sslscan --xml={2}{1}/SSL-{3}.xml {0} > {2}{1}/SSL-{3}.txt".format(target, host, location, op)
    print(sslscan)
    os.system(sslscan)

#sslscan('/root/Tests/House/')