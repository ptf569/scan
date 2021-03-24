#!/usr/bin/env python3

from datetime import datetime
from termcolor import colored
from .create import appendlog, creatfile
from .parser import ports, parse
import os
import re


def allports(host, location, options, rescan):
    output = location + host + '/TCP-' + host
    if os.path.isfile(output + ".xml"):
        if rescan == False:
            appendlog(location, colored("[*] HOST {0} appears to already have nmap output, "
                                        "use the '-R' option to rescan hosts".format(host), 'white'))
            return
        else:
            appendlog(location, colored("[+] PERFORMING RESCAN ON HOST: {0}".format(host), 'green'))

    creatfile(location, host)
    start = datetime.now()
    message = colored("[*] {0} : TCP SCAN STARTED AT {1}".format(host, start), 'white')
    appendlog(location, message)


    scan = "nmap {0} -Pn -sSV -r -O {1} -p- -oA {2} > /dev/null".format(host, options, output)
    appendlog(location, colored("[+] PERFORMING TCP SCAN: {0}".format(scan), 'yellow'))
    os.system(scan)
    parse(location, host)
    ports(location, host)

    finish = datetime.now()
    message = colored("[*] {0} : TCP SCAN FINISHED AT {1}".format(host, finish), 'green')
    appendlog(location, message)


def topudpports(host, location):
    start = datetime.now()
    message = colored("[*] {0} : UDP SCAN STARTED AT {1}".format(host, start), 'green')
    appendlog(location, message)

    output = location + host + '/UDP-' + host
    scan = "nmap {0} -Pn -sU -r -oA {1}".format(host, output)
    appendlog(location, colored("[+] PERFORMING UDP SCAN: {0}".format(scan), 'magenta'))
    os.system(scan)
    parse(location, host)

    finish = datetime.now()
    message = colored("[*] {0} : UDP SCAN FINISHED AT {1}".format(host, finish), 'green')
    appendlog(location, message)


def testssl(testssl, location, target, rescan):
    match = re.compile("^([^:]*)*")
    start = datetime.now()
    message = colored("[+] {0} : PERFORMING TESTSSL SCAN AT {1}".format(target, start), 'green')
    op = target.replace(':', '-')
    host = re.search(match, target).group(0)
    data = location + host + '/SSL-' + op + ".log"
    if os.path.isfile(data):
        if rescan == False:
            appendlog(location, colored("[*] {0} appears to already have TESTSSL output, "
                                        "use the '-R' option to rescan hosts".format(target), 'yellow'))
            return
        else:
            message = colored("[+] {0} : PERFORMING TESTSSL RESCAN ON HOST AT {1}".format(target, start), 'green')
    if os.path.isfile(testssl):
        appendlog(location, message)
        testssl = "{0} -oA {3}{2}/SSL-{4} --append {1}".format(testssl, target, host, location, op)
        print(testssl)
        os.system(testssl)
    else:
        appendlog(location, colored("[!] TESTSSL on target {0} FAILED, CHECK config.ini,"
                                    " attempting SSLSCAN".format(target), 'red'))
        sslscan(location, target, rescan)


def sslscan(location, target, rescan):
    match = re.compile("^([^:]*)*")
    start = datetime.now()
    message = colored("[+] {0} : PERFORMING SSLSCAN AT {1}".format(target, start), 'green')

    op = target.replace(':', '-')
    app = '>'
    host = re.search(match, target).group(0)
    data = location + host + '/SSL-'+ op + ".txt"
    if os.path.isfile(data):
        if rescan == False:
            appendlog(location, colored("[*] {0} appears to already have SSLSCAN output, "
                                        "use the '-R' option to rescan hosts".format(host), 'yellow'))
            return
        else:
            message = colored("[+] {0} : PERFORMING SSLSCAN RESCAN ON HOST AT {1}".format(target, start), 'green')
            app = '>>'

    appendlog(location, message)

    sslscan = "sslscan --xml={2}{1}/SSL-{3}.xml {0} {4} {2}{1}/SSL-{3}.txt".format(target, host, location, op, app)
    print(sslscan)
    try:
        os.system(sslscan)
    except:
        message = colored("Looks like sslscan is not installed", 'red')
        appendlog(location, message)

