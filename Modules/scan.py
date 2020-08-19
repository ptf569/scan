from datetime import datetime
from termcolor import colored
from Modules.create import appendlog
from Modules.parser import http
import os


def allports(host, location, options):
    start = datetime.now()
    message = colored("{0} : SCAN STARTED AT {1} \n".format(host, start), 'green')
    appendlog(location, message)

    output = location + host + '/' + host
    scan = "nmap {0} -Pn -sSV -n -r -O {1} -p- -oA {2}".format(host, options, output)
    print(scan)
    os.system(scan)
    http(location, host)

    finish = datetime.now()
    message = colored("{0} : SCAN FINISHED AT {1} \n".format(host, finish), 'green')
    appendlog(location, message)