from datetime import datetime
from termcolor import colored
import os


def allports(host, location, options):
    start = datetime.now()
    log = open(location + "scan.log", "a+")
    print(colored("{0} : SCAN STARTED AT {1}".format(host, start), 'green'))
    log.write(colored("{0} : SCAN STARTED AT {1} \n".format(host, start), 'green'))
    log.close()


    output = location + host + '/' + host
    scan = "nmap {0} -Pn -sS -T4 -n -r -O {1} -p- -oA {2}".format(host, options, output)
    print(scan)
    os.system(scan)


    finish = datetime.now()
    log = open(location + "scan.log", "a+")
    log.write(colored("{0} : SCAN FINISHED AT {1} \n".format(host, finish), 'green'))
    log.close()