#!/usr/bin/env python3

import os
from termcolor import colored


def checkdir(location):
    if os.path.isdir(location):
        if location.endswith(('/')):
            logdata = colored("[*] SAVING PROJECT IN {0}".format(location), 'yellow')
        else:
            location = location + '/'
            logdata = colored("[*] SAVING PROJECT IN {0}".format(location), 'yellow')
        appendlog(location, logdata)
    else:
        appendlog(location, colored("[!] {0} IS NOT A DIRECTORY BOZO!".format(location), 'red'))
        exit(99)
    return location


def projfile(location):
    if os.path.exists(location):
        appendlog(location, colored("[*] {0} ALREADY EXISTS".format(location), 'yellow'))
    else:
        os.mkdir(location)
    return location


def creatfile(location, host):
    if os.path.exists(location + '/' + host):
        appendlog(location, colored("[*] {0} ALREADY EXISTS IN {1}".format(host, location), 'yellow'))
    else:
        os.mkdir(location + '/' + host)


def appendlog(location, message):
    log = open(location + "scan.log", "a+")
    print(message)
    log.write(message + "\n")
    log.close()

