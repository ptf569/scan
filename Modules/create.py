import os
from termcolor import colored

def checkdir(location):
    if os.path.isdir(location):
        if location.endswith(('/')):
            logdata = colored("[*] SAVING PROJECT IN {0}\n".format(location), 'yellow')
        else:
            location = location + '/'
            logdata = colored("[*] SAVING PROJECT IN {0}\n".format(location), 'yellow')
        appendlog(location, logdata)
    else:
        appendlog(location, colored("[!] {0} IS NOT A DIRECTORY BOZO!\n".format(location), 'red'))
        exit(99)
    return location

def projfile(location):
    if os.path.exists(location):
        appendlog(location, colored("[*] {0} ALREADY EXISTS\n".format(location), 'yellow'))
    else:
        os.mkdir(location)

def creatfiles(location, hosts):
    for host in hosts:
        if os.path.exists(location + '/' + host):
            appendlog(location, colored("[*] {0} ALREADY EXISTS IN {1}\n".format(host, location), 'yellow'))
        else:
            os.mkdir(location + '/' + host)
    return location


def appendlog(location, message):
    log = open(location + "scan.log", "a+")
    print(message)
    log.write(message)
    log.close()

