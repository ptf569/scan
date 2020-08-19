import os
from termcolor import colored

def projfile(location):
    if os.path.exists(location):
        print(colored('{0} Already exists'.format(location), 'red'))
    else:
        os.mkdir(location)

def creatfiles(location, hosts):

    for host in hosts:
        if os.path.exists(location + '/' + host):
            print(colored('{0} Already exists in {1}'.format(host, location), 'red'))
        else:
            os.mkdir(location + '/' + host)

    return location

def appendlog(location, message):
    log = open(location + "scan.log", "a+")
    print(message)
    log.write(message)
    log.close()