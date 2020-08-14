import xml.etree.ElementTree as ET
import argparse
from datetime import datetime
from termcolor import colored
from multiprocessing import Pool
from Modules.discover import discover
from Modules.create import *
from Modules.scan import allports

parser = argparse.ArgumentParser("A small program to automate some recon")

scope = []
location = ""
options = "--min-rate 3000 --max-retries 2 --script-timeout 120 --host-timeout 6000"
POOL_SIZE = 5

#================ MAIN ========================

if __name__ == '__main__':

    parser.add_argument("-t", "--targets", dest="targets", help="Location of targets file")
    parser.add_argument("-s", "--subnet", dest="subnet", help="Targets subnet")
    parser.add_argument("-n", "--name", dest="project_name",
                        help="The name of the project")
    parser.add_argument("-l", "--location", default="/tmp/", dest="project_location",
                        help="Location where to save the project")

    args = parser.parse_args()

    start = datetime.now()

    if args.targets:
        scope = [line.rstrip('\n') for line in open(args.targets)]
        print(scope)
    elif args.subnet:
        scope = [args.subnet]
    else:
        print("No Scope Provided!!")
        exit(99)

# check if location is given, if not, to /tmp
    if args.project_location:
        location = args.project_location
    else:
        print('NO LOCATION SPECIFIED, SAVING TO /tmp/')

    if os.path.isdir(location):
        if location.endswith(('/')):
            print(colored("SAVING PROJECT IN {0}".format(location), "green"))
        else:
            location = location + '/'
            print(colored("SAVING PROJECT IN {0}".format(location), "green"))
    else:
        print("{0} IS NOT A DIRECTORY BOZO!".format(location))
        exit(99)


    projfile(location)
    log = open(location + "scan.log", "a+")
    print(colored("PROGRAM STARTED AT {0}".format(start), 'green'))
    log.write("PROGRAM STARTED AT {0} \n".format(start))
    log.close()

#take our scope and get a list of active hosts
    targets = discover(scope, location)
    print(targets)

#create a dir for each host
    creatfiles(location, targets)

#Start our pool of nmap scans
    t = []
    jobs = [(target, location, options) for target in targets]
    with Pool(int(POOL_SIZE)) as p:
        t.append(p.starmap(allports, jobs))



    # Our end point
    finish = datetime.now()
    log = open(location + "scan.log", "a+")
    log.write("PROGRAM FINISHED AT {0} \n".format(finish))
    log.close()
    print("===========================================\n DONE\n===========================================")
#===================================================================


"""
tree = ET.parse('/home/p10507925/Tests/pro-data/nmap-scans/full_tcp.xml')
root = tree.getroot()

d = [
        {'path': 'address', 'el': 'addr'},
        {'path': 'hostnames/hostname', 'el': 'name'},
        {'path': 'os/osmatch/osclass', 'el': 'osfamily'},
]


for i in root.iter('host'):
    for h in d:
        e = i.find(h['path'])
        if e is not None:
            print((h['path']), e.get(h['el']))
        else:
            print((h['path']), "UNKNOWN ")


    ports = i.find('ports')
    for port in ports:
        if 'portid' in port.attrib:
            print(port.get('portid'), port.get('protocol'))

        else:
            print('not a port')
"""