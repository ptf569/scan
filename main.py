import argparse
from datetime import datetime
from termcolor import colored
from multiprocessing import Pool
from Modules.discover import discover, outofscope
from Modules.create import *
from Modules.scan import allports
from Modules.parser import http

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
    parser.add_argument("-o", "--outofscope", dest="oos_file",
                        help="Location of IP's not to scan")


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
            logdata = colored("SAVING PROJECT IN {0} \n".format(location), "green")
        else:
            location = location + '/'
            logdata = colored("SAVING PROJECT IN {0} \n".format(location), "green")
    else:
        print("{0} IS NOT A DIRECTORY BOZO!".format(location))
        logdata = "{0} IS NOT A DIRECTORY BOZO! \n".format(location)
        exit(99)
    appendlog(location, logdata)

    projfile(location)
    log = open(location + "scan.log", "a+")
    print(colored("PROGRAM STARTED AT {0}".format(start), 'green'))
    log.write("PROGRAM STARTED AT {0} \n".format(start))
    log.close()

#take our scope and get a list of active hosts
    targets = discover(scope, location)
    print(targets)

    if args.oos_file:
        oos_file = args.oos_file
        targets = outofscope(oos_file, targets)


#create a dir for each host
    creatfiles(location, targets)

#Start our pool of nmap scans
    t = []
    jobs = [(target, location, options) for target in targets]
    with Pool(int(POOL_SIZE)) as p:
        t.append(p.starmap(allports, jobs))


    # Our end point
    finish = datetime.now()
    message = "PROGRAM FINISHED AT {0} \n".format(finish)
    appendlog(location, message)

    print("===========================================\n DONE\n===========================================")
#===================================================================


