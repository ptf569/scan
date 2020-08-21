import argparse
from datetime import datetime
from multiprocessing import Pool
from Modules.discover import discover, outofscope
from Modules.create import *
from Modules.scan import allports
from Modules.lookup import shodanSearch
import configparser
import os


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
    parser.add_argument("-O", "--outofscope", dest="oos_file",
                        help="Location of IP's not to scan")


    args = parser.parse_args()
    start = datetime.now()
    # check if location is given, if not, to /tmp
    location = args.project_location
    location = checkdir(location)

    if args.targets:
        scope = [line.rstrip('\n') for line in open(args.targets)]
        print(scope)
    elif args.subnet:
        scope = [args.subnet]
    else:
        print(location)
        appendlog(location, colored("[-] NO SCOPE PROVIDED, PLEASE USE EITHER -t <target file> OR -s <subnet> \n", 'red'))
        exit(99)





    projfile(location)
    appendlog(location, "\n\n===================================================================\n "
                        "[\o/]PROGRAM STARTED AT {0} "
                        "\n=================================================================== \n \n".format(start))

#take our scope and get a list of active hosts
    targets = discover(scope, location)
    print(targets)

    if args.oos_file:
        oos_file = args.oos_file
        targets = outofscope(location, oos_file, targets)


#create a dir for each host
    creatfiles(location, targets)

#Start our pool of nmap scans
    t = []
    jobs = [(target, location, options) for target in targets]
    with Pool(int(POOL_SIZE)) as p:
        t.append(p.starmap(allports, jobs))

    ####### LOAD CONFIG FROM OUR INI FILE #######
    config = configparser.ConfigParser()
    if os.path.isfile('config.ini'):
        config.read('config.ini')
        try:
            SHODAN_API_KEY = config['SHODAN']['SHODAN_API_KEY']
            for host in targets:
                shodanSearch(host, SHODAN_API_KEY, location)
        except:
            appendlog(location, 'NO SHODAN KEY, PLEASE ENTER: "SHODAN_API_KEY = <API KEY>" INTO config.ini')



    # Our end point
    finish = datetime.now()
    message = "===================================================================\n " \
              "[\o/] PROGRAM FINISHED AT {0} " \
              "\n=================================================================== \n \n".format(finish)
    appendlog(location, message)


#===================================================================


