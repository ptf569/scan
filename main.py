import argparse
from termcolor import colored
from datetime import datetime
from multiprocessing import Pool
from Modules.discover import discover, outofscope
from Modules.create import *
from Modules.scan import allports, topudpports, sslscan
from Modules.lookup import shodanSearch
import configparser
import os



scope = []
location = ""
options = "--min-rate 3000 --max-retries 2 --script-timeout 120 --host-timeout 6000"
POOL_SIZE = 8


header = colored("""                                          
___________________ _______   _____________  __
__  ___/  ___/  __ `/_  __ \  ___  __ \_  / / /
_(__  )/ /__ / /_/ /_  / / /____  /_/ /  /_/ / 
/____/ \___/ \__,_/ /_/ /_/_(_)  .___/_\__, /  
                              /_/     /____/   

By PTF569                              """, 'blue')


#================ MAIN ========================

if __name__ == '__main__':
    parser = argparse.ArgumentParser("A small program to automate some host discovery and some basic scanning")
    parser.add_argument("-t", "--targets", dest="targets", help="Location of targets file")
    parser.add_argument("-s", "--subnet", dest="subnet", help="Targets subnet")
    parser.add_argument("-n", "--name", dest="project_name",
                        help="The name of the project")
    parser.add_argument("-l", "--location", default="/tmp/", dest="project_location",
                        help="Location where to save the project")
    parser.add_argument("-O", "--outofscope", dest="oos_file",
                        help="Location of IP's not to scan")
    parser.add_argument("-U", "--udp", action="store_true",
                        help="Perform UDP scan of targets")

    args = parser.parse_args()
    # check if location is given, if not, to /tmp
    location = args.project_location
    location = checkdir(location)
    start = datetime.now()
    appendlog(location, header)
    appendlog(location, "\n\n===================================================================\n "
                        "[\o/]PROGRAM STARTED AT {0} "
                        "\n=================================================================== \n".format(start))

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


#take our scope and get a list of active hosts
    targets = discover(scope, location)
    print(targets)

    if args.oos_file:
        oos_file = args.oos_file
        targets = outofscope(location, oos_file, targets)


#create a dir for each host
    creatfiles(location, targets)

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


#Start our pool of nmap scans
    scan = []

#TCP
    tcp = [(target, location, options) for target in targets]
    with Pool(int(POOL_SIZE)) as p:
        scan.append(p.starmap(allports, tcp))

    if location + 'https.txt':
        targets = [line.rstrip('\n') for line in open(location + 'https.txt')]
        ssl = []
        scan = [(location, target) for target in targets]
        with Pool(int(POOL_SIZE)) as p:
            ssl.append(p.starmap(sslscan, scan))




#UDP
    if args.udp:
        udp = [(target, location) for target in targets]
        with Pool(int(POOL_SIZE)) as p:
            scan.append(p.starmap(topudpports, udp))


    # Our end point
    finish = datetime.now()
    message = "===================================================================\n " \
              "[\o/] PROGRAM FINISHED AT {0} " \
              "\n=================================================================== \n \n".format(finish)
    appendlog(location, message)


#===================================================================


