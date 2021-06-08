#!/usr/bin/env python3

import argparse
from termcolor import colored
from datetime import datetime
from multiprocessing import Pool
from components import *
import os

scope = []
location = ""
tcpoptions = "--min-rate 3000 --max-retries 2 --script-timeout 120 --host-timeout 6000 -n"
SHODAN_API_KEY = ""
TESTSSL = ""



header = colored("""                                          
___________________ _______   _____________  __
__  ___/  ___/  __ `/_  __ \  ___  __ \_  / / /
_(__  )/ /__ / /_/ /_  / / /____  /_/ /  /_/ / 
/____/ \___/ \__,_/ /_/ /_/_(_)  .___/_\__, /  
                              /_/     /____/   

By PTF569                              """, 'blue')


#================ MAIN ========================


if __name__ == '__main__':
    if os.geteuid() != 0:
        print(colored("Jeepers Creepers Batman, you need to run me as root!\n\nLets try that again shall we!\n", 'red'))
    create.initialize()
    parser = argparse.ArgumentParser("A small program to automate some host discovery and some basic scanning")
    parser.add_argument("-t", "--targets", dest="targets", help="Location of targets file")
    parser.add_argument("-s", "--subnet", dest="subnet", help="Targets subnet")
    parser.add_argument("-R", "--rescan", action="store_true",
                        help="Rescan the host even if we detect an nmap xml file")
    parser.add_argument("-n", "--name", dest="project_name",
                        help="The name of the project") # Not currently in use
    parser.add_argument("-l", "--location", default="/tmp/", dest="project_location",
                        help="Location where to save the project")
    parser.add_argument("-O", "--outofscope", dest="oos_file",
                        help="Location of IP's not to scan")
    parser.add_argument("-U", "--udp", action="store_true", help="Perform UDP scan of targets")
    parser.add_argument("-T", "--threads", dest="threads", default=5,
                        help="Number of concurrent nmap scans. Default is 5")
    parser.add_argument("-y", "--testssl", dest="testssl", help="Location of testssl.sh")
    parser.add_argument("-z", "--shodan", dest="shodan", help="Shodan API key")
    parser.add_argument("-d", "--discord", dest="discord", help="Discord webhook")

    args = parser.parse_args()
    # check if location is given, if not, to /tmp
    location = args.project_location

    start = datetime.now()

    location = create.checkdir(location)
    create.appendlog(location, header)
    create.appendlog(location, "\n\n===================================================================\n "
                        "[\o/]PROGRAM STARTED AT {0} "
                        "\n=================================================================== \n".format(start))

    if args.targets:
        scope = [line.rstrip('\n') for line in open(args.targets)]
        print(scope)
    elif args.subnet:
        scope = [args.subnet]
    else:
        print(location)
        create.appendlog(location, colored("[-] NO SCOPE PROVIDED, PLEASE USE EITHER -t <target file> OR -s <subnet>", 'red'))
        exit(99)

    if args.testssl:
        TESTSSL = args.testssl
    if args.shodan:
        SHODAN_API_KEY = args.shodan
    if args.discord:
        create.webhook = args.discord
        create.welcome(create.webhook)

    POOL_SIZE = args.threads

    create.projfile(location)



# take our scope and get a list of active hosts
    targets = discover.discover(scope, location)
    rescan = args.rescan

    if args.oos_file:
        oos_file = args.oos_file
        targets = scans.outofscope(location, oos_file, targets)

# ###### LOAD CONFIG FROM OUR INI FILE #######
    try:
        for host in targets:
            lookup.shodanSearch(host, SHODAN_API_KEY, location)
    except:
        create.appendlog(location, 'NO SHODAN KEY, PLEASE ENTER YOUR API KEY ON LINE 13 OF scan.py')


# Start our pool of nmap scans
    scan = []

# TCP
    tcp = [(target, location, tcpoptions, rescan) for target in targets]
    with Pool(int(POOL_SIZE)) as p:
        scan.append(p.starmap(scans.allports, tcp))

    if os.path.isfile(location + "https.txt"):
        ips = [line.rstrip('\n') for line in open(location + 'https.txt')]
        targets = []
        for ip in ips:
            if ip not in targets:
                targets.append(ip)

        https = open(location + "https.txt", "w+")
        for target in targets:
            https.write("{0}\n".format(target))
        https.close()

        ssl = []

        if TESTSSL:
            scan = [(TESTSSL, location, target, rescan) for target in targets]
            with Pool(int(POOL_SIZE)) as p:
                ssl.append(p.starmap(scans.testssl, scan))

        else:
            print('If you rather testssl.sh, please enter its location on line 14, or use --testssl option')
            scan = [(location, target, rescan) for target in targets]
            with Pool(int(POOL_SIZE)) as p:
                ssl.append(p.starmap(scans.sslscan, scan))

# UDP
    if args.udp:
        udp = [(target, location) for target in targets]
        with Pool(int(POOL_SIZE)) as p:
            scan.append(p.starmap(scans.topudpports, udp))

# Our end point
    finish = datetime.now()
    message = "===================================================================\n " \
              "[\o/] PROGRAM FINISHED AT {0} " \
              "\n=================================================================== \n".format(finish)
    create.appendlog(location, message)
    create.discord(create.webhook, "Complete", "[\o/] PROGRAM FINISHED AT {0} ".format(finish))

# ===================================================================





