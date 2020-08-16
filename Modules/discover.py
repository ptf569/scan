#!/usr/bin/env python

import nmap
import os
from termcolor import colored
from datetime import datetime

nm = nmap.PortScanner()


def discover(targets, location):
    host_list = []
    if os.path.isfile(location + 'hosts.txt'):
        print('hostfile exists')
        host_list = [line.rstrip('\n') for line in open(location + 'hosts.txt')]
    else:
        hl = open(location + "hosts.txt", "w+")
        hl.close()
    print(host_list)
    now = datetime.now()
    print(colored("SCAN STARTED AT {0}".format(now.strftime("%d/%m/%Y %H:%M:%S")), 'green'))
    print(colored("The scope of our scanning is: {0}".format(targets), 'white'))
    scan_types = [('arp', '-n -sn -PR --max-rtt-timeout 1000ms'),
                  ('tcpsyn', '-n -sn -PS22-25,53,80,111,135,443,445 --max-rtt-timeout 500ms'),
                  ('tcpack', '-n -sn -PA22-25,53,80,111,135,443,445 --max-rtt-timeout 500ms'),
                  ('udp', '-n -sn -PU53,123,137,500,200,2001,4500,5355,6129,40125,65133 --max-rtt-timeout 500ms'),
                  ('sctp', '-n -sn -PY22-25,53,80,111,113,1050,3500 --max-rtt-timeout 500ms'),
                  ('icmp_echo', '-n -sn -PE --max-rtt-timeout 500ms'),
                  ('icmptime', '-n -sn -PP --max-rtt-timeout 500ms'),
                  ('icmpaddrmsk', '-n -sn -PM --max-rtt-timeout 500ms'),
                  ('ipp', '-n -sn -PO --max-rtt-timeout 500ms'),
                  ]

    i = 0
    while i < 2:
        for s in scan_types:
            for t in targets:
                try:
                    print(colored("RUNNING {0} DISCOVERY SCAN..".format(s[0].upper()), 'cyan'))
                    nm.scan(hosts=t, arguments=s[1])
                    dlist = nm.all_hosts()
                    for ip in dlist:
                        if ip not in host_list:
                            log = open(location + "scan.log", "a+")
                            print(colored("[+] ADDING HOST: ", 'cyan'), colored("{0} ".format(ip), 'green'))
                            log.write(colored("[+] ADDING HOST: ", 'cyan'))
                            log.write(colored("{0} \n".format(ip), 'green'))
                            log.close()
                            host_list.append(ip)
                            hl = open(location + "/hosts.txt", "a+")
                            hl.write(ip + "\n")
                            hl.close()

                except:
                    print(colored("SCAN ERROR WITH SCAN: {0}, MOVING ON".format(s)))
                    log = open(location + "scan.log", "a+")
                    log.write(colored("SCAN ERROR WITH SCAN: {0}, MOVING ON \n".format(s)))
                    log.close()
        i += 1

    print(colored("{0} HOSTS IN TARGET LIST".format(len(host_list)), 'green'))
    return host_list

def outofscope(oos, host_list):

    oos_discovered = []
    oos_ips = []
    if os.path.isfile(oos):
        print('hostfile exists')
        oos_ips = [line.rstrip('\n') for line in open(oos)]
        logdata = "THE FOLLOWING IP'S ARE OUT OT SCOPE: {0}".format(oos_ips)
    else:
        logdata = "ERROR WITH OUT OF SCOPE FILE: {0}".format(oos)

    print(logdata)

    for ip in oos_ips:
        if ip in host_list:
            host_list.remove(ip)
            oos_discovered.append(ip)
            print("{0} REMOVED".format(ip))
    print(host_list)
    print(colored("THE FOLLOWING IP'S WERE DISCOVERED AND REMOVED FROM SCOPE: {0}".format(oos_discovered), "red"))

    return host_list

