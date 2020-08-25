#!/usr/bin/env python

import nmap
import os
from termcolor import colored
from datetime import datetime
from Modules.create import appendlog

nm = nmap.PortScanner()


def discover(targets, location):
    host_list = []
    if os.path.isfile(location + 'hosts.txt'):
        print('hostfile exists')
        host_list = [line.rstrip('\n') for line in open(location + 'hosts.txt')]
    else:
        hl = open(location + "hosts.txt", "w+")
        hl.close()
    if len(host_list) > 0:
        message = colored("[*] HOSTS CURRENTLY IN host.txt: {0}\n".format(str(host_list)), 'yellow')
        appendlog(location, message)
    now = datetime.now()
    appendlog(location, colored("[+] DISCOVERY SCAN OF SCOPE {0} STARTED AT {1}\n".format(targets, now), 'green'))
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
                            newhost = colored("[+] {0} SCAN DISCOVERED HOST: ".format(s[0].upper()), 'cyan') + \
                                      colored("{0}\n".format(ip), 'green')
                            appendlog(location, newhost)
                            host_list.append(ip)
                            hl = open(location + "/hosts.txt", "a+")
                            hl.write(ip + "\n")
                            hl.close()

                except:
                    appendlog(location, colored("[!] SCAN ERROR WITH SCAN: {0}, MOVING ON...\n".format(s), 'red'))
        i += 1

    appendlog(location, colored("[*] {0} HOSTS IN TARGET LIST \n[#] DISCOVERY COMPLETE\n".format(len(host_list)),
                                'green'))
    return host_list

def outofscope(location, oos, host_list):

    oos_discovered = []
    oos_ips = []
    if os.path.isfile(oos):
        appendlog(location, colored("[#] OUT OF SCOPE FILE\n", 'yellow'))
        oos_ips = [line.rstrip('\n') for line in open(oos)]
        logdata = colored("[*] THE FOLLOWING TARGETS ARE OUT OT SCOPE: {0}\n".format(oos_ips), 'yellow')
        appendlog(location, logdata)
    else:
        logdata = colored("[!]ERROR WITH OUT OF SCOPE FILE: {0}\n".format(oos), 'red')
        appendlog(location, logdata)

    for ip in oos_ips:
        if ip in host_list:
            host_list.remove(ip)
            oos_discovered.append(ip)
    if len(oos_discovered) > 0:
        appendlog(location, colored("[-] THE FOLLOWING IP'S WERE DISCOVERED AND REMOVED FROM SCOPE: "
                                    "{0}\n".format(oos_discovered), 'magenta'))
    scope = colored("[+] TARGETS IN SCOPE FOR SCANNING: ", 'cyan') + colored("{0}\n".format(host_list), 'green')
    appendlog(location, scope)

    return host_list

