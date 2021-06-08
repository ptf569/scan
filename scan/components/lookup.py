#!/usr/bin/env python3

from shodan import Shodan, APIError
from termcolor import colored
import ipaddress
from .create import appendlog


def shodanSearch(host, key, location):
    ip = ipaddress.ip_address(host)
    if ip.is_global is True:
        appendlog(location, colored("[*] {0} IP A GLOBAL IP, ATTEMPTING TO PERFORM SHODAN LOOKUP".format(host),
                                    'yellow'))
        try:
            api = Shodan(key)
            lookup = api.host(host)
            f = open(location + host + "/SHO-" + host + ".txt", "w")

            # Print general info
            f.write("""
                    IP: {0}
                    Organization: {1}
                    Operating System: {2}
            """.format(lookup['ip_str'], lookup.get('org', 'n/a'), lookup.get('os', 'n/a')))



            # Print all banners
            for item in lookup['data']:
                f.write("""
                            Port: {0}
                            Banner: {1}
        
                    """.format(item['port'], item['data']))
            appendlog(location, colored("[+] {0} LOOKUP COMPLETE".format(host), 'green'))
        except:
            appendlog(location, colored("[!] CAN'T GET TO SHODAN RIGHT NOW, YOU'LL HAVE TO DO THIS ANOTHER TIME",
                                        'red'))
            print("[-] Error: {0}".format(APIError))
