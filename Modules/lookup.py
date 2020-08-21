from shodan import Shodan, APIError
import ipaddress
from Modules.create import appendlog


def shodanSearch(host, key, location):
    ip = ipaddress.ip_address(host)
    if ip.is_global is True:
        appendlog(location, "[+] {0} IP A GLOBAL IP, ATTEMPTING TO PERFORM SHODAN LOOKUP \n".format(host))
        try:
            api = Shodan(key)
            lookup = api.host(host)
            f = open(location + host + "/SHODAN-" + host + ".txt", "w")

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
            appendlog(location, "[+] {0} LOOKUP COMPLETE \n".format(host))
        except:
            appendlog(location, "CAN'T GET TO SHODAN RIGHT NOW, YOU'LL HAVE TO DO THIS ANOTHER TIME \n")
            print("[-] Error: {0}".format(APIError))
