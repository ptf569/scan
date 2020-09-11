import xml.etree.ElementTree as ET
from Modules.create import appendlog
from termcolor import colored

def test(location,ip):

    tree = ET.parse("{0}/{1}/{1}.xml".format(location, ip))
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

def http(location, ip):
    tree = ET.parse("{0}/{1}/TCP-{1}.xml".format(location, ip))
    root = tree.getroot()

    for i in root.iter('host'):
        ports = i.find('ports')
        for port in ports:
            if 'portid' in port.attrib:
                service = port.find('service')
                try:
                    if service.get('name') in ('http') or service.get('name') in ('https'):
                        #print("{0}:{1}".format(ip,port.get('portid')))
                        message = colored("[+] WEB SERVICE DISCOVERED: {0}:{1}\n".format(ip,port.get('portid'), 'green'))
                        appendlog(location, message)
                        web = open(location + "web.txt", "a+")
                        web.write("{0}:{1}\n".format(ip,port.get('portid')))
                        web.close()
                        ssl = service.get('tunnel')
                        if ssl or int(service.get('portid') == 443):
                            message = colored("[+] HTTPS SERVICE DISCOVERED: {0}:{1}\n".format(ip,port.get('portid'), 'green'))
                            appendlog(location, message)
                            ssl = open(location + "https.txt", "a+")
                            ssl.write("{0}:{1}\n".format(ip, port.get('portid')))
                            ssl.close()
                except:
                    print('NO SERVICE IDENTIFIED ON PORT {0}'.format(port.get('portid')))


def ports(location, ip):
    tree = ET.parse("{0}/{1}/TCP-{1}.xml".format(location, ip))
    root = tree.getroot()

    for i in root.iter('host'):
        ports = i.find('ports')
        print("Host {0}".format(ip))
        for port in ports:
            proto = port.get('protocol')
            num = port.get('portid')
            if num is not None:
                print("{0}:{1}".format(num, proto))
        stats = i.find('runstats')


        print(stats)


#ports('/root/Tests/House/', '10.57.151.1')