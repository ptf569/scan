import xml.etree.ElementTree as ET
from Modules.create import appendlog

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
                        message = "[+] WEB SERVICE DISCOVERED: {0}:{1}\n".format(ip,port.get('portid'))
                        appendlog(location, message)
                        web = open(location + "web.txt", "a+")
                        web.write("{0}:{1}\n".format(ip,port.get('portid')))
                        web.close()
                        ssl = service.get('tunnel')
                        if ssl or int(service.get('portid') == 443):
                            message = "[+] HTTPS SERVICE DISCOVERED: {0}:{1}\n".format(ip,port.get('portid'))
                            appendlog(location, message)
                            ssl = open(location + "https.txt", "a+")
                            ssl.write("{0}:{1}\n".format(ip, port.get('portid')))
                            ssl.close()
                except:
                    print('NO SERVICE IDENTIFIED ON PORT {0}'.format(port.get('portid')))

