import xml.dom.minidom
from Modules.create import appendlog
from termcolor import colored

class PortScannerHostDict(dict):
    def hostname(self):
        return self['hostname']

    def state(self):
        return self['status']['state']

    def uptime(self):
        return self['uptime']

    def all_protocols(self):
        lp = list(self.keys())
        lp.remove('status')
        lp.remove('hostname')
        lp.sort()
        return lp


def scandata(location, ip):
    scan_result = {}
    scan = "{0}/{1}/TCP-{1}.xml".format(location, ip)
    dom = xml.dom.minidom.parse(scan)
    scan_result['nmap'] = {
        'command_line': dom.getElementsByTagName('nmaprun')[0].getAttributeNode('args').value,
        'scaninfo': {},
        'scanstats': {'timestr': dom.getElementsByTagName("finished")[0].getAttributeNode('timestr').value,
                      'elapsed': dom.getElementsByTagName("finished")[0].getAttributeNode('elapsed').value,
                      'uphosts': dom.getElementsByTagName("hosts")[0].getAttributeNode('up').value,
                      'downhosts': dom.getElementsByTagName("hosts")[0].getAttributeNode('down').value,
                      'totalhosts': dom.getElementsByTagName("hosts")[0].getAttributeNode('total').value}
    }

    scan_result['scan'] = {}

    for dhost in dom.getElementsByTagName('host'):
        # host ip
        host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
        hostname = ''
        for dhostname in dhost.getElementsByTagName('hostname'):
            hostname = dhostname.getAttributeNode('name').value

        scan_result['scan'][host] = PortScannerHostDict({'hostname': hostname})

        for dstatus in dhost.getElementsByTagName('status'):
            # status : up...
            scan_result['scan'][host]['status'] = {'state': dstatus.getAttributeNode('state').value,
                                                   'reason': dstatus.getAttributeNode('reason').value}

        for dstatus in dhost.getElementsByTagName('uptime'):
            # uptime : seconds, lastboot
            scan_result['scan'][host]['uptime'] = {'seconds': dstatus.getAttributeNode('seconds').value,
                                                   'lastboot': dstatus.getAttributeNode('lastboot').value}
        for dport in dhost.getElementsByTagName('port'):
            # protocol
            proto = dport.getAttributeNode('protocol').value
            # port number converted as integer
            port = int(dport.getAttributeNode('portid').value)
            # state of the port
            state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
            # reason
            reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
            # name, product, version, extra info and conf if any
            name, product, version, extrainfo, conf, tunnel = '', '', '', '', '', ''
            for dname in dport.getElementsByTagName('service'):
                name = dname.getAttributeNode('name').value
                if dname.hasAttribute('product'):
                    product = dname.getAttributeNode('product').value
                if dname.hasAttribute('version'):
                    version = dname.getAttributeNode('version').value
                if dname.hasAttribute('extrainfo'):
                    extrainfo = dname.getAttributeNode('extrainfo').value
                if dname.hasAttribute('conf'):
                    conf = dname.getAttributeNode('conf').value
                if dname.hasAttribute('tunnel'):
                    tunnel = dname.getAttributeNode('tunnel').value
            # store everything
            if not proto in list(scan_result['scan'][host].keys()):
                scan_result['scan'][host][proto] = {}
            scan_result['scan'][host][proto][port] = {'state': state,
                                                      'reason': reason,
                                                      'name': name,
                                                      'product': product,
                                                      'version': version,
                                                      'extrainfo': extrainfo,
                                                      'conf': conf,
                                                      'tunnel': tunnel}

            script_id = ''
            script_out = ''
            # get script output if any
            for dscript in dport.getElementsByTagName('script'):
                script_id = dscript.getAttributeNode('id').value
                script_out = dscript.getAttributeNode('output').value
                if not 'script' in list(scan_result['scan'][host][proto][port].keys()):
                    scan_result['scan'][host][proto][port]['script'] = {}

                scan_result['scan'][host][proto][port]['script'][script_id] = script_out

        for dport in dhost.getElementsByTagName('osclass'):
            # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
            ostype = ''
            vendor = ''
            osfamily = ''
            osgen = ''
            accuracy = ''
            try:
                ostype = dport.getAttributeNode('type').value
                vendor = dport.getAttributeNode('vendor').value
                osfamily = dport.getAttributeNode('osfamily').value
                osgen = dport.getAttributeNode('osgen').value
                accuracy = dport.getAttributeNode('accuracy').value
            except AttributeError:
                pass
            if not 'osclass' in list(scan_result['scan'][host].keys()):
                scan_result['scan'][host]['osclass'] = []

            scan_result['scan'][host]['osclass'].append(
                {
                    'type': ostype,
                    'vendor': vendor,
                    'osfamily': osfamily,
                    'osgen': osgen,
                    'accuracy': accuracy
                }
            )

        for dport in dhost.getElementsByTagName('osmatch'):
            # <osmatch name="Linux 2.6.31" accuracy="98" line="30043"/>
            name = ''
            accuracy = ''
            line = ''
            try:
                name = dport.getAttributeNode('name').value
                accuracy = dport.getAttributeNode('accuracy').value
                line = dport.getAttributeNode('line').value
            except AttributeError:
                pass
            if not 'osmatch' in list(scan_result['scan'][host].keys()):
                scan_result['scan'][host]['osmatch'] = []

            scan_result['scan'][host]['osmatch'].append(
                {
                    'name': name,
                    'accuracy': accuracy,
                    'line': line,
                }
            )

        for dport in dhost.getElementsByTagName('osfingerprint'):
            # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
            fingerprint = ''
            try:
                fingerprint = dport.getAttributeNode('fingerprint').value
            except AttributeError:
                pass

            scan_result['scan'][host]['fingerprint'] = fingerprint

    return scan_result


def parse(location, ip):
    scan = scandata(location, ip)
    if scan['scan']:
        try:
            for port in scan['scan'][ip]['tcp']:
                if 'http' in scan['scan'][ip]['tcp'][port]['name']:
                    message = colored("[+] WEB SERVICE DISCOVERED: {0}:{1}".format(ip, port), 'white')
                    appendlog(location, message)
                    web = open(location + "web.txt", "a+")
                    web.write("{0}:{1}\n".format(ip, port))
                    web.close()
                    if scan['scan'][ip]['tcp'][port]['tunnel']:
                        message = colored("[+] HTTPS SERVICE DISCOVERED: {0}:{1}".format(ip, port), 'white')
                        appendlog(location, message)
                        ssl = open(location + "https.txt", "a+")
                        ssl.write("{0}:{1}\n".format(ip, port))
                        ssl.close()

                if port in [139, 445]:
                    message = colored("[+] POSSIBLE SMB SERVICE DISCOVERED: {0}:{1}".format(ip, port), 'white')
                    if 'netbios-ssn' in scan['scan'][ip]['tcp'][port]['name']:
                        message = colored("[+] SMB NETBIOS DISCOVERED: {0}:{1}".format(ip, port), 'white')
                    if 'microsoft-ds' in scan['scan'][ip]['tcp'][port]['name']:
                        message = colored("[+] SMB SERVER DISCOVERED: {0}:{1}".format(ip, port), 'white')
                    smb = open(location + "smb.txt", "a+")
                    smb.write("{0}:{1}\n".format(ip, port))
                    smb.close()
                    appendlog(location, message)


        except:
            message = colored("[-] NO TCP PORTS ON HOST: {0}".format(ip), 'magenta')
            appendlog(location, message)
    else:
        message = colored("[-] NO SCAN DATA ON HOST: {0}".format(ip), 'magenta')
        appendlog(location, message)

def ports(location, ip):
    scan = scandata(location, ip)
    if scan['scan']:
        try:
            portdata = {}
            for port in scan['scan'][ip]['tcp']:
                portdata[port] = [scan['scan'][ip]['tcp'][port]['state'], scan['scan'][ip]['tcp'][port]['name'],
                                  scan['scan'][ip]['tcp'][port]['product'], scan['scan'][ip]['tcp'][port]['version']]
            #print(portdata)
#----- SCAN TABLE
            print("\n\nHOST: {0} \n".format(ip))

            print("{:<8} {:<10} {:<15} {:<20}".format('PORT', 'STATE', 'SERVICE', 'VERSION'))
            print("{:<8} {:<10} {:<15} {:<20}".format('----', '-----', '-------', '-------'))
            for k, v in portdata.items():
                print("{:<8} {:<10} {:<15} {:<20}".format(k, v[0], v[1], v[2]))

            print("\nOS: {0} \nACCURACY: {1}\n\n".format(scan['scan'][ip]['osclass'][0]['vendor'],
                                                     scan['scan'][ip]['osclass'][0]['accuracy']))

        except:
            message = colored("[-] NO TCP PORTS ON HOST: {0}".format(ip), 'magenta')
            appendlog(location, message)


#loc = '/Users/pentest/Documents/Tests/House/'
loc = '/root/Tests/House/'
tgt = '10.57.151.1'

#parse(loc, tgt)

#ports(loc, tgt)

#print(scan['nmap'])
#print(scan['scan']['10.57.151.1'])
#print(scan['scan']['10.57.151.1']['status'])
#print(scan['scan']['10.57.151.1']['tcp'][22])
#for port in scan['scan']['10.57.151.1']['tcp']:
#    print(port)
#    print(scan['scan']['10.57.151.1']['tcp'][port])
