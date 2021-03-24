# scan.py

Network scanning script to drive recon tools.

Install with ```bash pip3 install -r requirements.txt```

```bash
./main.py -h                                                                                                                                                                                                                       130 ⨯
usage: A small program to automate some host discovery and some basic scanning [-h] [-t TARGETS] [-s SUBNET] [-R] [-n PROJECT_NAME] [-l PROJECT_LOCATION] [-O OOS_FILE] [-U] [-T THREADS] [-y TESTSSL] [-z SHODAN]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        Location of targets file
  -s SUBNET, --subnet SUBNET
                        Targets subnet
  -R, --rescan          Rescan the host even if we detect an nmap xml file
  -n PROJECT_NAME, --name PROJECT_NAME
                        The name of the project
  -l PROJECT_LOCATION, --location PROJECT_LOCATION
                        Location where to save the project
  -O OOS_FILE, --outofscope OOS_FILE
                        Location of IP's not to scan
  -U, --udp             Perform UDP scan of targets
  -T THREADS, --threads THREADS
                        Number of concurrent nmap scans. Default is 5
  -y TESTSSL, --testssl TESTSSL
                        Location of testssl.sh
  -z SHODAN, --shodan SHODAN
                        Shodan API key


```

Required tools:

 - nmap
 - sslscan

Optional:
 - testssl.sh
 - Shodan.io API key

