#!/usr/bin/env python3

import os
import subprocess
import sys
import time
from xml.etree import ElementTree

if len(sys.argv) != 2:
    print("auto-sslscan.py <nmap-xml-file>")
    sys.exit(0)

filename = sys.argv[1]
if not os.path.isfile(filename):
    print("Error: {} does not appear to exist".format(filename))
    sys.exit(0)

# Parse Nmap XML file
tree = ElementTree.parse(filename)
root = tree.getroot()

# List for storing host:port
targets = []

# Loop through XML to get hostname and port
for host in root.iter('host'):
    ip = host.find('address').get('addr')
    for port in host.iter('port'):
        if port.get('protocol') == 'tcp':
            targets.append("{}:{}".format(ip, port.get('portid')))

# Count number of targets
target_count = len(targets)

# For each target
for idx, target in enumerate(targets):
    # If not last target
    if idx < target_count - 1:
        # Print host:port
        print("sslscan --no-failed {} > {}.txt &".format(target, target.replace(':', '_')))
        subprocess.Popen("sslscan --no-failed {} > {}.txt &".format(target, target.replace(':', '_')), shell=True)
    # If last target
    else:
        # Print host:port and wait for scans to complete
        print("sslscan --no-failed {} > {}.txt".format(target, target.replace(':', '_')))
        subprocess.Popen("sslscan --no-failed {} > {}.txt".format(target, target.replace(':', '_')), shell=True)
        print("Waiting for all scans to complete...")
        time.sleep(2)
        while True:
            try:
                ret = subprocess.Popen("pgrep sslscan", stdout=subprocess.PIPE, shell=True)
                output = ret.communicate()[0].decode('utf-8')
                if output == '':
                    break
                else:
                    time.sleep(2)
            except KeyboardInterrupt:
                print("Caught KeyboardInterrupt, terminating scans")
                os.system("pkill sslscan")
