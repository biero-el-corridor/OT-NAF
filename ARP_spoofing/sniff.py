from scapy.all import *
from Protocol.Modbus import *
from collections import Counter
import argparse
import time
import os
import sys
import yaml




def Protocol_Filter(packet):

    sport = packet[TCP].sport
    dport = packet[TCP].dport
    
    if sport > dport : 
        Request = True 
        Response = False  
    if sport < dport : 
        Request = False
        Response = True
    
    # modbus is defined by multiple thing
    # generaly the post 502 is what modbus is defined by 
    # for his one i whant to base myself on other think , because the port 502 in not relly mendatory 
    try:
        
        packt = packet[Raw].load 
        
        #if ord(packt[2:3]) == 0 and ord(packt[3:4]) == 0 and packt[7] in ModbusFunctionsCodeNumber:
        if dport == 502:
            #print("ffff")
            parse_modbus(packt,Request,Response)
    except:
        pass
