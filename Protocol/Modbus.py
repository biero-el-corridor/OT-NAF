from scapy.all import *
from Protocol.Modbus import *
from collections import Counter
import argparse
import time
import os
import sys
import yaml
import json

"""
récuperer les élément constater 

- [ ] le nombre de machine sniffer (Unit identifier). 
- [ ] le nombre de fois que il y a ue un ON OFF
- [ ] le type de décriture effecteur (sigle/multiple coil/register)
- [ ] le type 

"""




# basif fo all of the modbus packet
class ModbusTCP(Packet):  #Packet,TID,size,UID):
    name = 'Modbus/TCP'
    fields_desc = [
        ShortField("Transaction_Identifier", 33614),
        ShortField("Protocol_Identifier", 0), # standart ProcessID for modbus 
        ShortField("Lenght", 6), # only when coil is present lenght is equal to 6
        ByteField("Unit_Identifier", 0x01)
    ]

class Write_Single_Coil_Modbus(Packet): #Packet,Fcode,Ref_Number,ON_OFF):
    name = 'Modbus'
    fields_desc = [
    ByteField("Function_Code",0x05),
    ShortField("Reference_Number",40),
    ShortField("Data",65280  )
    ]



Functions_code = {
  'READ_COILS': 1,
  'READ_DISCRETE_INPUTS': 2,
  'READ_HOLDING_REGS': 3,
  'READ_INPUT_REGS': 4,
  'WRITE_SINGLE_COIL': 5,
  'WRITE_SINGLE_REG': 6,
  'READ_EXCEPT_STAT': 7,
  'DIAGNOSTICS': 8,
  'GET_COMM_EVENT_CTRS': 11,
  'GET_COMM_EVENT_LOG': 12,
  'WRITE_MULT_COILS': 15,
  'WRITE_MULT_REGS': 16,
  'REPORT_SLAVE_ID': 17,
  'READ_FILE_RECORD': 20,
  'WRITE_FILE_RECORD': 21,
  'MASK_WRITE_REG': 22,
  'READ_WRITE_REG': 23,
  'READ_FIFO_QUEUE': 24,
  'ENCAP_INTERFACE_TRANSP': 43,
  'UNITY_SCHNEIDER': 90  
}

blank_json = {
    "Modbus": {
        "WRITE_SINGLE_COIL": {
            "q1": {
                "UID": 0,
                "REGISTER": 0
            }
        },
        "WRITE_MULT_COILS": {
            "q1": {
                "UID": 0,
                "REGISTER": 0
            }
        },
        "WRITE_SINGLE_REG": {
            "q1": {
                "UID": 0,
                "REGISTER": 0
            }
        },
        "WRITE_MULT_REGS": {
            "q1": {
                "UID": 0,
                "REGISTER": 0
            }
        },
    }
}

def check_if_file_exist(file_path):
    # check if result file exist 
    check_file = os.path.isfile(file_path)
    # si le fichier n'existe pas un fichier de référence va étre crée 
    if check_file == False:
        with open("file.json", "w") as file:
            json_string = json.dumps(blank_json, indent=3)
            file.write(json_string)


def add_element_in_file(UID,functions_name,filename):
    print("chk1", UID)
    # Opening JSON file
    with open("modbus.json","r+") as f:
        data = json.load(f)
        for keys1 in data["Modbus"].keys():
            """
            print("chk2")
            print("value of functions_name :", functions_name )
            print("value of the key :", keys1 )
            """
            if functions_name == keys1: 
                #print("pass the key")
                for keys2 in data["Modbus"][keys1].keys():
                    #print("for loop :", keys2)
                    for unit in data["Modbus"][keys1][keys2]:
                        uid = unit
                        unid_value = data["Modbus"][keys1][keys2][unit]
                        #print("hello", data["Modbus"][keys1][keys2].values())
                        if unit != "UID":
                            
                            new_name = "q2"
                            new_Coil = { 'UID': "1", 'REGISTER': "40" }
                            print(new_Coil)
                            try:
                                data["Modbus"][keys1][new_name]=new_Coil
                                json_object = json.dumps(data, indent=4)
                                f.seek(0)
                                f.write(json_object)
                            except:
                                print("error in the writing")
            else:
                print("")
        """
        if "q3" not in data["Modbus"][keys]:
            dict_example2 = {"qsfsdfsdfsdfsddf":"TEST","TOMATE":"PATATE"}
            data['Modbus'][keys]["q3"]=dict_example2 
        """
                    
        #print(data)
        json_object = json.dumps(data, indent=4)
        f.seek(0)
        f.write(json_object)
        # Closing file


def parse_modbus(packt,Request,Response):
        # verify if result file exist
        #check_if_file_exist("b.json")
        
        Transactions_Identifier = ord(packt[0:1])*256 + ord(packt[1:2])
        Protocol_Identifier     = 0
        Lenght                  = ord(packt[5:6])
        Unit_Identifier         = packt[6]
        Functions_code_sniffed  = packt[7]

        # Very Verbose 
        # define the structure of the Modbus/TCP
        # print("Transactions Identifier: ", Transactions_Identifier)  # transactions identifier
        # print("Protocol Identifier:     ", Protocol_Identifier )     # protocol identifier (is already tcheked before entering)
        # print("Lenght:                  ", Lenght)                   # lenght
        # print("Unit Identifier:         ", Unit_Identifier)          # Unit identifier                       
        # search and define the functions code found

        # test pkt send of offensif modbus
        pkt = IP(src="192.168.90.116",dst="192.168.92.2")/TCP(window=502,sport=37927,dport=502,flags=tcp_flags)/ModbusTCP()/Write_Single_Coil_Modbus()
        sr1(pkt) 

        if Functions_code_sniffed == 5 and Request == True:
        
            Reference_Number = ord(packt[8:9])*256   + ord(packt[9:10])
            Data             = ord(packt[10:11])*256 + ord(packt[11:12])
            # check if uid alredy exist
            #print(Unit_Identifier)
            print("test1")
            #https://www.guru99.com/python-dictionary-append.html
            # verifiy if elemnt is in the result json
            add_element_in_file(Unit_Identifier,list(Functions_code.keys())[list(Functions_code.values()).index(Functions_code_sniffed)], "modbus.json")
             
            
            #print("Bit Count: ", packt[11]) 
            #print("Reference Number:   " ,  Reference_Number) # The Data Address of the coil
            #print("Data:               " ,  Data) # Value of the single coil

        if Functions_code_sniffed == 15 and Request == True:
            # try to count the number of coil writen 
            
            Payload_size = len(packt[TCP].payload)
            number_of_coil_writen = Payload_size / 14
            # round to the sup int because the lenght who whas devided the payload lenght 
            # is the max lenght possible (15) when the minimum legnt possible is (14) 

            # need to reparse the tcp value 

            number_of_coil_writen = round(number_of_coil_writen)
            while number_of_coil_writen != 0: 
            Reference_Number = ord(packt[8:9])*256   + ord(packt[9:10])
            Data             = ord(packt[10:11])*256 + ord(packt[11:12])
            pass