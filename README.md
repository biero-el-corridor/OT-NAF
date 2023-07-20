# OT-NAF
Operational Technologie network analyser Framework


## Objective

The objective of this tool is to assist in the analysis of network behavior between a PLC and its HMI (Human-Machine Interface).

The behavior of a PLC is often linked to concrete actions, such as activating a lever, moving a robotic arm, etc. These actions are represented in network packets and are very clear.

The goal is to retrieve and aggregate these values, and then represent them to aid in the analysis of the relationships between the PLC and its HMI.

This tool is based on ARP spoofing between a PLC and an HMI.

To put it simply, the tool serves to have a prototype HMI without having to access the actual HMI itself.

## Operation

The parsed information will be stored in a json file and will be defined by the protocol type and its functions. 
Here's an example of parsing a modbus packet, it has the function "WRITE_SINGLE_COIL" , it targets the PLC with id 1 on register number 40

```json 
    "Modbus": {
        "WRITE_SINGLE_COIL": {
            "q1": {
                "UID": 0,
                "REGISTER": 0
            },
            "q2": {
                "UID": "1",
                "REGISTER": "40"
            }
```

## Protocol Suport

For now only modbus is supported by the tool. 

| protocol | soported |
| -------- | -------- |
| Modbus   | ✅      |
| s7comm   | ❌      |
| OPC-UA   | ❌      |

# Use case

Let's take a simple example.

Here is [GRFIDSv2](https://github.com/Fortiphyd/GRFICSv2), an OT lab developed by Fortiphyd Logic, which demonstrates how to attack a production factory using the Modbus protocol.

The objective of the lab is to activate a switch to create abnormal behavior from the machine.

For this, we need certain informations, such as:

- The slave ID of the PLC
- The type of variable (coil, register)
- The address of the "coil" or switch, which will be either 0 (OFF) or 1 (ON)

With these informations, we can perform certain actions (in the case of Modbus) like send a request to enable or disable the chemical plan present in the GRFIDSv2 lab , you can do it with [mbtget](https://github.com/sourceperl/mbtget) .

These informations is located at the level of the ScadaBR Human-Machine Interface.

However, this interface is protected by a password. If we find ourselves in a scenario where we don't have the password, this is where OT-NA comes into play.

By performing ARP spoofing, which will relay all network traffic to our machine, we are capable of intercepting and parsing the requests that interest us.

This was an example, but the core idea is here, spoof the network, parse the result and gather informations for offensive or defensive use.