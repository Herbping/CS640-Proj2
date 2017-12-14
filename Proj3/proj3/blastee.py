#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time

def create_ack(pkt,blaster_ip,myips):
    log_debug("received pck: {}".format(pkt))
    ack_packet_header = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
    #Ethernet
    ack_packet_header[0].src = pkt.get_header(Ethernet).dst
    ack_packet_header[0].dst = pkt.get_header(Ethernet).src
    #IPv4
    ack_packet_header[1].src = myips[0]
    ack_packet_header[1].dst = blaster_ip
    #seq number
    seq = ((pkt.get_header(RawPacketContents)).to_bytes())[:4]#first 4bytes/32bits
    #payload
    length = int.from_bytes(((pkt.get_header(RawPacketContents)).to_bytes())[4:6],'big')#16bits
    if length < 8:
        payload = ((pkt.get_header(RawPacketContents)).to_bytes())[6:]
        payload += bytes(8-length)
    else:
        payload = ((pkt.get_header(RawPacketContents)).to_bytes())[6:14]
    ack_packet = ack_packet_header + seq + payload
    return ack_packet

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    myips = [intf.ipaddr for intf in my_interfaces]

    params_path = "blastee_params.txt"
    params = open(params_path,"r").read().split()
    blaster_ip = None
    num = 0
    for i in range(len(params)):
        if params[i] == "-b":
            blaster_ip = params[i+1]
        if params[i] == "-n":
            num = int(params[i+1])
    

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            ack_packet = create_ack(pkt,blaster_ip,myips)
            net.send_packet(dev,ack_packet)

    net.shutdown()
