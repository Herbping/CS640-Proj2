#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import random
import time

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    params_path = "middlebox_params.txt"
    params = open(params_path,"r").read().split()
    drop_rate = 1
    for i in range(len(params)):
        if params[i] == "-d":
            drop_rate = float(params[i+1])

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
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            random_rate = random.uniform(0,1)
            if random_rate>drop_rate:
                pkt.get_header(Ethernet).src = "40:00:00:00:00:02"#middlebox-eth1
                pkt.get_header(Ethernet).dst = "20:00:00:00:00:01"#blastee
                net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            pkt.get_header(Ethernet).src = "40:00:00:00:00:01"#middlebox-eth0
            pkt.get_header(Ethernet).dst = "10:00:00:00:00:01"#blaster
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()
