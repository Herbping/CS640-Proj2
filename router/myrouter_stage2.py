#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''

        # interfaces
        my_interfaces = self.net.interfaces()
        myaddr = [[intf.ethaddr, intf.ipaddr] for intf in my_interfaces]
        log_debug("My_Addr: {}".format(myaddr))
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
					########## TASK 1 ##########
                # recv packet check arp
                arp = pkt.get_header(Arp)
                log_debug(" Arp: {}".format(arp))

                if(arp):
                    # store the source addr
                    #if arp.senderhwaddr not in [addr[0] for addr in myaddr]:
                    #    myaddr.append([arp.senderhwaddr,arp.senderprotoaddr])
                    # find mac by ip
                    for addr in myaddr:
                        if addr[1] == arp.targetprotoaddr:
                            self.net.send_packet(dev,
                            create_ip_arp_reply(addr[0],arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr))
                            break
                    log_debug("My_Addr: {}".format(myaddr))
                    continue

					########## Stage 2 ##########
                print("-----------stage2-----------")
                IP_BROADCAST = ip_address("255.255.255.255")
                myip = [intf.ipaddr for intf in my_interfaces]
                if pkt.get_header(Ethernet).dst in myaddr and pkt.get_header(IPv4).dst in myip:#packet for the router itself
                    log_debug ("Packet intended for me")
                    continue
                pkt.get_header(IPv4).ttl -= 1
                forwarding_table = []
                forwarding_table_path = "forwarding_table.txt"
                forwarding_t  = open(forwarding_table_path, "r")
                for forwarding in forwarding_t:
                    forwarding_item = forwarding.split()
                    forwarding_table.append(forwarding_item)

                destaddr = pkt.get_header(IPv4).dst
                for addr in forwarding_table:
                    prefixnet = IPv4Network(addr[0]+"/"+addr[1])
                    matches = destaddr in prefixnet
                    #print(matches)
                    if matches:#sending packet to next hop
                        senderhwaddr = pkt.get_header(Ethernet).src
                        senderprotoaddr = pkt.get_header(IPv4).src
                        arp_dest = addr[2]

                        self.net.send_packet(arp_dest,create_ip_arp_request(senderhwaddr, senderprotoaddr,IP_BROADCAST))
                        time.sleep(1)
                        i = 0
                        while i < 5:
                            i += 1
                            arp_gotpkt = False
                            try:
                                arp_timestamp,arp_dev,arp_pkt = self.net.recv_packet(timeout=1.0)
                                arp_gotpkt = True
                            except NoPackets:
                                log_debug("No packets available in recv_packet")
                                self.net.send_packet(arp_dest,create_ip_arp_request(senderhwaddr, senderprotoaddr,IP_BROADCAST))
                                time.sleep(1)
                                continue
                            if arp_gotpkt:
                                arp = arp_pkt.get_header(Arp)
                                if arp.targethwaddr in myaddr:
                                    targethwaddr = arp.senderhwaddr
                                    #
                                    self.net.send_packet(targethwaddr,pkt)
                                    break
                if matches:
                    continue
                #no match in the table
                log_debug ("Destination address does not match")

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
