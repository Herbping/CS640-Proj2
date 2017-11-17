#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *


def get_ip_from_port(interfaces, dev):
    for intf in interfaces:
        if intf.name == dev:
            return intf.ipaddr
    return null

def get_eth_from_port(interfaces, dev):
    for intf in interfaces:
        if intf.name == dev:
            return intf.ethaddr
    return null

def get_port_from_eth(interfaces, eth):
    for intf in interfaces:
        if intf.ethaddr == eth:
            return intf.name
    return null

def icmp_unreachable(origpkt):
    i = origpkt.get_header_index(Ethernet)
    if i >= 0:
        del origpkt[i]
    icmp = ICMP()
    icmp.icmptype = ICMPType.DestinationUnreachable
    icmp.icmpdata.data = origpkt.to_bytes()[:28]
    ip = IPv4()
    ip.protocol = IPProtocol.ICMP
    ip.dst = origpkt.get_header(IPv4).src
    ip.ttl = 64


def icmp_timeexceeded(self):
    True


def icmp_host_unreachable(self):
    True


def icmp_port_unreachable(self):
    True


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
        for intf in my_interfaces:
            log_debug("My_Intf: {}".format(intf))

        myeth = [intf.ethaddr for intf in my_interfaces]
        myip = [intf.ipaddr for intf in my_interfaces]

        # forwarding table
        forwarding_table = []
        forwarding_table_path = "forwarding_table.txt"
        forwarding_t = open(forwarding_table_path, "r")
        for forwarding in forwarding_t:
            forwarding_item = forwarding.split()
            forwarding_table.append(forwarding_item)

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
                            create_ip_arp_reply(addr[0], arp.senderhwaddr,arp.targetprotoaddr , arp.senderprotoaddr))
                            break
                    log_debug("My_Addr: {}".format(myaddr))

                ########## END #########
                    ########## Stage 2 ##########
                    print("-----------stage2-----------")
                    IP_BROADCAST = ip_address("255.255.255.255")
                    if (pkt.get_header(Ethernet).dst in myeth) and (
                        pkt.get_header(IPv4).dst in myip):  # packet for the router itself
                        log_debug("Packet intended for me")
                        continue

                    ### TODO ###
                    pkt.get_header(IPv4).ttl -= 1
                    ### TODO ###

                    destaddr = pkt.get_header(IPv4).dst
                    for entry in forwarding_table:
                        prefixnet = IPv4Network(entry[0] + "/" + entry[1])
                        matches = destaddr in prefixnet
                        # print(matches)
                        if matches:  # sending packet to next hop
                            out_port = entry[3]
                            senderINTFhwaddr = get_ip_from_port(my_interfaces, out_port)
                            senderINTFprotoaddr = get_ip_from_port(my_interfaces, out_port)

                            i = 0
                            while i < 5:
                                i += 1
                                arp_gotpkt = False
                                self.net.send_packet(out_port,
                                                     create_ip_arp_request(senderINTFhwaddr, senderINTFprotoaddr,
                                                                           IP_BROADCAST))
                                try:
                                    arp_timestamp, arp_dev, arp_pkt = self.net.recv_packet(timeout=1.0)
                                    arp_gotpkt = True
                                except NoPackets:
                                    log_debug("No packets available in recv_packet")
                                    continue
                                if arp_gotpkt:
                                    ###TODO###
                                    # update forwarding table
                                    ###TODO###

                                    arp = arp_pkt.get_header(Arp)
                                    ethhead = Ethernet()
                                    ethhead.src = arp
                                    #
                                    self.net.send_packet(targethwaddr, pkt)
                                    break
                    if matches:
                        continue
                    # no match in the table
                    log_debug("Destination address does not match")
                    ######### END ##########

                ########## TASK 3 ##########
                icmp = pkt.get_header(ICMP)

                if icmp:
                    if(icmp.icmptype == ICMPType.EchoRequest):
                        icmpreply = ICMP()
                        icmpreply.icmptype = ICMPType.EchoReply
                        icmpreply.icmpcode = ICMPCodeEchoReply.EchoReply
                        icmpreply.icmpdata = icmp.icmpdata
                        ipreply = IPv4()
                        ipreply.dst = pkt.get_header(IPv4).src
                        ipreply.protocol = IPProtocol.ICMP
                        ipreply.src = get_ip_from_port(my_interfaces,dev)






def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
