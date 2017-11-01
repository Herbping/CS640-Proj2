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
                            create_ip_arp_reply(addr[0], arp.senderhwaddr,arp.targetprotoaddr , arp.senderprotoaddr))
                            break
                    log_debug("My_Addr: {}".format(myaddr))

                ########## END #########

                ########## TASK 3 ##########
                icmp = pkt.get_header(ICMP)

                if(icmp.icmptype == ICMPType.EchoRequest):
                    icmpreply = ICMP()
                    icmpreply.icmptype = ICMPType.EchoReply
                    icmpreply.





def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
