#!/usr/bin/env python3

import ipaddress

from switchyard.lib.userlib import *

class Router(object):
    def get_ip_from_port(self, dev):
        for intf in self.my_interfaces:
            if intf.name == dev:
                return intf.ipaddr
        return None

    def get_eth_from_port(self, dev):
        for intf in self.my_interfaces:
            if intf.name == dev:
                return intf.ethaddr
        return None

    def get_port_from_eth(self, eth):
        for intf in self.my_interfaces:
            if intf.ethaddr == eth:
                return intf.name
        return None

    def icmp_unreachable(self, origpkt, dev):
        result_pkt = Packet()
        i = origpkt.get_header_index(Ethernet)
        if i >= 0:
            del origpkt[i]
        icmp = ICMP()
        icmp.icmptype = ICMPType.DestinationUnreachable
        icmp.icmpcode = ICMPCodeDestinationUnreachable.NetworkUnreachable
        icmp.icmpdata.data = origpkt.to_bytes()[:28]
        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.dst = origpkt.get_header(IPv4).src
        ip.ttl = 64
        ip.src = Router.get_ip_from_port(self, dev)
        Router.router_recv_ipv4_echo(self, ip+icmp+result_pkt, dev)

    def icmp_timeexceeded(self, pkt, dev):
        result_pkt = Packet()
        i = pkt.get_header_index(Ethernet)
        if i >= 0:
            del pkt[i]
        icmp = ICMP()
        icmp.icmptype = ICMPType.TimeExceeded
        icmp.icmpcode = ICMPCodeTimeExceeded.TTLExpired
        icmp.icmpdata.data = pkt.to_bytes()[:28]
        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.dst = pkt.get_header(IPv4).src
        ip.ttl = 64
        ip.src = Router.get_ip_from_port(self, dev)
        Router.router_recv_ipv4_echo(self, ip+icmp+result_pkt, dev)

    def icmp_host_unreachable(self, pkt, dev):
        result_pkt = Packet()
        i = pkt.get_header_index(Ethernet)
        if i >= 0:
            del pkt[i]
        icmp = ICMP()
        icmp.icmptype = ICMPType.DestinationUnreachable
        icmp.icmpcode = ICMPCodeDestinationUnreachable.HostUnreachable
        icmp.icmpdata.data = pkt.to_bytes()[:28]
        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.dst = pkt.get_header(IPv4).src
        ip.ttl = 64
        ip.src = Router.get_ip_from_port(self, dev)
        Router.router_recv_ipv4_echo(self, ip+icmp+result_pkt, dev)

    def icmp_port_unreachable(self, pkt, dev):
        result_pkt = Packet()
        i = pkt.get_header_index(Ethernet)
        if i >= 0:
            del pkt[i]
        icmp = ICMP()
        icmp.icmptype = ICMPType.DestinationUnreachable
        icmp.icmpcode = ICMPCodeDestinationUnreachable.PortUnreachable
        icmp.icmpdata.data = pkt.to_bytes()[:28]
        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.dst = pkt.get_header(IPv4).src
        ip.ttl = 64
        ip.src = Router.get_ip_from_port(self, dev)
        Router.router_recv_ipv4_echo(self, ip+icmp+result_pkt, dev)

    def __init__(self, net):
        self.net = net
        # other initialization stuff here        # forwarding table
        self.forwarding_table = []
        forwarding_table_path = "forwarding_table.txt"
        forwarding_t = open(forwarding_table_path, "r")
        for forwarding in forwarding_t:
            forwarding_item = forwarding.split()
            self.forwarding_table.append(forwarding_item)

        # interfaces
        self.my_interfaces = self.net.interfaces()
        self.myaddr = [[intf.ethaddr, intf.ipaddr] for intf in self.my_interfaces]
        for intf in self.my_interfaces:
            log_debug("My_Intf: {}".format(intf))
            log_debug("My_Intf: {}".format(intf.netmask))
            self.forwarding_table.append([str(ipaddress.ip_address(int(intf.ipaddr) & int(intf.netmask))), str(intf.netmask), str(intf.ipaddr), intf.name])

        self.myeth = [intf.ethaddr for intf in self.my_interfaces]
        self.myip = [intf.ipaddr for intf in self.my_interfaces]
        log_debug("IPs: {}".format(self.myip))
        log_debug("Lookup table: {}".format(self.forwarding_table))
        self.arp_table = []
        self.ip_queue = []

    def router_main(self):
        while True:
            gotpkt = True
            log_debug("ARP table: {}".format(self.arp_table))
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)

            except NoPackets:
                log_debug("No packets available in recv_packet")

                sent_arp = []

                for ip_entry in self.ip_queue:
                    if ip_entry[3] >= 5:
                        Router.icmp_host_unreachable(self, ip_entry[1], ip_entry[4])

                self.ip_queue = [ip_entry for ip_entry in self.ip_queue if ip_entry[3] >= 5]
                for ip_entry in self.ip_queue:
                    ip_entry[3] += 1
                    if ip_entry[0] not in sent_arp:
                        sent_arp.append(ip_entry[0])
                        Router.router_make_arp_request(self, ip_entry[0], ip_entry[2])

                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

                arp = pkt.get_header(Arp)
                log_debug(" Arp: {}".format(arp))

                # ARP
                if arp:
                    if arp.operation == ArpOperation.Request:
                        Router.router_recv_arp_request(self, timestamp, dev, arp)
                    if arp.operation == ArpOperation.Reply:
                        Router.router_recv_arp_reply(self, timestamp, dev, arp)
                    else:
                        Router.icmp_port_unreachable(self, pkt, dev)

                # ICMP

                # IPV4
                ipv4 = pkt.get_header(IPv4)
                if ipv4:
                    Router.router_recv_ipv4(self, pkt, dev)
                # END #

    def router_recv_ipv4(self, pkt, dev):
        log_debug("dest ip {}".format(pkt.get_header(IPv4).dst))
        ipv4 = pkt.get_header(IPv4)
        if pkt.get_header(IPv4).dst in self.myip:  # packet for the router itself
            log_debug("Packet intended for me")
            icmp = pkt.get_header(ICMP)
            if icmp:
                if icmp.icmptype == ICMPType.EchoRequest:
                    Router.router_recv_echo_request(self, pkt, dev)
            return

        destip = pkt.get_header(IPv4).dst
        for entry in self.arp_table:
            if entry[0] == str(destip):
                log_debug("found in arp")
                pkt[0].src = Router.get_eth_from_port(self, entry[2])
                pkt[0].dst = entry[1]
                self.net.send_packet(entry[2], pkt)
                return

        forward_entry = Router.get_forward_entry(self, pkt)
        if forward_entry is None:
            Router.icmp_unreachable(self, pkt, dev)
            return
        pkt.get_header(IPv4).ttl -= 1
        log_debug("TTL: {}".format(ipv4.ttl))
        if pkt.get_header(IPv4).ttl == 0:
            Router.icmp_timeexceeded(self, pkt, dev)

        found_in_queue = False
        for ip_entry in self.ip_queue:
            if ip_entry[0] == str(pkt.get_header(IPv4).dst):
                self.ip_queue.append([str(pkt.get_header(IPv4).dst), pkt, forward_entry, ip_entry[3], dev])
                found_in_queue = True
                break

        if not found_in_queue:
            self.ip_queue.append([str(pkt.get_header(IPv4).dst), pkt, forward_entry, 1, dev])
            Router.router_make_arp_request(self,str(pkt.get_header(IPv4).dst),forward_entry)

    def router_recv_arp_reply(self,timestamp,dev,arp):
        ip_got = arp.senderprotoaddr
        eth_got = arp.senderhwaddr
        log_debug("ip_queue: {}".format(self.ip_queue))
        self.arp_table.append([str(arp.senderprotoaddr), str(arp.senderhwaddr), dev])
        for ip_entry in self.ip_queue:
            if(ip_entry[0] == str(ip_got)):
                self.arp_table.append([str(ip_entry[1].get_header(IPv4).dst), str(arp.senderhwaddr), dev])
                if(ip_entry[1].get_header(Ethernet) is None):
                    ip_entry[1].insert_header(0,Ethernet())
                    ip_entry[1][0].ethertype = EtherType.IP
                log_debug("send packet: {}".format(ip_entry))
                ip_entry[1][0].dst = eth_got
                ip_entry[1][0].src = Router.get_eth_from_port(self,dev)
                log_debug("ready to sent: {}".format(ip_entry[1]))
                log_debug("ready to sent: {}".format(ip_entry[1].get_header(ICMP).icmptype))
                self.net.send_packet(dev, ip_entry[1])
        self.ip_queue = [ip_entry for ip_entry in self.ip_queue if ip_entry[0] != str(ip_got)]
        log_debug("ip_queue: {}".format(self.ip_queue))

    def router_recv_arp_request(self, timestamp, dev, arp):
        self.arp_table.append([str(arp.senderprotoaddr), str(arp.senderhwaddr), dev])

        for addr in self.myaddr:
            if addr[1] == arp.targetprotoaddr:
                self.net.send_packet(dev,
                                     create_ip_arp_reply(addr[0], arp.senderhwaddr, arp.targetprotoaddr,
                                                         arp.senderprotoaddr))
                break
        log_debug("My_Addr: {}".format(self.myaddr))

    def router_recv_echo_request(self, pkt,dev):
        result_pkt = Packet()
        icmp = pkt.get_header(ICMP)
        icmpreply = ICMP()
        icmpreply.icmptype = ICMPType.EchoReply
        icmpreply.icmpcode = ICMPCodeEchoReply.EchoReply
        icmpreply.icmpdata.data = icmp.icmpdata.data
        log_debug("icmpreply: {}".format(icmpreply))
        ipreply = IPv4()
        ipreply.dst = pkt.get_header(IPv4).src
        ipreply.protocol = IPProtocol.ICMP
        ipreply.ttl = 64
        ipreply.src = pkt.get_header(IPv4).dst
        Router.router_recv_ipv4_echo(self, ipreply+icmpreply+result_pkt,dev)

    def get_forward_entry(self,pkt):
        destip = pkt.get_header(IPv4).dst
        matched_len = 0
        matched_entry = None
        matches = False

        for entry in self.forwarding_table:
            log_debug("start look at entry {} ".format(entry[0] + "/" + entry[1]))
            prefixnet = IPv4Network(entry[0] + "/" + entry[1])
            log_debug("prefix net: {}".format(prefixnet))
            matches = (destip in prefixnet) | matches
            log_debug("matches: {}".format(matches))

            if (destip in prefixnet) and matched_len<prefixnet.prefixlen:
                matched_entry = entry
            # exact next hop
            log_debug("str1 {} str2 {}".format(entry[2],str(destip)))
            if entry[2] == str(destip):
                matched_entry = entry
                matches = True
                break
        if matches:
            return matched_entry
        return None


    def router_make_arp_request(self, destip, forward_entry):
        log_debug("matched entry: {} destip {}".format(forward_entry, destip))
        out_port = forward_entry[3]
        senderINTFhwaddr = Router.get_eth_from_port(self, out_port)
        senderINTFprotoaddr = Router.get_ip_from_port(self, out_port)
        log_debug("HWADDR: {} IPADDR: {}".format(senderINTFhwaddr, senderINTFprotoaddr))
        self.net.send_packet(out_port,
                        create_ip_arp_request(senderINTFhwaddr, senderINTFprotoaddr,
                                                       destip))

    def router_recv_ipv4_echo(self, pkt, dev):
        log_debug("dest ip {}".format(pkt.get_header(IPv4).dst))
        ipv4 = pkt.get_header(IPv4)
        if pkt.get_header(IPv4).dst in self.myip:  # packet for the router itself
            log_debug("Packet intended for me")
            icmp = pkt.get_header(ICMP)
            if icmp:
                if icmp.icmptype == ICMPType.EchoRequest:
                    Router.router_recv_echo_request(self, pkt, dev)
            return

        destip = pkt.get_header(IPv4).dst
        for entry in self.arp_table:
            if entry[0] == str(destip):
                log_debug("found in arp: {}".format(entry))
                if pkt.get_header(Ethernet) is None:
                    pkt.insert_header(0, Ethernet())
                    pkt[0].ethertype = EtherType.IP
                pkt[0].src = Router.get_eth_from_port(self, entry[2])
                pkt[0].dst = entry[1]
                self.net.send_packet(entry[2], pkt)
                return

        forward_entry = Router.get_forward_entry(self, pkt)
        if forward_entry is None:
            Router.icmp_unreachable(self, pkt, dev)
            return
        pkt.get_header(IPv4).ttl -= 1
        log_debug("TTL: {}".format(ipv4.ttl))
        if pkt.get_header(IPv4).ttl == 0:
            Router.icmp_timeexceeded(self, pkt, dev)

        found_in_queue = False
        for ip_entry in self.ip_queue:
            if ip_entry[0] == str(pkt.get_header(IPv4).dst):
                self.ip_queue.append([str(pkt.get_header(IPv4).dst), pkt, forward_entry, ip_entry[3], dev])
                found_in_queue = True
                break

        if not found_in_queue:
            self.ip_queue.append([str(forward_entry[2]), pkt, forward_entry, 1, dev])
            Router.router_make_arp_request(self, forward_entry[2], forward_entry)


def main(net):
    r = Router(net)
    r.router_main()
    net.shutdown()