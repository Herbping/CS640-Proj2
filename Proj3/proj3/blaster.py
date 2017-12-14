#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time

def create_pkt(blastee_ip,mymacs,myips,seq,length):
    pkt_header = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
    #Ethernet
    pkt_header[0].src = mymacs[0]
    pkt_header[0].dst = '40:00:00:00:00:01'#middlebox-eth0
    #IPv4
    pkt_header[1].src = myips[0]
    pkt_header[1].dst = blastee_ip
    #seq number 4 bytes
    seq = seq.to_bytes(4,'big')
    #payload
    payload = bytes(length)
    #length 2 bytes
    length = length.to_bytes(2,'big')
    pkt = pkt_header + seq + length + payload
    return pkt


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    log_debug("MyMacs: {}".format(mymacs))
    log_debug("MyIps: {}".format(myips))

    params_path = "blaster_params.txt"
    params = open(params_path,"r").read().split()
    blastee_ip = None
    num = 0
    length = 0
    sw = 0
    timeout = 0
    recv_timeout = 0
    for i in range(len(params)):
        if params[i] == "-b":
            blastee_ip = params[i+1]
        if params[i] == "-n":
            num = int(params[i+1])
        if params[i] == "-l":
            length = int(params[i+1])
        if params[i] == "-w":
            sw = int(params[i+1])
        if params[i] == "-t":
            timeout = int(params[i+1])
        if params[i] == "-r":
            recv_timeout = int(params[i+1])

    timeout_num = 0
    resend_num = 0
    lhs = 1 # the least index of sent but not Acked packet
    rhs = 0 # the greatest index of sent packet
    ack_list = []
    t = time.time()
    start = None
    while True:
        if lhs == num:
            break

        while (rhs-lhs)<sw-1 and rhs<num:
            rhs+=1
            send_pkt = create_pkt(blastee_ip,mymacs,myips,rhs,length)
            net.send_packet("blaster-eth0",send_pkt)

        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(recv_timeout/1000.0)
            if start == None:
                start = timestamp
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            log_debug("AckList: {}".format(ack_list))
            log_debug("LHS RHS: {} {}".format(lhs,rhs))
            ack_seq = int.from_bytes(((pkt.get_header(RawPacketContents)).to_bytes())[:4],'big')
            log_debug("Got Ack: {}".format(ack_seq))
            if ack_seq == lhs:
                lhs += 1
                if lhs == num:
                    break
                while lhs in ack_list:
                    lhs += 1
                    if lhs == num:
                        break
                ack_list = [x for x in ack_list if x>lhs]
            elif (ack_seq not in ack_list) and (ack_seq >= lhs):
                ack_list.append(ack_seq)
            t = time.time()
            log_debug("LHS RHS: {} {}".format(lhs,rhs))

        else:
            log_debug("Didn't receive anything")

            '''
            Creating the headers for the packet
            
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP

            
            Do other things here and send packet
            '''
            #resend
            if time.time()-t > timeout/1000.0:
                timeout_num += 1
                n = lhs
                while (n <= rhs) and (n <= num):
                    if n not in ack_list:
                        resend_num += 1
                        send_pkt = create_pkt(blastee_ip,mymacs,myips,n,length)
                        net.send_packet("blaster-eth0",send_pkt)
                    n += 1

    print("Total TX time (in seconds): "+str(timestamp-start))
    print("Number of reTX: "+str(resend_num))
    print("Number of coarse TOs: "+str(timeout_num))
    print("Throughput (Bps): "+str((num+resend_num)*length/(timestamp-start)))
    print("Goodput (Bps): "+str((num*length)/(timestamp-start)))

    net.shutdown()
