#!/usr/bin/python3

import sys
from scapy.all import *
import scapy.contrib.gtp

from scapy.contrib.gtp import *

#pcap = rdpcap("/mydata/test-packet/dl_gtp_udp_echo_request_128.pcap")#with absolute path
pcap = rdpcap("../gtp-ping_dl.pcap")#with absolute path
#pcap = rdpcap("gtp-ping.pcap")
outer_payload_len = 68
ping_loop_times = 256

SRC_MAC = "90:e2:ba:81:46:b5"
DST_MAC = "90:e2:ba:26:f0:bc"
SRC_OUTER_IP = "10.100.200.1"
DST_OUTER_IP = "10.100.200.3"
SRC_INNER_IP = "60.60.0.1"
DST_INNER_IP = "192.168.0.1"

if len(sys.argv) == 2:
    outer_payload_len = int(str(sys.argv[1]))

for packet in pcap:
    #print(packet[GTP_U_Header][ICMP])
    #packet[GTP_U_Header][ICMP] = pincap[0][ICMP]

    x = packet[Ether]
    x.src = SRC_MAC
    x.dst = DST_MAC
    x.type = 0x800
    del x.chksum

    y = packet[IP]
    y.src = SRC_OUTER_IP
    y.dst = DST_OUTER_IP
    y.len = outer_payload_len
    del y.chksum

    u = packet[UDP]
    udp_len = outer_payload_len - 20
    u.len = udp_len
    del u.chksum

    gtp_len = udp_len - 16 # 8 for UDP header and 8 for GTP mandatory header
    packet[GTP_U_Header].length = gtp_len

    w = packet[GTP_U_Header][GTPPDUSessionContainer][ICMP]
    del w.chksum

    z = packet[GTP_U_Header][GTPPDUSessionContainer][IP]
    z.src = SRC_INNER_IP
    z.dst = DST_INNER_IP
    inner_payload_len = gtp_len - 4 - 4 # 4 for GTP seq and padding
    z.len = inner_payload_len
    del z.chksum

    payload = ""
    for i in range(inner_payload_len - 20 - 8): # 20 for IP header len & 8 for ICMP header len, rest of it is ICMP Rest of header
        payload += "z"
    packet[GTP_U_Header][GTPPDUSessionContainer][ICMP][Raw].load = payload
    #packet[GTP_U_Header][Raw].load = payload
    del packet[Ether].chksum
    #del packet[Padding]

    packet.show()
    #wireshark(packet)
    wrpcap("dl_gtp_icmp_echo_request_" + str(outer_payload_len) + ".pcap", packet)

    #send(y)
    for i in range(ping_loop_times):
        wrpcap("dl_gtp_icmp_echo_request_" + str(outer_payload_len) + "_loop.pcap", packet, append=True)
    #send(packet, loop=10)
    #send(packet)
