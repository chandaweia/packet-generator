#!bin/bash

echo $PWD

genpacketfile=$HOME/packet-generator/gtp_dl_udp_packet.py
moongenfile=$HOME/MoonGen/build/MoonGen
luafile=$HOME/MoonGen/examples/pcap/replay-pcap.lua
#pcapfile=$PWD/gtp_icmp_echo_request_$1.pcap
pcapfile=$PWD/dl_gtp_udp_echo_request_$1.pcap
pcaploop=$PWD/dl_gtp_udp_echo_request_$1_loop.pcap
$genpacketfile $1

if [ "$2" = "l" ]
then
	sudo $moongenfile $luafile 0 $pcaploop -l
elif [ "$2" = "s" ]
then
	sudo $moongenfile $luafile 0 $pcapfile
else
	sudo $moongenfile $luafile 0 $pcapfile -l
fi

rm dl_gtp_udp_echo_request*.pcap
