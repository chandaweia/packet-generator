#!bin/bash

echo $PWD

genpacketfile=$HOME/packet-generator/icmp_packet.py
moongenfile=$HOME/MoonGen/build/MoonGen
luafile=$HOME/MoonGen/examples/pcap/replay-pcap.lua
pcapfile=$PWD/icmp_echo_request_$1.pcap
pcaploop=$PWD/icmp_echo_request_$1_loop.pcap
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

rm icmp_echo_request*
