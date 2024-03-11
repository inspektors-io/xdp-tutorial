#!/bin/bash

BUILD="build"
CLEAN="clean"
ATTACH="attach"
DETACH="detach"
READELF="readelf"

if [ "$BUILD" = "$1" ]; then
	ip netns add node1
	ip link add veth0 type veth peer veth1
	ip link set veth1 netns node1
	ip addr add 192.168.0.3/24 dev veth0
	ip netns exec node1 ip addr add 192.168.0.2/24 dev veth1
	ip link set up dev veth0
	ip netns exec node1 ip link set up dev veth1
	ip netns exec node1 ip link set up dev lo

elif [ "$CLEAN" = "$1" ]; then
	ip netns del node1

elif [ "$ATTACH" = "$1" ]; then
	ip netns exec node1 ip link set dev veth1 xdp obj xdpdump_bpfel.o sec xdp

elif [ "$DETACH" = "$1" ]; then
	ip link set dev eth0 xdp off

elif [ "$READELF" = "$1" ]; then
	readelf -S xdpdump_bpfeb.o

else
	echo "help:"
	echo "	build: build a network to test with netns"
	echo "	clean: clean up a network"
fi


