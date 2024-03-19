go generate
go build .
sudo ip netns exec node1 ./grpc-nobin -iface veth1
sudo rm -rf grpc-nobin