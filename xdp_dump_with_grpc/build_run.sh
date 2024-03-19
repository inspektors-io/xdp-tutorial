protoc --go_out=./grpc-test --proto_path=/home/pegasus/Documents/fresh_work/xdp-tutorial/copy_xdp_dump_with_grpc --go_opt=paths=source_relative --go-grpc_out=./grpc-test --go-grpc_opt=paths=source_relative /home/pegasus/Documents/fresh_work/xdp-tutorial/copy_xdp_dump_with_grpc/event.proto
go generate
go build .
sudo ./grpc-nobin -iface enp2s0