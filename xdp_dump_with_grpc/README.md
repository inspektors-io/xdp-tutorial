In order to run the code.

Use the following code to generate the protobuf files used in gRPC.
```
cd xdp_dump_with_grpc
protoc --go_out=./grpc-test --proto_path=/home/pegasus/Documents/repo/xdp-tutorial/xdp_dump_with_grpc --go_opt=paths=source_relative --go-grpc_out=./grpc-test --go-grpc_opt=paths=source_relative /Documents/repo/xdp-tutorial/xdp_dump_with_grpc/event.proto
```
To generate the binary from go and attach it to an interface

```
go generate
go build .
sudo ./grpc-nobin -iface <interface_name>
```