package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	pb "github.com/inspektors-io/grpc-nobin/grpc-test" // Update with your actual package name

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedUserServiceServer
}

func (s *server) SendUserData(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// Printing received data including packet number
	fmt.Printf("Received:\nPacket Number: %d\nSource IP: %d\nDestination IP: %d\nSource Port: %d\nDestination Port: %d\n",
		req.PacketNumber, intToIPv4(req.IpHeader.SourceIp), intToIPv4(req.IpHeader.DestinationIp), req.TcpHeader.SourcePort, req.TcpHeader.DestinationPort)

	return &pb.UserResponse{Message: "Data received successfully"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &server{})
	log.Println("gRPC server started on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func intToIPv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8) | (value >> 8)
}
