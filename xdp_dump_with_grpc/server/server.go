package main

import (
	"context"
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
	fmt.Printf("Received:\nPacket Number: %d\nSource IP: %s\nDestination IP: %s\nSource Port: %d\nDestination Port: %d\n",
		req.PacketNumber, req.SourceIp, req.DestinationIp, req.SourcePort, req.DestinationPort)

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
