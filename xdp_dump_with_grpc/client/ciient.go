package main

import (
	"context"
	"log"

	pb "github.com/inspektors-io/grpc-nobin/grpc-test" // Update with your actual package name

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewUserServiceClient(conn)

	// Send data to the server
	_, err = c.SendUserData(context.Background(), &pb.UserRequest{
		SourceIp:        "192.168.1.1",
		DestinationIp:   "10.0.0.1",
		SourcePort:      8080,
		DestinationPort: 80,
	})
	if err != nil {
		log.Fatalf("Failed to send data: %v", err)
	}
	log.Println("Data sent successfully")
}
