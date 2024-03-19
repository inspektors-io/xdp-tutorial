package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"

	pb "github.com/inspektors-io/grpc-nobin/grpc-test" // Update with your actual package name

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedUserServiceServer
}

func (s *server) SendUserData(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	fmt.Printf("Received:\nPacket Number: %d\n", req.PacketNumber)

	// Printing received data including packet number
	// fmt.Printf("Received:\nPacket Number: %d\nSource IP: %d\nDestination IP: %d\nSeq: %d\nAckSeq: %d\n",
	// req.PacketNumber, intToIPv4(req.IpHeader.SourceIp), intToIPv4(req.IpHeader.DestinationIp), req.TcpHeader.Seq, req.TcpHeader.AckSeq)

	// TCP Information print
	// fmt.Printf("Ethernet Header:\n")
	// fmt.Printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", req.EthernetHeader.DestinationMac[0], req.EthernetHeader.DestinationMac[1], req.EthernetHeader.DestinationMac[2], req.EthernetHeader.DestinationMac[3], req.EthernetHeader.DestinationMac[4], req.EthernetHeader.DestinationMac[5])
	// fmt.Printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", req.EthernetHeader.SourceMac[0], req.EthernetHeader.SourceMac[1], req.EthernetHeader.SourceMac[2], req.EthernetHeader.SourceMac[3], req.EthernetHeader.SourceMac[4], req.EthernetHeader.SourceMac[5])
	// fmt.Printf("  Protocol: %x\n", req.EthernetHeader.EtherType)

	// IP Header information print

	// fmt.Printf("  Version IHL: %x\n", req.IpHeader.VersionIhl)
	// fmt.Printf("  TOS: %x\n", req.IpHeader.Tos)
	// fmt.Printf("  Total Length: %d\n", req.IpHeader.TotLen)
	// fmt.Printf("  ID: %d\n", req.IpHeader.Id)
	// fmt.Printf("  Fragment Offset: %d\n", req.IpHeader.FragOff)
	// fmt.Printf("  TTL: %d\n", req.IpHeader.Ttl)
	// fmt.Printf("  Protocol: %d\n", req.IpHeader.Protocol)
	// fmt.Printf("  Checksum: %d\n", req.IpHeader.Check)
	// fmt.Printf("  Source IP: %s\n", intToIPv4(req.IpHeader.SourceIp).String())
	// fmt.Printf("  Destination IP: %s\n", intToIPv4(req.IpHeader.DestinationIp).String())

	// TCP Header Information print
	// Extracting flags
	flags := extractFlags(req.TcpHeader.Flag)
	fmt.Println("Extracted Flags:")
	fmt.Println("NS:", flags["ns"])
	fmt.Println("RES:", flags["res"])
	fmt.Println("DOFF:", flags["doff"])
	fmt.Println("FIN:", flags["fin"])
	fmt.Println("SYN:", flags["syn"])
	fmt.Println("RST:", flags["rst"])
	fmt.Println("PSH:", flags["psh"])
	fmt.Println("ACK:", flags["ack"])
	fmt.Println("URG:", flags["urg"])
	fmt.Println("ECE:", flags["ece"])
	fmt.Println("CWR:", flags["cwr"])
	fmt.Printf("  Window: %d\n", req.TcpHeader.Window)
	fmt.Printf("  Checksum: %d\n", req.TcpHeader.Check)
	fmt.Printf("  Urgent Pointer: %d\n", req.TcpHeader.UrgPtr)
	// Decode hexadecimal string to binary data
	// rawData := hex.DecodeString(req.RawData)

	// Print binary data in hex dump format

	// Convert hexadecimal string to bytes
	// binaryData :=
	fmt.Println(hex.Dump(req.RawData))

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

func ntohs(value uint32) uint32 {
	return ((value & 0xff) << 8) | (value >> 8)
}

func extractFlags(flags uint32) map[string]uint32 {
	result := make(map[string]uint32)
	result["cwr"] = (flags >> 15) & 0x1
	result["ece"] = (flags >> 14) & 0x1
	result["urg"] = (flags >> 13) & 0x1
	result["ack"] = (flags >> 12) & 0x1
	result["psh"] = (flags >> 11) & 0x1
	result["rst"] = (flags >> 10) & 0x1
	result["syn"] = (flags >> 9) & 0x1
	result["fin"] = (flags >> 8) & 0x1
	result["doff"] = (flags >> 4) & 0xF
	result["res"] = (flags >> 1) & 0x7
	result["ns"] = flags & 0x1
	return result
}

// generateHexDump generates a hex dump of the given data
func generateHexDump(data []byte, bytesPerLine int) string {
	var lines []string
	for i := 0; i < len(data); i += bytesPerLine {
		chunk := data[i:min(i+bytesPerLine, len(data))]
		hexStr := hex.EncodeToString(chunk)
		hexChunks := make([]string, len(chunk))
		for j := range chunk {
			hexChunks[j] = fmt.Sprintf("%02x", chunk[j])
		}
		asciiStr := string(chunk)
		for j := range chunk {
			if chunk[j] < 32 || chunk[j] > 126 {
				asciiStr = strings.ReplaceAll(asciiStr, string(chunk[j]), ".")
			}
		}
		line := fmt.Sprintf("%08x  %-48s  |%s|", i, hexStr, asciiStr)
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
