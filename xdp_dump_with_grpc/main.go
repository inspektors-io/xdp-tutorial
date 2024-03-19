package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	pb "github.com/inspektors-io/grpc-nobin/grpc-test" // Update with your actual package name

	"google.golang.org/grpc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpDump ./bpf/xdp_dump.c -- -I../header

var (
	iface string
	conn  *grpc.ClientConn
)

const (
	METADATA_SIZE = 12
)

type Collect struct {
	Prog    *ebpf.Program `ebpf:"xdp_dump"`
	PerfMap *ebpf.Map     `ebpf:"perfmap"`
}

type perfEventItem struct {
	EthHdr struct {
		DestMAC   [6]uint8
		SourceMAC [6]uint8
		Proto     uint16
	}
	IpHdr struct {
		VersionIHL  byte
		TOS         byte
		TotalLen    uint16
		ID          uint16
		FragmentOff uint16
		TTL         uint8
		Protocol    uint8
		Checksum    uint16
		SrcIP       uint32
		DstIP       uint32
	}
	Tcphdr struct {
		Source uint16
		Dest   uint16
		Seq    uint32
		AckSeq uint32
		Flags  uint16 // For holding the flags field (4 bytes)
		Window uint16
		Check  uint16
		UrgPtr uint16
	}
}

func main() {
	flag.StringVar(&iface, "iface", "", "interface attached xdp program")
	flag.Parse()

	if iface == "" {
		fmt.Println("interface is not specified.")
		os.Exit(1)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		fmt.Printf("Failed to get interface by name: %v\n", err)
		os.Exit(1)
	}

	spec, err := LoadXdpDump()
	if err != nil {
		fmt.Printf("Failed to load XDP dump: %v\n", err)
		os.Exit(1)
	}

	var collect = &Collect{}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		fmt.Printf("Failed to load and assign XDP program: %v\n", err)
		os.Exit(1)
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		fmt.Printf("Failed to attach XDP program to interface: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE); err != nil {
			fmt.Printf("Error detaching program: %v\n", err)
		}
	}()

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	perfEvent, err := perf.NewReader(collect.PerfMap, 4096)
	if err != nil {
		fmt.Printf("Failed to create perf event reader: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
	fmt.Println()

	var (
		received int = 0
		lost     int = 0
		counter  int = 0
	)

	// Connect to gRPC server
	conn, err = grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		fmt.Printf("Failed to connect to gRPC server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Create gRPC client
	client := pb.NewUserServiceClient(conn)

	go func() {
		var event perfEventItem
		for {
			evnt, err := perfEvent.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					break
				}
				fmt.Printf("Error reading perf event: %v\n", err)
				continue
			}

			reader := bytes.NewReader(evnt.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
				fmt.Printf("Error decoding perf event: %v\n", err)
				continue
			}

			// fmt.Printf("Ethernet Header:\n")
			// fmt.Printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", event.EthHdr.DestMAC[0], event.EthHdr.DestMAC[1], event.EthHdr.DestMAC[2], event.EthHdr.DestMAC[3], event.EthHdr.DestMAC[4], event.EthHdr.DestMAC[5])
			// fmt.Printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", event.EthHdr.SourceMAC[0], event.EthHdr.SourceMAC[1], event.EthHdr.SourceMAC[2], event.EthHdr.SourceMAC[3], event.EthHdr.SourceMAC[4], event.EthHdr.SourceMAC[5])
			// fmt.Printf("  Protocol: %x\n", event.EthHdr.Proto)

			// fmt.Printf("IP Header:\n")
			// fmt.Printf("  Version IHL: %x\n", event.IpHdr.VersionIHL)
			// fmt.Printf("  TOS: %x\n", event.IpHdr.TOS)
			// fmt.Printf("  Total Length: %d\n", event.IpHdr.TotalLen)
			// fmt.Printf("  ID: %d\n", event.IpHdr.ID)
			// fmt.Printf("  Fragment Offset: %d\n", event.IpHdr.FragmentOff)
			// fmt.Printf("  TTL: %d\n", event.IpHdr.TTL)
			// fmt.Printf("  Protocol: %d\n", event.IpHdr.Protocol)
			// fmt.Printf("  Checksum: %d\n", event.IpHdr.Checksum)
			// fmt.Printf("  Source IP: %s\n", intToIPv4(event.IpHdr.SrcIP).String())
			// fmt.Printf("  Destination IP: %s\n", intToIPv4(event.IpHdr.DstIP).String())

			// fmt.Printf("TCP Header:\n")
			// fmt.Printf("  Source Port: %d\n", ntohs(event.Tcphdr.Source))
			// fmt.Printf("  Destination Port: %d\n", ntohs(event.Tcphdr.Dest))
			// fmt.Printf("  Sequence Number: %d\n", event.Tcphdr.Seq)
			// fmt.Printf("  Acknowledgment Number: %d\n", event.Tcphdr.AckSeq)

			// // Extracting flags
			// flags := extractFlags(event.Tcphdr.Flags)
			// fmt.Println("Extracted Flags:")
			// fmt.Println("NS:", flags["ns"])
			// fmt.Println("RES:", flags["res"])
			// fmt.Println("DOFF:", flags["doff"])
			// fmt.Println("FIN:", flags["fin"])
			// fmt.Println("SYN:", flags["syn"])
			// fmt.Println("RST:", flags["rst"])
			// fmt.Println("PSH:", flags["psh"])
			// fmt.Println("ACK:", flags["ack"])
			// fmt.Println("URG:", flags["urg"])
			// fmt.Println("ECE:", flags["ece"])
			// fmt.Println("CWR:", flags["cwr"])
			// fmt.Printf("  Window: %d\n", event.Tcphdr.Window)
			// fmt.Printf("  Checksum: %d\n", event.Tcphdr.Check)
			// fmt.Printf("  Urgent Pointer: %d\n", event.Tcphdr.UrgPtr)

			counter++
			fmt.Printf("Counter: %d\n", counter)

			rawData := evnt.RawSample[METADATA_SIZE:]

			if len(evnt.RawSample)-METADATA_SIZE > 0 {
				fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
				rawData = evnt.RawSample[METADATA_SIZE:]
			}

			received += len(evnt.RawSample)
			lost += int(evnt.LostSamples)

			// Send data to gRPC server
			err = sendDataToServer(client, int32(counter), event, string(rawData))
			if err != nil {
				fmt.Printf("Failed to send data to gRPC server: %v\n", err)
				continue
			}
			fmt.Println("Data sent successfully to gRPC server")

		}
	}()

	defer conn.Close()
	<-ctrlC
	perfEvent.Close()

	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", received)
	fmt.Printf("\t%d Event(s) Lost(e.g. small buffer, delays in processing)\n", lost)
	fmt.Println("\nDetaching program and exiting...")
}

func sendDataToServer(client pb.UserServiceClient, packetNumber int32, event perfEventItem, rawDumpString string) error {
	// Create gRPC message types for TCP, IP, and Ethernet headers
	ipHeader := &pb.IpHeader{
		SourceIp:      event.IpHdr.SrcIP,
		DestinationIp: event.IpHdr.DstIP,
		// Version:       uint32(event.IPHeader.Version),
		Protocol: uint32(event.IpHdr.Protocol),
		Check:    uint32(event.IpHdr.Checksum),
		// Ihl:           uint32(event.IPHeader.IHL),
		FragOff: uint32(event.IpHdr.FragmentOff),
		Id:      uint32(event.IpHdr.ID),
		Tos:     uint32(event.IpHdr.TOS),
		Ttl:     uint32(event.IpHdr.TTL),
		TotLen:  uint32(event.IpHdr.TotalLen),
	}
	tcpHeader := &pb.TcpHeader{
		SourcePort:      uint32(event.Tcphdr.Source),
		DestinationPort: uint32(event.Tcphdr.Dest),
		Seq:             event.Tcphdr.Seq,
		AckSeq:          event.Tcphdr.AckSeq,
		Flag:            uint32(event.Tcphdr.Flags),
		Check:           uint32(event.Tcphdr.Check),
		UrgPtr:          uint32(event.Tcphdr.UrgPtr),
	}
	ethernetHeader := &pb.EthernetHeader{
		EtherType:      uint32(event.EthHdr.Proto),
		DestinationMac: event.EthHdr.DestMAC[:],
		SourceMac:      event.EthHdr.SourceMAC[:],
	}

	// Convert raw binary data to hexadecimal string
	rawDumpHex := hex.EncodeToString([]byte(rawDumpString))

	// Send data to server
	_, err := client.SendUserData(context.Background(), &pb.UserRequest{
		IpHeader:       ipHeader,
		TcpHeader:      tcpHeader,
		EthernetHeader: ethernetHeader,
		PacketNumber:   packetNumber,
		RawData:        rawDumpHex, // Send hexadecimal string instead of raw binary
	})
	return err
}

func intToIPv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8) | (value >> 8)
}

func extractFlags(flags uint16) map[string]uint16 {
	result := make(map[string]uint16)
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
