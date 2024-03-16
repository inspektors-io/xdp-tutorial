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
	SrcIp   uint32
	DstIp   uint32
	SrcPort uint16
	DstPort uint16
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

			fmt.Printf("TCP: %v:%d -> %v:%d\n",
				intToIPv4(event.SrcIp), ntohs(event.SrcPort),
				intToIPv4(event.DstIp), ntohs(event.DstPort),
			)
			counter++
			fmt.Printf("Counter: %d\n", counter)

			if len(evnt.RawSample)-METADATA_SIZE > 0 {
				fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
			}

			received += len(evnt.RawSample)
			lost += int(evnt.LostSamples)

			// Send data to gRPC server
			err = sendDataToServer(client, event, int32(counter))
			if err != nil {
				fmt.Printf("Failed to send data to gRPC server: %v\n", err)
				continue
			}
			fmt.Println("Data sent successfully to gRPC server")

		}
	}()

	<-ctrlC
	perfEvent.Close()

	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", received)
	fmt.Printf("\t%d Event(s) Lost(e.g. small buffer, delays in processing)\n", lost)
	fmt.Println("\nDetaching program and exiting...")
}

func sendDataToServer(client pb.UserServiceClient, event perfEventItem, packetNumber int32) error {
	// Send data to server
	_, err := client.SendUserData(context.Background(), &pb.UserRequest{
		SourceIp:        intToIPv4(event.SrcIp).String(),
		DestinationIp:   intToIPv4(event.DstIp).String(),
		SourcePort:      int32(event.SrcPort),
		DestinationPort: int32(event.DstPort),
		PacketNumber:    packetNumber, // Include packet number
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
