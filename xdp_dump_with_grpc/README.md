# xdp_dump

## Diagrams

### Environment

![Alt text](https://dummyim.s3.amazonaws.com/img1.png)

### Program Dataflow

![alt text](https://dummyim.s3.amazonaws.com/img2.png)

### Env Setup

```c
cd xdp_dump
go generate
go build .
sudo ./xdp_dump -iface <your NIC name>
# if you want to run into some netns, run below
# sudo ip netns exec <your netns> ./xdp_dump -iface <your NIC name> 
```

### PoC
We first use SSH to connect to the remote server.
We check the network interfaces informations on the server.

![Alt text](https://dummyim.s3.amazonaws.com/img10.png) 

#### Building the binary files

We first build the binaries.

![Alt text](https://dummyim.s3.amazonaws.com/img11.png)

Then we attach the xdp_dump code to eth0 interface on the server.
![Alt text](https://dummyim.s3.amazonaws.com/img13.png) 

Finally we open another terminal on our host and ping the address(95.217.22.143) of the xdp attached interface. We can see the source, destination ports and ips on the left terminal being stored in eBPF map and getting retrieved from go userspace code. Here we are tracing only the ICMP requests. Inside the bpf code we can adjust to just capture our desirable type of packets.
![Alt text](https://dummyim.s3.amazonaws.com/img12.png) 


### BPF Code

```c
// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// XDP dump is simple program that dumps new IPv4 TCP connections through perf events.

#include "bpf_helpers.h"

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

// TCP header
struct tcphdr {
  __u16 source;
  __u16 dest;
  __u32 seq;
  __u32 ack_seq;
  union {
    struct {
      // Field order has been converted LittleEndiand -> BigEndian
      // in order to simplify flag checking (no need to ntohs())
      __u16 ns : 1,
      reserved : 3,
      doff : 4,
      fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
    };
  };
  __u16 window;
  __u16 check;
  __u16 urg_ptr;
};

// PerfEvent eBPF map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);


// PerfEvent item
struct perf_event_item {
  __u32 src_ip, dst_ip;
  __u16 src_port, dst_port;
};
_Static_assert(sizeof(struct perf_event_item) == 12, "wrong size of perf_event_item");

// XDP program //
SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u64 packet_size = data_end - data;

  // L2
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return XDP_ABORTED;
  }

  // L3
  if (ether->h_proto != 0x08) {  // htons(ETH_P_IP) -> 0x08
    // Non IPv4
    return XDP_PASS;
  }
  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    return XDP_ABORTED;
  }

  // // L4
  // if (ip->protocol != 0x06) {  // IPPROTO_TCP -> 6
  //   // Non TCP
  //   return XDP_PASS;
  // }
  data += ip->ihl * 4;
  struct tcphdr *tcp = data;
  if (data + sizeof(*tcp) > data_end) {
    return XDP_ABORTED;
  }

  // Emit perf event for every TCP SYN packet
  if (ip->protocol == 0x01) {
    struct perf_event_item evt = {
      .src_ip = ip->saddr,
      .dst_ip = ip->daddr,
      .src_port = tcp->source,
      .dst_port = tcp->dest,
    };
    // flags for bpf_perf_event_output() actually contain 2 parts (each 32bit long):
    //
    // bits 0-31: either
    // - Just index in eBPF map
    // or
    // - "BPF_F_CURRENT_CPU" kernel will use current CPU_ID as eBPF map index
    //
    // bits 32-63: may be used to tell kernel to amend first N bytes
    // of original packet (ctx) to the end of the data.

    // So total perf event length will be sizeof(evt) + packet_size
    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &evt, sizeof(evt));
  }


  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

```

The tcphdr, ethhdr, iphdr are structs used to denote tcp, ip and ethernet packet related properties. For ethhdr it just stores destination, source ip and protocol. For iphdr it stores ip header length, ip version, type of service, total length, id, fragmentation size, time to live, protocol, checksum, source and destination addresses. The tcphdr stores source port, destination port. sequence number, acknowledge number, It has six original 1-bit control flags (URG, ACK, PSH, RST, SYN, FIN), and three additional flags (ECE, NS, CWR). Details of TCP flag can be found [here](https://medium.com/liveonnetwork/tcp-flags-4e2df36c1a9d). The window field represents the size of the receive window, which specifies how much data the sender can transmit before receiving an acknowledgment. The checksum is used to check for corruption. And at last there’s urgent packet flag.

__attribute__((packed));

Tells the compiler to avoid padding in between each entries of the struct. It is used for optimization purpose.

Here we define a BPF_MAP named perfmap which has maximum 128 entries.

### BPF_MAP_TYPE_PERF_EVENT_ARRAY

`perf_events: where` eBPF `map key maps to` cpu_id. So eBPF and go parts actually bind cpu_id to map index. and in that case the associated value for each key will be the fd associated with the perf event opened for that CPU. Array map which is used by the kernel in `bpf_perf_event_output()` to associate tracing output with a specific key. User-space programs associate fds with each key, and can poll() those fds to receive notification that data has been traced. `bpf_perf_event_output()` is supported for tc, XDP, lightweight tunnel, and kprobe, tracepoint and perf events program types. The context passed in is the relevant context for each of those program types.A perf event array contains multiple perf event ringbuffers which can be used to exchange sample like data with user space. 
The ctx parameter is the pointer to the parameters struct provided to the eBPF program. The map is that defined in the shared section, perfmap in this case. The flags specify which ring buffer index to write to, but is usually set to the define BPF_F_CURRENT_CPU. The data and size specify the data.

### Writing into the perf buffer

When a sample is taken and saved into the ring buffer, the kernel prepares sample fields based on the sample type; then it prepares the info for writing ring buffer which is stored in the structure perf_output_handle. In the end, the kernel outputs the sample into the ring buffer and updates the head pointer in the user page so the perf tool can see the latest value.

The structure perf_output_handle serves as a temporary context for tracking the information related to the buffer. The advantages of it is that it enables concurrent writing to the buffer by different events. For example, a software event and a hardware PMU event both are enabled for profiling, two instances of perf_output_handle serve as separate contexts for the software event and the hardware event respectively. This allows each event to reserve its own memory space for populating the record data.

### Reading from perf buffer

Similar to the kernel, the perf tool in the user space first reads out the recorded data from the ring buffer, and then updates the buffer's tail pointer `perf_event_mmap_page::data_tail`.

```c
    // Define special, perf_events map where key maps to CPU_ID
    BPF_MAP_DEF(perfmap) = {
        .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .max_entries = 128,     // Max supported CPUs
    };
    BPF_MAP_ADD(perfmap);

    // ...

    // Emit perf event with "evt" to map "perfmap" where index is current CPU_ID
    // So total perf event length will be sizeof(evt) + packet_size
    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &evt, sizeof(evt));
```

It creates a perf_event_item struct. 

```c
// PerfEvent item
struct perf_event_item {
  __u32 src_ip, dst_ip;
  __u16 src_port, dst_port;
};
_Static_assert(sizeof(struct perf_event_item) == 12, "wrong size of perf_event_item");

```

This function uses compile time assertion to check the size of perf_event_item is 12 bytes or not. Here src_ip (4 bytes), dst_ip (4 bytes), 

src_port (2 bytes), dst_port (2 bytes). So in total we get 12 bytes.

```c
[// XDP program //
SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u64 packet_size = data_end - data;

  // L2
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return XDP_ABORTED;
  }

  // L3
  if (ether->h_proto != 0x08) {  // htons(ETH_P_IP) -> 0x08
    // Non IPv4
    return XDP_PASS;
  }
  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    return XDP_ABORTED;
  }

  // L4
  if (ip->protocol != 0x06) {  // IPPROTO_TCP -> 6
    // Non TCP
    return XDP_PASS;
  }
  data += ip->ihl * 4;
  struct tcphdr *tcp = data;
  if (data + sizeof(*tcp) > data_end) {
    return XDP_ABORTED;
  }](bpf/xdp_dump.c)
```

Finally inside the xdp_dump function it checks if the packet is corrupted or not. And checks for ICMP packet. This check is discussed in details on [
On the above code snippet we are taking the xdp context as the parameter `struct xdp_md *ctx` . A data packet has a start and end.
If the `data + sizeof(data)` becomes greater than the data end, it indicates that the data is corrupted. In that case we just return `XDP_ABORTED` which indicates there’s some error and drops the packet. This check is done on various levels, at the time of TCP packets, IP packet or even the ethernet frames. That’s why we see multiple checks like below at various stages of the code:
](https://www.notion.so/On-the-above-code-snippet-we-are-taking-the-xdp-context-as-the-parameter-struct-xdp_md-ctx-A-data-a886983d512a44ccbd0f4c57581f8a71?pvs=21) 

Whenever it gets a ICMP packet output the evt values on perfmap. It stores ip source, destination and tcp source and destination ports inside the evt struct.

```c
 // Emit perf event for every ICMP packet
  if (ip->protocol == 0x01) {
    struct perf_event_item evt = {
      .src_ip = ip->saddr,
      .dst_ip = ip->daddr,
      .src_port = tcp->source,
      .dst_port = tcp->dest,
    };
    // flags for bpf_perf_event_output() actually contain 2 parts (each 32bit long):
    //
    // bits 0-31: either
    // - Just index in eBPF map
    // or
    // - "BPF_F_CURRENT_CPU" kernel will use current CPU_ID as eBPF map index
    //
    // bits 32-63: may be used to tell kernel to amend first N bytes
    // of original packet (ctx) to the end of the data.

    // So total perf event length will be sizeof(evt) + packet_size
    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &perfmap, flags, &evt, sizeof(evt));
  }
```

### Go interfacing (Userspace code)

```c
module github.com/terassyi/go-xdp-examples/xdp_dump

go 1.16

require (
	github.com/cilium/ebpf v0.7.0
	github.com/vishvananda/netlink v1.1.0
)

```

This are the dependencies of the main.go code.

```c
package main

import (
	"bytes"
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
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpDump ./bpf/xdp_dump.c -- -I../header

var iface string

const (
	METADATA_SIZE = 12
)

type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_dump"`
	PerfMap *ebpf.Map `ebpf:"perfmap"`
}

type perfEventItem struct {
	SrcIp uint32
	DstIp uint32
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
		panic(err)
	}

	spec, err := LoadXdpDump()
	if err != nil {
		panic(err)
	}
	var collect = &Collect{}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	defer func() {
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
	}()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	perfEvent, err := perf.NewReader(collect.PerfMap, 4096)
	if err != nil {
		panic(err)
	}
	fmt.Println("All new ICMP packets coming to this host will be dumped here.")
	fmt.Println()
	var (
		received int = 0
		lost int = 0
	)

	go func() {
		var event perfEventItem
		for {
			evnt, err := perfEvent.Read()
			if err != nil {
				if errors.Unwrap(err) == perf.ErrClosed {
					break
				}
				panic(err)
			}
			reader := bytes.NewReader(evnt.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
				panic(err)
			}
			fmt.Printf("ICMP: %v:%d -> %v:%d\n",
				intToIpv4(event.SrcIp), ntohs(event.SrcPort),
				intToIpv4(event.DstIp), ntohs(event.DstPort),
			)
			if len(evnt.RawSample) - METADATA_SIZE > 0 {
				fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
			}
			received += len(evnt.RawSample)
			lost += int(evnt.LostSamples)
		}
	}()
	<-ctrlC
	perfEvent.Close()
	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", received)
	fmt.Printf("\t%d Event(s) Lost(e.g. small buffer, delays in processing)\n", lost)
	fmt.Println("\nDetaching program and exit...")
}

func intToIpv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8 ) | (value >> 8)
}

```

Here we are creating a interface variable and creating a const of size 12. Then we are creating a struct interface in go. Inside this struct we have the bpf program and bpf map information.

```c
var iface string

const (
	METADATA_SIZE = 12
)

type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_dump"`
	PerfMap *ebpf.Map `ebpf:"perfmap"`
}
```

We are then creating a struct to store source, dest ip, port.

```c
type perfEventItem struct {
	SrcIp uint32
	DstIp uint32
	SrcPort uint16
	DstPort uint16
}
```

Finally comes the main function. This code is elaborated on [These are like the template code here. It loads and assigns  the xdp program and attaches it to the interface using `LoadAndAssign()` and `LinkSetXdpFdWithFlags()` functions.](https://www.notion.so/These-are-like-the-template-code-here-It-loads-and-assigns-the-xdp-program-and-attaches-it-to-the--9d34b4406e7040e1816bd439d750df72?pvs=21) 

```c

func main() {
	flag.StringVar(&iface, "iface", "", "interface attached xdp program")
	flag.Parse()

	if iface == "" {
		fmt.Println("interface is not specified.")
		os.Exit(1)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}

	spec, err := LoadXdpDump()
	if err != nil {
		panic(err)
	}
	var collect = &Collect{}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	defer func() {
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
	}()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	
```

1. **`flag.StringVar(&iface, "iface", "", "interface attached xdp program")`**:
    - **`flag.StringVar`**: This function is used to define a flag whose value will be stored in the provided string variable (**`iface`** in this case).
    - **`&iface`**: This is the address of the variable where the value of the flag will be stored. It's a pointer to the **`iface`** variable.
    - **`"-iface"`**: This is the name of the flag. When parsing command-line arguments, users can provide this flag followed by a value to set the value of **`iface`**.
    - **`""`**: This is the default value of the flag. Since the **`iface`** variable is a string, an empty string is provided as the default value.
    - **`"interface attached xdp program"`**: This is the usage message associated with the flag. It's a brief description of what the flag is used for. It helps users understand how to use the flag when they request help or provide invalid input.
2. **`flag.Parse()`**:
    - **`flag.Parse`** parses the command-line arguments. It scans the command line from os.Args[1] onward, looking for flags it has declared.
    - Once **`flag.Parse()`** is called, it scans the command line for flags and updates the variables accordingly.

In summary, these two lines of code define a command-line flag **`-iface`** that users can use to specify an interface for an attached XDP (eXpress Data Path) program. When the program is run, it parses the command-line arguments and updates the **`iface`** variable with the value provided by the user for the **`-iface`** flag.

1. **`netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE)`**:
    - **`netlink`**: This is the package providing functionality for communication with the Linux kernel netlink interface.
    - **`LinkSetXdpFdWithFlags`**: This function sets an XDP program on a network interface specified by the **`link`** parameter.
    - **`link`**: This variable represents a network interface. It is obtained earlier in the code using **`netlink.LinkByName(iface)`**.
    - **`collect.Prog.FD()`**: This retrieves the file descriptor (FD) of the XDP program. **`collect`** seems to be a structure that holds information about the loaded XDP program, and **`Prog`** seems to be a field or method of this structure that provides access to the XDP program.
    - **`nl.XDP_FLAGS_SKB_MODE`**: This is a flag indicating the mode in which the XDP program should be run. **`nl`** seems to refer to the **`netlink`** package, and **`XDP_FLAGS_SKB_MODE`** is likely a constant defined in that package, representing the SKB (Socket Buffer) mode for XDP.
2. **`if err != nil { panic(err) }`**:
    - This code checks if there was an error returned by the **`LinkSetXdpFdWithFlags`** function call. If there was an error, it immediately panics, causing the program to exit abruptly. **`panic(err)`** is a Go idiom used to handle unrecoverable errors by immediately terminating the program and printing an error message.

In summary, this line of code sets an XDP program on a network interface, and if there's any error during this process, it panics, indicating that the operation couldn't be completed successfully.

The defer function is called whenever the main function returns. It detaches the interface by setting the second argument ot -1.

```c
	defer func() {
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
	}()
```

```c
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	perfEvent, err := perf.NewReader(collect.PerfMap, 4096)
	if err != nil {
		panic(err)
	}
	fmt.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
	fmt.Println()
	var (
		received int = 0
		lost int = 0
	)
```

1. **`signal.Notify(ctrlC, os.Interrupt)`**:
    - This line sets up a notification channel **`ctrlC`** to receive **`os.Interrupt`** signals. **`os.Interrupt`** signals typically occur when the user presses CTRL+C to interrupt the program. The **`Notify`** function from the **`signal`** package is used to register the channel to receive such signals.
2. **`perfEvent, err := perf.NewReader(collect.PerfMap, 4096)`**:
    - This line creates a new **`perfEvent`** object by calling the **`NewReader`** function from the **`perf`** package. This function initializes a new performance event reader.
    - **`collect.PerfMap`**: This seems to be a field or variable that holds information about a performance map. It's used here to provide a reference to the performance map that the **`perfEvent`** will monitor. This PerfMap is defined within the bpf code
    - **`4096`**: This value represents the buffer size for the performance event reader.
3. **`fmt.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")`**:
    - This line prints a message to the standard output indicating that all new TCP connection requests (SYN) coming to the host will be dumped at the location monitored by the program. This is just an informational message for the user or operator.
4. **`var ( received int = 0 lost int = 0 )`**:
    - This block declares and initializes two variables, **`received`** and **`lost`**, both of type **`int`**. These variables are used to track the number of events received and the number of events lost by the performance event reader, respectively.
    
    ### perf.NewReader
    
    ```go
    func NewReader(array *ebpf.Map, perCPUBuffer int) (*Reader, error) {
    	return NewReaderWithOptions(array, perCPUBuffer, ReaderOptions{})
    }
    ```
    
    NewReader creates a new reader with default options. Array must be a PerfEventArray. perCPUBuffer gives the size of the per CPU buffer in bytes. It is rounded up to the nearest multiple of the current page size.
    
    - **NewReaderWithOptions**
        
        ```go
        // NewReaderWithOptions creates a new reader with the given options.
        func NewReaderWithOptions(array *ebpf.Map, perCPUBuffer int, opts ReaderOptions) (pr *Reader, err error) {
        	if perCPUBuffer < 1 {
        		return nil, errors.New("perCPUBuffer must be larger than 0")
        	}
        
        	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
        	if err != nil {
        		return nil, fmt.Errorf("can't create epoll fd: %v", err)
        	}
        
        	var (
        		fds      = []int{epollFd}
        		nCPU     = int(array.MaxEntries())
        		rings    = make([]*perfEventRing, 0, nCPU)
        		pauseFds = make([]int, 0, nCPU)
        	)
        
        	defer func() {
        		if err != nil {
        			for _, fd := range fds {
        				unix.Close(fd)
        			}
        			for _, ring := range rings {
        				if ring != nil {
        					ring.Close()
        				}
        			}
        		}
        	}()
        
        	// bpf_perf_event_output checks which CPU an event is enabled on,
        	// but doesn't allow using a wildcard like -1 to specify "all CPUs".
        	// Hence we have to create a ring for each CPU.
        	for i := 0; i < nCPU; i++ {
        		ring, err := newPerfEventRing(i, perCPUBuffer, opts.Watermark)
        		if errors.Is(err, unix.ENODEV) {
        			// The requested CPU is currently offline, skip it.
        			rings = append(rings, nil)
        			pauseFds = append(pauseFds, -1)
        			continue
        		}
        
        		if err != nil {
        			return nil, fmt.Errorf("failed to create perf ring for CPU %d: %v", i, err)
        		}
        		rings = append(rings, ring)
        		pauseFds = append(pauseFds, ring.fd)
        
        		if err := addToEpoll(epollFd, ring.fd, len(rings)-1); err != nil {
        			return nil, err
        		}
        	}
        
        	closeFd, err := unix.Eventfd(0, unix.O_CLOEXEC|unix.O_NONBLOCK)
        	if err != nil {
        		return nil, err
        	}
        	fds = append(fds, closeFd)
        
        	if err := addToEpoll(epollFd, closeFd, -1); err != nil {
        		return nil, err
        	}
        
        	array, err = array.Clone()
        	if err != nil {
        		return nil, err
        	}
        
        	pr = &Reader{
        		array:   array,
        		rings:   rings,
        		epollFd: epollFd,
        		// Allocate extra event for closeFd
        		epollEvents: make([]unix.EpollEvent, len(rings)+1),
        		epollRings:  make([]*perfEventRing, 0, len(rings)),
        		closeFd:     closeFd,
        		pauseFds:    pauseFds,
        	}
        	if err = pr.Resume(); err != nil {
        		return nil, err
        	}
        	runtime.SetFinalizer(pr, (*Reader).Close)
        	return pr, nil
        }
        ```
        
        1. The function takes several parameters: **`array`**, a pointer to an eBPF map; **`perCPUBuffer`**, an integer indicating the buffer size per CPU; and **`opts`**, an object of type **`ReaderOptions`** containing additional options.
        2. It first checks if the **`perCPUBuffer`** is valid (larger than 0). If not, it returns an error.
        3. It creates an epoll file descriptor (**`epollFd`**) using **`unix.EpollCreate1`**, which is used for event notification.
        4. It initializes some variables including slices for file descriptors (**`fds`**), rings (**`rings`**), and pause file descriptors (**`pauseFds`**). These will be used for managing the event rings.
        5. It enters a loop to create a perf event ring for each CPU. If a CPU is offline, it skips creating the ring for that CPU.
        6. For each ring created, it adds the file descriptor to the epoll instance.
        7. It creates an event file descriptor (**`closeFd`**) using **`unix.Eventfd`**. This is used to signal when the reader should be closed.
        8. It adds the **`closeFd`** to the epoll instance.
        9. It clones the input eBPF map to ensure thread safety.
        10. It initializes a **`Reader`** struct with the necessary attributes, including the array, rings, epoll file descriptor, epoll events, and other related attributes.
        11. It calls the **`Resume`** method on the **`Reader`** object to start monitoring events. If an error occurs during this process, it returns an error.
        12. It sets a finalizer function to automatically close the reader when it's garbage collected.
        13. Finally, it returns the **`Reader`** object and **`nil`** error if everything was successful.
    
    ```c
    go func() {
    		var event perfEventItem
    		for {
    			evnt, err := perfEvent.Read()
    			if err != nil {
    				if errors.Unwrap(err) == perf.ErrClosed {
    					break
    				}
    				panic(err)
    			}
    			reader := bytes.NewReader(evnt.RawSample)
    			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
    				panic(err)
    			}
    			fmt.Printf("TCP: %v:%d -> %v:%d\n",
    				intToIpv4(event.SrcIp), ntohs(event.SrcPort),
    				intToIpv4(event.DstIp), ntohs(event.DstPort),
    			)
    			if len(evnt.RawSample) - METADATA_SIZE > 0 {
    				fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
    			}
    			received += len(evnt.RawSample)
    			lost += int(evnt.LostSamples)
    		}
    	}()
    	<-ctrlC
    ```
    
    - Definition of Read()
        
        ```go
        func (pr *Reader) Read() (Record, error) {
        	pr.mu.Lock()
        	defer pr.mu.Unlock()
        
        	if pr.epollFd == -1 {
        		return Record{}, fmt.Errorf("%w", ErrClosed)
        	}
        
        	for {
        		if len(pr.epollRings) == 0 {
        			nEvents, err := unix.EpollWait(pr.epollFd, pr.epollEvents, -1)
        			if temp, ok := err.(temporaryError); ok && temp.Temporary() {
        				// Retry the syscall if we we're interrupted, see https://github.com/golang/go/issues/20400
        				continue
        			}
        
        			if err != nil {
        				return Record{}, err
        			}
        
        			for _, event := range pr.epollEvents[:nEvents] {
        				if int(event.Fd) == pr.closeFd {
        					return Record{}, fmt.Errorf("%w", ErrClosed)
        				}
        
        				ring := pr.rings[cpuForEvent(&event)]
        				pr.epollRings = append(pr.epollRings, ring)
        
        				// Read the current head pointer now, not every time
        				// we read a record. This prevents a single fast producer
        				// from keeping the reader busy.
        				ring.loadHead()
        			}
        		}
        
        		// Start at the last available event. The order in which we
        		// process them doesn't matter, and starting at the back allows
        		// resizing epollRings to keep track of processed rings.
        		record, err := readRecordFromRing(pr.epollRings[len(pr.epollRings)-1])
        		if err == errEOR {
        			// We've emptied the current ring buffer, process
        			// the next one.
        			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
        			continue
        		}
        
        		return record, err
        	}
        }
        ```
        
    
    ### perfEvent.Read()
    
    Read the next record from the perf ring buffer.
    
    The function blocks until there are at least Watermark bytes in one of the per CPU buffers. Watermark is the number of written bytes required in any per CPU buffer before Read will process data. Must be smaller than PerCPUBuffer. The default is to start processing as soon as data is available. Records from buffers below the Watermark are not returned. `Record` can contain between 0 and 7 bytes of trailing garbage from the ring depending on the input sample's length. It's possible to encounter some additional bytes at the end of the record that do not correspond to the actual data and should be treated as garbage. The number of these garbage bytes can vary, but it's limited to a maximum of 7 bytes. Therefore, when interpreting the data read from the buffer, it's important to account for and handle these potential trailing garbage bytes appropriately. Calling Close interrupts the function.
    
    - Definition of struct Record
        
        ```c
        // Record contains either a sample or a counter of the
        // number of lost samples.
        type Record struct {
        	// The CPU this record was generated on.
        	CPU int
        
        	// The data submitted via bpf_perf_event_output.
        	// Due to a kernel bug, this can contain between 0 and 7 bytes of trailing
        	// garbage from the ring depending on the input sample's length.
        	RawSample []byte
        
        	// The number of samples which could not be output, since
        	// the ring buffer was full.
        	LostSamples uint64
        }
        ```
        
    
    ```c
    reader := bytes.NewReader(evnt.RawSample)
    ```
    
    The reader stores the specified number of bytes read from the buffer.
    
    - Definition of NewReader
        
        ```c
        // NewReader returns a new Reader reading from b.
        func NewReader(b []byte) *Reader { return &Reader{b, 0, -1} }
        ```
        
    - Definition of struct Reader
        
        ```c
        // A Reader implements the io.Reader, io.ReaderAt, io.WriterTo, io.Seeker,
        // io.ByteScanner, and io.RuneScanner interfaces by reading from
        // a byte slice.
        // Unlike a Buffer, a Reader is read-only and supports seeking.
        // The zero value for Reader operates like a Reader of an empty slice.
        type Reader struct {
        	s        []byte
        	i        int64 // current reading index
        	prevRune int   // index of previous rune; or < 0
        }
        ```
        
    
    ```c
    binary.Read(reader, binary.LittleEndian, &event)
    ```
    
    It reads saves the reader data into the event struct in littleEndian format. reader actually stores the data from the ebpf map. it’s stored than into a struct defined in go.
    
    ```
    			fmt.Printf("TCP: %v:%d -> %v:%d\n",
    				intToIpv4(event.SrcIp), ntohs(event.SrcPort),
    				intToIpv4(event.DstIp), ntohs(event.DstPort),
    			)
    			if len(evnt.RawSample) - METADATA_SIZE > 0 {
    				fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
    			}
    			received += len(evnt.RawSample)
    			lost += int(evnt.LostSamples)
    		}
    	}()
    ```
    
    Finally, it prints the event source destination ips and ports. It uses some formatting using `intToIpv4` which converts integer to ipv4 format and it uses `**ntohs**`. The function working is explained [here](https://www.notion.so/xdp_dump-2db81fc9f0594a62befe1f28c972365d?pvs=21).
    It increases the number of bytes received and also calculates and increases the lost samples also, by fetching the LostSamples field from struct Record.
    
    1. **Anonymous Goroutine**:
        
        ```go
        goCopy code
        go func() {
            // Goroutine body
        }()
        
        ```
        
        - This starts an anonymous goroutine, which is a function literal defined inline. It runs concurrently with the rest of the program.
    2. **Goroutine Body**:
        - The body of the goroutine contains a loop that continuously reads events from a **`perfEvent`** object and processes them:
            
            ```go
            goCopy code
            var event perfEventItem
            for {
                // Read event from perfEvent
                evnt, err := perfEvent.Read()
                // Error handling
                // Process event
            }
            
            ```
            
        - Inside the loop, events are read from the **`perfEvent`** object using the **`Read`** method. The loop continues indefinitely until an error occurs or until the **`perfEvent`** object is closed.
        - Each event is processed, which involves extracting relevant information and printing it to the console.
    3. **Signal Handling**:
        
        ```go
        goCopy code
        <-ctrlC
        ```
        
        - This line blocks the main goroutine until a value is received from the **`ctrlC`** channel. This channel was set up earlier to receive interrupt signals (e.g., CTRL+C).
        - Once the signal is received, the main goroutine proceeds to the next lines.
    4. **Cleanup and Summary**:
        - After receiving the interrupt signal, the program proceeds to close the **`perfEvent`** object and print a summary:
            
            ```go
            goCopy code
            perfEvent.Close()
            fmt.Println("\nSummary:")
            fmt.Printf("\t%d Event(s) Received\n", received)
            fmt.Printf("\t%d Event(s) Lost (e.g., small buffer, delays in processing)\n", lost)
            fmt.Println("\nDetaching program and exiting...")
            
            ```
            
        - It closes the **`perfEvent`** object to release resources.
        - It prints a summary of the events received and the events lost during processing.
        - Finally, it prints a message indicating that the program is detaching and exiting.
        
        Finally the following functions are used for encoding and format changing purposes:
        
        ```c
        func intToIpv4(ip uint32) net.IP {
        	res := make([]byte, 4)
        	binary.LittleEndian.PutUint32(res, ip)
        	return net.IP(res)
        }
        
        func ntohs(value uint16) uint16 {
        	return ((value & 0xff) << 8 ) | (value >> 8)
        }
        ```
        
        The **`intToIpv4`** function takes a 32-bit integer representation of an IPv4 address, converts it into a byte slice, and then constructs a **`net.IP`** object from that byte slice, effectively representing the IPv4 address in a format suitable for use within Go's networking libraries.
        
        The **`ntohs`** function swaps the bytes of the input **`value`**, effectively converting it from network byte order (big-endian) to host byte order (platform-dependent). Most modern architectures use little-endian byte order where the least significant byte (LSB) is stored first.