// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Define console flags
	interfaceName := flag.String("i", "eth0", "Network interface; Default is eth0")
	timeout := flag.Int("t", 5, "Timout in seconds; default is 5")
	// Define error message / help
	flag.Usage = func() {
		fmt.Printf("Usage: %s -i <network-interface> -t <timeout in sec> <target ipv6 address>\n", path.Base(os.Args[0]))
	}
	// Parse command line flags
	flag.Parse()
	// Validate arguments count
	if flag.NArg() != 1 {
		flag.Usage()
		return
	}
	// Validate and parse the destination IPv6 address
	lookupAddr := net.ParseIP(flag.Arg(0))
	if lookupAddr == nil || lookupAddr.To4() != nil {
		return // as requested in the assignment
	}
	// Find the network interface by its name
	networkInterface, err := net.InterfaceByName(*interfaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The selected network interface %s does not exist.\n", *interfaceName)
		return
	}
	// Create raw socket, sudo required see man 7 raw
	socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socket)

	// Get source address
	sAddr := getSrcAddr(networkInterface)
	if sAddr == nil {
		return
	}

	// Create solicited-node multicast address prefix ff02::1:ff00:0/104
	dAddr := net.ParseIP(fmt.Sprintf("ff02::1:ff%02x:%02x%02x", lookupAddr[13], lookupAddr[14], lookupAddr[15]))
	if dAddr == nil {
		return
	}

	// Build destination mac
	dMac := net.HardwareAddr{0x33, 0x33, dAddr[12], dAddr[13], dAddr[14], dAddr[15]}
	// Create new ethernet frame
	eFrame := NewEthernetFrame(0x86DD, networkInterface.HardwareAddr, dMac)

	// Create icmp payload
	icmp := ICMPv6NeighborSolicitation{
		Header: ICMPv6MessageHeader{
			Type:     0x87,
			Code:     0x00,
			Checksum: 0x0,
		},
		Reserved:     0x0,
		OptionType:   0x01,
		OptionLength: 0x01,
	}
	// Copy target address
	copy(icmp.TargetAddress[:], lookupAddr)
	copy(icmp.SourceLinkAddress[:], networkInterface.HardwareAddr)

	// Create IPv6 Packet
	ipHeader := IPv6Header{
		Version:      0x6,
		TrafficClass: 0,
		FlowLabel:    0,
		PayloadLen:   len(icmp.Marshal()),
		NextHeader:   0x3a,
		HopLimit:     0xff,
		Src:          sAddr,
		Dst:          dAddr,
	}
	// Calculate and set icmp checksum
	icmp.Header.Checksum = ICMPv6Checksum(ipHeader, icmp)
	// Get ethernet frame bytes
	eFrameBytes := eFrame.Marshal()
	// Append IPv6 header
	data := append(eFrameBytes, ipHeader.Marshal()...)
	data = append(data, icmp.Marshal()...)
	// Make socket address
	sockAddr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  networkInterface.Index,
	}
	// Send data
	err = syscall.Sendto(socket, data, 0, &sockAddr)
	if err != nil {
		panic(err)
	}

	// Concurrency patterns : http://blog.golang.org/go-concurrency-patterns-timing-out-and

	// Signalling channel
	timedout := make(chan bool, 1)
	go func() {
		time.Sleep(time.Duration(*timeout) * time.Second)
		timedout <- true
	}()

	// Data channel
	dataIn := make(chan *ICMPv6NeighborAdvertisement, 1)

	// Create socket, taken from http://www.darkcoding.net/software/raw-sockets-in-go-link-layer/
	f := os.NewFile(uintptr(socket), fmt.Sprintf("fd %d", socket))
	defer f.Close()

	// package parsing
	go func() {
		// Adapted from http://www.darkcoding.net/software/raw-sockets-in-go-link-layer/
		for {
			b := make([]byte, 1024)
			numRead, err := f.Read(b)
			if err != nil {
				panic(err)
			}
			eFrame, err := EthernetFrameParse(b[:EthernetFrameLen])
			// only ipv6 and only for the choosen interface
			if eFrame.Ethertype == 0x86DD && bytes.Equal(eFrame.DstMac[:], networkInterface.HardwareAddr) {
				// Parse ipv6 package
				offset := binary.Size(eFrame)
				header, err := IPv6ParseHeader(b[offset:numRead])
				if err == nil && header != nil && header.NextHeader == 0x3a && header.HopLimit == 0xff {
					// increase offset
					offset += IPv6HeaderLen
					// try to parse neighbor advertisement
					na, err := ICMPv6ParseNeighborAdvertisement(b[offset:numRead])
					if err == nil {
						// Put message into channel
						dataIn <- na
					}
				}
			}
		}
	}()

	select {
	case m := <-dataIn:
		mac := strings.Replace(fmt.Sprintf("% x", m.SourceLinkAddress), " ", ":", -1)
		fmt.Printf("%s is at %s\n", lookupAddr.String(), mac)
	case <-timedout:
		fmt.Println("Message timed out")
		return
	}
}

func getSrcAddr(iface *net.Interface) (src net.IP) {
	// Get network addresses
	addrs, err := iface.Addrs()
	if err != nil {
		panic(err)
	}
	// Loop over addresses to find a suitable sender address
	for _, addr := range addrs {
		// Parse each address until we have one that we can use
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() == nil {
			src = ip
			break
		}
	}

	return src
}

// Taken from https://github.com/xiezhenye/harp/blob/master/src/arp/arp.go#L53
func htons(n uint16) uint16 {
	var (
		high uint16 = n >> 8
		ret  uint16 = n<<8 + high
	)
	return ret
}
