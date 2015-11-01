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
	"syscall"
)

//the ethernet header
type etherHeader struct {
	DHost [6]byte
	SHost [6]byte
	Type  uint16
}

//wake on lan payload
type wolPayload struct {
	Sync   [6]byte
	Target [96]byte
}

//complete package
type magicPacket struct {
	Hdr etherHeader
	Wol wolPayload
}

func main() {
	//define interface flag
	interfaceName := flag.String("i", "eth0", "Network interface; Default is eth0")
	//define error message / help
	flag.Usage = func() {
		fmt.Printf("Usage: %s -i <network-interface> <mac-adress>\n", path.Base(os.Args[0]))
	}
	//parse command line flags
	flag.Parse()
	//validate arguments
	if flag.NArg() != 1 {
		flag.Usage()
		return
	}
	//validate and parse the mac address
	targetMac, err := net.ParseMAC(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s is no valid MAC adress.\n%s", flag.Arg(0), err.Error())
		os.Exit(1)
	}
	//find the network interface by its name
	networkInterface, err := net.InterfaceByName(*interfaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The selected network interface %s does not exist.\n", *interfaceName)
		os.Exit(1)
	}
	//create raw socket
	socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to create socket.")
		os.Exit(2)
	}
	//create a ethernet header for the wol package
	// The ether type is taken from here https://wiki.wireshark.org/WakeOnLAN
	header := etherHeader{
		DHost: [6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, //MAC Broadcast
		Type:  0x0842,
	}
	//copy the mac address of the interface to the ether_header
	copy(header.SHost[:], networkInterface.HardwareAddr[0:6])
	//create the wol payload
	payload := wolPayload{
		[6]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		[96]byte{},
	}
	//copy the target address 16 times to the wol payload
	for i := 0; i < len(payload.Target); i++ {
		payload.Target[i] = targetMac[i%6]
	}
	//concat header and payload the create the whole package
	packet := magicPacket{
		header,
		payload,
	}
	//set the networking interface and protocol
	sockAddr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  networkInterface.Index,
	}
	//encode struct
	var buffer bytes.Buffer
	err = binary.Write(&buffer, binary.BigEndian, packet)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to encode packet.")
		os.Exit(2)
	}
	//send wol package
	err = syscall.Sendto(socket, buffer.Bytes(), 0, &sockAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to send packet.")
		os.Exit(2)
	}
}

// Taken from https://github.com/xiezhenye/harp/blob/master/src/arp/arp.go#L53
func htons(n uint16) uint16 {
	var (
		high uint16 = n >> 8
		ret  uint16 = n<<8 + high
	)
	return ret
}
