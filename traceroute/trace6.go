package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"grnvs/icmp6"
	"grnvs/ipv6"
	"grnvs/netu"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	EtherLen = 14
)

type response struct {
	Sender                 net.IP
	DestinationUnreachable bool
	TimeExceeded           bool
	EchoReply              bool
	Timeout                bool
}

// Global app params
var Params *AppParams

// socket for reading
var sockRead int
var fileRead *os.File

// connection for writing
var connWrite net.PacketConn

var chanReply chan *response

type request struct {
	Header *ipv6.Header
	Body   *icmp6.EchoRequest
}

func (p *request) Marshal(hl int, seq uint16) []byte {
	// Set hop limit and sequence number
	p.Body.SequenceNumber = seq
	p.Header.HopLimit = hl
	// Reset checksum
	p.Body.Header.Checksum = 0
	// Calculate checksum
	p.Body.Header.Checksum = icmp6.MakeChecksum(p.Body, Params.LocalAddress.IP, Params.RemoteAddress.IP)
	// marshal packages
	return append(p.Header.Marshal(), p.Body.Marshal()...)
}

func main() {
	// Get app params from console args
	var err error
	Params, err = NewAppParams(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	// seed pseudo random generator; We'll need it later
	rand.Seed(time.Now().UnixNano())

	// Overwrite local only because my network is a bitch
	if localAddr := os.Getenv("GRNVS_TRACE6_LADDR"); localAddr != "" {
		fmt.Fprintf(os.Stderr, "Using %s as local ip address\n", localAddr)
		Params.LocalAddress, err = net.ResolveIPAddr("ip6", localAddr)
		if err != nil {
			panic(err)
		}
	}

	// Init raw socket for writing (IPPROTO_RAW is only for writing -> man 7 raw)
	connWrite = createConn(syscall.AF_INET6, syscall.IPPROTO_RAW)
	defer connWrite.Close()
	// Socket for reading
	sockRead, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(netu.Htons(syscall.ETH_P_IPV6)))
	if err != nil {
		panic(err)
	}
	fileRead = os.NewFile(uintptr(sockRead), fmt.Sprintf("fd-sock-read-%d", sockRead))
	defer syscall.Close(sockRead)
	defer fileRead.Close()

	// Create the base package, IPv6-Header + ICMP6 Echo Request
	// Generate id for icmp package
	id := uint16(rand.Uint32())
	pck, l := icmp6.NewEchoRequest(id, 0)
	// craft request package
	req := &request{
		Header: ipv6.NewHeader(&Params.LocalAddress.IP, &Params.RemoteAddress.IP),
		Body:   pck,
	}
	// set some ipv6 header values
	req.Header.NextHeader = 0x3a
	req.Header.PayloadLen = l

	chanReply = make(chan *response, 1)

	// Start traceing
	//done := false
	seq := uint16(0)
	var resp *response
	for i := 1; i <= Params.MaxHops; i++ {
		// print current hop
		fmt.Printf("%d", i)
		// Send a package for each hop
		for j := 0; j < Params.Attempts; j++ {
			// get request data
			p := req.Marshal(i, seq)
			// Send icmp package
			connWrite.WriteTo(p, Params.RemoteAddress)
			// Wait for response
			resp, err = recvResponse(req, &Params.RemoteAddress.IP)
			if err != nil {
				fmt.Printf(err.Error())
				return
			}
			if resp.Timeout {
				fmt.Printf("  *")
			} else if resp.EchoReply || resp.TimeExceeded {
				fmt.Printf("  %s", resp.Sender.String())
			} else if resp.DestinationUnreachable {
				fmt.Printf("  %s!X", resp.Sender.String())
			}
			// increment sequence
			seq++
		}
		fmt.Print("\n")
		// stop if we are done
		if resp.EchoReply || resp.DestinationUnreachable {
			os.Exit(1) // Termination
		}
	}
}

func recvResponse(req *request, from *net.IP) (r *response, err error) {

	// package parsing
	go func() {
		for {
			buf := make([]byte, Params.NetworkInterface.MTU)
			l, err := fileRead.Read(buf)
			if err != nil {
				panic(err)
			}
			// Parse IP header
			header, o, err := ipv6.ParseHeader(buf)
			if err != nil {
				continue
			}
			// Validate destination of the incoming package + Checksum verification
			if !Params.LocalAddress.IP.Equal(header.Dst) || !icmp6.VerifyChecksum(header, buf[o:l]) {
				continue
			}
			// Parse icmp package
			msg, err := icmp6.Unmarshal(buf[o:l])
			if err != nil {
				continue
			}

			resp := &response{
				Sender: header.Src,
			}

			switch msg.(type) {
			case *icmp6.TimeExceeded:
				resp.TimeExceeded = true
			case *icmp6.EchoReply:
				r := msg.(*icmp6.EchoReply)
				// Validate echo reply
				if r.Identifier != req.Body.Identifier || r.SequenceNumber != req.Body.SequenceNumber || !from.Equal(header.Src) {
					continue
				}
				resp.EchoReply = true
			case *icmp6.DestinationUnreachable:
				// Decode the invoking packet to get the unreachable ip
				invPck := msg.(*icmp6.DestinationUnreachable).InvokingPacket
				off := 0
				// Look for ipv6 header offset
				for i := 0; i < len(invPck); i++ {
					if (int(invPck[i]) >> 4) == 6 {
						off = i
						break
					}
				}
				h, _, err := ipv6.ParseHeader(invPck[off:])
				if err != nil {
					fmt.Println(err.Error())
					continue
				}
				resp.Sender = h.Dst
				resp.DestinationUnreachable = true
			}
			chanReply <- resp
		}
	}()

	select {
	case r := <-chanReply:
		return r, nil
	case <-time.After(Params.Timeout):
		r = new(response)
		r.Timeout = true
		return r, nil
	}

	return nil, errors.New("Unkown error")
}

func createConn(domain, proto int) net.PacketConn {
	s, err := syscall.Socket(domain, syscall.SOCK_RAW, proto) //int(htons(syscall.ETH_P_ALL))
	if err != nil {
		panic(err)
	}
	f := os.NewFile(uintptr(s), fmt.Sprintf("fd-%d-%d-%d", domain, proto, s))
	// create ne file packet connection
	c, err := net.FilePacketConn(f)
	if err != nil {
		panic(err)
	}
	// FilePacketConn uses copy so we can close these
	syscall.Close(s)
	f.Close()

	return c
}

func dump(b []byte) {
	fmt.Println("====")
	fmt.Println(hex.Dump(b))
}
