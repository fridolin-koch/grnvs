package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"time"
)

type AppParams struct {
	NetworkInterface *net.Interface
	Timeout          time.Duration
	Attempts         int
	MaxHops          int
	RemoteAddress    *net.IPAddr
	LocalAddress     *net.IPAddr
}

func (p *AppParams) String() string {
	return fmt.Sprintf("Interface: %s, timeout: %d, attempts: %d, max hops: %d, remote address: %s, local adresss: %s", p.NetworkInterface.Name, p.Timeout, p.Attempts, p.MaxHops, p.RemoteAddress, p.LocalAddress)
}

func NewAppParams(args []string) (*AppParams, error) {
	// create new flag set
	set := flag.NewFlagSet("trace6", flag.ContinueOnError)
	// define help
	set.Usage = func() {
		fmt.Printf("Usage: %s -i <network inter-face> -t <probe timeout in sec> -q <attempts> -m <max hops> <target addr>\n", path.Base(os.Args[0]))
	}
	// Define console flags
	i := set.String("i", "eth0", "Network interface; Default is eth0")
	t := set.Uint("t", 5, "Timeout in seconds; Default: 5")
	q := set.Int("q", 3, "Max Attempts default is 3")
	m := set.Int("m", 15, "Max hops default is 15")
	// Try to parse arguments
	err := set.Parse(args)
	if err != nil {
		return nil, err
	}
	// Validate arguments count
	if set.NArg() != 1 {
		return nil, errors.New("No target address provided")
	}
	// parse remote ip
	rIp, err := net.ResolveIPAddr("ip6", set.Arg(0))
	if err != nil {
		return nil, err
	}
	c := &AppParams{
		RemoteAddress: rIp,
		Timeout:       time.Duration(*t) * time.Second,
		Attempts:      *q,
		MaxHops:       *m,
	}
	// Find the network interface by its name
	c.NetworkInterface, err = net.InterfaceByName(*i)
	if err != nil {
		return nil, err
	}
	// Get local IPv6 from network interface
	addrs, err := c.NetworkInterface.Addrs()
	if err != nil {
		return nil, err
	}
	// This loop takes the first IPv6 Address it gets
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip.To4() == nil {
			//TODO: Better detection for multiple addresses
			lIP, err := net.ResolveIPAddr("ip6", ip.String())
			if err != nil {
				continue
			}
			c.LocalAddress = lIP
			break
		}
	}
	if c.LocalAddress == nil {
		return nil, errors.New("Unable to determine local address")
	}
	return c, nil
}
