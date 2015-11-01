package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	EthernetFrameLen = 14 // As defined in assignment2
)

// Minimum ethernet frame
type EthernetFrame struct {
	DstMac    [6]byte
	SrcMac    [6]byte
	Ethertype uint16
}

// Constructor
func NewEthernetFrame(eType uint16, src net.HardwareAddr, dst net.HardwareAddr) *EthernetFrame {
	// Init struct
	frame := new(EthernetFrame)
	// Copy dst and src to struct
	copy(frame.DstMac[:], dst[0:6])
	copy(frame.SrcMac[:], src[0:6])
	// Ethertype
	frame.Ethertype = 0x86DD

	return frame
}

func (f *EthernetFrame) String() string {
	return fmt.Sprintf("Dst: %x, Src: %x, Ethertype: %x\n", f.DstMac, f.SrcMac, f.Ethertype)
}

// Get bytes from struct
func (f *EthernetFrame) Marshal() []byte {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, f)
	if err != nil {
		panic(err)
	}

	return buffer.Bytes()
}

// Parse ethnet frame
func EthernetFrameParse(b []byte) (f *EthernetFrame, err error) {
	f = new(EthernetFrame)
	buf := bytes.NewReader(b)
	err = binary.Read(buf, binary.BigEndian, f)
	if err != nil {
		return nil, err
	}

	return f, nil
}
