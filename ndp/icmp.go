package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ICMPv6NeighborAdvertisementFlagR uint8 = 4
	ICMPv6NeighborAdvertisementFlagS uint8 = 2
	ICMPv6NeighborAdvertisementFlag0 uint8 = 1
)

// ICMPv6 base header (4 byte)
type ICMPv6MessageHeader struct {
	Type     byte
	Code     byte
	Checksum uint16
}

// ICMPv6 neighbor solicitation message (request) (4 byte + 28 byte)
type ICMPv6NeighborSolicitation struct {
	Header            ICMPv6MessageHeader
	Reserved          uint32
	TargetAddress     [16]byte
	OptionType        byte
	OptionLength      byte
	SourceLinkAddress [6]byte
}

// IMCPv6 neighbor advertisement message (response)
type ICMPv6NeighborAdvertisement struct {
	Header            ICMPv6MessageHeader
	Flags             uint32 // 3 bit flags + 29 bit reserved
	TargetAddress     [16]byte
	OptionType        byte
	OptionLength      byte
	SourceLinkAddress [6]byte
}

func (m *ICMPv6NeighborAdvertisement) FlagSet(flag uint8) bool {
	return uint8(m.Flags>>29)&flag == 1
}

func (m *ICMPv6NeighborAdvertisement) String() string {
	if m == nil {
		return "<nil>"
	}
	return fmt.Sprintf("Header-Type: %x, Header-Code: %x, Header-Checksum: %x, Target-Address: %x, Option-Type: %x, Option-Length: %x, Source-Link-Address: %x", m.Header.Type, m.Header.Code, m.Header.Checksum, m.TargetAddress, m.OptionType, m.OptionLength, m.SourceLinkAddress)
}

// Convert the struct to a byte slice
func (m *ICMPv6NeighborSolicitation) Marshal() []byte {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, m)
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

// ICMPv6 Checksum calculation
// Adapted from https://github.com/golang/net/blob/bdcab5d1425b3bc74ab0f2be70acb9e4a2b2f73e/icmp/message.go#L35
func ICMPv6Checksum(ipHeader IPv6Header, icmpPayload ICMPv6NeighborSolicitation) uint16 {
	// get icmp payload bytes
	b := icmpPayload.Marshal()
	// make pseudo header
	pHeader := IPv6PseudoHeader{
		Length:     uint32(len(b)),
		NextHeader: byte(0x3a),
	}
	copy(pHeader.Src[:], ipHeader.Src)
	copy(pHeader.Dst[:], ipHeader.Dst)
	// append icmp bytes to pseudo header
	b = append(pHeader.Marshal(), b...)

	// Make checksum
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}

	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}

	s = s>>16 + s&0xffff
	s = s + s>>16

	return htons(^uint16(s))
}

// This function discards neighbor advertisement without options (Because we need the targets mac address)
func ICMPv6ParseNeighborAdvertisement(b []byte) (m *ICMPv6NeighborAdvertisement, err error) {
	m = new(ICMPv6NeighborAdvertisement)
	buf := bytes.NewReader(b)
	err = binary.Read(buf, binary.BigEndian, m)
	if err != nil {
		return nil, err
	} else if m.Header.Type != 0x88 || m.OptionType != 0x02 || m.OptionLength != 0x01 || !m.FlagSet(ICMPv6NeighborAdvertisementFlag0) {
		return nil, errors.New("Message is no neighbor advertisement")
	}

	return m, nil
}
