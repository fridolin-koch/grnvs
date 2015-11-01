package icmp6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"grnvs/ipv6"
	"grnvs/netu"
	"net"
)

const (
	TypeDestinationUnreachable = 0x01
	TypeTimeExceeded           = 0x03
	TypeEchoRequest            = 0x80
	TypeEchoReply              = 0x81
)

// ICMP Message interface
type Message interface {
	// Returns the message in Network Byte Order / Big Endian
	Marshal() []byte
	// String representation of the message
	String() string
}

type Header struct {
	Type     byte
	Code     byte
	Checksum uint16
}

func (h *Header) String() string {
	return fmt.Sprintf("Type: %X, Code: %x, Checksum: %x", h.Type, h.Code, h.Checksum)
}

func (h *Header) Marshal() ([]byte, error) {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, h)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func Unmarshal(b []byte) (m Message, err error) {
	// verify min length
	if len(b) < 8 {
		return nil, errors.New("ICMPv6 packet is to short")
	}
	// Parse header
	h := Header{
		Type:     b[0],
		Code:     b[1],
		Checksum: binary.BigEndian.Uint16(b[2:4]),
	}
	// verify header code
	if !verifyHeaderCode(h) {
		return nil, errors.New("Invalid header code")
	}
	// Build package from data
	switch h.Type {
	case TypeTimeExceeded:
		m = &TimeExceeded{
			Header:         h,
			Unused:         binary.BigEndian.Uint32(b[4:8]),
			InvokingPacket: b[8:],
		}
	case TypeEchoReply:
		if len(b) > 8 {
			return nil, errors.New("ICMPv6 packet is to long")
		}
		m = &EchoReply{
			Header:         h,
			Identifier:     binary.BigEndian.Uint16(b[4:6]),
			SequenceNumber: binary.BigEndian.Uint16(b[6:8]),
			//Data:           b[8:],
		}
	case TypeDestinationUnreachable:
		m = &DestinationUnreachable{
			Header:         h,
			Unused:         binary.BigEndian.Uint32(b[4:8]),
			InvokingPacket: b[8:],
		}
	default:
		return nil, errors.New("Unkown ICMPv6 meesage type")
	}

	return m, nil
}

// ICMPv6 Checksum calculation
// Adapted from https://github.com/golang/net/blob/bdcab5d1425b3bc74ab0f2be70acb9e4a2b2f73e/icmp/message.go#L35
func MakeChecksum(packet Message, src, dst net.IP) uint16 {
	b := packet.Marshal()
	// Create new pseudo header
	pHeader := ipv6.NewPseudoHeader(len(b), 0x3a, src, dst)
	// append icmp bytes to pseudo header
	b = append(pHeader.Marshal(), b...)
	// Make checksum
	return csum(b)
}

func VerifyChecksum(h *ipv6.Header, b []byte) bool {
	// get checksum from package
	co := binary.BigEndian.Uint16(b[2:4])
	// Create pseudo header
	ph := ipv6.NewPseudoHeader(h.PayloadLen, h.NextHeader, h.Src, h.Dst)
	// Set checksum to 0x0
	b[2] = 0
	b[3] = 0
	// make packet
	b = append(ph.Marshal(), b...)
	// calculate checksum and compare
	return co == csum(b)
}

func csum(b []byte) uint16 {
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

	return netu.Htons(^uint16(s))
}

func verifyHeaderCode(h Header) bool {
	var min, max byte
	switch h.Type {
	case TypeEchoReply:
		min, max = 0, 0
	case TypeTimeExceeded:
		min, max = 0, 1
	case TypeDestinationUnreachable:
		min, max = 0, 6
	default:
		return true
	}

	return h.Code >= min && h.Code <= max
}
