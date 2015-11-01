package ipv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Source: https://github.com/golang/net/blob/master/ipv6/header.go
const (
	IPv6Version = 6  // protocol version
	HeaderLen   = 40 // header length
)

type ExtensionHeader struct {
	NextHeader      byte
	ExtensionLength byte
	Data            []byte
}

// A Header represents an IPv6 base header.
type Header struct {
	Version          int    // protocol version
	TrafficClass     int    // traffic class
	FlowLabel        int    // flow label
	PayloadLen       int    // payload length
	NextHeader       int    // next header
	HopLimit         int    // hop limit
	Src              net.IP // source address
	Dst              net.IP // destination address
	ExtensionHeaders []ExtensionHeader
}

func (h *Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver: %v, tclass: %#x, flowlbl: %#x, payloadlen: %v, nxthdr: %v, hoplim: %v, src: %v, dst: %v", h.Version, h.TrafficClass, h.FlowLabel, h.PayloadLen, h.NextHeader, h.HopLimit, h.Src, h.Dst)
}

// ParseHeader parses b as an IPv6 base header.
func ParseHeader(b []byte) (*Header, int, error) {
	if len(b) < HeaderLen {
		return nil, 0, errors.New("header too short")
	}
	h := &Header{
		Version:      int(b[0]) >> 4,
		TrafficClass: int(b[0]&0x0f)<<4 | int(b[1])>>4,
		FlowLabel:    int(b[1]&0x0f)<<16 | int(b[2])<<8 | int(b[3]),
		PayloadLen:   int(b[4])<<8 | int(b[5]),
		NextHeader:   int(b[6]),
		HopLimit:     int(b[7]),
	}
	// validate version
	if h.Version != 0x06 {
		return nil, 0, errors.New("No IPv6 packet")
	}
	h.Src = make(net.IP, net.IPv6len)
	copy(h.Src, b[8:24])
	h.Dst = make(net.IP, net.IPv6len)
	copy(h.Dst, b[24:40])
	// make new slice
	h.ExtensionHeaders = make([]ExtensionHeader, 0, 1)
	// offset
	o := HeaderLen
	// next header value
	n := byte(h.NextHeader)
	for {
		// ExHeader types we should handle
		if n != 0x00 && n != 0x2b && n != 0x3c || n == 0x3a {
			break
		}
		// set next
		n = b[o]
		o++
		eH := ExtensionHeader{
			NextHeader:      n,
			ExtensionLength: b[o],
		}
		o++
		// end offset for the payload
		end := o + 8 + int(eH.ExtensionLength)
		// copy payload
		eH.Data = b[o:end]
		// append extension header
		h.ExtensionHeaders = append(h.ExtensionHeaders, eH)
		o = end
	}

	return h, o, nil
}

// End external content

func NewHeader(src, dst *net.IP) *Header {
	h := &Header{
		Version:      0x6,
		TrafficClass: 0,
		FlowLabel:    0,
		Src:          *src,
		Dst:          *dst,
	}

	return h
}

// Btw.: Thank you grnvs, now I understand bit shifting yay!
func (h *Header) Marshal() []byte {
	b := make([]byte, HeaderLen)
	// Version and first 4 bits of traffic class
	b[0] = byte((h.Version&0x0f)<<4) | byte((h.TrafficClass&0xf0)>>4)
	// Last 4 bits of traffic class & first 4 bits of flow label
	b[1] = byte((h.TrafficClass&0x0f)<<4) | byte(h.FlowLabel>>16)
	// 8 more bytes of flow label
	b[2] = byte(h.FlowLabel >> 8)
	// last 8 bytes of flow label
	b[3] = byte(h.FlowLabel & 0xff)
	// payload len first byte
	b[4] = byte(h.PayloadLen >> 8)
	// payload len second byte
	b[5] = byte(h.PayloadLen & 0xff)
	// next header & hop limit
	b[6] = byte(h.NextHeader)
	b[7] = byte(h.HopLimit)
	// source address
	copy(b[8:24], h.Src)
	// destination address
	copy(b[24:40], h.Dst)
	// 0x3a

	return b
}

type PseudoHeader struct {
	Src        [16]byte // source address
	Dst        [16]byte // destination address
	Length     uint32
	Reserved   [3]byte
	NextHeader byte
}

func (h *PseudoHeader) Marshal() []byte {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, h)
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func NewPseudoHeader(length, next int, src, dst net.IP) (h *PseudoHeader) {
	h = &PseudoHeader{
		Length:     uint32(length),
		NextHeader: byte(next),
	}
	copy(h.Src[:], src[:])
	copy(h.Dst[:], dst[:])

	return h
}
