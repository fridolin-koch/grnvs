package icmp6

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type EchoRequest struct {
	Header         Header
	Identifier     uint16
	SequenceNumber uint16
}

// Create new ICMP echo request
func NewEchoRequest(identifier, sequence uint16) (*EchoRequest, int) {
	r := &EchoRequest{
		Header: Header{
			Type:     TypeEchoRequest,
			Code:     0,
			Checksum: 0,
		},
		Identifier:     identifier,
		SequenceNumber: sequence,
	}
	return r, binary.Size(r)
}

// ICMP Message interface methods

func (m *EchoRequest) Marshal() []byte {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, m)
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func (m *EchoRequest) String() string {
	return fmt.Sprintf("%s, Identifier: %s, SequenceNumber: %s", m.Header, m.Identifier, m.SequenceNumber)
}
