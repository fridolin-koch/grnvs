package icmp6

import (
	"encoding/binary"
	"fmt"
)

type EchoReply struct {
	Header         Header
	Identifier     uint16
	SequenceNumber uint16
	Data           []byte
}

// ICMP Message interface methods
func (m *EchoReply) Marshal() []byte {
	b, _ := m.Header.Marshal()
	binary.BigEndian.PutUint16(b, m.Identifier)
	binary.BigEndian.PutUint16(b, m.SequenceNumber)
	b = append(b, m.Data...)

	return b
}

func (m *EchoReply) String() string {
	return fmt.Sprintf("%s, Identifier: %s, SequenceNumber: %s", m.Header, m.Identifier, m.SequenceNumber)
}
