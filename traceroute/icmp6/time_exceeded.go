package icmp6

import (
	"encoding/binary"
)

type TimeExceeded struct {
	Header         Header
	Unused         uint32
	InvokingPacket []byte
}

func (m *TimeExceeded) Marshal() []byte {
	b, _ := m.Header.Marshal()
	binary.BigEndian.PutUint32(b, m.Unused)
	b = append(b, m.InvokingPacket...)

	return b
}

func (m *TimeExceeded) String() string {
	return m.Header.String()
}
