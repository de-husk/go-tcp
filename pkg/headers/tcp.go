package headers

import (
	"encoding/binary"
	"errors"
)

type TcpHeader struct {
	SourcePort                                 uint16
	DestinationPort                            uint16
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	// TODO: Finish the rest of the fields:
	// https://datatracker.ietf.org/doc/html/rfc793#page-15
}

var (
	ErrInvalidProtocol  = errors.New("not TCP protocol")
	ErrInvalidTCPHeader = errors.New("invalid TCP header")
)

func ParseTcpHeader(packet *Ipv4Header) (*TcpHeader, error) {
	if packet.Protocol != 0x06 {
		return nil, ErrInvalidProtocol
	}

	d := packet.Payload
	if len(d) < 20 {
		return nil, ErrInvalidTCPHeader
	}

	return &TcpHeader{
		SourcePort:      binary.BigEndian.Uint16(d[0:2]),
		DestinationPort: binary.BigEndian.Uint16(d[2:4]),
		Seq:             binary.BigEndian.Uint32(d[4:8]),
		Ack:             binary.BigEndian.Uint32(d[8:12]),
		DataOffset:      d[12] >> 4,
		FIN:             d[13]&0x01 != 0,
		SYN:             d[13]&0x02 != 0,
		RST:             d[13]&0x04 != 0,
		PSH:             d[13]&0x08 != 0,
		ACK:             d[13]&0x10 != 0,
		URG:             d[13]&0x20 != 0,
		ECE:             d[13]&0x40 != 0,
		CWR:             d[13]&0x80 != 0,
		NS:              d[12]&0x01 != 0,
		Window:          binary.BigEndian.Uint16(d[14:16]),
		Checksum:        binary.BigEndian.Uint16(d[16:18]),
		Urgent:          binary.BigEndian.Uint16(d[18:20]),
	}, nil
}
