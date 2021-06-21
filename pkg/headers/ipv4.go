package headers

import (
	"errors"
	"net"

	"github.com/songgao/water/waterutil"
)

type Ipv4Header struct {
	Source      net.IP
	Destination net.IP
	Protocol    byte
	Payload     []byte
}

var (
	ErrNotIPV4Packet = errors.New("can only parse ipv4 packets")
)

func ParseIpV4Header(packet []byte) (*Ipv4Header, error) {
	// tun/tap library already implements IP header parsing:
	if !waterutil.IsIPv4(packet) {
		return nil, ErrNotIPV4Packet
	}

	return &Ipv4Header{
		Payload:     waterutil.IPv4Payload(packet),
		Source:      waterutil.IPv4Source(packet),
		Destination: waterutil.IPv4Destination(packet),
		Protocol:    (byte)(waterutil.IPv4Protocol(packet)),
	}, nil
}
