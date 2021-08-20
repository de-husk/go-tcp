package main

import (
	"log"

	"github.com/Samangan/go-tcp/pkg/protocol"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

type ConnectionKey struct {
	SourceIP        string
	SourcePort      uint16
	DestinationIP   string
	DestinationPort uint16
}

// NOTE: This must be run as root

func main() {
	nic, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Virtual interface name: %s\n", nic.Name())

	connections := map[ConnectionKey]*protocol.Connection{}

	packet := make([]byte, 2000)
	for {
		_, err := nic.Read(packet)
		if err != nil {
			log.Fatal(err)
		}

		p := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)

		if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)

			if ip.Protocol != layers.IPProtocolTCP {
				// ignore non tcp packets
				continue
			}

			if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)

				k := ConnectionKey{
					SourceIP:        ip.SrcIP.String(),
					SourcePort:      uint16(tcp.SrcPort),
					DestinationIP:   ip.DstIP.String(),
					DestinationPort: uint16(tcp.DstPort),
				}

				conn := connections[k]
				if conn == nil {
					conn = protocol.NewConnection()
					connections[k] = conn
				}

				err := conn.ProcessPacket(ip, tcp, nic)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}
