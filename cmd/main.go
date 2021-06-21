package main

import (
	"fmt"
	"log"

	"github.com/Samangan/go-tcp/pkg/headers"
	"github.com/songgao/water"
)

// NOTE: This must be run as root

func main() {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Virtual interface name: %s\n", ifce.Name())

	packet := make([]byte, 2000)
	for {
		_, err := ifce.Read(packet)
		if err != nil {
			log.Fatal(err)
		}

		ipHeader, err := headers.ParseIpV4Header(packet)
		if err != nil {
			// ignore non valid IPv4 packets
			continue
		}

		tcpHeader, err := headers.ParseTcpHeader(ipHeader)
		if err != nil {
			// ignore non valid TCP packets
			continue
		}

		fmt.Printf("Packet  : %s -> %s %d bytes over protocol %d \n",
			ipHeader.Source.String(),
			ipHeader.Destination.String(),
			len(ipHeader.Payload),
			ipHeader.Protocol,
		)

		// TODO: Implement TCP protocol

		fmt.Println(tcpHeader)
	}
}
