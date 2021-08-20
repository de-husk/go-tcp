package protocol

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

/*
                              +---------+ ---------\      active OPEN
                              |  CLOSED |            \    -----------
                              +---------+<---------\   \   create TCB
                                |     ^              \   \  snd SYN
                   passive OPEN |     |   CLOSE        \   \
                   ------------ |     | ----------       \   \
                    create TCB  |     | delete TCB         \   \
                                V     |                      \   \
                              +---------+            CLOSE    |    \
                              |  LISTEN |          ---------- |     |
                              +---------+          delete TCB |     |
                   rcv SYN      |     |     SEND              |     |
                  -----------   |     |    -------            |     V
 +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 |         |<-----------------           ------------------>|         |
 |   SYN   |                    rcv SYN                     |   SYN   |
 |   RCVD  |<-----------------------------------------------|   SENT  |
 |         |                    snd ACK                     |         |
 |         |------------------           -------------------|         |
 +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
   |           --------------   |     |   -----------
   |                  x         |     |     snd ACK
   |                            V     V
   |  CLOSE                   +---------+
   | -------                  |  ESTAB  |
   | snd FIN                  +---------+
   |                   CLOSE    |     |    rcv FIN
   V                  -------   |     |    -------
 +---------+          snd FIN  /       \   snd ACK          +---------+
 |  FIN    |<-----------------           ------------------>|  CLOSE  |
 | WAIT-1  |------------------                              |   WAIT  |
 +---------+          rcv FIN  \                            +---------+
   | rcv ACK of FIN   -------   |                            CLOSE  |
   | --------------   snd ACK   |                           ------- |
   V        x                   V                           snd FIN V
 +---------+                  +---------+                   +---------+
 |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 +---------+                  +---------+                   +---------+
   |                rcv ACK of FIN |                 rcv ACK of FIN |
   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
   |  -------              x       V    ------------        x       V
    \ snd ACK                 +---------+delete TCB         +---------+
     ------------------------>|TIME WAIT|------------------>| CLOSED  |
							  +---------+                   +---------+

*/

type State int

const (
	Closed State = iota
	Listen
	SynRcvd
	Estab
)

type Connection struct {
	state State
	send  SendSequenceSpace
	recv  RecvSequenceSpace
}

// Send Sequence Space
//
//                    1         2          3          4
//               ----------|----------|----------|----------
//                      SND.UNA    SND.NXT    SND.UNA
//                                           +SND.WND
//
//         1 - old sequence numbers which have been acknowledged
//         2 - sequence numbers of unacknowledged data
//         3 - sequence numbers allowed for new data transmission
//         4 - future sequence numbers which are not yet allowed

type SendSequenceSpace struct {
	una uint32 // send unacknowledged
	nxt uint32 // send next
	wnd uint16 // send window
	up  bool   // send urgent pointer
	wl1 uint32 // segment sequence number used for last window update
	wl2 uint32 // segment acknowledgment number used for last window update
	iss uint32 // initial send sequence number
}

// Receive Sequence Space
//
// 1          2          3
// ----------|----------|----------
//    RCV.NXT    RCV.NXT
// 			 +RCV.WND
//
// 1 - old sequence numbers which have been acknowledged
// 2 - sequence numbers allowed for new reception
// 3 - future sequence numbers which are not yet allowed

type RecvSequenceSpace struct {
	nxt uint32 // receive next
	wnd uint16 // receive window
	up  bool   // receive urgent pointer
	irs uint32 // initial receive sequence number
}

func NewConnection() *Connection {
	return &Connection{
		state: Listen,
	}
}

func (conn *Connection) ProcessPacket(ipHeader *layers.IPv4, tcpHeader *layers.TCP, nic *water.Interface) error {
	// NOTE: We are trusting clients since this is just for learning,
	// so we aren't going to protect against SYN flood attacks for example.

	log.Printf(
		"%s:%s -> %s:%s %db of proto: %d \n",
		ipHeader.SrcIP,
		tcpHeader.SrcPort,
		ipHeader.DstIP,
		tcpHeader.DstPort,
		len(tcpHeader.Payload),
		ipHeader.Protocol,
	)

	switch conn.state {
	case Closed:
		return nil
	case Listen:
		if !tcpHeader.SYN {
			return nil
		}

		// keep track of sender's state:
		conn.recv.irs = tcpHeader.Seq
		conn.recv.nxt = tcpHeader.Seq + 1
		conn.recv.wnd = tcpHeader.Window

		// keep track of our state:
		conn.send.iss = 0
		conn.send.una = conn.send.iss
		conn.send.nxt = conn.send.una + 1
		conn.send.wnd = 10

		conn.state = SynRcvd

		// start establishing a connection with client:
		ip := &layers.IPv4{
			SrcIP:    ipHeader.DstIP,
			DstIP:    ipHeader.SrcIP,
			Protocol: layers.IPProtocolTCP,
			Version:  4,
		}

		tcp := &layers.TCP{
			SrcPort: tcpHeader.DstPort,
			DstPort: tcpHeader.SrcPort,
			SYN:     true,
			ACK:     true,
			Seq:     conn.send.iss,
			Ack:     conn.recv.nxt,
			Window:  conn.send.wnd,
		}
		tcp.SetNetworkLayerForChecksum(ip)

		return sendPacket(ip, tcp, nic)

	case SynRcvd:
		log.Println("TODO")
	}

	return nil
}

// TODO: Dont expose `nic` directly to this package
func sendPacket(ipHeader *layers.IPv4, tcpHeader *layers.TCP, nic *water.Interface) error {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, ipHeader, tcpHeader)
	if err != nil {
		return err
	}

	_, err = nic.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}
