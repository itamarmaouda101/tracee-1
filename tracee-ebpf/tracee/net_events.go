package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"time"

	"github.com/google/gopacket"
	"inet.af/netaddr"
)

type pktMeta struct {
	SrcIP    [16]byte `json:"src_ip"`
	DestIP   [16]byte `json:"dest_ip"`
	SrcPort  uint16   `json:"src_port"`
	DestPort uint16   `json:"dest_port"`
	Protocol uint8    `json:"protocol"`
	_        [3]byte  //padding
}

type NetPacketData struct {
	timestamp uint64  `json:"time_stamp"`
	comm      string  `json:"comm"`
	hostTid   uint32  `json:"host_tid"`
	pktLen    uint32  `json:"pkt_len"`
	metaData  pktMeta `json:"meta_data"`
}
type DnsQueryData struct {
	query      string `json:"query"`
	queryType  string `json:"queryType"`
	queryClass string `json:"queryclass"`
}

type DnsRequestPacketData struct {
	netData NetPacketData `json:"netData"`
	Query   DnsQueryData  `json:"query"`
}

type DnsAnswerData struct {
	name        string   `json:"name"`
	answerType  string   `json:"answer_type"`
	answerClass string   `json:"answer_class"`
	ttl         int      `json:"ttl"`
	recordName  string   `json:"record_name"`
	ip4         [4]byte  `json:"ip"`
	ip6         [16]byte `json:"ip"`
}
type DnsResponsePacketData struct {
	netData    NetPacketData `json:"net_data"`
	answerData DnsAnswerData `json:"answer_data"`
}

func cutEndNullbytes(dataBytes []byte) []byte {
	for _ = range dataBytes {
		if dataBytes[len(dataBytes)-1] == 0 {
			dataBytes = dataBytes[:len(dataBytes)-1]
		} else {
			break
		}
	}
	return dataBytes
}

func DnsPaseName(payload []byte) string {
	for idx, val := range payload {
		if int16(val) < 32 && idx != 0 {
			payload[idx] = byte('.')
		}
	}
	return string(payload)
}

func parseDnsResponseData(dataBytes []byte, offset uint32, queryAsked string) (DnsResponsePacketData, uint32) {
	var dnsResponsePacket DnsResponsePacketData
	ansMetaData, ansOffset := ParseDnsMetaData(dataBytes[offset:])
	if ansMetaData[0] == "prev" {
		ansMetaData[0] = queryAsked
	}
	dnsResponsePacket.answerData.name = ansMetaData[0]
	offset += uint32(ansOffset)

	answerTtl := int32(binary.BigEndian.Uint32(dataBytes[offset+1 : offset+5]))
	dataLen := uint32(binary.BigEndian.Uint16(dataBytes[offset+5 : offset+7]))
	dnsResponsePacket.answerData.ttl = int(answerTtl)
	switch ansMetaData[1] {
	case "CNAME":
		dnsResponsePacket.answerData.recordName = DnsPaseName(dataBytes[offset+7 : uint32(offset+6+(uint32(dataLen)))])
	case "A (IPv4)":
		responseAddr := [4]byte{0}
		copy(responseAddr[:], dataBytes[offset+7:offset+11])
		dnsResponsePacket.answerData.ip4 = responseAddr
	case "AAAA (IPv6)":
		responseAddr := [16]byte{0}
		copy(responseAddr[:], dataBytes[offset+7:offset+23])
		dnsResponsePacket.answerData.ip6 = responseAddr

	}

	dnsResponsePacket.answerData.answerType = ansMetaData[1]
	dnsResponsePacket.answerData.answerClass = ansMetaData[2]
	return dnsResponsePacket, dataLen + uint32(ansOffset)
}
func (t Tracee) parsePacketMetaData(payload *bytes.Buffer) (pktMeta, error, uint32, int) {
	var pktMetaData pktMeta
	var pktLen uint32

	err := binary.Read(payload, binary.LittleEndian, &pktLen)
	if err != nil {
		return pktMetaData, err, 0, 0
	}
	var ifindex uint32
	err = binary.Read(payload, binary.LittleEndian, &ifindex)
	if err != nil {
		return pktMetaData, err, 0, 0
	}
	interfaceIndex, ok := t.ngIfacesIndex[int(ifindex)]
	if !ok {
		return pktMetaData, err, 0, 0
	}
	err = binary.Read(payload, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err, 0, 0
	}
	return pktMetaData, nil, pktLen, interfaceIndex
}

//asumme we get the payload as the start of the name and then we parse the name, class , type
func ParseDnsMetaData(payload []byte) ([3]string, int32) {
	queryData := [3]string{"", "Unknown", "Unknown"} //name, type, class
	for idx, val := range payload {
		if val == 0 || val == 0xc0 {
			if val == 0xc0 {
				queryData[0] = "prev"
				idx++
			} else if payload[idx+1] == 0xc0 {
				idx += 2
				queryData[0] = "prev"
			} else {
				queryData[0] = DnsPaseName(payload[0:idx])

			}
			dataTypeB := payload[idx+2]
			dataClassB := payload[idx+4]
			switch dataClassB {
			case 0:
				queryData[2] = "Reserved"
			case 1:
				queryData[2] = "IN"
			case 2:
				queryData[2] = "Unassigned"
			case 3:
				queryData[2] = "CH"
			case 4:
				queryData[2] = "HS"
			}
			switch dataTypeB {
			case 1:
				queryData[1] = "A (IPv4)"

			case 28:
				queryData[1] = "AAAA (IPv6)"
			case 16:
				queryData[1] = "TXT"
			case 33:
				queryData[1] = "SRV (location of service)"
			case 5:
				queryData[1] = "CNAME"
			case 15:
				queryData[1] = "MX"
			case 2:
				queryData[2] = "NS"

			}
			return queryData, int32(idx + 4)
		}

	}
	return queryData, 0
}
func (t *Tracee) processNetEvents() {
	// Todo: split pcap files by context (tid + comm)
	// Todo: add stats for network packets (in epilog)
	for {
		select {
		case in := <-t.netChannel:
			// Sanity check - timestamp, event id, host tid and comm must exist in all net events
			if len(in) < 32 {
				continue
			}

			timeStamp := binary.LittleEndian.Uint64(in[0:8])
			netEventId := binary.LittleEndian.Uint32(in[8:12])
			hostTid := binary.LittleEndian.Uint32(in[12:16])
			comm := string(bytes.TrimRight(in[16:32], "\x00"))
			dataBuff := bytes.NewBuffer(in[32:])

			// timeStamp is nanoseconds since system boot time
			timeStampObj := time.Unix(0, int64(timeStamp+t.bootTime))

			if netEventId == NetPacket {
				netPacket, err, pktLen, idx := t.parsePacketMetaData(dataBuff)
				if err != nil {
					t.handleError(err)
					continue
				}
				if t.config.Debug {
					fmt.Printf("%v  %-16s  %-7d  debug_net/packet               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d\n",
						timeStampObj,
						comm,
						hostTid,
						pktLen,
						netaddr.IPFrom16(netPacket.SrcIP),
						netPacket.SrcPort,
						netaddr.IPFrom16(netPacket.DestIP),
						netPacket.DestPort,
						netPacket.Protocol)
				}

				info := gopacket.CaptureInfo{
					Timestamp:      timeStampObj,
					CaptureLength:  int(pktLen),
					Length:         int(pktLen),
					InterfaceIndex: idx,
				}

				err = t.pcapWriter.WritePacket(info, dataBuff.Bytes()[:pktLen])
				if err != nil {
					t.handleError(err)
					continue
				}

				// todo: maybe we should not flush every packet?
				err = t.pcapWriter.Flush()
				if err != nil {
					t.handleError(err)
					continue
				}
			} else if netEventId == NetDnsRequest {
				netPacket, err, pktLen, _ := t.parsePacketMetaData(dataBuff)
				if err != nil {
					t.handleError(err)
					continue
				}

				dataBytes := dataBuff.Bytes()
				packet := gopacket.NewPacket(dataBytes, layers.LayerTypeEthernet, gopacket.Lazy)
				dnsPacket := packet.Layer(layers.LayerTypeDNS)
				requestMetaData, _ := ParseDnsMetaData(dnsPacket.LayerContents()[12:])
				fmt.Printf("%v  %-16s  %-7d  net_events/dns_request               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, Query: %s, Type: %s , Class %s \n",
					timeStampObj,
					comm,
					hostTid,
					pktLen,
					netaddr.IPFrom16(netPacket.SrcIP),
					netPacket.SrcPort,
					netaddr.IPFrom16(netPacket.DestIP),
					netPacket.DestPort,
					netPacket.Protocol,
					requestMetaData[0],
					requestMetaData[1],
					requestMetaData[2])

			} else if netEventId == NetDnsResponse {
				netPacket, err, pktLen, _ := t.parsePacketMetaData(dataBuff)
				if err != nil {
					t.handleError(err)
					continue
				}

				dataBytes := dataBuff.Bytes()
				packet := gopacket.NewPacket(dataBytes, layers.LayerTypeEthernet, gopacket.Lazy)
				dnsPacket := packet.Layer(layers.LayerTypeDNS)
				dataBytes = cutEndNullbytes(dataBytes)
				ansNumber := int(dataBytes[49])
				//parse query metadata
				queryData, offset := ParseDnsMetaData(dnsPacket.LayerContents()[12:])

				offset += 55
				//loop over the response answers
				for i := 0; i < ansNumber; i++ {
					dnsPacketData, dataLen := parseDnsResponseData(dataBytes, uint32(offset), queryData[0])
					switch dnsPacketData.answerData.answerType {
					case "CNAME":
						fmt.Printf("%v  %-16s  %-7d  net_event/dns_response               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, Query: %s, Type: %s , Class: %s, Answer[%d]: Name:%v, Type: %v, Class: %v, record_name: %s, TTL: %v\n",
							timeStampObj,
							comm,
							hostTid,
							pktLen,
							netaddr.IPFrom16(netPacket.SrcIP),
							netPacket.SrcPort,
							netaddr.IPFrom16(netPacket.DestIP),
							netPacket.DestPort,
							netPacket.Protocol,
							queryData[0],
							queryData[1],
							queryData[2],
							i+1,
							dnsPacketData.answerData.name, // need to fix that
							dnsPacketData.answerData.answerType,
							dnsPacketData.answerData.answerClass,
							dnsPacketData.answerData.recordName,
							dnsPacketData.answerData.ttl)

					case "A (IPv4)":
						fmt.Printf("%v  %-16s  %-7d  net_event/dns_response               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, Query: %s, Type: %s , Class: %s, Answer[%d]: Name:%v, Type: %v, Class: %v, Address: %v, TTL: %v\n",
							timeStampObj,
							comm,
							hostTid,
							pktLen,
							netaddr.IPFrom16(netPacket.SrcIP),
							netPacket.SrcPort,
							netaddr.IPFrom16(netPacket.DestIP),
							netPacket.DestPort,
							netPacket.Protocol,
							queryData[0],
							queryData[1],
							queryData[2],
							i+1,
							dnsPacketData.answerData.name, // need to fix that
							dnsPacketData.answerData.answerType,
							dnsPacketData.answerData.answerClass,
							netaddr.IPFrom4(dnsPacketData.answerData.ip4),
							dnsPacketData.answerData.ttl)
					case "AAAA (IPv6)":
						fmt.Printf("%v  %-16s  %-7d  net_event/dns_response               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, Query: %s, Type: %s , Class: %s, Answer[%d]: Name:%v, Type: %v, Class: %v, Address: %v, TTL: %v\n",
							timeStampObj,
							comm,
							hostTid,
							pktLen,
							netaddr.IPFrom16(netPacket.SrcIP),
							netPacket.SrcPort,
							netaddr.IPFrom16(netPacket.DestIP),
							netPacket.DestPort,
							netPacket.Protocol,
							queryData[0],
							queryData[1],
							queryData[2],
							i+1,
							dnsPacketData.answerData.name, // need to fix that
							dnsPacketData.answerData.answerType,
							dnsPacketData.answerData.answerClass,
							netaddr.IPFrom16(dnsPacketData.answerData.ip6),
							dnsPacketData.answerData.ttl)
					default:
						fmt.Println("errorr\n\n")
						fmt.Printf("string: %s", dataBytes[offset:])
						fmt.Printf("bytes: %v", dataBytes[offset:])
					}

					offset += int32(dataLen) + 7

				}

			} else if t.config.Debug {
				var pkt struct {
					LocalIP     [16]byte
					RemoteIP    [16]byte
					LocalPort   uint16
					RemotePort  uint16
					Protocol    uint8
					_           [3]byte //padding
					TcpOldState uint32
					TcpNewState uint32
					_           [4]byte //padding
					SockPtr     uint64
				}
				err := binary.Read(dataBuff, binary.LittleEndian, &pkt)
				if err != nil {
					t.handleError(err)
					continue
				}

				switch netEventId {
				case DebugNetSecurityBind:
					fmt.Printf("%v  %-16s  %-7d  debug_net/security_socket_bind LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						comm,
						hostTid,
						netaddr.IPFrom16(pkt.LocalIP),
						pkt.LocalPort,
						netaddr.IPFrom16(pkt.RemoteIP),
						pkt.RemotePort,
						pkt.Protocol,
						pkt.TcpOldState,
						pkt.TcpNewState,
						pkt.SockPtr)
				case DebugNetTcpConnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/tcp_connect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, comm, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				}
			}
		case lost := <-t.lostNetChannel:
			t.stats.lostNtCounter.Increment(int(lost))
		}
	}
}
