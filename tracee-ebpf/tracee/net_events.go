package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	pktLen    int     `json:"pkt_len"`
	metaData  pktMeta `json:"meta_data"`
}
type DnsRequestPacketData struct {
	netData    NetPacketData `json:"netData"`
	query      string        `json:"query"`
	queryType  string        `json:"queryType"`
	queryclass string        `json:"queryclass"`
}
type DnsAnswerData struct {
	number      int    `json:"number"`
	answerType  string `json:"answer_type"`
	answerClass string `json:"answer_class"`
	recordName  string `json:"record_name"`
	ttl         int    `json:"ttl"`
}
type DnsResponsePacketData struct {
	netData   NetPacketData   `json:"net_data"`
	queryData []DnsAnswerData `json:"query_data"`
}

func parsePacketMetaData(payload []byte) (pktMeta, error) {
	var pktMetaData pktMeta
	payloadReader := bytes.NewReader(payload)
	err := binary.Read(payloadReader, binary.LittleEndian, &pktMetaData)
	if err != nil {
		return pktMetaData, err
	}
	return pktMetaData, nil
}
func parseNetPacketData(payload []byte) (NetPacketData, error) {
	var pktData NetPacketData
	//payloadReader := bytes.NewBuffer(payload)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &payload)
	timeStamp := binary.LittleEndian.Uint64(payload[0:8])
	hostTid := binary.LittleEndian.Uint32(payload[12:16])
	comm := string(bytes.TrimRight(payload[16:32], "\x00"))
	pktData.timestamp = timeStamp
	pktData.hostTid = hostTid
	pktData.comm = comm
	var pktLen int
	err := binary.Read(bytes.NewBuffer(payload), binary.LittleEndian, &pktLen)
	if err != nil {
		return pktData, err
	}
	pktData.pktLen = pktLen
	pktMeta, err := parsePacketMetaData(payload)
	if err != nil {
		return pktData, err
	}
	pktData.metaData = pktMeta
	return pktData, nil
}
func parseDnsAnswerData(payload []byte) (DnsAnswerData, error) {
	var dnsAnswer DnsAnswerData
	var err error = nil

	return dnsAnswer, err
}

func parseDnsRequestPacket(payload []byte) (DnsRequestPacketData, error) {
	var request DnsRequestPacketData
	var err error = nil
	request.netData, err = parseNetPacketData(payload)
	if err != nil {
		return request, err
	}
	question, idx := ParseDnsQuestion(payload)
	if idx == 0 {
		return DnsRequestPacketData{}, fmt.Errorf("Error in ParseDnsQuestion")
	}
	request.query = question[0]
	request.queryType = question[1]
	request.queryclass = question[2]
	return request, nil
}

func ParseDnsRequestDomain(payload []byte) string {
	for idx, val := range payload {
		if int16(val) < 32 && idx != 0 {
			payload[idx] = byte('.')
		}
	}
	return string(payload)
}

//we asumme the payload is the start of the name and then we parse the name, class , type
func ParseDnsQuestion(payload []byte) ([3]string, int32) {

	queryData := [3]string{"", "Unknown", "Unknown"} //name, type, class
	for idx, val := range payload {
		if val == 0 || val == 0xc0 {
			if val == 0xc0 {
				idx++
			} else if payload[idx+1] == 0xc0 {
				idx += 2
				queryData[0] = "prev"
			} else {
				if idx != 0 {
					queryData[0] = ParseDnsRequestDomain(payload[1:idx])
				}
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
				var pktLen uint32
				err := binary.Read(dataBuff, binary.LittleEndian, &pktLen)
				if err != nil {
					t.handleError(err)
					continue
				}
				var ifindex uint32
				err = binary.Read(dataBuff, binary.LittleEndian, &ifindex)
				if err != nil {
					t.handleError(err)
					continue
				}
				idx, ok := t.ngIfacesIndex[int(ifindex)]
				if !ok {
					t.handleError(err)
					continue
				}

				if t.config.Debug {
					var pktMeta struct {
						SrcIP    [16]byte
						DestIP   [16]byte
						SrcPort  uint16
						DestPort uint16
						Protocol uint8
						_        [3]byte //padding
					}
					err = binary.Read(dataBuff, binary.LittleEndian, &pktMeta)
					if err != nil {
						t.handleError(err)
						continue
					}

					fmt.Printf("%v  %-16s  %-7d  debug_net/packet               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d\n",
						timeStampObj,
						comm,
						hostTid,
						pktLen,
						netaddr.IPFrom16(pktMeta.SrcIP),
						pktMeta.SrcPort,
						netaddr.IPFrom16(pktMeta.DestIP),
						pktMeta.DestPort,
						pktMeta.Protocol)
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
				//payload := dataBuff.Bytes()
				request, err := parseDnsRequestPacket(in[32:])
				if err != nil {
					fmt.Println("error  netEventId == NetDnsRequest")
					fmt.Println(err)
				}
				fmt.Println("\n\n", request)
				//var pktMeta struct {
				//	SrcIP    [16]byte
				//	DestIP   [16]byte
				//	SrcPort  uint16
				//	DestPort uint16
				//	Protocol uint8
				//	_        [3]byte //padding
				//}
				//var pktLen uint32
				//err := binary.Read(dataBuff, binary.LittleEndian, &pktLen)
				//if err != nil {
				//	t.handleError(err)
				//	continue
				//}
				//var ifindex uint32
				//err = binary.Read(dataBuff, binary.LittleEndian, &ifindex)
				//if err != nil {
				//	t.handleError(err)
				//	continue
				//}
				//
				//err = binary.Read(dataBuff, binary.LittleEndian, &pktMeta)
				//if err != nil {
				//	t.handleError(err)
				//	continue
				//}
				//
				//dataBytes := dataBuff.Bytes()
				//for _ = range dataBytes {
				//	if dataBytes[len(dataBytes)-1] == 0 {
				//		dataBytes = dataBytes[:len(dataBytes)-1]
				//	} else {
				//		break
				//	}
				//}
				//requestMetaDeta, _ := P(dataBytes[len(dataBytes)-28:])
				//
				//fmt.Printf("%v  %-16s  %-7d  net_events/dns_request               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, Query: %s, Type: %s , Class %s \n",
				//	timeStampObj,
				//	comm,
				//	hostTid,
				//	pktLen,
				//	netaddr.IPFrom16(pktMeta.SrcIP),
				//	pktMeta.SrcPort,
				//	netaddr.IPFrom16(pktMeta.DestIP),
				//	pktMeta.DestPort,
				//	pktMeta.Protocol,
				//	requestMetaDeta[0],
				//	requestMetaDeta[1],
				//	requestMetaDeta[2])

			} else if netEventId == NetDnsResponse {
				var pktMeta struct {
					SrcIP    [16]byte
					DestIP   [16]byte
					SrcPort  uint16
					DestPort uint16
					Protocol uint8
					_        [3]byte //padding
				}
				var pktLen uint32
				err := binary.Read(dataBuff, binary.LittleEndian, &pktLen)
				if err != nil {
					t.handleError(err)
					continue
				}
				var ifindex uint32
				err = binary.Read(dataBuff, binary.LittleEndian, &ifindex)
				if err != nil {
					t.handleError(err)
					continue
				}

				err = binary.Read(dataBuff, binary.LittleEndian, &pktMeta)
				if err != nil {
					t.handleError(err)
					continue
				}

				dataBytes := dataBuff.Bytes()
				for _ = range dataBytes {
					if dataBytes[len(dataBytes)-1] == 0 {
						dataBytes = dataBytes[:len(dataBytes)-1]
					} else {
						break
					}
				}
				ansNumber := int(dataBytes[49])
				//parse query metadata
				queryData, offset := ParseDnsQuestion(dataBytes[54:])

				offset += 54
				//loop over the response answers
				for i := 0; i < ansNumber; i++ {
					ansMetaData, ansOffset := ParseDnsQuestion(dataBytes[offset:])
					offset += ansOffset
					if ansMetaData[0] == "prev" {
						ansMetaData[0] = queryData[0]
					}
					TTL := int32(binary.BigEndian.Uint32(dataBytes[offset+1 : offset+5]))
					fmt.Printf("ttl is %d\n", TTL)

					dataLen := binary.BigEndian.Uint16(dataBytes[offset+5 : offset+7])

					addr := netaddr.IP{}
					nameRecord := ""
					switch ansMetaData[1] {
					case "CNAME":
						nameRecord = string(dataBytes[offset+7 : offset+7+(int32(dataLen))])
						//fmt.Printf("name record is %s\n", nameRecod)
					case "A (IPv4)":
						responseAddr := [4]byte{0}
						copy(responseAddr[:], dataBytes[offset+7:offset+11])
						addr = netaddr.IPFrom4(responseAddr)
						//fmt.Printf("IPv4 is %v\n", addr)
					case "AAAA (IPv6)":
						responseAddr := [16]byte{0}
						copy(responseAddr[:], dataBytes[offset+7:offset+23])
						addr = netaddr.IPFrom16(responseAddr)
						//fmt.Printf("IPv6 is %v\n", addr)
					}
					if ansMetaData[1] == "CNAME" {
						fmt.Printf("%v  %-16s  %-7d  net_event/dns_response               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, Query: %s, Type: %s , Class: %s, Answer[%d]: Name:%v, Type: %v, Class: %v, record_name: %s, TTL: %v\n",
							timeStampObj,
							comm,
							hostTid,
							pktLen,
							netaddr.IPFrom16(pktMeta.SrcIP),
							pktMeta.SrcPort,
							netaddr.IPFrom16(pktMeta.DestIP),
							pktMeta.DestPort,
							pktMeta.Protocol,
							queryData[0],
							queryData[1],
							queryData[2],
							i+1,
							ansMetaData[0],
							ansMetaData[1],
							ansMetaData[2],
							nameRecord,
							TTL)
						//fmt.Printf("dns_response: Name:%v, Type: %v, Class: %v, Address: %v, TTL: %v, addr: %-16s\n",ansMetaData[0],ansMetaData[1],ansMetaData[2],0,TTL, nameRecord )

					} else {
						fmt.Printf("%v  %-16s  %-7d  net_event/dns_response               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, Query: %s, Type: %s , Class: %s, Answer[%d]: Name:%v, Type: %v, Class: %v, Address: %-16s, TTL: %v\n",
							timeStampObj,
							comm,
							hostTid,
							pktLen,
							netaddr.IPFrom16(pktMeta.SrcIP),
							pktMeta.SrcPort,
							netaddr.IPFrom16(pktMeta.DestIP),
							pktMeta.DestPort,
							pktMeta.Protocol,
							queryData[0],
							queryData[1],
							queryData[2],
							i+1,
							ansMetaData[0],
							ansMetaData[1],
							ansMetaData[2],
							addr,
							TTL)
					}
					offset += int32(dataLen + 7)

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
