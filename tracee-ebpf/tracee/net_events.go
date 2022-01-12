package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"strconv"
	"time"

	"github.com/google/gopacket"
	irc "gopkg.in/sorcix/irc.v2"
	"inet.af/netaddr"
)

var ircParamMaxLen = 15
var ircCommandMaxLen = 50
var ircCommands = map[string]bool{
	"PASS":     true,
	"NICK":     true,
	"USER":     true,
	"OPER":     true,
	"MODE":     true,
	"SERVICE":  true,
	"QUIT":     true,
	"SQUIT":    true,
	"JOIN":     true,
	"PART":     true,
	"TOPIC":    true,
	"NAMES":    true,
	"LIST":     true,
	"INVITE":   true,
	"KICK":     true,
	"PRIVMSG":  true,
	"NOTICE":   true,
	"MOTD":     true,
	"LUSERS":   true,
	"VERSION":  true,
	"STATS":    true,
	"LINKS":    true,
	"TIME":     true,
	"CONNECT":  true,
	"TRACE":    true,
	"ADMIN":    true,
	"INFO":     true,
	"SERVLIST": true,
	"SQUERY":   true,
	"WHO":      true,
	"WHOIS":    true,
	"WHOWAS":   true,
	"KILL":     true,
	"PING":     true,
	"PONG":     true,
	"ERROR":    true,
	"AWAY":     true,
	"REHASH":   true,
	"DIE":      true,
	"RESTART":  true,
	"SUMMON":   true,
	"USERS":    true,
	"WALLOPS":  true,
	"USERHOST": true,
	"ISON":     true,
	"SERVER":   true,
	"NJOIN":    true,
	"CAP":      true,
}

func isASCII(s string) bool {
	for _, c := range s {
		if c > 127 {
			return false
		}
	}
	return true
}
func analyzeLayerTypeIRC(ircMessage *irc.Message) (string, []string) {
	fmt.Println(1)
	// check: 1) command len <=50. 2) command is ascii. 3) no more than 15 parameters
	if len(ircMessage.Command) <= ircCommandMaxLen && isASCII(ircMessage.Command) && len(ircMessage.Params) <= ircParamMaxLen {
		// check if params are ascii, this condition is a bit demanding so it's inside.
		fmt.Println(2, ircMessage.Command)

		_, err := strconv.Atoi(ircMessage.Command)
		if isASCII(ircMessage.Params[0]) && (ircCommands[ircMessage.Command] || err == nil) {
			//fmt.Println(3)
			//fmt.Printf("IRC detected!\nCommand: %v, Parameters: \n", ircMessage.Command)
			//for idx, param := range ircMessage.Params {
			//	fmt.Printf("param [%d]: %v\n", idx, param)
			//}
			return ircMessage.Command, ircMessage.Params
		}
	}
	return "", nil
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
			if netEventId == NetPacketIrc {
				//raw := bytes()

				//fmt.Println("potensial IRC: ", string(dataBuff.Bytes()[114:]))
				//fmt.Println("potensial IRC: ", dataBuff.Bytes()[114:])
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
				_, ok := t.ngIfacesIndex[int(ifindex)]
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
					packet := gopacket.NewPacket(dataBuff.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
					//fmt.Println(packet)
					//fmt.Println(in[32:])
					// Get the TCP layer from this packet
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						//fmt.Println("This is a TCP packet!")
						// Get actual TCP data from this layer
						tcp, _ := tcpLayer.(*layers.TCP)
						//fmt.Println("potensial IRC: ", tcp.Payload)
						//fmt.Println("potensial IRC: ", dataBuff.Bytes()[114:])
						if len(tcp.Payload) > 0 {
							message := irc.ParseMessage(string(tcp.Payload))
							cmd, params := analyzeLayerTypeIRC(message)
							fmt.Printf("%v  %-16s  %-7d  IRC_PACKET               Len: %d, SrcIP: %v, SrcPort: %d, DestIP: %v, DestPort: %d, Protocol: %d, cmd: %v, parms: %v\n",
								timeStampObj,
								comm,
								hostTid,
								pktLen,
								netaddr.IPFrom16(pktMeta.SrcIP),
								pktMeta.SrcPort,
								netaddr.IPFrom16(pktMeta.DestIP),
								pktMeta.DestPort,
								pktMeta.Protocol,
								cmd,
								params)
						}

					}

				}
			}
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
