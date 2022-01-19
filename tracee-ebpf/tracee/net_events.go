package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
	"time"

	"github.com/google/gopacket"
	"inet.af/netaddr"
)

type PktMeta struct {
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
	metaData  PktMeta `json:"meta_data"`
}

func (t Tracee) parsePacketMetaData(payload *bytes.Buffer) (PktMeta, error, uint32, int) {
	var pktMetaData PktMeta
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

func isIpv6(ip [16]byte) bool {
	zeroedPattern := make([]byte, 9, 9)
	if bytes.Compare(ip[:9], zeroedPattern) == 0 {
		return false
	}
	return true
}
func createNetworkArgs(packetmeta PktMeta) []external.Argument {
	eventArgs := make([]external.Argument, 0, 0)
	if isIpv6(packetmeta.SrcIP) {
		eventArgs = append(eventArgs, external.Argument{
			ArgMeta: external.ArgMeta{"src_ip", "string"},
			Value:   netaddr.IPFrom16(packetmeta.SrcIP).String(),
		})
	} else {
		var ip [4]byte
		copy(ip[:], packetmeta.SrcIP[12:])
		eventArgs = append(eventArgs, external.Argument{
			ArgMeta: external.ArgMeta{"src_ip", "string"},
			Value:   netaddr.IPFrom4(ip).String(),
		})
	}
	if isIpv6(packetmeta.DestIP) {
		eventArgs = append(eventArgs, external.Argument{
			ArgMeta: external.ArgMeta{"dst_ip", "string"},
			Value:   netaddr.IPFrom16(packetmeta.DestIP).String(),
		})
	} else {
		var ip [4]byte
		copy(ip[:], packetmeta.SrcIP[12:])
		eventArgs = append(eventArgs, external.Argument{
			ArgMeta: external.ArgMeta{"dst_ip", "string"},
			Value:   netaddr.IPFrom4(ip).String(),
		})
	}
	eventArgs = append(eventArgs, external.Argument{
		ArgMeta: external.ArgMeta{"src_port", "uint16"},
		Value:   packetmeta.SrcPort,
	})
	eventArgs = append(eventArgs, external.Argument{
		ArgMeta: external.ArgMeta{"dest_port", "uint16"},
		Value:   packetmeta.DestPort,
	})
	eventArgs = append(eventArgs, external.Argument{
		ArgMeta: external.ArgMeta{"protocol", "uint8"},
		Value:   packetmeta.Protocol,
	})

	return eventArgs
}
func createNetEvent(ts int, hostTid uint32, processName string, eventId int32, eventName string, meta PktMeta) external.Event {
	args := createNetworkArgs(meta)
	evt := external.Event{
		Timestamp:           ts,
		ProcessID:           int(0),
		ThreadID:            int(0),
		ParentProcessID:     int(0),
		HostProcessID:       int(0),
		HostThreadID:        int(0),
		HostParentProcessID: int(0),
		UserID:              int(0),
		MountNS:             int(0),
		PIDNS:               int(0),
		ProcessName:         processName,
		HostName:            "string(bytes.TrimRight(ctx.UtsName[:], ))",
		ContainerID:         "0",
		EventID:             int(eventId),
		EventName:           eventName,
		ArgsNum:             len(args),
		ReturnValue:         int(0),
		Args:                args,
		StackAddresses:      make([]uint64, 0, 0),
	}
	return evt
}
func (t *Tracee) processNetEvents() {
	// Todo: split pcap files by context (tid + comm)
	// Todo: add stats for network packets (in epilog)
	for {
		select {
		case in := <-t.netChannel:
			// Sanity check - timestamp, event id, host tid and processName must exist in all net events
			if len(in) < 32 {
				continue
			}

			timeStamp := binary.LittleEndian.Uint64(in[0:8])
			netEventId := int32(binary.LittleEndian.Uint32(in[8:12]))
			hostTid := binary.LittleEndian.Uint32(in[12:16])
			processName := string(bytes.TrimRight(in[16:32], "\x00"))
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
					evt := createNetEvent(int(timeStamp+t.bootTime), hostTid, processName, netEventId, "net_packet", netPacket)
					t.config.ChanEvents <- evt
					t.stats.eventCounter.Increment()
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
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpSendmsg:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_sendmsg          LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDisconnect:
					fmt.Printf("%v  %-16s  %-7d  debug_net/__udp_disconnect     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpDestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udp_destroy_sock     LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetUdpV6DestroySock:
					fmt.Printf("%v  %-16s  %-7d  debug_net/udpv6_destroy_sock   LocalIP: %v, LocalPort: %d, Protocol: %d\n",
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				case DebugNetInetSockSetState:
					fmt.Printf("%v  %-16s  %-7d  debug_net/inet_sock_set_state  LocalIP: %v, LocalPort: %d, RemoteIP: %v, RemotePort: %d, Protocol: %d, OldState: %d, NewState: %d, SockPtr: 0x%x\n",
						timeStampObj,
						processName,
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
						timeStampObj, processName, hostTid, netaddr.IPFrom16(pkt.LocalIP), pkt.LocalPort, pkt.Protocol)
				}
			}
		case lost := <-t.lostNetChannel:
			t.stats.lostNtCounter.Increment(int(lost))
		}
	}
}
