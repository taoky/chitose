package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type InterfaceInfo struct {
	MAC net.HardwareAddr
	IPs []net.IP
}

var noNetstat *bool
var useInbound *bool

var deltaStats map[string]uint64
var sizeStats map[string]uint64
var statLock sync.Mutex
var printTimestamp time.Time

var boldStart = "\u001b[1m"
var boldEnd = "\u001b[22m"

func getInterfaceAddrs(ifaceName string) (info InterfaceInfo, err error) {
	info = InterfaceInfo{}
	info.IPs = make([]net.IP, 0)

	ifaces, err := net.Interfaces()
	if err != nil {
		return info, err
	}
	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			info.MAC = iface.HardwareAddr

			addrs, err := iface.Addrs()
			if err != nil {
				log.Printf("Error getting addresses for interface %s: %s\n", iface.Name, err)
				continue
			}
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					info.IPs = append(info.IPs, v.IP)
				case *net.IPAddr:
					info.IPs = append(info.IPs, v.IP)
				}
			}
		}
	}
	return info, nil
}

func isOutbound(info InterfaceInfo, linkFlow gopacket.Flow, networkFlow gopacket.Flow) bool {
	if info.MAC != nil && linkFlow != (gopacket.Flow{}) {
		return linkFlow.Src().String() == info.MAC.String()
	}
	if len(info.IPs) > 0 && networkFlow != (gopacket.Flow{}) {
		for _, ip := range info.IPs {
			if networkFlow.Src().String() == ip.String() {
				return true
			}
		}
	}
	return false
}

func getIPPrefixString(ip netip.Addr) string {
	var clientPrefix netip.Prefix
	if ip.Is4() {
		clientPrefix = netip.PrefixFrom(ip, 24)
	} else {
		clientPrefix = netip.PrefixFrom(ip, 48)
	}
	clientPrefix = clientPrefix.Masked()
	return clientPrefix.String()
}

func printTopValues() {
	var keys []string
	activeConn := make(map[string]int)

	if !*noNetstat {
		// Get active connections
		tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Established
		})
		if err != nil {
			log.Printf("netstat error: %v", err)
		} else {
			for _, tab := range tabs {
				ip, ok := netip.AddrFromSlice(tab.RemoteAddr.IP)
				if !ok {
					continue
				}
				activeConn[getIPPrefixString(ip)] += 1
			}
		}
		tabs, err = netstat.TCP6Socks(func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Established
		})
		if err != nil {
			log.Printf("netstat error: %v", err)
		} else {
			for _, tab := range tabs {
				ip, ok := netip.AddrFromSlice(tab.RemoteAddr.IP)
				if !ok {
					continue
				}
				activeConn[getIPPrefixString(ip)] += 1
			}
		}
	}

	duration := time.Since(printTimestamp)
	printTimestamp = time.Now()
	statLock.Lock()
	for k, v := range deltaStats {
		sizeStats[k] += v
	}
	for k := range sizeStats {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return sizeStats[keys[i]] > sizeStats[keys[j]]
	})
	top := 10
	if len(keys) < top {
		top = len(keys)
	}

	delta := make(map[string]uint64)
	for i := 0; i < top; i++ {
		key := keys[i]
		delta[key] = deltaStats[key]
	}
	deltaStats = make(map[string]uint64)
	statLock.Unlock()

	for i := 0; i < top; i++ {
		key := keys[i]
		total := sizeStats[key]

		connection := ""
		if !*noNetstat {
			if _, ok := activeConn[key]; ok {
				activeString := fmt.Sprintf(" (active, %d)", activeConn[key])
				connection = fmt.Sprintf("%s%s%s", boldStart, activeString, boldEnd)
			}
		}

		fmt.Printf("%s%s: %s (%s/s)\n", key, connection, humanize.IBytes(total), humanize.IBytes(delta[key]/uint64(duration.Seconds())))
	}
}

func printStats() {
	printTimestamp = time.Now()
	for {
		time.Sleep(5 * time.Second)
		printTopValues()
		fmt.Println()
	}
}

func loop(info InterfaceInfo, packetSource *gopacket.PacketSource) {
	for packet := range packetSource.Packets() {
		var linkFlow gopacket.Flow
		var networkFlow gopacket.Flow
		linkLayer := packet.LinkLayer()
		if linkLayer != nil {
			linkFlow = linkLayer.LinkFlow()
		}
		networkLayer := packet.NetworkLayer()
		if networkLayer != nil {
			networkFlow = networkLayer.NetworkFlow()
		} else {
			continue
		}

		out := isOutbound(info, linkFlow, networkFlow)
		if (out && !*useInbound) || (!out && *useInbound) {
			var resIP netip.Addr
			len := 0
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				if !*useInbound {
					resIP, _ = netip.AddrFromSlice(ip.DstIP)
				} else {
					resIP, _ = netip.AddrFromSlice(ip.SrcIP)
				}
				len = int(ip.Length) + 40
			}
			if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv6)
				if !*useInbound {
					resIP, _ = netip.AddrFromSlice(ip.DstIP)
				} else {
					resIP, _ = netip.AddrFromSlice(ip.SrcIP)
				}
				len = int(ip.Length) + 40
			}
			if len == 0 {
				continue
			}
			resIPPrefix := getIPPrefixString(resIP)
			// log.Printf("Outbound packet to %s, %d bytes\n", destIP, len)
			statLock.Lock()
			deltaStats[resIPPrefix] += uint64(len)
			statLock.Unlock()
		}
	}
}

func main() {
	deltaStats = make(map[string]uint64)
	sizeStats = make(map[string]uint64)
	iface := flag.String("i", "eth0", "Interface to listen on")
	noNetstat = flag.Bool("no-netstat", false, "Do not detect active connections")
	useInbound = flag.Bool("inbound", false, "Show inbound traffic instead of outbound")
	flag.Parse()

	handle, err := pcap.OpenLive(*iface, 72, false, 1000)
	if err != nil {
		log.Fatal(err)
	}

	ifaceInfo, err := getInterfaceAddrs(*iface)
	if err != nil {
		log.Fatal(err)
	}
	if ifaceInfo.MAC != nil {
		log.Printf("MAC: %s\n", ifaceInfo.MAC)
	}
	for _, ip := range ifaceInfo.IPs {
		log.Printf("IP: %s\n", ip)
	}

	linkType := handle.LinkType()
	log.Printf("Handle link type: %s (%d)\n", linkType.String(), linkType)

	packetSource := gopacket.NewPacketSource(handle, linkType)
	// totalBytes := 0

	fmt.Println("Starting...")
	go printStats()
	loop(ifaceInfo, packetSource)
}
