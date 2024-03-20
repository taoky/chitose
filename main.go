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

	"github.com/dustin/go-humanize"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type InterfaceInfo struct {
	MAC net.HardwareAddr
	IPs []net.IP
}

var sizeStats map[string]uint64
var statLock sync.Mutex

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
	statLock.Lock()
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
	for i := 0; i < top; i++ {
		key := keys[i]
		total := sizeStats[key]
		fmt.Printf("%s: %s\n", key, humanize.Bytes(total))
	}
	statLock.Unlock()
}

func printStats() {
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
		if out {
			var destIP netip.Addr
			len := 0
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				destIP, _ = netip.AddrFromSlice(ip.DstIP)
				len = int(ip.Length) + 40
			}
			if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv6)
				destIP, _ = netip.AddrFromSlice(ip.DstIP)
				len = int(ip.Length) + 40
			}
			if len == 0 {
				continue
			}
			destIPPrefix := getIPPrefixString(destIP)
			// log.Printf("Outbound packet to %s, %d bytes\n", destIP, len)
			statLock.Lock()
			sizeStats[destIPPrefix] += uint64(len)
			statLock.Unlock()
		}
	}
}

func main() {
	sizeStats = make(map[string]uint64)
	iface := flag.String("i", "eth0", "Interface to listen on")
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
