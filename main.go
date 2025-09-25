package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Config structure matching the C struct
type Config struct {
	TargetPort uint32
	Enabled    uint32
}

// PortKey structure matching the C struct
type PortKey struct {
	Port uint32
}

// PortValue structure matching the C struct
type PortValue struct {
	PacketCount uint64
	DropCount   uint64
}

func main() {
	var (
		ifaceName  = flag.String("iface", "", "Network interface to attach to (required)")
		targetPort = flag.Uint("port", 4040, "TCP port to drop packets for")
		statsInterval = flag.Duration("stats", 5*time.Second, "Statistics display interval")
	)
	flag.Parse()

	if *ifaceName == "" {
		fmt.Println("Usage: tcp-port-dropper -iface <interface> [-port <port>] [-stats <interval>]")
		fmt.Println("Example: sudo ./tcp-port-dropper -iface eth0 -port 4040")
		os.Exit(1)
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("tcp_drop.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Get network interface
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", *ifaceName, err)
	}

	// Attach XDP program to interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["tcp_port_drop"],
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()

	// Configure the target port
	configKey := uint32(0)
	config := Config{
		TargetPort: uint32(*targetPort),
		Enabled:    1,
	}

	if err := coll.Maps["config_map"].Put(&configKey, &config); err != nil {
		log.Fatalf("Failed to update config map: %v", err)
	}

	fmt.Printf("eBPF TCP port dropper loaded successfully!\n")
	fmt.Printf("Interface: %s\n", *ifaceName)
	fmt.Printf("Target port: %d\n", *targetPort)
	fmt.Printf("Press Ctrl+C to stop...\n\n")

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Statistics ticker
	ticker := time.NewTicker(*statsInterval)
	defer ticker.Stop()

	// Main loop
	for {
		select {
		case <-sigChan:
			fmt.Println("\nShutting down...")
			return
		case <-ticker.C:
			printStats(coll.Maps["port_stats"], uint32(*targetPort))
		}
	}
}

func printStats(portStatsMap *ebpf.Map, targetPort uint32) {
	fmt.Printf("\n=== TCP Port Statistics (%s) ===\n", time.Now().Format("15:04:05"))
	fmt.Printf("%-8s %-12s %-12s %-8s\n", "Port", "Packets", "Dropped", "Drop%")
	fmt.Println(repeatString("-", 45))

	// Iterate through all entries in the map
	var key PortKey
	var value PortValue
	iter := portStatsMap.Iterate()

	totalPackets := uint64(0)
	totalDropped := uint64(0)
	targetFound := false

	for iter.Next(&key, &value) {
		dropPercent := float64(0)
		if value.PacketCount > 0 {
			dropPercent = float64(value.DropCount) / float64(value.PacketCount) * 100
		}

		status := ""
		if key.Port == targetPort {
			status = " (TARGET)"
			targetFound = true
		}

		fmt.Printf("%-8d %-12d %-12d %6.1f%%%-s\n", 
			key.Port, value.PacketCount, value.DropCount, dropPercent, status)

		totalPackets += value.PacketCount
		totalDropped += value.DropCount
	}

	if err := iter.Err(); err != nil {
		log.Printf("Error iterating map: %v", err)
		return
	}

	fmt.Println(repeatString("-", 45))
	totalDropPercent := float64(0)
	if totalPackets > 0 {
		totalDropPercent = float64(totalDropped) / float64(totalPackets) * 100
	}
	fmt.Printf("%-8s %-12d %-12d %6.1f%%\n", "TOTAL", totalPackets, totalDropped, totalDropPercent)

	if !targetFound && totalPackets > 0 {
		fmt.Printf("Note: No packets seen on target port %d yet\n", targetPort)
	}
}

// Helper function for repeating strings
func repeatString(s string, count int) string {
	if count <= 0 {
		return ""
	}
	result := make([]byte, len(s)*count)
	copy(result, s)
	for i := len(s); i < len(result); i *= 2 {
		copy(result[i:], result[:i])
	}
	return string(result)
}
