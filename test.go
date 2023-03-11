package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
)

const (
	ProgramNameHttpCapture = "http_capture"
	MapNameConnections     = "connections"
)

func main() {
	// Start the API server as a child process
	apiCmd := exec.Command("./api_server")
	apiCmd.Stdout = os.Stdout
	apiCmd.Stderr = os.Stderr
	if err := apiCmd.Start(); err != nil {
		log.Fatalf("failed to start API server: %v", err)
	}

	// Wait for the API server to start up
	if err := waitForApiServer(); err != nil {
		log.Fatalf("failed to wait for API server: %v", err)
	}

	// Load eBPF program from file
	objs, err := ebpf.LoadCollectionFromFile("http_capture.o")
	if err != nil {
		log.Fatalf("failed to load eBPF program: %v", err)
	}

	// Retrieve eBPF map from program
	connectionsMap, err := ebpf.LoadMap(objs, MapNameConnections)
	if err != nil {
		log.Fatalf("failed to load eBPF map: %v", err)
	}

	// Create a new eBPF program from the loaded objects
	httpCapture := objs.Programs[ProgramNameHttpCapture]

	// Attach the eBPF program to the kernel TCP/IP stack
	if err := httpCapture.Attach(ebpf.AttachToTCP); err != nil {
		log.Fatalf("failed to attach eBPF program: %v", err)
	}

	// Wait for the API server to exit
	if err := apiCmd.Wait(); err != nil {
		log.Fatalf("API server exited with error: %v", err)
	}

	// Iterate over all connections in the eBPF map and print the HTTP method and path
	for it := connectionsMap.Iterate(); it.Next(); {
		var hash uint32
		var data httpData
		if err := it.ReadBinary(&hash, &data); err != nil {
			log.Fatalf("failed to read connection data from eBPF map: %v", err)
		}
		fmt.Printf("PID %d: %s %s\n", data.pid, string(data.method), string(data.path[:]))
	}
}

// httpData represents the data captured by the eBPF program for an HTTP connection
type httpData struct {
	pid        uint32
	ts         uint64
	localAddr  uint32
	localPort  uint16
	remoteAddr uint32
	remotePort uint16
	bytesSent  uint64
	bytesRecv  uint64
	method     uint16
	path       [256]byte
}

// waitForApiServer waits for the API server to start up by attempting to connect to its HTTP endpoint
func waitForApiServer() error {
	url := "http://localhost:8080/healthz"
	for i := 0; i < 30; i++ {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("API server did not start up within 30 seconds")
}
