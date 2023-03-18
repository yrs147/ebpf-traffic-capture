package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/libbpfgo"
)

const (
	HTTP_FILTER_PATH = "/sys/fs/bpf/http_filter"
)

func main() {
	// Start API server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})

	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			panic(err)
		}
	}()

	fmt.Println("Started API server")

	// Load eBPF program
	obj, err := libbpfgo.NewModuleFromFile(HTTP_FILTER_PATH)
	if err != nil {
		panic(err)
	}
	defer obj.Close()

	prog, err := obj.LoadXDP("http_filter", libbpfgo.XDPFlags{})
	if err != nil {
		panic(err)
	}

	// Create perf map
	perfMap, err := libbpfgo.InitPerfMap(prog, "http_events")
	if err != nil {
		panic(err)
	}

	// Start polling for events
	perfMap.PollStart()

	// Wait for SIGINT or SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Stopping API server")

	// Stop polling for events
	perfMap.PollStop()
}
