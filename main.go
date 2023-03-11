package main

import(
	"bytes"
	"encoding"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
	"log"
	"of"
)

type exec_data_t struct {
	Pid uint32
	F_name [32]byte
	Comm [32]byte
}

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		$unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
			
		}); err !=nil {
			log.Fatalf("Failed to set temporary rlimit: %v", err)
		}
}

func main() {
	setlimit()

	objs := gen_execveObjects{}

	loadGen_execveObjects(&objs, nil)
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err")
	}

	for {
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}

		if ev.LostDamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		b_arr := bytes.NewBuffer(ev.RawSample)

		var data exec_data_t
		if err := binary.Read(b_arr, binary.LittleEndian. &data){
			log.Printf("parsing perf event: %s",err)
			continue
		}

		fmt.Printf("On cpu %02d %s ran : %d %s \n",
			ev.CPU, data.Comm, data.Pid, data.F_name )
	}

}