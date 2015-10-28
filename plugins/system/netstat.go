package system

import (
	"fmt"
	"syscall"
	"strconv"

	"github.com/influxdb/telegraf/plugins"
)

type NetStats struct {
	ps PS
	Total bool
	PerRemote bool
	RemotesAddr 	[]string
}

func (_ *NetStats) Description() string {
	return "Read metrics about TCP status such as established, time wait etc and UDP sockets counts."
}

var tcpstatSampleConfig = `
 # Decomment to not collect total metrics
 # total = false

 # Set to true to collect metrics for each remote address separately
 perRemote = false

 # Use to limit metrics collection to listed remote address
 # remotesAddr = [ "192.168.0.10:443" ]

`

func (_ *NetStats) SampleConfig() string {
	return tcpstatSampleConfig
}

func accumulate(acc plugins.Accumulator, counts map[string]int, tags map[string]string){
	acc.Add("tcp_established", counts["ESTABLISHED"], tags)
	acc.Add("tcp_syn_sent", counts["SYN_SENT"], tags)
	acc.Add("tcp_syn_recv", counts["SYN_RECV"], tags)
	acc.Add("tcp_fin_wait1", counts["FIN_WAIT1"], tags)
	acc.Add("tcp_fin_wait2", counts["FIN_WAIT2"], tags)
	acc.Add("tcp_time_wait", counts["TIME_WAIT"], tags)
	acc.Add("tcp_close", counts["CLOSE"], tags)
	acc.Add("tcp_close_wait", counts["CLOSE_WAIT"], tags)
	acc.Add("tcp_last_ack", counts["LAST_ACK"], tags)
	acc.Add("tcp_listen", counts["LISTEN"], tags)
	acc.Add("tcp_closing", counts["CLOSING"], tags)
	acc.Add("tcp_none", counts["NONE"], tags)
	acc.Add("udp_socket", counts["UDP"], tags)
}

func (s *NetStats) Gather(acc plugins.Accumulator) error {
	netconns, err := s.ps.NetConnections()
	if err != nil {
		return fmt.Errorf("error getting net connections info: %s", err)
	}

	var	counts map[string]int
	var perRemoteCounts map[string]map[string]int
	var enabledRemotes map[string]bool
	var remotesPass bool

	if s.Total {
		counts = make(map[string]int)
		counts["UDP"] = 0
	}

	if s.PerRemote {
		perRemoteCounts = make(map[string]map[string]int)
	}

	if remotesPass = s.RemotesAddr != nil; remotesPass {
		enabledRemotes = make(map[string]bool)
		for _, r := range s.RemotesAddr {
			enabledRemotes[r] = true
		}
	}

	for _, netcon := range netconns {
		target := netcon.Raddr.IP + ":" + strconv.Itoa(int(netcon.Raddr.Port))

		if s.PerRemote {

			if !remotesPass || enabledRemotes[target] {

				if _, ok := perRemoteCounts[target]; !ok {
					perRemoteCounts[target] = make(map[string]int)
				}

				if netcon.Type == syscall.SOCK_DGRAM {
					c, ok := perRemoteCounts[target]["UDP"]
					if(!ok){
						perRemoteCounts[target]["UDP"] = 0
					}
					perRemoteCounts[target]["UDP"] += c + 1
				} else {

					c, ok := perRemoteCounts[target][netcon.Status]
					if(!ok){
						perRemoteCounts[target][netcon.Status] = 0
					}
					perRemoteCounts[target][netcon.Status] = c + 1

				}
			}
		}

		if s.Total && (!remotesPass || enabledRemotes[target]) {

			if netcon.Type == syscall.SOCK_DGRAM {
				counts["UDP"] += 1
				continue // UDP has no status
			}
			c, ok := counts[netcon.Status]
			if !ok {
				counts[netcon.Status] = 0
			}
			counts[netcon.Status] = c + 1
		}


	}

	if perRemoteCounts != nil {
		for t, cs := range perRemoteCounts{
			accumulate(acc, cs, map[string]string{"remoteAddr": t})
		}
	}

	if s.Total {
			accumulate(acc, counts, map[string]string{})
	}


	return nil
}

func init() {
	plugins.Add("netstat", func() plugins.Plugin {
		return &NetStats{ps: &systemPS{}}
	})
}
