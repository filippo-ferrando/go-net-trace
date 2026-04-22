package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("50")).Underline(true)
	pidStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Width(8)
	nameStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Width(20)
	rxStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Width(15)
	txStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Width(15)
)

type procStats struct {
	PID	uint32
	Name	string
	TXRate	float64
	RXRate	float64
	Total	float64
}

type model struct {
	objs	bpfObjects
	stats	map[uint32]*procStats
	prevTotals	map[uint32]bpfTrafficStats
}

func formatSpeed(bytesPerSec float64) string {
	units := []string{"B/s", "KB/s", "MB/s", "GB/s"}
	unitIdx := 0
	for bytesPerSec >= 1024 && unitIdx < len(units)-1 {
		bytesPerSec /= 1024
		unitIdx++
	}
	return fmt.Sprintf("%.2f %s", bytesPerSec, units[unitIdx])
}

func (m model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return t
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg.(type) {
	case tea.KeyMsg:
		return m, tea.Quit
	case time.Time:
		var pid uint32
		var current bpfTrafficStats
		entries := m.objs.ProcTraffic.Iterate()

		for entries.Next(&pid, &current) {
			if _, ok := m.stats[pid]; !ok {
				m.stats[pid] = &procStats{PID: pid, Name: getProgName(pid)}
			}

			prev := m.prevTotals[pid]
			rxDelta := float64(current.RxBytes - prev.RxBytes)
			txDelta := float64(current.TxBytes - prev.TxBytes)

			m.stats[pid].RXRate = rxDelta
			m.stats[pid].TXRate = txDelta
			m.stats[pid].Total = rxDelta + txDelta

			m.prevTotals[pid] = current
		}

		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg{
			return t
		})
	}
	return m, nil
}

func (m model) View() string {
	var list []*procStats
	for _, p := range m.stats {
		list = append(list, p)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Total > list[j].Total
	})

	const (
		wPid  = 8
		wName = 20
		wTx   = 18
		wRx   = 18
	)

	s := headerStyle.Render("go-net-trace - Process Traffic") + "\n\n"
	
	hPid := lipgloss.PlaceHorizontal(wPid, lipgloss.Left, "PID")
	hName := lipgloss.PlaceHorizontal(wName, lipgloss.Left, "NAME")
	hTx := lipgloss.PlaceHorizontal(wTx, lipgloss.Left, "TX")
	hRx := lipgloss.PlaceHorizontal(wRx, lipgloss.Left, "RX")
	
	s += fmt.Sprintf("%s %s %s %s\n", hPid, hName, hTx, hRx)
	s += strings.Repeat("-", wPid+wName+wTx+wRx+3) + "\n"

	for i := 0; i < len(list) && i < 10; i++ {
		p := list[i]

		cId := lipgloss.PlaceHorizontal(wPid, lipgloss.Left, pidStyle.Render(fmt.Sprintf("%d", p.PID)))
		cName := lipgloss.PlaceHorizontal(wName, lipgloss.Left, nameStyle.Render(p.Name))
		cTx := lipgloss.PlaceHorizontal(wTx, lipgloss.Left, txStyle.Render(formatSpeed(p.TXRate)))
		cRx := lipgloss.PlaceHorizontal(wRx, lipgloss.Left, rxStyle.Render(formatSpeed(p.RXRate)))

		s += fmt.Sprintf("%s %s %s %s\n", cId, cName, cTx, cRx)
	}
	
	s += "\nPress any key to quit."
	return s
}
func getProgName(pid uint32) string {
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSpace(string(comm))
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	
	
	tcpSend, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("kprobe tcp_sendmsg: %v", err)
	}
	defer tcpSend.Close()
 
	tcpRecv, err := link.Kprobe("tcp_recvmsg", objs.KprobeTcpRecvmsg, nil)
	if err != nil {
		log.Fatalf("kprobe tcp_recvmsg: %v", err)
	}
	defer tcpRecv.Close()
 
	udpSend, err := link.Kprobe("udp_sendmsg", objs.KprobeUdpSendmsg, nil)
	if err != nil {
		log.Fatalf("kprobe udp_sendmsg: %v", err)
	}
	defer udpSend.Close()
 
	udpRecv, err := link.Kprobe("udp_recvmsg", objs.KprobeUdpRecvmsg, nil)
	if err != nil {
		log.Fatalf("kprobe udp_recvmsg: %v", err)
	}
	defer udpRecv.Close()

	m := model{
		objs: objs,
		stats: make(map[uint32]*procStats),
		prevTotals: make(map[uint32]bpfTrafficStats),
	}

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
