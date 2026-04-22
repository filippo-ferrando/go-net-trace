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
	pidStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Width(8)
	nameStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Width(20)
	rxtStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Width(15)
	txtStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Width(15)
	rxuStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("43")).Width(15)
	txuStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("215")).Width(15)
)

type procStats struct {
	PID        uint32
	Name       string
	TXURate    float64
	TXTRate    float64
	RXURate    float64
	RXTRate    float64
	Total      float64
	lastActive time.Time
}

type model struct {
	objs       bpfObjects
	stats      map[uint32]*procStats
	prevTotals map[uint32]bpfTrafficStats
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
			rxuDelta := float64(current.RxUdpBytes - prev.RxUdpBytes)
			rxtDelta := float64(current.RxTcpBytes - prev.RxTcpBytes)
			txuDelta := float64(current.TxUdpBytes - prev.TxUdpBytes)
			txtDelta := float64(current.TxTcpBytes - prev.TxTcpBytes)

			m.stats[pid].RXURate = rxuDelta
			m.stats[pid].RXTRate = rxtDelta
			m.stats[pid].TXTRate = txtDelta
			m.stats[pid].TXURate = txuDelta
			m.stats[pid].Total = rxtDelta + txtDelta + rxuDelta + txuDelta

			if rxuDelta > 0 || rxtDelta > 0 || txuDelta > 0 || txtDelta > 0 {
				m.stats[pid].lastActive = time.Now()
			}

			m.prevTotals[pid] = current
		}

		now := time.Now()
		for pid, stats := range m.stats {
			if stats.lastActive.IsZero() {
				stats.lastActive = now
			} else if now.Sub(stats.lastActive) > 5*time.Second {
				delete(m.stats, pid)
				delete(m.prevTotals, pid)
			}
		}

		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
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
	hTxt := lipgloss.PlaceHorizontal(wTx, lipgloss.Left, "TX TCP")
	hRxt := lipgloss.PlaceHorizontal(wRx, lipgloss.Left, "RX TCP")
	hTxu := lipgloss.PlaceHorizontal(wTx, lipgloss.Left, "TX UDP")
	hRxu := lipgloss.PlaceHorizontal(wRx, lipgloss.Left, "RX UDP")

	s += fmt.Sprintf("%s %s %s %s %s %s\n", hPid, hName, hTxt, hRxt, hTxu, hRxu)
	s += strings.Repeat("-", wPid+wName+wTx+wRx+wTx+wRx+3) + "\n"

	for i := 0; i < len(list) && i < 10; i++ {
		p := list[i]

		cId := lipgloss.PlaceHorizontal(wPid, lipgloss.Left, pidStyle.Render(fmt.Sprintf("%d", p.PID)))
		cName := lipgloss.PlaceHorizontal(wName, lipgloss.Left, nameStyle.Render(p.Name))
		cTxt := lipgloss.PlaceHorizontal(wTx, lipgloss.Left, txtStyle.Render(formatSpeed(p.TXTRate)))
		cRxt := lipgloss.PlaceHorizontal(wRx, lipgloss.Left, rxtStyle.Render(formatSpeed(p.RXTRate)))
		cTxu := lipgloss.PlaceHorizontal(wTx, lipgloss.Left, txuStyle.Render(formatSpeed(p.TXURate)))
		cRxu := lipgloss.PlaceHorizontal(wRx, lipgloss.Left, rxuStyle.Render(formatSpeed(p.RXURate)))

		s += fmt.Sprintf("%s %s %s %s %s %s\n", cId, cName, cTxt, cRxt, cTxu, cRxu)
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
		objs:       objs,
		stats:      make(map[uint32]*procStats),
		prevTotals: make(map[uint32]bpfTrafficStats),
	}

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
