package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"

	"github.com/jsimonetti/rtnetlink"

	"github.com/florianl/go-tc"
	helper "github.com/florianl/go-tc/core"

	"golang.org/x/sys/unix"
)

// setupDummyInterface installs a temporary dummy interface
func setupDummyInterface(iface string) (*rtnetlink.Conn, error) {
	con, err := rtnetlink.Dial(nil)
	if err != nil {
		return &rtnetlink.Conn{}, err
	}
	if err := con.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   unix.ARPHRD_NETROM,
		Index:  0,
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{
			Name: iface,
			Info: &rtnetlink.LinkInfo{Kind: "dummy"},
		},
	}); err != nil {
		return con, err
	}
	return con, err
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Load eBPF from an elf file
	coll, err := ebpf.LoadCollectionSpec("ebpf/drop")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load collection from file: %v\n", err)
		return
	}

	// Load the eBPF program ingress_drop
	ingressDrop, err := ebpf.NewProgramWithOptions(coll.Programs["ingress_drop"],
		ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  65536,
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load program: %v\n", err)
		return
	}
	defer ingressDrop.Close()

	// Print verifier feedback
	fmt.Printf("%s", ingressDrop.VerifierLog)

	info, _ := ingressDrop.Info()

	// Setup tc socket for communication with the kernel
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// Setup dummy interface for testing
	var rtnl *rtnetlink.Conn
	tcIface := "tcDevTesting"
	if rtnl, err = setupDummyInterface(tcIface); err != nil {
		fmt.Fprintf(os.Stderr, "could not setup dummy interface: %v\n", err)
		return
	}
	defer rtnl.Close()
	devID, err := net.InterfaceByName(tcIface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}
	defer func(devID uint32, rtnl *rtnetlink.Conn) {
		if err := rtnl.Link.Delete(devID); err != nil {
			fmt.Fprintf(os.Stderr, "could not delete interface %s: %v\n", tcIface, err)
		}
	}(uint32(devID.Index), rtnl)

	qdisc := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  helper.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	}

	// Install Qdisc on testing interface
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", tcIface, err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdisc)

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Parent:  helper.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    helper.FilterInfo(0, unix.ETH_P_ALL),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(ingressDrop.FD())),
				Name:  stringPtr(info.Name),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}

	<-ctx.Done()

	if err := tcnl.Filter().Delete(&tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0x1,
			Parent:  helper.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    helper.FilterInfo(0, unix.ETH_P_ALL),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
		},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "could not delete eBPF filter: %v\n", err)
		return
	}

}
