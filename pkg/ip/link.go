// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types"
	cnisysctl "github.com/containernetworking/cni/pkg/utils/sysctl"
	"github.com/vishvananda/netlink"
)

const (
	IPv4InterfaceArpProxySysctlTemplate = "net.ipv4.conf.%s.proxy_arp"
)

func makeVethPair(name, peer string, mtu int) (netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Flags: net.FlagUp,
			MTU:   mtu,
		},
		PeerName: peer,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, err
	}

	return veth, nil
}

func makeVeth(name string, mtu int) (peerName string, veth netlink.Link, err error) {
	for i := 0; i < 10; i++ {
		peerName, err = RandomVethName()
		if err != nil {
			return
		}

		veth, err = makeVethPair(name, peerName, mtu)
		switch {
		case err == nil:
			return

		case os.IsExist(err):
			continue

		default:
			err = fmt.Errorf("failed to make veth pair: %v", err)
			return
		}
	}

	// should really never be hit
	err = fmt.Errorf("failed to find a unique veth name")
	return
}

// RandomVethName returns string "veth" with random prefix (hashed from entropy)
func RandomVethName() (string, error) {
	entropy := make([]byte, 4)
	_, err := rand.Reader.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random veth name: %v", err)
	}

	// NetworkManager (recent versions) will ignore veth devices that start with "veth"
	return fmt.Sprintf("veth%x", entropy), nil
}

// SetupVeth sets up a virtual ethernet link.
// Should be in container netns, and will switch back to hostNS to set the host
// veth end up.
func SetupVeth(contVethName string, mtu int, hostNS ns.NetNS) (hostVeth, contVeth netlink.Link, err error) {
	var hostVethName string
	hostVethName, contVeth, err = makeVeth(contVethName, mtu)
	if err != nil {
		return
	}

	if err = netlink.LinkSetUp(contVeth); err != nil {
		err = fmt.Errorf("failed to set %q up: %v", contVethName, err)
		return
	}

	hostVeth, err = netlink.LinkByName(hostVethName)
	if err != nil {
		err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
		return
	}

	if err = netlink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
		err = fmt.Errorf("failed to move veth to host netns: %v", err)
		return
	}

	err = hostNS.Do(func(_ ns.NetNS) error {
		hostVeth, err := netlink.LinkByName(hostVethName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q in %q: %v", hostVethName, hostNS.Path(), err)
		}

		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}
		return nil
	})
	return
}

func SetupTap(mtu int) (tap netlink.Link, err error) {
	tapName, err := RandomTapName()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random tap name: %v", err)
	}
	la := netlink.NewLinkAttrs()
	la.Name = tapName
	la.MTU = mtu
	mode := netlink.TUNTAP_MODE_TAP
	flags := netlink.TUNTAP_NO_PI | netlink.TUNTAP_VNET_HDR
	tunDesc := &netlink.Tuntap{la, mode, flags}
	if err := netlink.LinkAdd(tunDesc); err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	link, err := netlink.LinkByName(tunDesc.Name)
	if err != nil {
		return nil, fmt.Errorf("cannot find link %v %v", tunDesc.Name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("cannot set link up %q", tapName)
	}

	return link, nil
}

// SetupMacVtap creates persistent macvtap device
// and returns a newly created netlink.Link structure
// using part of pod hash and interface number in interface name
func SetupMacVtap(config types.MacVlanNetConf) (netlink.Link, error) {
	master, err := netlink.LinkByName(config.Master)
	if err != nil {
		return nil, fmt.Errorf("cannot find master device '%v'", config.Master)
	}
	var mode netlink.MacvlanMode
	switch config.Mode {
	// if not set - defaults to bridge mode as in:
	// https://github.com/coreos/rkt/blob/master/Documentation/networking.md#macvlan
	case "", "bridge":
		mode = netlink.MACVLAN_MODE_BRIDGE
	case "private":
		mode = netlink.MACVLAN_MODE_PRIVATE
	case "vepa":
		mode = netlink.MACVLAN_MODE_VEPA
	case "passthru":
		mode = netlink.MACVLAN_MODE_PASSTHRU
	default:
		return nil, fmt.Errorf("unsupported macvtap mode: %v", config.Mode)
	}
	mtu := master.Attrs().MTU
	if config.MTU != 0 {
		mtu = config.MTU
	}

	interfaceName, err := RandomTapName()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random tap name: %v", err)
	}

	link := &netlink.Macvtap{
		Macvlan: netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        interfaceName,
				MTU:         mtu,
				ParentIndex: master.Attrs().Index,
			},
			Mode: mode,
		},
	}

	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("cannot create macvtap interface: %v", err)
	}

	// TODO: duplicate following lines for ipv6 support, when it will be added in other places
	ipv4SysctlValueName := fmt.Sprintf(IPv4InterfaceArpProxySysctlTemplate, interfaceName)
	if _, err := cnisysctl.Sysctl(ipv4SysctlValueName, "1"); err != nil {
		// remove the newly added link and ignore errors, because we already are in a failed state
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("failed to set proxy_arp on newly added interface %q: %v", interfaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		// remove the newly added link and ignore errors, because we already are in a failed state
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("cannot set up macvtap interface: %v", err)
	}
	return link, nil
}

func RandomTapName() (string, error) {
	entropy := make([]byte, 4)
	_, err := rand.Reader.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random veth name: %v", err)
	}

	return fmt.Sprintf("tap%x", entropy), nil
}

// DelLinkByName removes an interface link.
func DelLinkByName(ifName string) error {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	return nil
}

// DelLinkByNameAddr remove an interface returns its IP address
// of the specified family
func DelLinkByNameAddr(ifName string, family int) (*net.IPNet, error) {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	addrs, err := netlink.AddrList(iface, family)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("failed to get IP addresses for %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return nil, fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	return addrs[0].IPNet, nil
}
