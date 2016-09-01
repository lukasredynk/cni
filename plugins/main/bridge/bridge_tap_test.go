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

package main

import (
	"fmt"
	"net"
	"syscall"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/testutils"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("bridge Operations using TAP devices", func() {
	var originalNS ns.NetNS

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
	})

	It("configures and deconfigures a bridge with a TAP device with ADD/DEL", func() {
		// Used only to fill CNI_IFNAME, not actually used in this test
		const IFNAME = "tap"

		const TAP_PREFIX = "tap"
		const BRNAME = "cni0"

		gwaddr, subnet, err := net.ParseCIDR("10.1.2.1/24")
		Expect(err).NotTo(HaveOccurred())

		conf := fmt.Sprintf(`{
    "name": "mynet",
    "type": "bridge",
    "bridge": "%s",
    "isDefaultGateway": true,
    "ipMasq": false,
    "ipam": {
        "type": "host-local",
        "subnet": "%s"
    }
}`, BRNAME, subnet.String())

		targetNs, err := ns.NewNS()
		Expect(err).NotTo(HaveOccurred())
		// defer targetNs.Close()

		args := &skel.CmdArgs{
			ContainerID:   "dummy",
			Netns:         targetNs.Path(),
			IfName:        IFNAME,
			StdinData:     []byte(conf),
			UsesTapDevice: true,
		}

		err = targetNs.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, err := testutils.CmdAddWithResult(targetNs.Path(), IFNAME, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			// Make sure bridge link exists
			link, err := netlink.LinkByName(BRNAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(BRNAME))

			// Ensure bridge has gateway address
			addrs, err := netlink.AddrList(link, syscall.AF_INET)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(addrs)).To(BeNumerically(">", 0))
			found := false
			subnetPrefix, subnetBits := subnet.Mask.Size()
			for _, a := range addrs {
				aPrefix, aBits := a.IPNet.Mask.Size()
				if a.IPNet.IP.Equal(gwaddr) && aPrefix == subnetPrefix && aBits == subnetBits {
					found = true
					break
				}
			}
			Expect(found).To(Equal(true))

			// Check for the veth link in the main namespace
			links, err := netlink.LinkList()
			Expect(err).NotTo(HaveOccurred())
			Expect(len(links)).To(Equal(3)) // Bridge, TAP device, and loopback
			for _, l := range links {
				if l.Attrs().Name != BRNAME && l.Attrs().Name != "lo" {
					// Ensure we have created TAP device, not veth
					_, isVeth := l.(*netlink.Veth)
					Expect(isVeth).To(Equal(false))
				}
			}
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Delete the TAP device
		err = targetNs.Do(func(ns.NetNS) error {
			defer GinkgoRecover()
			// Assert that 3rd link is a TAP device
			tapDevice, err := netlink.LinkByIndex(3)
			Expect(err).NotTo(HaveOccurred())
			args.IfName = tapDevice.Attrs().Name
			Expect(args.IfName[:3]).To(Equal(TAP_PREFIX))

			err = testutils.CmdDelWithResult(targetNs.Path(), IFNAME, func() error {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Make sure TAP device has been deleted
		err = targetNs.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(args.IfName)
			Expect(err).To(HaveOccurred())
			Expect(link).To(BeNil())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
