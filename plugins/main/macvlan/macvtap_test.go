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
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("macvtap Operations", func() {
	var originalNS ns.NetNS

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// Add master
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: MASTER_NAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(MASTER_NAME)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
	})

	It("creates an macvtap link in a network namespace", func() {
		conf := &types.MacVlanNetConf{
			NetConf: types.NetConf{
				Name: "testConfig",
				Type: "macvlan",
			},
			Master: MASTER_NAME,
			Mode:   "bridge",
			MTU:    1500,
		}

		var tapIface netlink.Link
		var err error

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			tapIface, err = ip.SetupMacVtap(*conf)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Make sure macvtap link exists in the namespace
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			tapIfaceName := tapIface.Attrs().Name
			link, err := netlink.LinkByName(tapIfaceName)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(tapIfaceName))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
