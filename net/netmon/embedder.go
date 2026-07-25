// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net"

	"tailscale.com/types/nettype"
)

// embedderInterfaceName is the synthetic interface name used for embedder-provided
// addresses on platforms where Go cannot enumerate interfaces (js/wasm). The
// host reports addresses, not interfaces, so they are all attributed to one.
const embedderInterfaceName = "embedder"

// embedderInterfaces wraps the embedder-provided addresses (see
// nettype.SetEmbedderLocalAddresses) in a single synthetic, up, non-loopback
// interface so they can flow through the same classification and filtering as
// natively enumerated interfaces. It returns no interfaces when no embedder source
// is installed or none of its addresses are valid, which callers treat as
// simply having no addresses to report.
func embedderInterfaces() []Interface {
	pfxs := nettype.EmbedderLocalAddresses()
	addrs := make([]net.Addr, 0, len(pfxs))
	for _, pfx := range pfxs {
		ip := pfx.Addr().Unmap()
		if !ip.IsValid() {
			continue
		}
		// The classifier reads the mask (e.g. for the IPv6 per-subnet cap), so
		// carry the embedder's real subnet through. A missing or nonsensical
		// prefix length falls back to a single-host mask.
		bits := pfx.Bits()
		if bits < 0 || bits > ip.BitLen() {
			bits = ip.BitLen()
		}
		addrs = append(addrs, &net.IPNet{
			IP:   ip.AsSlice(),
			Mask: net.CIDRMask(bits, ip.BitLen()),
		})
	}
	if len(addrs) == 0 {
		return nil
	}
	return []Interface{{
		Interface: &net.Interface{
			Index: 1,
			Name:  embedderInterfaceName,
			Flags: net.FlagUp | net.FlagRunning,
		},
		AltAddrs: addrs,
	}}
}
