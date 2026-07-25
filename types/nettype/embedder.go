// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package nettype

// This file holds the embedder-provided network capabilities. On js/wasm the
// Go runtime cannot enumerate interfaces or open sockets itself, so a runtime
// that embeds the wasm module (e.g. Node.js, a Cloudflare Worker) supplies the
// missing pieces here and tailscale's normal machinery uses them.

import (
	"context"
	"net/netip"
	"runtime"
	"sync/atomic"
)

// embedderLocalAddresses is the embedder-provided source of local interface
// addresses, if any.
//
// On js/wasm the Go runtime cannot enumerate network interfaces, so
// [tailscale.com/net/netmon.LocalAddresses] has nothing to report and endpoint
// discovery is left with only STUN. An embedder that can see the host's
// addresses (e.g. os.networkInterfaces() under Node.js) installs a source
// here, and local endpoints are advertised as they are on any other platform —
// which is all a host with a public address needs to be reachable directly,
// STUN or no STUN.
//
// Each address is a [netip.Prefix] carrying the interface's subnet mask, as a
// natively enumerated interface would report it; an embedder that only knows
// the bare address can report a single-host prefix (/32 or /128).
var embedderLocalAddresses atomic.Pointer[func() []netip.Prefix]

// SetEmbedderLocalAddresses installs f as the embedder-provided source of local
// interface addresses, or clears it when f is nil.
//
// f is called whenever the addresses are needed (endpoint discovery, link
// state) so that a host whose interfaces change reports the current set. It
// must not block. Each returned prefix is the interface address with its subnet
// mask (a single-host prefix if the mask is unknown); the caller filters them
// as it does natively enumerated interfaces: Tailscale's own addresses,
// loopback and link-local are handled the same way.
func SetEmbedderLocalAddresses(f func() []netip.Prefix) {
	if f == nil {
		embedderLocalAddresses.Store(nil)
		return
	}
	embedderLocalAddresses.Store(&f)
}

// EmbedderLocalAddresses returns the embedder-provided local interface
// addresses (each with its subnet mask), or nil if no source is installed.
func EmbedderLocalAddresses() []netip.Prefix {
	f := embedderLocalAddresses.Load()
	if f == nil {
		return nil
	}
	return (*f)()
}

// SocketFunc creates a network socket for tailscale on platforms where the Go
// runtime cannot (js/wasm). It is modeled on tamago's net.SocketFunc: the
// network name selects the kind of socket, and the returned concrete type
// matches it.
//
// network is a Go network name:
//   - "tcp", "tcp4", "tcp6": a connected stream; tailscale layers TLS over it.
//   - "tls", "tls4", "tls6": a connected stream whose TLS the embedder itself
//     terminates (only offered when EmbedderCaps.TLS is set), over which
//     tailscale does not run its own TLS.
//   - "udp", "udp4", "udp6": a datagram socket.
//
// Exactly one of laddr/raddr is set, each a "host:port": raddr for a dial ("tcp"
// and "tls"), laddr for a bind ("udp"). The returned value's concrete type must
// match the network: a [net.Conn] for a stream, or a [PacketConn] (a net.PacketConn
// with the UDPAddrPort methods magicsock needs) for a datagram. It returns an
// error for anything the embedder does not provide, and the caller falls back to
// its default (DERP over WebSocket for streams, DERP-only for UDP).
type SocketFunc func(ctx context.Context, network, laddr, raddr string) (any, error)

// EmbedderCaps declares which sockets a SocketFunc can create. A single factory
// can't be probed for this statically, and the capabilities are independent —
// a Cloudflare Worker can dial TCP but not bind UDP, Node can do both — so
// callers gate on the specific capability they need.
type EmbedderCaps struct {
	TCP bool // can dial raw TCP; tailscale layers TLS over it as needed
	TLS bool // can dial a stream with the embedder terminating TLS (network "tls")
	UDP bool // can bind UDP, unlocking disco, STUN and direct paths
}

// embedderSocket pairs a SocketFunc with its declared capabilities so the two
// can never drift apart.
type embedderSocket struct {
	fn   SocketFunc
	caps EmbedderCaps
}

var embedderSocketFunc atomic.Pointer[embedderSocket]

// SetEmbedderSocket installs fn as the embedder's socket factory with the given
// declared capabilities, or clears it when fn is nil. It must be called before
// the sockets are needed (DERP connect, magicsock bind).
func SetEmbedderSocket(fn SocketFunc, caps EmbedderCaps) {
	if fn == nil {
		embedderSocketFunc.Store(nil)
		return
	}
	embedderSocketFunc.Store(&embedderSocket{fn: fn, caps: caps})
}

// EmbedderSocket returns the installed socket factory and its declared
// capabilities, or (nil, zero) if none is installed.
func EmbedderSocket() (SocketFunc, EmbedderCaps) {
	if s := embedderSocketFunc.Load(); s != nil {
		return s.fn, s.caps
	}
	return nil, EmbedderCaps{}
}

// CanUDP reports whether this process can send and receive UDP packets: true
// everywhere except js/wasm, and true there once an embedder socket that
// declares UDP support has been installed.
func CanUDP() bool {
	if runtime.GOOS != "js" {
		return true
	}
	_, caps := EmbedderSocket()
	return caps.UDP
}
