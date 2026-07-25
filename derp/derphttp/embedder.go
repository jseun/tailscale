// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"fmt"
	"net"

	"tailscale.com/types/nettype"
)

// embedderDial opens the DERP TCP connection through the embedder's socket
// factory (see nettype.SetEmbedderSocket), for js/wasm where Go cannot open
// sockets itself but the surrounding runtime (e.g. a Cloudflare Worker) can. It
// asks for a host-TLS-terminated "tls" stream when the embedder offers one for
// an https DERP — so Go-level TLS is skipped, see embedderTerminatesTLS — and a
// raw "tcp" stream otherwise. It reports ok=false when no factory can provide a
// stream, so the caller falls back to its normal transport (the websocket
// fallback on js, or the default dialer).
func (c *Client) embedderDial(ctx context.Context, addr string) (_ net.Conn, ok bool, err error) {
	fn, caps := nettype.EmbedderSocket()
	if fn == nil {
		return nil, false, nil
	}
	network := "tcp"
	switch {
	case c.useHTTPS() && caps.TLS:
		network = "tls"
	case !caps.TCP:
		// The embedder can't give us a raw stream to layer TLS over.
		return nil, false, nil
	}
	s, err := fn(ctx, network, "", addr)
	if err != nil {
		return nil, false, err
	}
	conn, ok := s.(net.Conn)
	if !ok {
		return nil, false, fmt.Errorf("embedder socket for %q returned %T, want net.Conn", network, s)
	}
	return conn, true, nil
}

// embedderTerminatesTLS reports whether a stream from the embedder socket for
// this client is already TLS-terminated, so Go must not run its own TLS over
// it. True only for an https DERP when the embedder declares the TLS
// capability — exactly when embedderDial requests the "tls" network.
func (c *Client) embedderTerminatesTLS() bool {
	_, caps := nettype.EmbedderSocket()
	return c.useHTTPS() && caps.TLS
}
