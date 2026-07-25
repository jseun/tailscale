// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
)

// embedderSocketRecorder is a nettype.SocketFunc that records each dial and, for
// a "tls" network, terminates TLS itself — playing the role of a host runtime
// such as Cloudflare Workers' connect({secureTransport:"on"}).
type embedderSocketRecorder struct {
	mu    sync.Mutex
	dials []embedderDialRecord
}

type embedderDialRecord struct {
	network string
	raddr   string
}

func (r *embedderSocketRecorder) socket(ctx context.Context, network, laddr, raddr string) (any, error) {
	r.mu.Lock()
	r.dials = append(r.dials, embedderDialRecord{network, raddr})
	r.mu.Unlock()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", raddr)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(network, "tls") {
		return conn, nil
	}
	// The embedder terminates TLS: derphttp must speak cleartext HTTP over the
	// returned conn and skip its own TLS handshake.
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (r *embedderSocketRecorder) recorded() []embedderDialRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]embedderDialRecord(nil), r.dials...)
}

// TestEmbedderDialRegionClient verifies that a region client dials through the
// embedder socket factory, honors DERPNode.DERPPort, asks for a host-TLS
// ("tls") stream for an https DERP, and completes the DERP handshake over the
// returned conn without a Go-level TLS handshake.
func TestEmbedderDialRegionClient(t *testing.T) {
	// Real DERP server on TLS, ephemeral loopback port.
	serverKey := key.NewNode()
	s := derpserver.New(serverKey, t.Logf)
	defer s.Close()

	derpSrv := httptest.NewUnstartedServer(derpserver.Handler(s))
	derpSrv.StartTLS()
	defer derpSrv.Close()

	derpURL, err := url.Parse(derpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	derpPort, err := strconv.Atoi(derpURL.Port())
	if err != nil {
		t.Fatalf("parsing derp port %q: %v", derpURL.Port(), err)
	}
	if derpPort == 443 {
		t.Fatalf("test server bound to :443; can't distinguish bug from fix")
	}

	recorder := new(embedderSocketRecorder)
	nettype.SetEmbedderSocket(recorder.socket, nettype.EmbedderCaps{TCP: true, TLS: true})
	defer nettype.SetEmbedderSocket(nil, nettype.EmbedderCaps{})

	region := &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "test",
		Nodes: []*tailcfg.DERPNode{{
			Name:             "1a",
			RegionID:         1,
			HostName:         "127.0.0.1",
			IPv4:             "127.0.0.1",
			DERPPort:         derpPort,
			InsecureForTests: true,
		}},
	}
	c := derphttp.NewRegionClient(key.NewNode(), t.Logf, netmon.NewStatic(),
		func() *tailcfg.DERPRegion { return region })
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Pump Recv so the PONG gets dispatched.
	go func() {
		for {
			if _, err := c.Recv(); err != nil {
				return
			}
		}
	}()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping over embedder-dialed conn: %v", err)
	}

	dials := recorder.recorded()
	if len(dials) != 1 {
		t.Fatalf("embedder dials = %d, want 1: %v", len(dials), dials)
	}
	if got, want := dials[0].raddr, fmt.Sprintf("127.0.0.1:%d", derpPort); got != want {
		t.Errorf("embedder dial addr = %q, want %q", got, want)
	}
	if got, want := dials[0].network, "tls"; got != want {
		t.Errorf("embedder dial network = %q, want %q (region clients use HTTPS)", got, want)
	}
	// The embedder terminated TLS, so the client must not have recorded a
	// Go-level TLS handshake of its own.
	if _, ok := c.TLSConnectionState(); ok {
		t.Errorf("client has a Go-level TLS connection state; want TLS offloaded to the embedder")
	}
}

// TestEmbedderDialURLClient verifies the URL-client path: an http:// DERP URL
// dials through the embedder socket factory with a raw "tcp" stream.
func TestEmbedderDialURLClient(t *testing.T) {
	serverKey := key.NewNode()
	s := derpserver.New(serverKey, t.Logf)
	defer s.Close()

	derpSrv := httptest.NewServer(derpserver.Handler(s))
	defer derpSrv.Close()

	recorder := new(embedderSocketRecorder)
	nettype.SetEmbedderSocket(recorder.socket, nettype.EmbedderCaps{TCP: true, TLS: true})
	defer nettype.SetEmbedderSocket(nil, nettype.EmbedderCaps{})

	c, err := derphttp.NewClient(key.NewNode(), derpSrv.URL, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	dials := recorder.recorded()
	if len(dials) != 1 {
		t.Fatalf("embedder dials = %d, want 1: %v", len(dials), dials)
	}
	derpURL, err := url.Parse(derpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := dials[0].raddr, derpURL.Host; got != want {
		t.Errorf("embedder dial addr = %q, want %q", got, want)
	}
	if got, want := dials[0].network, "tcp"; got != want {
		t.Errorf("embedder dial network = %q, want %q for an http:// DERP URL", got, want)
	}
}
