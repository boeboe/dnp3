package dnp3

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// UDP to an outstation. A connected UDP socket on an ephemeral port only
// hears datagrams from the exact address and port it sent to, and the
// outstation only reaches it at that port. Device profiles let an
// outstation send its responses to a fixed port (often 20000) or from
// another source port than the one requests go to, so the master listens
// on an unconnected socket, on localPort when configured, and takes every
// datagram from the outstation's IP address.

// udpPeer is a net.Conn over an unconnected UDP socket that sends to the
// outstation and receives what comes from its address.
type udpPeer struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func dialUDP(ctx context.Context, host string, localPort int) (net.Conn, error) {
	ra, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostOnly(host))
	if err != nil || len(ra) == 0 {
		return nil, fmt.Errorf("resolving %s: %v", host, err)
	}
	_, ps, _ := net.SplitHostPort(host)
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, fmt.Errorf("udp://%s needs a port", host)
	}
	remote := &net.UDPAddr{IP: net.IP(ra[0].Unmap().AsSlice()), Port: port}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("listening on UDP port %d for %s: %w", localPort, host, err)
	}
	return &udpPeer{UDPConn: pc, remote: remote}, nil
}

func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

// Read returns the next datagram from the outstation's address, from any
// source port.
func (u *udpPeer) Read(b []byte) (int, error) {
	for {
		n, a, err := u.UDPConn.ReadFromUDP(b)
		if err != nil {
			return n, err
		}
		if a.IP.Equal(u.remote.IP) {
			return n, nil
		}
	}
}

// Write sends one datagram to the outstation.
func (u *udpPeer) Write(b []byte) (int, error) { return u.UDPConn.WriteToUDP(b, u.remote) }

// RemoteAddr is the outstation's address.
func (u *udpPeer) RemoteAddr() net.Addr { return u.remote }

var _ net.Conn = (*udpPeer)(nil)
