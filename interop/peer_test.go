// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// image is the reference peers' image, built from ./peer; saImage the
// Secure Authentication peers' image, built from ./peer-sa.
const (
	image   = "sigma-dnp3-interop:opendnp3-3.1.2"
	saImage = "sigma-dnp3-interop:opendnp3-2.1.0-rc5-sa"
)

var buildMu sync.Mutex
var built = map[string]bool{}

// needDocker skips the test unless SIGMA_DNP3_INTEROP=1 is set and Docker
// answers, and builds the peer image (once per run; Docker's cache makes
// an unchanged build quick).
func needDocker(t *testing.T) {
	t.Helper()
	needImage(t, image, "peer")
}

// needImage is needDocker for an image built from dir.
func needImage(t *testing.T, img, dir string) {
	t.Helper()
	if os.Getenv("SIGMA_DNP3_INTEROP") != "1" {
		t.Skip("set SIGMA_DNP3_INTEROP=1 to run the interop tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	buildMu.Lock()
	defer buildMu.Unlock()
	if built[img] {
		return
	}
	out, err := exec.Command("docker", "build", "-q", "-t", img, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	built[img] = true
}

// freePort returns a TCP port free on the loopback interface.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// peer is a reference program running in a container: its standard
// input takes commands, its output lines are collected.
type peer struct {
	t     *testing.T
	name  string
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string

	mu  sync.Mutex
	log []string
}

// startPeer runs `docker run --rm -i --name <unique> <args...>`.
func startPeer(t *testing.T, args ...string) *peer {
	t.Helper()
	p := &peer{t: t, name: fmt.Sprintf("sigma-dnp3-%d", time.Now().UnixNano()), lines: make(chan string, 1024)}
	full := append([]string{"run", "--rm", "-i", "--name", p.name}, args...)
	p.cmd = exec.Command("docker", full...)
	var err error
	if p.stdin, err = p.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	p.cmd.Stdout, p.cmd.Stderr = w, w
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.log = append(p.log, line)
			p.mu.Unlock()
			if strings.HasPrefix(line, "PEER ") {
				p.lines <- strings.TrimPrefix(line, "PEER ")
			}
		}
	}()
	go func() { _ = p.cmd.Wait(); _ = w.Close() }()
	t.Cleanup(func() {
		_, _ = io.WriteString(p.stdin, "quit\n")
		_ = p.stdin.Close()
		_ = exec.Command("docker", "stop", "-t", "2", p.name).Run()
		if t.Failed() || os.Getenv("SIGMA_DNP3_INTEROP_LOG") == "1" {
			t.Logf("peer output:\n%s", p.output())
		}
	})
	return p
}

func (p *peer) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.log, "\n")
}

// send writes one command line to the peer.
func (p *peer) send(line string) {
	p.t.Helper()
	if _, err := io.WriteString(p.stdin, line+"\n"); err != nil {
		p.t.Fatalf("peer stdin: %v", err)
	}
}

// expect waits for a "PEER " line containing all the parts, skipping
// others, and returns it.
func (p *peer) expect(within time.Duration, parts ...string) string {
	p.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			ok := true
			for _, part := range parts {
				if !strings.Contains(l, part) {
					ok = false
					break
				}
			}
			if ok {
				return l
			}
		case <-deadline:
			p.t.Fatalf("no peer line with %q within %s", parts, within)
			return ""
		}
	}
}

// until collects the "PEER " lines up to and including the first one
// containing stop.
func (p *peer) until(within time.Duration, stop string) []string {
	p.t.Helper()
	var out []string
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			out = append(out, l)
			if strings.Contains(l, stop) {
				return out
			}
		case <-deadline:
			p.t.Fatalf("no peer line with %q within %s", stop, within)
			return nil
		}
	}
}

// expectAll waits for lines matching each set of parts, in any order.
func (p *peer) expectAll(within time.Duration, sets ...[]string) {
	p.t.Helper()
	left := append([][]string(nil), sets...)
	deadline := time.After(within)
	for len(left) > 0 {
		select {
		case l := <-p.lines:
			for i, s := range left {
				if has([]string{l}, s...) {
					left = append(left[:i], left[i+1:]...)
					break
				}
			}
		case <-deadline:
			p.t.Fatalf("no peer lines with %q within %s", left, within)
		}
	}
}

// has reports whether one of lines contains all the parts.
func has(lines []string, parts ...string) bool {
	for _, l := range lines {
		ok := true
		for _, part := range parts {
			if !strings.Contains(l, part) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// drain discards the lines received so far.
func (p *peer) drain() {
	for {
		select {
		case <-p.lines:
		default:
			return
		}
	}
}
