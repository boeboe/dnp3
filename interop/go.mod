module github.com/cB-Sigma/dnp3/interop

go 1.24.0

require (
	github.com/cB-Sigma/dnp3 v0.0.0
	github.com/cB-Sigma/iotsec v0.1.0
	github.com/creack/pty v1.1.24
	golang.org/x/term v0.40.0
)

require (
	github.com/goburrow/serial v0.1.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/cB-Sigma/dnp3 => ../
