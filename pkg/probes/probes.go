package probes

import (
	"context"
	"net"
	"sync"
)

// Prober provides a common interface implemented by all probe types
type Prober interface {
	RegisterFlags()

	SendProbe(ip net.IP, name string, i int, verbose bool) error

	HandlePcap(ctx context.Context, iface string, tag string, wg *sync.WaitGroup)
}
