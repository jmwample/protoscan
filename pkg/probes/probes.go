package probes

import (
	"context"
	"net"
	"sync"
)

// Prober provides a common interface implemented by all probe types
type Prober interface {
	RegisterFlags()

	SendProbe(ip net.IP, name string, verbose bool) error

	HandlePcap(ctx context.Context, iface string, wg *sync.WaitGroup)
}
