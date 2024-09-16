package raw

import (
	"context"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/jmwample/protoscan/pkg/rate"
)

// Sender is our base level sender that writes packets into one or more raw
// sockets
type Sender struct {
	sendQueue chan<- *msg
	cancel    context.CancelFunc
	wg        *sync.WaitGroup

	*sendStats
}

// NewSender returns an initialized raw socket sender. you should `defer
// Close()` the sender. Returns an error only if an  error occurs while opening
// raw socket file descriptors (Note - ipv6 raw sock can be opened without error
// even with no ipv6 address).
func NewSender(ctx context.Context, device string, nWorkers int) (*Sender, error) {
	sendQueue := make(chan *msg)

	childCtx, cancel := context.WithCancel(ctx)
	wg := new(sync.WaitGroup)
	sendStats := newStats()

	r := &Sender{
		sendQueue,
		cancel,
		wg,
		sendStats,
	}

	for i := 0; i < nWorkers; i++ {
		fd4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}

		fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}

		wg.Add(1)
		go r.runRawSendWorker(childCtx, fd4, fd6, sendQueue, wg)
	}

	return r, nil
}

// NewSenderLimited returns an initialized raw socket sender. you should `defer
// Close()` the sender. Returns an error only if an  error occurs while opening
// raw socket file descriptors (Note - ipv6 raw sock can be opened without error
// even with no ipv6 address).
func NewSenderLimited(ctx context.Context, device string, nWorkers int, pps, bps string) (*Sender, error) {
	sendQueueIn := make(chan *msg)
	sendQueueOut := make(chan *msg)

	if bps != "" {
		rate.Limit[*msg](bps, sendQueueIn, sendQueueOut, func(m *msg) int64 {
			return int64(len(m.payload))
		})
	} else {
		// if pps == "" the limiter will run in unlimited mode
		err := rate.CountLimit(pps, sendQueueIn, sendQueueOut)
		if err != nil {
			return nil, err
		}
	}

	childCtx, cancel := context.WithCancel(ctx)
	wg := new(sync.WaitGroup)
	sendStats := newStats()

	r := &Sender{
		sendQueueIn,
		cancel,
		wg,
		sendStats,
	}

	for i := 0; i < nWorkers; i++ {
		fd4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}

		fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}

		wg.Add(1)
		go r.runRawSendWorker(childCtx, fd4, fd6, sendQueueOut, wg)
	}

	return r, nil
}

// SendPkt writes a message into a raw socket. Calls to SendPkt will block if no
// worker is available to send the packet.
func (r *Sender) SendPkt(ip *net.IP, payload []byte) {
	r.sendQueue <- &msg{ip, payload}
}

// Close shuts down and cleans up after the raw socket sender
func (r *Sender) Close() {
	r.cancel()
	r.wg.Wait()
}

// msg contains all fields required for a message to be written into
// a raw socket
type msg struct {
	ip      *net.IP
	payload []byte
}

func (r *Sender) runRawSendWorker(ctx context.Context, fd4, fd6 int, recv <-chan *msg, wg *sync.WaitGroup) {
	defer wg.Done()
	if fd4 != -1 {
		defer syscall.Close(fd4)
	}
	if fd6 != -1 {
		defer syscall.Close(fd6)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-recv:

			var addr syscall.Sockaddr
			var sockFd int

			if msg.ip.To4() != nil {
				if fd4 == -1 {
					continue
				}
				sockFd = fd4
				addr = &syscall.SockaddrInet4{
					Port: 0,
					Addr: *(*[4]byte)(msg.ip.To4()),
				}
			} else {
				if fd6 == -1 {
					continue
				}
				sockFd = fd6
				addr = &syscall.SockaddrInet6{
					Port: 0,
					Addr: *(*[16]byte)(msg.ip.To16()),
				}
			}

			r.sendPkt(sockFd, msg.payload, addr)
		}
	}
}

func (r *Sender) sendPkt(sockFd int, payload []byte, addr syscall.Sockaddr) error {
	var err error
	retries := 3
	retryDelay := 1 * time.Millisecond
	for i := 0; i < retries; i++ {
		err = syscall.Sendto(sockFd, payload, 0, addr)
		if err == nil {
			// TODO jmwample: fix stats
			r.incPacketPerSec()
			r.incBytesPerSec(len(payload))
			return nil
		}
		if err != nil {
			time.Sleep(retryDelay)
		}
	}

	r.incErrPerSec()
	return os.NewSyscallError("sendto", err)
}
