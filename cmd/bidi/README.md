
# Bidirectional Censorship Protocol Scanner

Send packets to addresses that should not respond on UDP 53 _FAST_.

* If they respond to controls - probably actual resolvers by accident
* If they respond to others - bidirectional censorship

This file is meant to pair with the address generators in `cmd/generate_*`.

## Usage

```txt
Usage of ./bidi:
  -domains string
        File with a list of domains to test (default "domains.txt")
  -iface string
        Interface to listen on (default "eth0")
  -laddr string
        Local address to send packets from - unset uses default interface
  -nsa
        [HTTP/TLS] No Syn Ack (nsa) disable syn, and ack warm up packets for tcp probes
  -qtype uint
        [DNS] Type of Query to send (1 = A / 28 = AAAA) (default 1)
  -seed int
        [HTTP/TLS/QUIC] seed for random elements of generated packets. default seeded with time.Now.Nano (default -1)
  -syn-delay duration
        [HTTP/TLS] when syn ack is enabled delay between syn and data (default 2ms)
  -type string
        probe type to send (default "dns")
  -verbose
        Verbose prints sent/received DNS packets/info (default true)
  -wait duration
        Duration a worker waits after sending a probe (default 5s)
  -workers uint
        Number worker threads (default 50)
```

So for example

```sh
 echo "52.44.73.6" | sudo ./bidi -type http -iface "wlo1" -domains domains.txt -workers 1 -wait 1s
```

To dump in more addresses more quickly you can do something like:

```sh
cat may-11/generated_addr* | cut -d " " -f 1 | zblocklist -b /etc/zmap/blacklist.conf | sudo ./bidi -laddr "<local_addr>" -qtype 1  -workers 2000 -wait 5ms -iface enp1s0f0:0 > may-11/bidi_3.out 2>&1
```

## TODO

After testing with KNOWN censored networks and domains:

* tcp "random" indicators for domain (we should get ip in injected response)
* pcap handler (HTTP, TLS, & Quic)

(once we know TLS injection is worth it.)

* TLS match chrome ciphersuites, curve points, etc.
