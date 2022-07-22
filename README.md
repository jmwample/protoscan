# Protoscan

Protocol Scanner for high speed packet crafting and injection in several
different protocols. This is intended to test bidirectional censorship
mechanisms the world over.

## Generating address lists

See the Readme in each of `cmd/generate_by_alloc`, `cmd/generate_from_addrs`,
and `cmd/generate_from_subnets` for more details.

```sh
./generate_by_alloc -d /data/GeoLite2/ -filter "./zmap-udp53.csv" -all
```

## Scanning

The bidirectional censorship scanner currently supports DNS, HTTP, TLS, and Quic
injection in both IPv4 and IPv6.

See the Readme in `cmd/bidi/` for more details on usage.

```sh
echo "52.44.73.6" | sudo ./bidi-http -type http -iface "wlo1" -domains domains.txt -workers 1 -wait 1s
```
