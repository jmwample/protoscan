
# Generate From Addrs

Generates random addresses from the same subnet as addresses passed through
stdin. If a `filter` file is passed in (generated using zmap) it will
ignore addresses known to respond on 53.

The `maxminddb-golang` package allows us to get the subnet that a specific
address is associated with. We use this to select a random address from the same
subnet. We also use the forward lookup of country code for debug and output.
The base directory for the mmdb files can be modified using the `-d` option,
but the directory should be organized like follows:

```txt
GeoLite2
├── GeoLite2-ASN
│   └── GeoLite2-ASN.mmdb
└── GeoLite2-Country
    └── GeoLite2-Country.mmdb
```

## Usage

```txt
Usage of generate_from_addrs:
  -d string
        Database directory path (default "./GeoLite2/")
  -filter string
        File containing list of addresses known to respond on UDP 53
  -n int
        Number of addresses per IP-version per input address (default 2)
  -o string
        Output file path (default "./generated_out")
  -s int
        PRNG seed (default seeded with time in ns) (default -1)
```

So for example

```sh
cat addrs.dat | zblocklist -b /etc/zmap/blacklist.conf | ./generate_from_addr -d /data/GeoLite2/ -filter "./zmap-udp53.csv"

```
