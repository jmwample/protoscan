
# Generate From Subnets

Generates random addresses from the subnets associated with country codes. If a
`filter` file is passed in (generated using zmap) it will ignore addresses known
to respond on 53.

We use the parsec CSV format MaxMindDB files to select a random address from the
by country. We also use the forward lookup of country code for debug and output.
The base directory for the mmdb files can be modified using the `-d` option, but
the directory should be organized like follows:

```txt
GeoLite2
└── GeoLite2-Country
    ├── GeoLite2-Country-Blocks-IPv4.csv
    ├── GeoLite2-Country-Blocks-IPv6.csv
    └── GeoLite2-Country-Locations-en.csv
```

## Usage

```txt
Usage of ./generate_from_subnets:
  -all
        Use all country codes instead of hard coded list
  -d string
        Database directory path (default "./GeoLite2/")
  -filter string
        File containing list of addresses known to respond on UDP 53
  -n int
        Number of addresses per IP-version per country (default 100)
  -o string
        Output file path (default "./generated_out")
  -s int
        PRNG seed (default seeded with time in ns) (default -1)
```

So for example

```sh
./generate_from_subnets -d /data/GeoLite2/ -filter "./zmap-udp53.csv" -all

```
