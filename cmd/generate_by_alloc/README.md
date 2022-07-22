
# Generate From Subnets

Generates random addresses from all subnets associated with a set of country
codes. If a `filter` file is passed in (generated using zmap) it will ignore
addresses known to respond on 53.

We use the CSV format MaxMindDB files to select random addresses from each
subnet allocation associated with each country code. The base directory for the
mmdb files can be modified using the `-d` option, but the directory should be
organized like follows:

```txt
GeoLite2
└── GeoLite2-Country
    ├── GeoLite2-Country-Blocks-IPv4.csv
    ├── GeoLite2-Country-Blocks-IPv6.csv
    └── GeoLite2-Country-Locations-en.csv
```

Alternatively you can point to locations file and blocks files independently
using the `id-file` and `csv-file` arguments respectively. Note that these will
override the `-d` and `-6` arguments which are just used for default csv file
locations.

**NOTE**: For allocations of size less than double N we add the subnet mask IP
and continue to avoid continuously colliding or handling /32 /128 specially. For
example -- if n=2, allocations must have at least 4 addresses (be /30 or /126 or
larger) otherwise the mask address is added and we move on to the next
allocation.

## Usage

```txt
Usage of ./generate_by_alloc:
  -6    Generate IPv6 addresses (generates IPv4 by default) by building map from default v6 maxmind db file path
  -all
        Use all country codes instead of hard coded list
  -csv-file string
        Maxmind CSV Country database file  (e.g. "<path_to>/GeoLite2-Country-Blocks-IPv4.csv"). Overrides '-d' and '-6' options.
  -d string
        Database directory path (default "./GeoLite2/")
  -filter string
        File containing list of addresses known to respond on UDP 53
  -id-file string
        MaxMind CSV Country locations file (e.g. "<path_to>/GeoLite2-Country-Locations-en.csv"). Overrides '-d' and '-6' options.
  -n int
        Number of addresses per IP-version per allocation (default 2)
  -o string
        Output file path (default "./generated_out")
  -s int
        PRNG seed (default seeded with time in ns) (default -1)
```

So for example

```sh
./generate_by_alloc -d /data/GeoLite2/ -filter "./zmap-udp53.csv" -all

```
