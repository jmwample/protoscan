
# Bidirectional Injection Benchmark

We want to evaluate the packet injection tool to answer a few questions about
the rate and consistency with which it injects packets.

Because of the high performance nature of the injection an expected difference
in packet injection rate depends on the time it takes to generate a payload. For
example generating a Quic probe requires an HKDF operation to generate the
initial keys, while http is created with a single format string operation.

Along with this we are still using golang `net.Dial` for sending DNS packets
(and raw sockets for all others) which has its own drawbacks.


## 1. How many packets can we send per second for each probe type?
![prelim benchmark results](./prober_benchmark_v0.1.png)


TODO:

- 0.2 Run will all (http, http-nsa, tls ,tls-nsa, quic, dns) probes
  - run on server with no other processing load
