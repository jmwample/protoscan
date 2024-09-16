
# Residual Censorship Measurement

Experiment to find out how residual censorship impacts our global measurement.

## Experiment Methodology

For each IP:

1. send control queries (confirm it works)
2. send domain under test (observe response)
3. send control queries until we get expected response again (Residual censorship ends)

![residual censorship methodology](../../images/residual_methodology_v1.0.png "Residual Censorship methodology")

---

### Experiment should answer the following Questions

* Which domains trigger residual censorship?
* Which networks implement residual censorship?
* Which protocols have residual censorship?
  * TLS
  * HTTP
  * DNS
* How is residual censorship happening?
  * Bad synack
  * Reset
  * Block-page?
  * etc.
* What are the conditions for a flow to qualify for residual censorship?
  * Match 3-tuple?
  * Match 2-tuple?
  * Other?
* What triggers residual censorship?
  * PSH/ACK w/ data             -- pretend censor missed syn, synack, & ack
  * SYN - PSH/ACK w/ data       -- pretend censor missed synack & ack
  * SYN - ACK - PSH/ACK w/ data -- pretend censor missed synack
* Is residual censorship distinguishable from initial censorship?
* How long does residual censorship last?

### Questions NOT answered by this experiment

* Does residual censorship based on src IP alone occur?
  * Sending domain under test to all IPs makes it difficult to know which
    triggered censorship and if it is really only src IP triggering residual response.
* Is residual censorship independent of source IP (i.e is it triggered by dst IP ~& dst port)?
  * we are conducting this from one vantage point (** we could send two and
    capture on the second)
* Does residual censorship preempt primary censorship responses?
  * we don't want to send other potentially censored domains to risk interfering
    with censor state.
* Does residual censorship happen for unidirectional censorship?
  * We cannot measure unidirectional censorship with this technique
* Does residual censorship happen when the primary censorship response requires a COMPLETE tcp handshake?
  * We cannot measure censorship that requires a complete tcp handshake with this technique
