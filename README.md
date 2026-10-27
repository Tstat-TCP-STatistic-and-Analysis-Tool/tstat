Tstat - TCP STatistic and Analysis Tool
======================================


Tstat is a passive sniffer able to provide several insights on 
the traffic patterns at both the network and transport levels. 

Tstat analyzes network traffic and generates three different types of measurement collections:
- **Log files** storing a complete transport-level log of all the measured parameters.
- **Round Robin Database** storing the distribution of a given quantity during a time interval using the RRD interface.


## Installation

Tstat runs on Linux (Ubuntu) and requires a few libraries. Install them with:
```
sudo apt-get install build-essential libpcap-dev libldns-dev libssl-dev librrd-dev
```

Then build and install:

```
  git clone git@github.com:Tstat-TCP-STatistic-and-Analysis-Tool/tstat.git tstat
  cd tstat
  make                  # builds tstat/tstat
  make libtstat         # optional: builds libtstat/libtstat.so (e.g., for tstat-dpdk)
  sudo make install     # installs tstat (and libtstat, if built) under /usr/local
```

Build options, both enabled by default (set them to 0 to disable them, and run `make clean` when changing them):
- `RRD_THREADED`: write the RRD files from a separate thread (suggested for libtstat used by tstat-dpdk)
- `PACKET_STATS`: log statistics on the first segments of each flow (extra columns in `log_tcp_complete` and `log_udp_complete`)

For example, to build tstat without them:
```
  make RRD_THREADED=0 PACKET_STATS=0
```

To build and install libtstat for [tstat-dpdk](https://github.com/Tstat-TCP-STatistic-and-Analysis-Tool/tstat-dpdk):
```
  make all libtstat
  sudo make install && sudo ldconfig
```

Input traces can be uncompressed pcap or pcapng files (or `stdin`, e.g. `zcat trace.pcap.gz | tstat stdin`), or live captures through libpcap (`-l -i <interface>`).

## Classification

TCP flows (`con_t` column of `log_tcp_complete`, bitmask):

| Value | Protocol |
|------:|----------|
| 0 | Unknown |
| 1 | HTTP |
| 2 | RTSP |
| 4 | RTP |
| 16 | RTCP |
| 1024 | SMTP |
| 2048 | POP3 |
| 4096 | IMAP4 |
| 8192 | SSL/TLS |
| 32768 | SSH 2.0/1.99 |
| 65536 | RTMP |

UDP flows (`c_type`/`s_type` columns of `log_udp_complete`):

| Value | Type | Protocol |
|------:|------|----------|
| 0 | UDP_UNKNOWN | Unknown (unclassified) |
| 1 | FIRST_RTP | Unknown (possible unclassified RTP flow) |
| 2 | FIRST_RTCP | Unknown (possible unclassified RTCP flow) |
| 3 | RTP | RTP |
| 4 | RTCP | RTCP |
| 19 | DNS | DNS |
| 26 | UDP_DTLS | DTLS |
| 27 | UDP_QUIC | QUIC |
| 28 | FIRST_RTP_PLUS | Unknown (possible unclassified RTP_PLUS flow) |
| 29 | RTP_PLUS | RTP_PLUS (RTP/RTCP/STUN/DTLS multiplexed flow) |
| 30 | UDP_MTURN | Multiplexed TURN (used by Skype and MS Teams) |

## Logs

- `log_tcp_complete`: TCP connections correctly terminated
- `log_tcp_nocomplete`: TCP connections not properly terminated
- `log_udp_complete`: UDP flows
- `log_mm_complete`: multimedia (RTP/RTCP) flows
- `log_http_complete`: HTTP requests/responses
- `log_dns_complete`: DNS queries/answers
- `log_tcp_periodic`: periodic info on TCP connections
- `log_udp_periodic`: periodic info on UDP flows

Logs are enabled/disabled with the runtime configuration file (`-T`, see `tstat-conf/runtime.conf`).

## Documentation

Please refer to the [Wiki](https://github.com/Tstat-TCP-STatistic-and-Analysis-Tool/tstat/wiki) for the documentation regarding all aspects of Tstat.

