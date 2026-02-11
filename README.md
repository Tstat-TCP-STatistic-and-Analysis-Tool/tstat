Tstat - TCP STatistic and Analysis Tool
======================================


Tstat is a passive sniffer able to provide several insights on 
the traffic patterns at both the network and transport levels. 

Tstat analyzes network traffic and generates three different types of measurement collections:
- **Log files** storing a complete transport-level log of all the measured parameters.
- **Round Robin Database** storing the distribution of a given quantity during a time interval using the RRD interface.


## Installation

Tstat requires various libraries. Install with:
```
sudo apt-get install make libpcap-dev rrdtool librrd-dev cpufrequtils autoconf libtool libnuma-dev libldns-dev tcpreplay
```

Simple install procedure:

```
  git clone git@github.com:Tstat-TCP-STatistic-and-Analysis-Tool/tstat.git tstat
  mv tstat
  ./autogen.sh
  ./configure [--enable-libtstat]   # use --enable-libtstat to build libtstat
  make                                    
  [ Become root if necessary ]
  % make install                            
```

## Documentation

Please refer to the [Wiki](https://github.com/Tstat-TCP-STatistic-and-Analysis-Tool/tstat/wiki) for the documentation regarding all aspects of Tstat.

