# Syslog sniffer written in Go
Listens for UDP/TCP traffic, counts the number of packages and takes a sample of the Syslog events and outputs the result in JSON.

## Install

### Dependencies

#### OS packages

```console
sudo apt install golang-go
sudo apt install libpcap-dev
```

#### Golang libraries

```console
go get github.com/google/gopacket
go get github.com/google/gopacket/layers
go get github.com/google/gopacket/pcap
```

## Compile

```console
make build
```

## Commandline arguments
| Argument | Description                              | Default |
| -------- |:----------------------------------------:|:-------:|
| -i       | Interface to listen on                   | eth0    |
| -p       | Port to listen for                       | 514     | 
| -t       | Number of seconds to listen on interface | 60      |

<p align="right">
  <a href="https://www.buymeacoffee.com/olofhellqvc">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" height="48">
  </a>
</p>
