# go_syslog_sniffer

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
