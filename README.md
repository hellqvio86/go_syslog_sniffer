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
| Argument | Description                              |
| -------- |:----------------------------------------:| 
| -i       | Interface to listen on. Default eth0     | 
| -p       | Port to listen for                       |   
| -t       | Number of seconds to listen on interface | 
