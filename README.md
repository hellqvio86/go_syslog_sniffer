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
go get github.com/vjeantet/grok
```

## Compile
```console
make build
```
