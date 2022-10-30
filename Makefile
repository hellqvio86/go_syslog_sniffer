clean:
	rm sniffer
build:
	go build sniffer.go
.PHONY: build clean