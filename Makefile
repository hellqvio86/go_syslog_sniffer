.PHONY: build clean lint
lint:
	golint .
clean:
	rm sniffer
build:
	go build sniffer.go
sniffer: build